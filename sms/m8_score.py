"""Two independent scores per session (never one grade) + the capture-level
HNDL differentiator.

Missing or unobservable evidence only ever lowers evidence_coverage; it must
never lower observed_risk.
"""

from __future__ import annotations

import math

from .contracts import Session
from .judgement.epistemic import AFFECTS_RISK_VALUES, Tier, partition, require_tier
from .registry import load as load_registry

_SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}
_DEPRECATED_VERSIONS = frozenset({"SSL3.0", "TLS1.0", "TLS1.1"})


def _exposure(affected_sessions: int) -> float:
    return 1 + min(1, math.log10(max(1, affected_sessions)) / 2)


def _raw_risk(facts: list[dict]) -> float:
    return sum(
        _SEVERITY_WEIGHT[finding.severity] * finding.confidence * _exposure(len(finding.affected_sessions))
        for fact in facts
        if fact.get("kind") == "finding"
        for finding in [fact["finding"]]
    )


def _risk_floor(facts: list[dict]) -> int:
    if any(fact.get("rule_id") == "CLEARTEXT-AUTH" for fact in facts):
        return 90
    if any(
        fact.get("key") == "tls.negotiated_version"
        and fact.get("value") in _DEPRECATED_VERSIONS
        for fact in facts
    ):
        return 80
    return 0


def _fact(session: Session, key: str, value, adequate: bool = True) -> dict:
    """Build one score input from the tier stamped by its producing stage."""
    return {
        "key": key,
        "value": value,
        "tier": session.fact_tiers.get(key),
        "adequate": adequate,
    }


def _scoring_facts(session: Session) -> list[dict]:
    """Collect only applicable score inputs; every one must be tiered."""
    facts = [
        {
            "kind": "finding",
            "rule_id": finding.rule_id,
            "finding": finding,
            "tier": finding.tier,
            "adequate": finding.tier != Tier.NOT_OBSERVABLE.value,
        }
        for finding in session.findings
    ]
    facts.extend({
        "kind": "association",
        "key": "certificate_seen_on_service",
        "value": association.get("fingerprint"),
        "tier": association.get("tier"),
        "adequate": True,
    } for association in session.certificate_seen_on_service)
    facts.extend([
        _fact(
            session, "protocol", session.protocol,
            session.protocol_confidence != "unknown",
        ),
        _fact(
            session, "transition.verdict", session.transition.verdict,
            session.transition.confidence_band is not None,
        ),
    ])
    if session.transition.verdict in {"upgraded", "failed"}:
        facts.append(_fact(
            session, "tls.negotiated_version", session.tls.negotiated_version,
            session.tls.negotiated_version is not None,
        ))
    if session.tls.negotiated_version is not None:
        facts.append(_fact(
            session, "tls.forward_secrecy", session.tls.forward_secrecy_status,
            session.tls.forward_secrecy_status in {"YES", "NO"},
        ))
        facts.append(_fact(
            session, "certificate.status", session.certificate.status,
            session.certificate.status in {"VALID", "INVALID"},
        ))
        if session.certificate.status != "NOT_OBSERVABLE":
            facts.append(_fact(
                session, "certificate.key_strength", session.certificate.key_strength,
                session.certificate.key_strength != "NOT_OBSERVABLE",
            ))
    if session.tls.ech_offered:
        facts.append(_fact(session, "tls.ech_identity", None, False))
    return facts


def _coverage_scores(facts: list[dict]) -> tuple[int, int, int]:
    if not facts:
        return 100, 0, 0
    denominator = len(facts)
    observed = deduced = inferred = 0
    for fact in facts:
        if not fact.get("adequate", False):
            continue
        tier = require_tier(fact)
        observed += tier == Tier.OBSERVED
        deduced += tier == Tier.DEDUCED
        inferred += tier == Tier.INFERRED
    return (
        round(100 * observed / denominator),
        round(100 * deduced / denominator),
        round(100 * inferred / denominator),
    )


def _observed_risk(facts: list[dict]) -> int:
    buckets = partition(facts)
    raw = _raw_risk(buckets["risk"])
    normalized = round(100 * raw / (raw + 100))
    return max(normalized, _risk_floor(buckets["risk"]))


def score_report(sessions: list[Session]) -> dict[str, int]:
    """Score the capture-wide fact pool without averaging session scores."""
    facts = [fact for session in sessions for fact in _scoring_facts(session)]
    evidence, deduced, inferred = _coverage_scores(facts) if facts else (0, 0, 0)
    return {
        "observed_risk": _observed_risk(facts),
        "evidence_coverage": evidence,
        "deduced_coverage": deduced,
        "inferred_coverage": inferred,
    }


def score_session(session: Session) -> Session:
    facts = _scoring_facts(session)
    session.observed_risk = _observed_risk(facts)

    (session.evidence_coverage,
     session.deduced_coverage,
     session.inferred_coverage) = _coverage_scores(facts)
    return session


def score_sessions(sessions: list[Session]) -> list[Session]:
    for session in sessions:
        score_session(session)
    return sessions


def _established(session: Session, *keys: str) -> bool:
    # Only risk-eligible tiers may establish transport or key exchange; a
    # populated value tiered INFERRED or NOT_OBSERVABLE establishes nothing.
    return all(session.fact_tiers.get(key) in AFFECTS_RISK_VALUES for key in keys)


def is_encrypted(session: Session) -> bool:
    """A TLS negotiation was established from a captured ServerHello."""
    return (session.tls.negotiated_version is not None
            and _established(session, "tls.negotiated_version"))


def is_cleartext(session: Session) -> bool:
    """Mail grammar was observed and TLS never started.

    No negotiated version is not cleartext once TLS started (upgraded:
    STARTTLS accepted then a TLS record, or implicit TLS). That is a handshake
    the capture did not complete, which is NOT_OBSERVABLE, and so is a session
    whose protocol grammar was never established.
    """
    return (session.protocol in {"smtp", "imap", "pop3"}
            and _established(session, "protocol")
            and session.tls.negotiated_version is None
            and session.transition.verdict != "upgraded"
            # A failed upgrade is cleartext only where the failure was observed.
            and (session.transition.verdict != "failed"
                 or _established(session, "transition.verdict")))


def compute_hndl(sessions: list[Session]) -> dict:
    """Report HNDL only where transport/key-exchange evidence supports it.

    Cleartext mail is observable and exposed. TLS 1.3 needs its ServerHello
    key-share group to establish whether hybrid PQ was used; older TLS needs a
    negotiated cipher suite, which establishes its non-hybrid key exchange.
    Mid-stream/unknown traffic is deliberately outside the fraction.
    """
    established, cleartext = _established, is_cleartext

    def key_exchange_observable(session: Session) -> bool:
        if session.tls.negotiated_version is None:
            return False
        if not established(session, "tls.negotiated_version"):
            return False
        if session.tls.negotiated_version == "TLS1.3":
            # Preserve the public library contract for callers that populate
            # only the historical group name, while excluding code points the
            # registry explicitly classified as UNKNOWN.
            return (established(session, "tls.group")
                    and session.tls.group is not None and session.tls.group_class != "UNKNOWN")
        # Identified by the registry, never by how the name happens to be spelled.
        return (established(session, "tls.cipher")
                and session.tls.cipher in load_registry().cipher_codes_by_name)

    def quantum_safe_key_exchange(session: Session) -> bool:
        """Decide this from the registry classification, never a group name.

        ``hybrid_pq_flag`` is ``registry.is_pq_hybrid``, so every RFC 10024
        hybrid group qualifies -- X25519MLKEM768 and both SecP variants -- while
        the obsolete Kyber drafts, classical groups and unclassifiable code
        points do not. Naming one group here would silently under-count the
        other two.
        """
        return (session.tls.hybrid_pq_flag
                and established(session, "tls.hybrid_pq_flag")
                and session.tls.group is not None
                and session.tls.group_class != "UNKNOWN")

    for session in sessions:
        # HNDL consumes these facts directly. Partitioning enforces their tier
        # contract even though HNDL retains its established observable-set math.
        partition([
            _fact(session, "protocol", session.protocol),
            _fact(session, "tls.negotiated_version", session.tls.negotiated_version),
            _fact(session, "tls.cipher", session.tls.cipher),
            _fact(session, "tls.group", session.tls.group),
            _fact(session, "tls.hybrid_pq_flag", session.tls.hybrid_pq_flag),
        ])

    observable = [session for session in sessions if cleartext(session) or key_exchange_observable(session)]
    total = len(observable)
    quantum_safe = sum(1 for session in observable
                       if quantum_safe_key_exchange(session))
    exposed = total - quantum_safe
    unobservable = len(sessions) - total
    assert exposed + quantum_safe == total
    percent = round(100 * exposed / total) if total else 0
    return {
        "exposed_sessions": exposed,
        "quantum_safe_sessions": quantum_safe,
        "total_sessions": total,
        "unobservable_sessions": unobservable,
        "unobservable_sessions_excluded": unobservable,
        "percent": percent,
    }
