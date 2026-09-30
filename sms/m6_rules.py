"""Rule catalog + finding construction for TLS/certificate facts.

CLEARTEXT-AUTH, STARTTLS-STRIP-SUSPECTED and STARTTLS-NOT-OFFERED are already
emitted by m3_transition (they need that module's own state-machine
evidence). This module only emits findings derivable from the m4_tls/m5_x509
facts: TLS version, downgrade, cipher, key exchange, certificate, and the
hybrid-PQ differentiator.

Rule metadata (severity, confidence_band, RFC citation, remediation) lives in
rules/*.yaml, as individual mappings or lists of rule mappings. YAML remains
data: v1.5 conditions use the ported closed-grammar evaluator, never eval/exec.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from .contracts import Evidence, Finding, Session
from .judgement.conditions import ConditionError, evaluate
from .judgement.epistemic import Tier, admit_finding, require_tier

_LOGGER = logging.getLogger(__name__)
_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
_BAND_CONFIDENCE = {"certain": 1.0, "inferred": 0.75, "anomaly": 0.5}
_RULE_FIELDS = (
    "rule_id", "severity", "confidence_band", "what", "why", "fix",
    "remediation_effort", "references",
)


def _load_rule_file(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"{path}: invalid YAML: {exc}") from exc


def _load_rules() -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for path in sorted(_RULES_DIR.glob("*.yaml")):
        document = _load_rule_file(path)
        if isinstance(document, dict) and "rule_id" in document:
            entries = [document]
        elif isinstance(document, list) and any(
            isinstance(item, dict) and any(key in item for key in _RULE_FIELDS)
            for item in document
        ):
            entries = document
        else:
            _LOGGER.debug("Skipping non-rule YAML file: %s", path)
            continue

        for index, rule in enumerate(entries, start=1):
            if not isinstance(rule, dict):
                raise ValueError(f"{path}: rule {index} must be a mapping")
            # Legacy finding metadata and v1.5 conditional rules have distinct
            # contracts. Preserve both without inventing confidence or fixes.
            extra_fields = ("tier", "condition") if "tier" in rule or "condition" in rule \
                else ("confidence", "remediation_id")
            missing = [
                key for key in (*_RULE_FIELDS, *extra_fields)
                if key not in rule or rule[key] is None
                or (isinstance(rule[key], str) and not rule[key].strip())
            ]
            if missing:
                raise ValueError(f"{path}: rule {index} missing required fields: {', '.join(missing)}")
            if not isinstance(rule["rule_id"], str):
                raise ValueError(f"{path}: rule {index} field rule_id must be a string")
            condition = rule.get("condition")
            if condition is not None:
                if not isinstance(condition, str):
                    raise ValueError(
                        f"{path}: rule {index} condition must be a string"
                    )
                try:
                    evaluate(condition, {})
                except ConditionError as error:
                    raise ValueError(
                        f"{path}: rule {index} has invalid condition: {error}"
                    ) from error
            if "tier" in rule:
                try:
                    Tier(rule["tier"])
                except ValueError as error:
                    raise ValueError(
                        f"{path}: rule {index} has invalid tier: {rule['tier']!r}"
                    ) from error
            rules[rule["rule_id"]] = rule
    return rules


_RULES = _load_rules()


def _escalate(severity: str) -> str:
    index = _SEVERITY_ORDER.index(severity)
    return _SEVERITY_ORDER[min(index + 1, len(_SEVERITY_ORDER) - 1)]


# The tiered session facts each rule reads. A finding can be no more certain
# than the weakest of them, and M8 admits risk on the finding's tier alone.
_SOURCE_FACTS = {
    "TLS-VER-DEPRECATED": ("tls.negotiated_version",),
    "DOWNGRADE-DELTA": ("tls.negotiated_version",),
    "CIPHER-CBC": ("tls.cipher",),
    "KEX-NO-FS": ("tls.negotiated_version", "tls.forward_secrecy"),
    "CERT-EXPIRED": ("certificate.status",),
    "CERT-SELF-SIGNED": ("certificate.status",),
    "CERT-WEAK-KEY": ("certificate.key_strength",),
    "PQ-HYBRID-OBSERVED": ("tls.group", "tls.hybrid_pq_flag"),
    "TLS13-NO-FORWARD-SECRECY": ("tls.negotiated_version", "tls.forward_secrecy"),
    # "Not provided" is established only by the server's own ServerHello.
    "TLS-NO-OCSP-STAPLING": ("tls.negotiated_version",),
}
_TIER_RANK = {Tier.OBSERVED: 0, Tier.DEDUCED: 1, Tier.INFERRED: 2, Tier.NOT_OBSERVABLE: 3}


def _finding(rule_id: str, session: Session, evidence: list[Evidence], *, severity: str | None = None) -> Finding:
    rule = _RULES[rule_id]
    # A rule fires on a registry classification; its text may name the group
    # only through the registry name of the code point this session selected.
    what = rule["what"].replace("{group}", session.tls.group or "unidentified group")
    tier = max(
        [Tier(rule.get("tier", Tier.OBSERVED.value))] + [
            require_tier({"key": key, "tier": session.fact_tiers.get(key)})
            for key in _SOURCE_FACTS.get(rule_id, ())
        ],
        key=_TIER_RANK.__getitem__,
    )
    return Finding(
        rule_id=rule_id, tier=tier.value,
        confidence_band=rule["confidence_band"],
        severity=severity or rule["severity"],
        confidence=float(rule.get("confidence", _BAND_CONFIDENCE[rule["confidence_band"]])),
        what=what, why=rule["why"], fix=rule["fix"],
        remediation_id=rule.get("remediation_id", rule_id.lower().replace("-", "_")),
        remediation_effort=rule["remediation_effort"],
        affected_sessions=[session.id], evidence=list(evidence), references=list(rule["references"]),
    )


_DEPRECATED_VERSIONS = frozenset({"SSL3.0", "TLS1.0", "TLS1.1"})

_SIGNAL_EVIDENCE = {
    "TLS-DOWNGRADE-ANOMALY": "downgrade_anomaly",
    "TLS-LEGACY-CLIENT": "downgrade_legacy_client",
    "TLS-FALLBACK-RETRY": "has_fallback_scsv",
    "TLS13-NO-FORWARD-SECRECY": "forward_secrecy",
    "TLS13-EARLY-DATA": "early_data_offered",
    "TLS-ECH-IN-USE": "ech_offered",
    "TLS-NO-OCSP-STAPLING": "ocsp_stapling",
    "SERVER-INCONSISTENT": "server_contradictions",
}


def _apply_conditional_rules(session: Session, tls_evidence: dict) -> None:
    """Evaluate every v1.5 condition against a closed, deterministic fact map."""
    tls_facts = session.tls.to_dict()
    tls_facts.update(session.tls.signal_facts())
    # Reports retain the nullable compatibility boolean; conditional rules
    # consume the reference tri-state classification.
    tls_facts["forward_secrecy"] = (
        session.tls.forward_secrecy_status
        if session.tls.negotiated_version == "TLS1.3" else "UNKNOWN"
    )
    facts = {
        "tls": tls_facts,
        # P3 correlation populates this after apply_rules; apply_server_rules
        # re-evaluates once it exists. Before P3, empty is the honest value.
        "server": {"contradictions": getattr(session, "server_contradictions", [])},
    }
    for rule_id, rule in _RULES.items():
        condition = rule.get("condition")
        if condition is None or not evaluate(condition, facts):
            continue
        evidence = list(tls_evidence.get(_SIGNAL_EVIDENCE[rule_id], []))
        # Conditional findings require exact packet evidence, including
        # provenance for deduced server facts.
        if evidence:
            admit_finding(session, _finding(rule_id, session, evidence))


def apply_rules(session: Session) -> Session:
    """Append TLS/certificate findings to a session already analysed by
    m3_transition, m4_tls and m5_x509. Idempotent: safe to call once."""
    tls_evidence = getattr(session, "_tls_evidence", {})
    cert_evidence = getattr(session, "_cert_evidence", [])
    tls, cert = session.tls, session.certificate

    if tls.negotiated_version in _DEPRECATED_VERSIONS:
        # A big offered/negotiated gap on top of an already-deprecated
        # version is the "active downgrade" signal, not just an old default.
        severity = _escalate(_RULES["TLS-VER-DEPRECATED"]["severity"]) \
            if tls.downgrade_delta is not None and tls.downgrade_delta >= 2 \
            else _RULES["TLS-VER-DEPRECATED"]["severity"]
        admit_finding(session, _finding(
            "TLS-VER-DEPRECATED", session, tls_evidence.get("negotiated_version", []), severity=severity))

    if tls.downgrade_delta is not None and tls.downgrade_delta >= 2:
        evidence = list(tls_evidence.get("offered_version", [])) + list(tls_evidence.get("negotiated_version", []))
        admit_finding(session, _finding("DOWNGRADE-DELTA", session, evidence))

    if tls_evidence.get("cipher_is_cbc"):
        admit_finding(session, _finding("CIPHER-CBC", session, tls_evidence.get("cipher", [])))

    # TLS <= 1.2 forward secrecy is established by the negotiated cipher suite.
    # Only an explicit NO supports a finding: an unregistered cipher is a
    # coverage gap, not evidence of static key exchange.
    if tls.negotiated_version is not None and tls.negotiated_version != "TLS1.3" \
            and tls.forward_secrecy_status == "NO":
        admit_finding(session, _finding("KEX-NO-FS", session, tls_evidence.get("cipher", [])))

    if cert.status == "INVALID" and cert.expired:
        admit_finding(session, _finding("CERT-EXPIRED", session, cert_evidence))

    if cert.status == "INVALID" and cert.self_signed:
        admit_finding(session, _finding("CERT-SELF-SIGNED", session, cert_evidence))

    if cert.key_strength == "INVALID":
        admit_finding(session, _finding("CERT-WEAK-KEY", session, cert_evidence))

    if tls.hybrid_pq_flag:
        admit_finding(session, _finding("PQ-HYBRID-OBSERVED", session, tls_evidence.get("group", [])))

    _apply_conditional_rules(session, tls_evidence)

    return session


def apply_server_rules(sessions: list[Session], servers: list[dict]) -> None:
    """Evaluate rules conditioned on P3 server correlation, which runs after
    apply_rules. Only a session holding one side of a contradiction receives
    SERVER-INCONSISTENT; its evidence cites the bytes of both sides."""
    by_id = {session.id: session for session in sessions}
    for server in servers:
        matrix = server.get("support_matrix", {})
        for session_id in server.get("sessions", []):
            evidence = [
                Evidence(item["frame"], "tls.server_contradiction", item["byte_offset"],
                         item["byte_length"],
                         f"{contradiction['capability']} {item['kind']} in {item['session']}")
                for contradiction in server.get("contradictions", [])
                if session_id in contradiction["demonstrated_in"]
                or session_id in contradiction["excluded_in"]
                for item in matrix[contradiction["capability"]]["establishing_evidence"]
            ]
            if evidence:
                session = by_id[session_id]
                _apply_conditional_rules(session, {
                    **getattr(session, "_tls_evidence", {}),
                    "server_contradictions": evidence,
                })


apply_ruleset = apply_rules
