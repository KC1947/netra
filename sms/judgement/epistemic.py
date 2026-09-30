"""The enforced epistemic model for facts that can reach scoring."""

from __future__ import annotations

from enum import Enum


class Tier(str, Enum):
    OBSERVED = "OBSERVED"
    DEDUCED = "DEDUCED"
    INFERRED = "INFERRED"
    NOT_OBSERVABLE = "NOT_OBSERVABLE"


class UntieredFactError(Exception):
    """A fact reached scoring without a recognised tier."""


AFFECTS_RISK = frozenset({Tier.OBSERVED, Tier.DEDUCED})
# The same set as raw strings, for callers holding a serialized tier.
AFFECTS_RISK_VALUES = frozenset(tier.value for tier in AFFECTS_RISK)
AFFECTS_INFERRED = frozenset({Tier.INFERRED})
AFFECTS_COVERAGE = frozenset({Tier.NOT_OBSERVABLE})


def require_tier(fact: dict) -> Tier:
    tier = fact.get("tier")
    if tier is None:
        raise UntieredFactError(
            f"fact {fact.get('rule_id') or fact.get('key') or fact!r} has no tier"
        )
    try:
        return Tier(tier)
    except ValueError as error:
        raise UntieredFactError(f"unknown tier {tier!r}") from error


def may_affect_risk(fact: dict) -> bool:
    return require_tier(fact) in AFFECTS_RISK


def admit_finding(session, finding) -> None:
    """Append a finding to a session, enforcing the evidence/tier contract.

    Every finding in the engine passes through here, so the rule is structural
    rather than repeated per rule. OBSERVED and DEDUCED are the tiers m8 admits
    to ``observed_risk``, which makes them claims about specific bytes. A finding
    with no evidence has no bytes to point at, so it cannot hold one: it is
    demoted to NOT_OBSERVABLE, which lowers ``evidence_coverage`` and
    contributes no risk, and a reason code records why.

    Duplicate rule ids are dropped, preserving the previous append-once
    behaviour of the two call sites this replaces.
    """
    if not finding.evidence and finding.tier in AFFECTS_RISK_VALUES:
        finding.tier = Tier.NOT_OBSERVABLE.value
        key = f"finding.{finding.rule_id}"
        session.fact_tiers[key] = Tier.NOT_OBSERVABLE.value
        session.fact_reason_codes[key] = "not_present_in_capture"
    if not any(item.rule_id == finding.rule_id for item in session.findings):
        session.findings.append(finding)


def partition(facts: list[dict]) -> dict[str, list[dict]]:
    """Split facts by permitted influence, rejecting every untiered fact."""
    result = {"risk": [], "inferred": [], "coverage": []}
    for fact in facts:
        tier = require_tier(fact)
        if tier in AFFECTS_RISK:
            result["risk"].append(fact)
        elif tier in AFFECTS_INFERRED:
            result["inferred"].append(fact)
        else:
            result["coverage"].append(fact)
    return result
