"""Audit probes: xfails assert desired behavior and reproduce unfixed engine bugs."""
from copy import deepcopy
import json
from pathlib import Path
import ast

import pytest

from sms.contracts import Evidence, Finding, Session
from sms.judgement.epistemic import UntieredFactError, admit_finding
from sms.m6_rules import apply_rules
from sms.m8_score import score_session, score_report
from sms.m9_report import analyse_sessions


def finding(tier, rule="AUDIT", severity="high"):
    return Finding(rule, "certain", severity, 1.0, "audit", "audit", "audit",
                   "audit", "one_line_reload", tier=tier,
                   affected_sessions=["audit"],
                   evidence=[Evidence(1, "audit.synthetic", 0, 1)])


def known_session():
    s = Session("audit", {"server_ip": "192.0.2.2", "server_port": 25,
                          "client_ip": "192.0.2.1", "client_port": 40000})
    s.protocol, s.protocol_confidence = "smtp", "certain"
    s.transition.verdict, s.transition.confidence_band = "not_used", "certain"
    s.fact_tiers.update({"protocol": "OBSERVED", "transition.verdict": "OBSERVED"})
    return s


@pytest.mark.parametrize("route", ["finding", "fact", "association"])
def test_untiered_rejected(route):
    s = known_session()
    if route == "finding":
        s.findings = [finding(None)]
    elif route == "fact":
        del s.fact_tiers["protocol"]
    else:
        s.certificate_seen_on_service = [{"fingerprint": "audit"}]
    for scorer in (lambda: score_session(s), lambda: score_report([s])):
        with pytest.raises(UntieredFactError) as error:
            scorer()
        print(f"untiered {route}: {type(error.value).__name__}: {error.value}")


@pytest.mark.parametrize("tier", ["INFERRED", "NOT_OBSERVABLE"])
@pytest.mark.parametrize("route", ["weighted_finding", "auth_floor", "version_floor", "association"])
def test_direct_tier_gate(tier, route):
    s = known_session()
    if route == "weighted_finding":
        s.findings = [finding(tier, severity="critical")]
    elif route == "auth_floor":
        s.findings = [finding(tier, "CLEARTEXT-AUTH", "critical")]
    elif route == "version_floor":
        s.transition.verdict = "upgraded"
        s.tls.negotiated_version = "TLS1.0"
        s.fact_tiers["tls.negotiated_version"] = tier
    else:
        s.certificate_seen_on_service = [{"fingerprint": "audit", "tier": tier}]
    score_session(s)
    aggregate = score_report([s])
    print(f"direct {tier} {route}: session_risk={s.observed_risk} report_risk={aggregate['observed_risk']}")
    assert s.observed_risk == aggregate["observed_risk"] == 0


def test_not_observable_lowers_coverage_only():
    full = known_session()
    full.findings = [finding("OBSERVED")]
    missing = deepcopy(full)
    missing.fact_tiers["protocol"] = "NOT_OBSERVABLE"
    added = deepcopy(full)
    added.findings += [finding("NOT_OBSERVABLE", "UNAVAILABLE", "critical")]
    for s in (full, missing, added):
        score_session(s)
    values = [(s.observed_risk, s.evidence_coverage) for s in (full, missing, added)]
    print(f"NOT_OBSERVABLE full/replaced/added (risk,coverage)={values}")
    assert full.observed_risk == missing.observed_risk == added.observed_risk
    assert missing.evidence_coverage < full.evidence_coverage
    assert added.evidence_coverage < full.evidence_coverage


@pytest.fixture(scope="module")
def sample_sessions():
    return analyse_sessions("out/sample.pcap")


@pytest.mark.parametrize("tier", ["INFERRED", "NOT_OBSERVABLE"])
@pytest.mark.parametrize("route", ["version", "forward_secrecy", "certificate"])
def test_rules_preserve_source_tier(sample_sessions, tier, route):
    s = known_session()
    s.transition.verdict = "upgraded"
    s.tls.negotiated_version = "TLS1.2"
    s.fact_tiers["tls.negotiated_version"] = "OBSERVED"
    s.certificate.status = "NOT_OBSERVABLE"
    legacy, expired = sample_sessions[1], sample_sessions[4]
    if route == "version":
        s.tls.negotiated_version = "TLS1.0"
        s.fact_tiers["tls.negotiated_version"] = tier
        s._tls_evidence = {"negotiated_version": legacy._tls_evidence["negotiated_version"]}
    elif route == "forward_secrecy":
        s.tls.forward_secrecy_status = "NO"
        s.fact_tiers["tls.forward_secrecy"] = tier
        s._tls_evidence = {"cipher": legacy._tls_evidence["cipher"]}
    else:
        s.certificate.status, s.certificate.expired = "INVALID", True
        s.fact_tiers["certificate.status"] = tier
        s._cert_evidence = expired._cert_evidence
    score_session(s)
    before = s.observed_risk
    apply_rules(s)
    score_session(s)
    print(json.dumps({"route": route, "source_tier": tier, "before": before,
                      "after": s.observed_risk,
                      "report_risk": score_report([s])["observed_risk"],
                      "findings": [(f.rule_id, f.tier) for f in s.findings]}, sort_keys=True))
    assert s.observed_risk == before == 0


def test_finding_mutation_inventory():
    mutations, constructors, admission_calls = [], [], []
    def targets_findings(node):
        return any(
            (isinstance(part, ast.Attribute) and part.attr == "findings")
            or (isinstance(part, ast.Name) and part.id == "findings")
            or (isinstance(part, ast.Subscript) and isinstance(part.slice, ast.Constant)
                and part.slice.value == "findings")
            for part in ast.walk(node)
        )
    for root in (Path("sms"), Path("server")):
        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    target = ast.unparse(node.func)
                    if target == "Finding":
                        constructors.append(f"{path}:{node.lineno}")
                    if target == "admit_finding":
                        admission_calls.append(f"{path}:{node.lineno}")
                    if isinstance(node.func, ast.Attribute) and node.func.attr in {
                        "append", "extend", "insert", "__setitem__", "update"}:
                        if targets_findings(node.func.value):
                            mutations.append(f"{path}:{node.lineno}:{target}")
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, (ast.Attribute, ast.Subscript)) and targets_findings(target):
                            mutations.append(f"{path}:{node.lineno}:{ast.unparse(target)} assignment")
    print(json.dumps({"mutations": mutations, "Finding_constructors": constructors,
                      "admission_calls": admission_calls}, sort_keys=True))
    assert mutations == ["sms/judgement/epistemic.py:61:session.findings.append"]
