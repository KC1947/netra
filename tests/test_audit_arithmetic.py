from copy import deepcopy
import json

import pytest

from audit_support import Capture, client_hello, server_hello, wire
from test_audit_epistemic import known_session, finding
from sms.m9_report import build_report
from sms.m8_score import _scoring_facts, score_report, score_session, compute_hndl


def test_capture_coverage_is_pooled(tmp_path):
    cap = Capture().hello(version=wire.V_TLS10, cipher=0x002f, group=None)
    cap.add("s", wire.app_data(random_bytes=lambda n: b"\x42" * n), port=40001)
    report = build_report(cap.write(tmp_path / "unequal-denominators.pcap"), ml=False)
    pools = [_scoring_facts(s) for s in report.sessions]
    n = sum(f["tier"] == "OBSERVED" and f["adequate"] for pool in pools for f in pool)
    d = sum(map(len, pools))
    mean = round(sum(s.evidence_coverage for s in report.sessions) / len(pools))
    print(json.dumps({"counts": [len(p) for p in pools],
                      "session_coverage": [s.evidence_coverage for s in report.sessions],
                      "pooled_fraction": f"{n}/{d}", "pooled": round(100*n/d),
                      "mean": mean, "actual": report.evidence_coverage}, sort_keys=True))
    assert report.evidence_coverage == round(100*n/d)
    assert abs(report.evidence_coverage - mean) >= 15


def test_missing_evidence_both_directions():
    full = known_session()
    full.findings = [finding("OBSERVED")]
    missing = deepcopy(full)
    missing.fact_tiers["protocol"] = "NOT_OBSERVABLE"
    missing.tls.ech_offered = True
    missing.fact_tiers["tls.ech_identity"] = "NOT_OBSERVABLE"
    empty = known_session()
    empty.fact_tiers = {k: "NOT_OBSERVABLE" for k in empty.fact_tiers}
    for session in (full, missing, empty):
        score_session(session)
    scores = [score_report(pool) for pool in ([full], [missing], [full, empty])]
    print("missing evidence (full/replaced/added session): " + json.dumps(scores, sort_keys=True))
    assert {s["observed_risk"] for s in scores} == {17}
    assert scores[1]["evidence_coverage"] < scores[0]["evidence_coverage"]
    assert scores[2]["evidence_coverage"] < scores[0]["evidence_coverage"]


def test_hndl_unknowns_and_uncommon_pq(tmp_path):
    cap = Capture().hello(group=0x11ed)
    cap.hello(port=40001, group=29)
    cap.hello(port=40002, group=0xbeef)
    cap.hello(port=40003, group=None, version=wire.V_TLS12, cipher=0xbeef)
    cap.add("s", wire.app_data(random_bytes=lambda n: b"\x42" * n), port=40004)
    report = build_report(cap.write(tmp_path / "hndl-controls.pcap"), ml=False)
    print("HNDL controls: " + json.dumps(report.hndl, sort_keys=True))
    hybrid = report.sessions[0]
    print(f"uncommon hybrid: group={hybrid.tls.group} class={hybrid.tls.group_class}")
    assert report.hndl["total_sessions"] == 2
    assert report.hndl["exposed_sessions"] == 1
    assert report.hndl["quantum_safe_sessions"] == 1
    assert report.hndl["unobservable_sessions_excluded"] == 3
    hybrid.tls.group = "arbitrary display label"
    print("renamed hybrid HNDL: " + json.dumps(compute_hndl([hybrid]), sort_keys=True))
    assert compute_hndl([hybrid])["quantum_safe_sessions"] == 1


def test_hndl_excludes_missing_server_hello(tmp_path):
    cap = Capture().hello(group=0x11ed)
    cap.starttls(port=40001)
    cap.add("c", client_hello(), port=40001, server_port=25)
    report = build_report(cap.write(tmp_path / "incomplete-starttls.pcap"), ml=False)
    s = report.sessions[1]
    print("incomplete STARTTLS: " + json.dumps({"verdict": s.transition.verdict,
          "negotiated": s.tls.negotiated_version, "tier": s.fact_tiers["tls.negotiated_version"],
          "hndl": report.hndl}, sort_keys=True))
    assert report.hndl["total_sessions"] == 1
    assert report.hndl["exposed_sessions"] == 0
    assert report.hndl["unobservable_sessions_excluded"] == 1


def test_hndl_excludes_nonobservable_populated_group(tmp_path):
    report = build_report(Capture().hello(group=0x11ed).write(tmp_path / "pq.pcap"), ml=False)
    s = report.sessions[0]
    for key in ("tls.group", "tls.hybrid_pq_flag"):
        s.fact_tiers[key] = "NOT_OBSERVABLE"
    result = compute_hndl([s])
    print("nonobservable populated group: " + json.dumps(result, sort_keys=True))
    assert result["total_sessions"] == result["quantum_safe_sessions"] == 0
