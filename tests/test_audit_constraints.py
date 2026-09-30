import json

import pytest

from audit_support import Capture, client_hello, server_hello, with_extensions, wire
from test_audit_epistemic import finding, known_session
from sms.correlation.constraints import (State, Mode, build_support_matrix,
                                        detect_preference_mode, find_contradictions)
from sms.m8_score import score_session
from sms.pipeline import run_pipeline


def observation(sid, offered=(0xc02f, 0xc030), selected=0xc02f,
                versions=(0x304, 0x303), version=0x304, evidence=True):
    proof = [{"frame": int(sid[1:]), "byte_offset": 60, "byte_length": 2}] if evidence else []
    return {"id": sid, "offered_ciphers": list(offered), "selected_cipher": selected,
            "offered_versions": list(versions), "selected_version": version,
            "selected_cipher_evidence": proof, "selected_version_evidence": proof,
            "offered_cipher_evidence": {code: proof for code in offered},
            "offered_version_evidence": {code: proof for code in versions}}


@pytest.mark.parametrize("mode", list(Mode))
def test_selected_is_demonstrated(mode):
    # Selection is positive even if the observed client list did not include it.
    matrix = build_support_matrix([observation("s1", offered=(0xc030,))], mode)
    print(f"selected mode={mode.value}: cipher={matrix['cipher:0xc02f']['state']} version={matrix['version:0x0304']['state']}")
    assert matrix["cipher:0xc02f"]["state"] == "DEMONSTRATED"
    assert matrix["version:0x0304"]["state"] == "DEMONSTRATED"


def test_exclusion_branches_and_missing_provenance():
    obs = observation("s1", selected=0xc030)
    states = {mode.value: build_support_matrix([obs], mode)["cipher:0xc02f"]["state"] for mode in Mode}
    unproven = build_support_matrix([observation("s1", evidence=False)], Mode.CLIENT_ORDER)
    print("exclusion branches: " + json.dumps(states, sort_keys=True))
    print("selected without byte provenance: " + unproven["cipher:0xc02f"]["state"])
    print("state vocabulary: " + ",".join(state.value for state in State))
    assert states == {"client_order": "EXCLUDED_FIRM", "server_order": "UNDETERMINED", "unknown": "UNDETERMINED"}
    assert unproven["cipher:0xc02f"]["state"] == "UNDETERMINED"


def test_preference_controls():
    a = observation("s1")
    reversed_first = observation("s2", offered=(0xc030, 0xc02f), selected=0xc030)
    reversed_same = observation("s2", offered=(0xc030, 0xc02f), selected=0xc02f)
    alternative = observation("s3", offered=(0xc030,), selected=0xc030)
    cases = {"one": [a], "opposite_client_first": [a, reversed_first],
             "opposite_same_selection": [a, reversed_same],
             "opposite_plus_proven_alternative": [a, reversed_same, alternative]}
    result = {name: detect_preference_mode(rows)[0].value for name, rows in cases.items()}
    print("preference: " + json.dumps(result, sort_keys=True))
    assert result == {"one": "unknown", "opposite_client_first": "client_order",
                      "opposite_same_selection": "unknown",
                      "opposite_plus_proven_alternative": "server_order"}


def test_contradictions_are_order_independent():
    positive = observation("s1")
    negative = observation("s2", version=0x303)
    forward = build_support_matrix([positive, negative], Mode.UNKNOWN)
    reverse = build_support_matrix([negative, positive], Mode.UNKNOWN)
    result = find_contradictions(forward)
    print("matrix contradictions: " + json.dumps(result, sort_keys=True))
    assert forward == reverse
    assert forward["version:0x0304"]["state"] == "CONTRADICTED"
    assert result[0]["demonstrated_in"] == ["s1"]
    assert result[0]["excluded_in"] == ["s2"]


def test_pipeline_emits_inconsistency_finding(tmp_path):
    cap = Capture().hello()
    # s2 offers TLS 1.3 in a form a server could accept (supported_groups and
    # a key_share, plus a TLS 1.3 suite) and still gets TLS 1.2: a firm
    # exclusion that contradicts s1's TLS 1.3 at the same service.
    usable_tls13_offer = with_extensions(client_hello(), wire._ext(43, b"\x04\x03\x04\x03\x03")
                                         + wire._ext(10, b"\x00\x02\x00\x1d")
                                         + wire._ext(51, b"\x00\x24\x00\x1d\x00\x20" + b"\x42" * 32))
    cap.add("c", usable_tls13_offer, port=40001)
    cap.add("s", server_hello(wire.V_TLS12, 0xc02f, None), port=40001)
    report = run_pipeline(cap.write(tmp_path / "contradiction.pcap"), ml=False)
    print("pipeline contradiction: " + json.dumps({"contradictions": report["servers"][0]["contradictions"],
          "finding_ids": [f["rule_id"] for f in report["findings"]],
          "observed_risk": report["observed_risk"]}, sort_keys=True))
    assert "SERVER-INCONSISTENT" in {f["rule_id"] for f in report["findings"]}


def test_hypothetical_likely_exclusion_is_inert():
    s = known_session()
    s.findings = [finding("INFERRED", "EXCLUDED_LIKELY", "critical")]
    score_session(s)
    print(f"injected INFERRED EXCLUDED_LIKELY risk={s.observed_risk}; production state absent={not hasattr(State, 'EXCLUDED_LIKELY')}")
    assert s.observed_risk == 0
    assert not hasattr(State, "EXCLUDED_LIKELY")
