import json
import dpkt
import pytest

from audit_support import (Capture, FIXTURES, client_hello, server_hello, wire,
                           bounded_report, session_summary, with_extensions)


def report_case(name, capture):
    report = bounded_report(capture.write(FIXTURES / f"audit_{name}.pcap"))
    print(name + ": " + json.dumps(session_summary(report), sort_keys=True))
    return report


@pytest.mark.parametrize("new_syn", [True, pytest.param(False, marks=pytest.mark.xfail(
    strict=True, reason="AUD-04: RST only splits when next SYN is captured"))])
def test_a_port_reuse_after_rst(new_syn):
    cap = Capture()
    cap.add("c", flags=dpkt.tcp.TH_SYN, seq=999).hello(group=0x11ed)
    cap.add("s", flags=dpkt.tcp.TH_RST)
    if new_syn:
        cap.add("c", flags=dpkt.tcp.TH_SYN, seq=999)
    cap.add("c", client_hello(), seq=1000)
    cap.add("s", server_hello(wire.V_TLS10, 0x002f, None), seq=8000)
    report = report_case(f"rst_reuse_{'syn' if new_syn else 'no_syn'}", cap)
    assert len(report["sessions"]) == 2
    assert [s["tcp_stream"] for s in report["sessions"]] == [0, 1]
    assert [s["tls"]["negotiated_version"] for s in report["sessions"]] == ["TLS1.3", "TLS1.0"]


def test_b_conflicting_overlap_is_not_decisive():
    cap = Capture().hello(version=wire.V_TLS10, cipher=0x002f, group=None)
    cap.add("s", server_hello(wire.V_TLS12, 0xc02f, None), seq=8000)
    report = report_case("conflicting_overlap", cap)
    s = report["sessions"][0]
    assert s.get("incomplete") is True
    assert s["fact_tiers"]["tls.negotiated_version"] == "NOT_OBSERVABLE"
    assert s["observed_risk"] == 0


def test_c_oversized_tls_record():
    cap = Capture().add("c", client_hello())
    cap.add("s", b"\x16\x03\x03\xff\xff" + server_hello()[5:])
    report = report_case("oversized_record", cap)
    s = report["sessions"][0]
    assert s["tls"]["negotiated_version"] is None
    assert s["fact_tiers"]["tls.negotiated_version"] == "NOT_OBSERVABLE"
    assert s["observed_risk"] == 0
    assert s["evidence_coverage"] < 60


def test_a_syn_presence_preserves_tls_risk_floor():
    without_syn = report_case("tls10_without_syn", Capture().hello(
        version=wire.V_TLS10, cipher=0x002f, group=None))
    cap = Capture().add("c", flags=dpkt.tcp.TH_SYN, seq=999)
    with_syn = report_case("tls10_with_syn", cap.hello(
        version=wire.V_TLS10, cipher=0x002f, group=None))
    print("SYN floor comparison: " + json.dumps({"without_syn": without_syn["observed_risk"],
          "with_syn": with_syn["observed_risk"],
          "transition_without": without_syn["sessions"][0]["transition"]["verdict"],
          "transition_with": with_syn["sessions"][0]["transition"]["verdict"]}, sort_keys=True))
    assert with_syn["observed_risk"] == without_syn["observed_risk"] == 80


def test_d_truncated_clienthello_reduces_coverage():
    valid = report_case("clienthello_control", Capture().hello())
    cap = Capture().add("c", client_hello(groups=(29,))[:-3])
    cap.add("s", server_hello())
    report = report_case("truncated_clienthello", cap)
    s = report["sessions"][0]
    print(f"truncated ClientHello: offered={s['tls']['offered_version']} coverage_control={valid['evidence_coverage']} coverage_truncated={report['evidence_coverage']}")
    assert s["tls"]["offered_version"] is None
    assert report["evidence_coverage"] < valid["evidence_coverage"]


@pytest.mark.parametrize("bad", ["duplicate_versions", "zero_length_version"])
def test_e_invalid_server_extensions_are_not_negotiation(bad):
    from sms.m4_tls import parse_server_hello
    if bad == "duplicate_versions":
        extensions = wire._ext(43, b"\x03\x04") + wire._ext(43, b"\x03\x01")
    else:
        extensions = wire._ext(43, b"")
    sh = with_extensions(server_hello(), extensions)
    cap = Capture().add("c", client_hello()).add("s", sh)
    report = report_case(bad, cap)
    parsed = parse_server_hello(sh[9:])
    print(f"{bad} parse_status={parsed['parse_status']} selected_version={parsed['selected_version']}")
    s = report["sessions"][0]
    assert s["tls"]["negotiated_version"] is None
    assert s["fact_tiers"]["tls.negotiated_version"] == "NOT_OBSERVABLE"


def test_e_legal_zero_length_extension():
    ch = with_extensions(client_hello(), wire._ext(43, b"\x04\x03\x04\x03\x03") + wire._ext(42, b""))
    cap = Capture().add("c", ch).add("s", server_hello())
    report = report_case("zero_length_early_data", cap)
    s = report["sessions"][0]
    print(f"legal empty early_data={s['tls']['early_data_offered']}")
    assert s["tls"]["early_data_offered"] is True
    assert s["tls"]["negotiated_version"] == "TLS1.3"


def test_f_grease_is_not_capability():
    grease = tuple(0x0a0a + 0x1010*i for i in range(16))
    ch = client_hello(offered=(0x3a3a, 0x304, 0x303),
                      ciphers=grease + (0x1301,), groups=grease + (29,))
    cap = Capture().add("c", ch).add("s", server_hello())
    report = report_case("grease_vectors", cap)
    tls = report["sessions"][0]["tls"]
    matrix = report["servers"][0]["support_matrix"]
    print("GREASE filtered: " + json.dumps({"ciphers": tls["offered_ciphers"],
          "groups": tls["offered_groups"], "versions": tls["offered_versions"],
          "matrix_keys": sorted(matrix)}, sort_keys=True))
    assert tls["offered_ciphers"] == [0x1301]
    assert tls["offered_groups"] == [29]
    assert tls["offered_versions"] == [0x304, 0x303]
    assert not any(key.endswith(f"{g:#06x}") for key in matrix for g in grease)


@pytest.mark.parametrize("final_hello", [False, True])
def test_g_hrr_is_not_final_serverhello(final_hello):
    from sms.m4_tls import HRR_RANDOM
    hrr = with_extensions(server_hello(random_bytes=lambda n: HRR_RANDOM),
                          wire._ext(43, b"\x03\x04") + wire._ext(51, b"\x11\xed"))
    cap = Capture().add("c", client_hello(groups=(0x11ed, 29)))
    cap.add("s", hrr)
    if final_hello:
        cap.add("c", client_hello(groups=(29,)))
        cap.add("s", server_hello(group=29))
    report = report_case("hrr_then_final" if final_hello else "hrr_only", cap)
    s = report["sessions"][0]
    print("HRR details: " + json.dumps({"hrr_flag": s["tls"]["is_hello_retry_request"],
          "server_hello_frame": s["tls"]["server_hello_frame"],
          "forward_secrecy": s["tls"]["forward_secrecy_status"]}, sort_keys=True))
    if final_hello:
        # The final ServerHello (x25519) contradicts the HRR's requested group
        # (0x11ed); RFC 8446 §4.2.8 makes the client abort, so nothing was
        # negotiated even though the hello itself was captured at frame 4.
        assert s["tls"]["server_hello_frame"] == 4
        assert s["tls"]["negotiated_version"] is None
        assert s["tls"]["group"] is None
    else:
        assert s["tls"]["negotiated_version"] is None
        assert report["hndl"]["total_sessions"] == 0


def test_h_midstream_without_syn_stays_unknown():
    cap = Capture().add("s", wire.app_data(random_bytes=lambda n: b"\x42"*n))
    cap.add("c", wire.app_data(random_bytes=lambda n: b"\x43"*n))
    report = report_case("midstream_appdata", cap)
    s = report["sessions"][0]
    print("midstream tiers: " + json.dumps(s["fact_tiers"], sort_keys=True))
    assert report["capture_health"]["midstream_sessions"] == {"s1": True}
    assert s["protocol"] == "unknown"
    assert s["tls"]["negotiated_version"] is None
    for key in ("tls.negotiated_version", "tls.cipher", "tls.group", "certificate.status"):
        assert s["fact_tiers"][key] == "NOT_OBSERVABLE"
    assert s["observed_risk"] == s["evidence_coverage"] == 0
    assert report["hndl"]["total_sessions"] == 0


def test_i_supported_version_overrides_legacy():
    sh = server_hello()
    assert sh[9:11] == b"\x03\x03"
    report = report_case("supported_version_precedence", Capture().add("c", client_hello()).add("s", sh))
    s = report["sessions"][0]
    print(f"legacy_version=0x0303 supported_versions=0x0304 reported={s['tls']['negotiated_version']}")
    assert s["tls"]["negotiated_version"] == "TLS1.3"
    assert s["fact_tiers"]["tls.negotiated_version"] == "OBSERVED"


def test_j_starttls_accepted_but_cleartext_continues():
    cap = Capture().starttls()
    cap.add("c", b"EHLO audit.example\r\n", server_port=25)
    cap.add("s", b"250 mail.example\r\n", server_port=25)
    report = report_case("starttls_cleartext", cap)
    s = report["sessions"][0]
    print("STARTTLS continuation: " + json.dumps(s["transition"], sort_keys=True))
    assert s["transition"]["verdict"] == "failed"
    assert s["transition"]["confidence_band"] == "certain"
    assert s["tls"]["negotiated_version"] is None
    assert len(s["transition"]["evidence"]) >= 2


def test_k_unknown_cipher_is_unknown_not_safe():
    import math
    from sms.m7_anomaly import extract_features, FEATURES
    from sms.m9_report import analyse_sessions
    cap = Capture().hello(version=wire.V_TLS12, cipher=0xbeef, group=None)
    report = report_case("unknown_cipher", cap)
    sessions = analyse_sessions(FIXTURES / "audit_unknown_cipher.pcap")
    features = dict(zip(FEATURES, extract_features(sessions)[0]))
    relevant = {k: float(features[k]) for k in ("forward_secrecy", "hybrid_pq_flag", "aead_flag", "cbc_flag")}
    s = report["sessions"][0]
    print("unknown cipher feature values: " + json.dumps(relevant, sort_keys=True))
    print("unknown cipher FS: " + s["tls"]["forward_secrecy_status"])
    assert s["tls"]["cipher"] == "UNKNOWN_0xBEEF"
    assert s["tls"]["forward_secrecy_status"] == "UNKNOWN"
    assert all(math.isnan(value) for value in relevant.values())
    assert s["fact_tiers"]["tls.forward_secrecy"] == "NOT_OBSERVABLE"
    assert s["evidence_coverage"] < 100
    assert report["hndl"]["total_sessions"] == 0
    assert "KEX-NO-FS" not in {f["rule_id"] for f in s["findings"]}
