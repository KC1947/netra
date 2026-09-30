"""A ServerHello that fails validation must leave its session visible as unobserved.

M4 discards a ServerHello a client would abort on (AUD-08, item 5). The session
must not vanish from the evidence it could not supply: it stays in the report,
its version fact is NOT_OBSERVABLE, it lowers evidence coverage (its applicable
checks stay in the pooled denominator), it adds no risk, and the summary and
HNDL count it as not observable rather than dropping it.
"""
import pytest

from audit_support import Capture, client_hello, server_hello, with_extensions, wire
from sms.m4_tls import HRR_RANDOM
from sms.pipeline import run_pipeline


CCS = wire._record(20, 0x303, b"\x01")


def _malformed(cap, kind, port=40001):
    if kind == "supported_versions_below_tls13":
        cap.add("c", client_hello(), port=port)
        cap.add("s", with_extensions(server_hello(wire.V_TLS12, 0x002f, None),
                                     wire._ext(43, b"\x03\x01")), port=port)
    elif kind == "zero_length_supported_versions":
        cap.add("c", client_hello(), port=port)
        cap.add("s", with_extensions(server_hello(), wire._ext(43, b"")), port=port)
    elif kind == "duplicate_supported_versions":
        cap.add("c", client_hello(), port=port)
        cap.add("s", with_extensions(server_hello(), wire._ext(43, b"\x03\x04")
                                     + wire._ext(43, b"\x03\x01")), port=port)
    elif kind == "hrr_group_mismatch":
        hrr = with_extensions(server_hello(random_bytes=lambda n: HRR_RANDOM),
                              wire._ext(43, b"\x03\x04") + wire._ext(51, b"\x11\xed"))
        cap.add("c", client_hello(groups=(0x11ed, 29)), port=port)
        cap.add("s", hrr + CCS, port=port)
        cap.add("c", client_hello(groups=(0x11ed, 29)), port=port)
        cap.add("s", server_hello(group=29), port=port)
    return cap


@pytest.mark.parametrize("kind", ["supported_versions_below_tls13", "zero_length_supported_versions",
                                  "duplicate_supported_versions", "hrr_group_mismatch"])
def test_malformed_serverhello_is_not_observable_and_stays_counted(tmp_path, kind):
    alone = run_pipeline(Capture().hello().write(tmp_path / "alone.pcap"), ml=False)
    both_valid = run_pipeline(Capture().hello().hello(port=40001).write(tmp_path / "valid.pcap"), ml=False)
    mixed = run_pipeline(_malformed(Capture().hello(), kind).write(tmp_path / "mixed.pcap"), ml=False)

    # The session is still in the report, as a TLS session whose negotiation
    # is unknown: nothing negotiated, NOT_OBSERVABLE, no finding, no risk.
    assert [s["id"] for s in mixed["sessions"]] == ["s1", "s2"]
    bad = mixed["sessions"][1]
    assert bad["transition"]["verdict"] == "upgraded"
    assert bad["tls"]["negotiated_version"] is None
    assert bad["fact_tiers"]["tls.negotiated_version"] == "NOT_OBSERVABLE"
    assert bad["findings"] == [] and bad["observed_risk"] == 0

    # It lowers coverage: below the same session with a valid ServerHello, and
    # the capture's pooled coverage falls, so its checks are in the denominator.
    assert bad["evidence_coverage"] < both_valid["sessions"][1]["evidence_coverage"]
    assert mixed["evidence_coverage"] < alone["evidence_coverage"]
    assert mixed["observed_risk"] == alone["observed_risk"]

    # Counted, not dropped: the summary keeps it as not observable, and HNDL
    # reports it among the explicitly excluded unobservable sessions.
    assert mixed["summary"]["sessions_total"] == 2
    assert (mixed["summary"]["encrypted"], mixed["summary"]["cleartext"],
            mixed["summary"]["not_observable"]) == (1, 0, 1)
    assert mixed["hndl"]["total_sessions"] == 1
    assert mixed["hndl"]["unobservable_sessions_excluded"] == 1
