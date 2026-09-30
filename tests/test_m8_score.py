import unittest

from sms.contracts import Session
from sms.m1_ingest import ingest_pcap
from sms.m2_protocol import classify_protocols
from sms.m3_transition import analyse_transition
from sms.m4_tls import analyse_tls
from sms.m5_x509 import analyse_certificate
from sms.m6_rules import apply_rules
from sms.m8_score import compute_hndl, score_sessions


def analysed_sessions():
    sessions = classify_protocols(ingest_pcap("out/sample.pcap"))
    for session in sessions:
        analyse_transition(session)
        analyse_tls(session)
        analyse_certificate(session)
        apply_rules(session)
    score_sessions(sessions)
    return sessions


class ScoreTests(unittest.TestCase):
    def test_hndl_percent_is_83(self):
        hndl = compute_hndl(analysed_sessions())
        self.assertEqual(hndl, {
            "exposed_sessions": 5, "quantum_safe_sessions": 1,
            "total_sessions": 6, "unobservable_sessions": 0,
            "unobservable_sessions_excluded": 0, "percent": 83,
        })
        self.assertEqual(
            hndl["exposed_sessions"] + hndl["quantum_safe_sessions"],
            hndl["total_sessions"],
        )

    def test_mid_stream_unknown_session_is_excluded_from_hndl(self):
        # Tiers as the pipeline stamps them: M2's greeting grammar makes the
        # cleartext protocol OBSERVED; M4 makes a captured ServerHello's
        # version, cipher and group OBSERVED. A mid-stream session has none.
        cleartext = Session("s1", {"server_port": 25}, protocol="smtp")
        cleartext.fact_tiers["protocol"] = "OBSERVED"
        observed_tls = Session("s2", {"server_port": 465}, protocol="smtp")
        observed_tls.fact_tiers["protocol"] = "INFERRED"
        observed_tls.transition.verdict = "upgraded"
        observed_tls.tls.negotiated_version = "TLS1.3"
        observed_tls.tls.cipher = "TLS_AES_128_GCM_SHA256"
        observed_tls.tls.group = "x25519"
        observed_tls.tls.group_class = "CLASSICAL"
        for fact in ("tls.negotiated_version", "tls.cipher", "tls.group", "tls.hybrid_pq_flag"):
            observed_tls.fact_tiers[fact] = "OBSERVED"
        mid_stream = Session("s3", {"server_port": 993}, protocol="unknown")
        self.assertEqual(compute_hndl([cleartext, observed_tls, mid_stream]), {
            "exposed_sessions": 2, "quantum_safe_sessions": 0,
            "total_sessions": 2, "unobservable_sessions": 1,
            "unobservable_sessions_excluded": 1, "percent": 100,
        })
        # The same values with no established tier (a bare Session's default
        # NOT_OBSERVABLE) are not evidence of cleartext or of a key exchange.
        unestablished = [Session("s1", {"server_port": 25}, protocol="smtp"),
                         Session("s2", {"server_port": 465}, protocol="smtp")]
        unestablished[1].tls.negotiated_version = "TLS1.3"
        unestablished[1].tls.cipher = "TLS_AES_128_GCM_SHA256"
        unestablished[1].tls.group = "x25519"
        self.assertEqual(compute_hndl(unestablished)["total_sessions"], 0)

    def test_risk_floors_dominate_cleartext_auth_and_legacy_tls(self):
        sessions = analysed_sessions()
        s2, s3, s4 = sessions[1], sessions[2], sessions[3]
        self.assertGreaterEqual(s2.observed_risk, 80)   # TLS<=1.1 floor
        self.assertGreaterEqual(s3.observed_risk, 90)   # cleartext AUTH after absent upgrade
        self.assertGreaterEqual(s4.observed_risk, 90)   # cleartext AUTH after suspected strip

    def test_clean_sessions_score_lowest_risk(self):
        sessions = analysed_sessions()
        s1, s6 = sessions[0], sessions[5]
        self.assertEqual(s1.observed_risk, 0)
        self.assertEqual(s6.observed_risk, 0)

    def test_missing_evidence_never_raises_risk_only_lowers_coverage(self):
        sessions = analysed_sessions()
        for session in sessions:
            self.assertGreaterEqual(session.evidence_coverage, 0)
            self.assertLessEqual(session.evidence_coverage, 100)
        # s3/s4 never observed any TLS at all -- lots of unobservable checks --
        # yet their risk is the highest in the capture (credential exposure).
        s3, s4 = sessions[2], sessions[3]
        self.assertGreater(s3.observed_risk, sessions[0].observed_risk)
        self.assertGreater(s4.observed_risk, sessions[0].observed_risk)


if __name__ == "__main__":
    unittest.main()
