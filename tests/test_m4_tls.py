import unittest

from sms.m1_ingest import ingest_pcap
from sms.m2_protocol import classify_protocols
from sms.m3_transition import analyse_transition
from sms.m4_tls import analyse_tls


def analysed_sessions():
    sessions = classify_protocols(ingest_pcap("out/sample.pcap"))
    for session in sessions:
        analyse_transition(session)
        analyse_tls(session)
    return sessions


class TlsTests(unittest.TestCase):
    def test_fixture_tls_facts_match_the_build_spec(self):
        sessions = analysed_sessions()
        self.assertEqual(
            [(s.tls.offered_version, s.tls.negotiated_version, s.tls.downgrade_delta,
              s.tls.forward_secrecy, s.tls.hybrid_pq_flag, s.tls.cert_visibility) for s in sessions],
            [
                ("TLS1.3", "TLS1.3", 0, True, False, "NOT_OBSERVABLE"),   # s1
                ("TLS1.3", "TLS1.0", 3, False, False, "OBSERVABLE"),      # s2
                (None, None, None, None, False, "NOT_OBSERVABLE"),        # s3: no TLS, delta and FS unknown
                (None, None, None, None, False, "NOT_OBSERVABLE"),        # s4: no TLS, delta and FS unknown
                ("TLS1.3", "TLS1.2", 1, True, False, "OBSERVABLE"),       # s5
                ("TLS1.3", "TLS1.3", 0, True, True, "NOT_OBSERVABLE"),    # s6
            ],
        )
        self.assertEqual(sessions[0].tls.group, "x25519")
        self.assertEqual(sessions[5].tls.group, "X25519MLKEM768")
        self.assertIn("CBC", sessions[1].tls.cipher)
        self.assertTrue(sessions[1].tls.cipher.startswith("TLS_RSA"))
        self.assertIn("ECDHE", sessions[4].tls.cipher)

    def test_cert_der_is_stashed_privately_for_x509_and_never_serialized(self):
        sessions = analysed_sessions()
        self.assertIsNone(sessions[0]._cert_der)  # TLS1.3: never observable
        self.assertIsNotNone(sessions[1]._cert_der)
        self.assertIsNotNone(sessions[4]._cert_der)
        for session in sessions:
            self.assertNotIn("_cert_der", session.to_dict())
            self.assertNotIn("_tls_evidence", session.to_dict())


if __name__ == "__main__":
    unittest.main()
