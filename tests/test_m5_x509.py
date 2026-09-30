import unittest

from sms.m1_ingest import ingest_pcap
from sms.m2_protocol import classify_protocols
from sms.m3_transition import analyse_transition
from sms.m4_tls import analyse_tls
from sms.m5_x509 import analyse_certificate


def analysed_sessions():
    sessions = classify_protocols(ingest_pcap("out/sample.pcap"))
    for session in sessions:
        analyse_transition(session)
        analyse_tls(session)
        analyse_certificate(session)
    return sessions


class X509Tests(unittest.TestCase):
    def test_fixture_certificate_verdicts_match_the_build_spec(self):
        sessions = analysed_sessions()
        self.assertEqual([s.certificate.status for s in sessions],
                         ["NOT_OBSERVABLE", "INVALID", "NOT_OBSERVABLE", "NOT_OBSERVABLE",
                          "INVALID", "NOT_OBSERVABLE"])

        s2 = sessions[1]
        self.assertTrue(s2.certificate.self_signed)
        self.assertEqual(s2.certificate.key_bits, 1024)
        self.assertFalse(s2.certificate.expired)
        self.assertIn("self-signed", s2.certificate.reason)
        self.assertIn("weak key", s2.certificate.reason)

        s5 = sessions[4]
        self.assertTrue(s5.certificate.expired)
        self.assertFalse(s5.certificate.self_signed)
        self.assertEqual(s5.certificate.key_bits, 2048)
        self.assertIn("expired", s5.certificate.reason)

    def test_certificate_dates_are_compared_to_capture_time_not_wall_clock(self):
        sessions = analysed_sessions()
        s5 = sessions[4]
        # The fixture's expired cert is only expired relative to the Sept 2026
        # capture, not relative to whenever this test happens to run.
        self.assertEqual(s5.certificate.notAfter[:4], "2026")

    def test_certificate_never_serializes_der_and_stays_not_observable_without_one(self):
        sessions = analysed_sessions()
        for session in sessions:
            self.assertEqual(
                set(session.to_dict()["certificate"].keys()),
                {"status", "reason", "key_bits", "sig_alg", "self_signed", "expired", "notBefore", "notAfter"},
            )
        self.assertEqual(sessions[0].to_dict()["certificate"]["status"], "NOT_OBSERVABLE")


if __name__ == "__main__":
    unittest.main()
