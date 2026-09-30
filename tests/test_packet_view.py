import json
import unittest

from sms.m9_report import build_report
from sms.packet_view import packet_view


class PacketViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = build_report("out/sample.pcap", ml=False).to_dict()

    def test_strip_capability_and_auth_are_exactly_linked_and_redacted(self):
        view = packet_view("out/sample.pcap", self.report, "s4")
        capability = next(frame for frame in view["frames"] if "STARTTLS-STRIP-SUSPECTED" in frame["evidence_rules"])
        auth = next(frame for frame in view["frames"] if "CLEARTEXT-AUTH" in frame["evidence_rules"])
        self.assertIn("XSNVVQRW", capability["summary"])
        self.assertEqual(auth["summary"], "C: AUTH PLAIN [REDACTED]")
        auth_evidence = next(item for item in view["evidence"] if item["rule_id"] == "CLEARTEXT-AUTH")
        self.assertEqual((auth_evidence["hex_window"], auth_evidence["ascii_window"], auth_evidence["redacted"]),
                         ("", "AUTH PLAIN [REDACTED]", True))

    def test_tls_handshakes_and_privacy(self):
        view = packet_view("out/sample.pcap", self.report, "s1")
        summaries = [frame["summary"] for frame in view["frames"]]
        self.assertTrue(any("TLS ClientHello" in summary for summary in summaries))
        self.assertTrue(any("TLS ServerHello" in summary for summary in summaries))
        all_views = json.dumps([packet_view("out/sample.pcap", self.report, session["id"])
                                for session in self.report["sessions"]])
        for secret in ("supersecret", "AGxvZ2lu", "login"):
            self.assertNotIn(secret, all_views)

