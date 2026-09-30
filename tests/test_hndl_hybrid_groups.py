"""HNDL must classify every RFC 10024 hybrid group, not one group by name.

``tests/test_regressions.py`` case 09a already asserts that the registry
classifies 0x11EB, 0x11EC and 0x11ED as ``PQ_HYBRID``.  That is a classifier
test, and it passed while ``compute_hndl`` compared the group *name* against
the single literal ``"X25519MLKEM768"`` -- so a SecP hybrid session was
reported as HNDL-exposed while its own ``hybrid_pq_flag`` was true and
``PQ-HYBRID-OBSERVED`` fired on it.  These tests close that gap by asserting at
the HNDL level, on real captures, which is where the claim is actually made.
"""

import datetime
from pathlib import Path
import tempfile
import unittest

from scapy.utils import wrpcap

from lab.generate_pcap import C_AES128_GCM_13, Session
from lab.tls_wire import (G_SECP256R1MLKEM768, G_SECP384R1MLKEM1024,
                          G_X25519, G_X25519KYBER768DRAFT00, G_X25519MLKEM768,
                          V_TLS13, app_data, client_hello, server_hello)
from sms.m9_report import build_report

TIMESTAMP = datetime.datetime(2026, 9, 5, tzinfo=datetime.timezone.utc).timestamp()


class HndlHybridGroupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def capture(self, *groups):
        """One implicit-TLS 1.3 session per group, in a throwaway capture."""
        packets = []
        for index, group in enumerate(groups):
            session = Session(40100 + index, 465)
            session.c(client_hello())
            session.s(server_hello(V_TLS13, C_AES128_GCM_13, group=group))
            session.s(app_data())
            session.c(app_data())
            frames, _ = session.packets(TIMESTAMP + index)
            packets.extend(frames)
        path = Path(self.directory.name) / "hybrid.pcap"
        wrpcap(str(path), packets)
        return build_report(path, ml=False).to_dict()

    def test_secp256r1mlkem768_session_is_quantum_safe(self):
        report = self.capture(G_SECP256R1MLKEM768)
        session = report["sessions"][0]
        self.assertEqual(session["tls"]["group"], "SecP256r1MLKEM768")
        self.assertEqual(session["tls"]["group_class"], "PQ_HYBRID")
        self.assertTrue(session["tls"]["hybrid_pq_flag"])
        self.assertEqual(report["hndl"], {
            "exposed_sessions": 0, "quantum_safe_sessions": 1,
            "total_sessions": 1, "unobservable_sessions": 0,
            "unobservable_sessions_excluded": 0, "percent": 0,
        })

    def test_secp384r1mlkem1024_session_is_quantum_safe(self):
        report = self.capture(G_SECP384R1MLKEM1024)
        self.assertEqual(report["sessions"][0]["tls"]["group"], "SecP384r1MLKEM1024")
        self.assertEqual(report["hndl"]["quantum_safe_sessions"], 1)
        self.assertEqual(report["hndl"]["exposed_sessions"], 0)

    def test_all_three_rfc_10024_groups_count_together(self):
        report = self.capture(G_SECP256R1MLKEM768, G_X25519MLKEM768,
                             G_SECP384R1MLKEM1024)
        self.assertEqual(report["hndl"]["quantum_safe_sessions"], 3)
        self.assertEqual(report["hndl"]["exposed_sessions"], 0)
        self.assertEqual(report["hndl"]["percent"], 0)

    def test_obsolete_kyber_draft_is_exposed_not_quantum_safe(self):
        report = self.capture(G_X25519KYBER768DRAFT00)
        session = report["sessions"][0]
        self.assertEqual(session["tls"]["group"], "X25519Kyber768Draft00")
        self.assertEqual(session["tls"]["group_class"], "PQ_OBSOLETE_DRAFT")
        self.assertFalse(session["tls"]["hybrid_pq_flag"])
        self.assertEqual(report["hndl"]["quantum_safe_sessions"], 0)
        self.assertEqual(report["hndl"]["exposed_sessions"], 1)

    def test_classical_group_is_exposed(self):
        report = self.capture(G_X25519)
        self.assertEqual(report["sessions"][0]["tls"]["group_class"], "CLASSICAL")
        self.assertEqual(report["hndl"]["quantum_safe_sessions"], 0)
        self.assertEqual(report["hndl"]["exposed_sessions"], 1)

    def test_hybrid_and_classical_mix_reports_the_hybrid_as_safe(self):
        report = self.capture(G_SECP256R1MLKEM768, G_X25519)
        self.assertEqual(report["hndl"]["quantum_safe_sessions"], 1)
        self.assertEqual(report["hndl"]["exposed_sessions"], 1)
        self.assertEqual(report["hndl"]["percent"], 50)

    def test_no_session_is_both_hybrid_and_exposed(self):
        """The contradiction the name comparison produced: a report cannot say
        a session negotiated hybrid PQ and also count it HNDL-exposed."""
        report = self.capture(G_SECP256R1MLKEM768, G_X25519MLKEM768,
                              G_SECP384R1MLKEM1024, G_X25519KYBER768DRAFT00,
                              G_X25519)
        hybrid = [session for session in report["sessions"]
                  if session["tls"]["hybrid_pq_flag"]]
        self.assertEqual(len(hybrid), 3)
        for session in hybrid:
            self.assertIn("PQ-HYBRID-OBSERVED",
                          {finding["rule_id"] for finding in session["findings"]})
        self.assertEqual(report["hndl"]["quantum_safe_sessions"], len(hybrid))
        self.assertEqual(report["hndl"]["exposed_sessions"],
                         len(report["sessions"]) - len(hybrid))


if __name__ == "__main__":
    unittest.main()
