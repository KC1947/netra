"""Acceptance checks for the three-server multi-client correlation fixture."""

from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from lab.generate_pcap import generate_multiclient
from sms.m9_report import build_report


class MulticlientCaptureTests(unittest.TestCase):
    def test_policies_versions_and_certificate_association_precondition(self):
        with TemporaryDirectory() as directory:
            first = Path(directory) / "first.pcap"
            second = Path(directory) / "second.pcap"
            output = io.StringIO()
            with redirect_stdout(output):
                generate_multiclient(first)
                generate_multiclient(second)

            self.assertEqual(
                hashlib.sha256(first.read_bytes()).digest(),
                hashlib.sha256(second.read_bytes()).digest(),
            )
            report = build_report(first, ml=False)

        self.assertEqual(len(report.sessions), 18)
        by_server = {}
        for session in report.sessions:
            by_server.setdefault(session.five_tuple["server_ip"], {})[
                session.five_tuple["client_ip"]
            ] = session
        self.assertEqual({server: len(sessions) for server, sessions in by_server.items()}, {
            "10.0.1.20": 6,
            "10.0.2.20": 6,
            "10.0.3.20": 6,
        })

        server_a = by_server["10.0.1.20"]
        a_first, a_reverse = server_a["10.0.0.11"], server_a["10.0.0.12"]
        self.assertEqual(a_first.tls.offered_ciphers, list(reversed(a_reverse.tls.offered_ciphers)))
        self.assertEqual(
            [(a_first.tls.negotiated_version, a_first.tls.cipher),
             (a_reverse.tls.negotiated_version, a_reverse.tls.cipher)],
            [("TLS1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")] * 2,
        )
        self.assertEqual(
            server_a["10.0.0.13"].tls.cipher,
            "TLS_RSA_WITH_AES_128_CBC_SHA",
        )

        server_b = by_server["10.0.2.20"]
        b_first, b_reverse = server_b["10.0.0.11"], server_b["10.0.0.12"]
        self.assertEqual(b_first.tls.offered_ciphers, list(reversed(b_reverse.tls.offered_ciphers)))
        self.assertEqual(
            [(b_first.tls.negotiated_version, b_first.tls.cipher),
             (b_reverse.tls.negotiated_version, b_reverse.tls.cipher)],
            [
                ("TLS1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
                ("TLS1.2", "TLS_RSA_WITH_AES_128_CBC_SHA"),
            ],
        )

        server_c = by_server["10.0.3.20"]
        self.assertTrue(all(
            server_c[f"10.0.0.{client}"].tls.negotiated_version is None
            for client in (11, 12, 13)
        ))
        self.assertTrue(all(
            server_c[f"10.0.0.{client}"].tls.negotiated_version == "TLS1.3"
            for client in (14, 15, 16)
        ))

        # Server A has visible TLS 1.2 certificate evidence and an encrypted
        # TLS 1.3 session on the same service for later association logic.
        self.assertEqual(server_a["10.0.0.11"].tls.cert_visibility, "OBSERVABLE")
        self.assertEqual(server_a["10.0.0.14"].certificate.status, "NOT_OBSERVABLE")

        rendered = output.getvalue()
        for label in ("server A", "server B", "server C"):
            self.assertIn(label, rendered)
        self.assertEqual(rendered.count("c1_tls12_ecdhe_first:"), 6)


if __name__ == "__main__":
    unittest.main()
