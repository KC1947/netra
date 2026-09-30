import json
from pathlib import Path
import unittest

from lab.build_demo_library import LIBRARY, build_library
from sms.m9_report import build_report


class DemoLibraryTests(unittest.TestCase):
    def test_library_generation_is_byte_reproducible(self):
        """Capture generation must be byte-identical across repeated runs.

        tls_wire defaults to os.urandom, so a scenario that forgets to name a
        fixed seed produces a different capture on every run and silently
        invalidates the committed manifest hashes.
        """
        first, second = build_library(), build_library()
        self.assertEqual({item["id"]: item["sha256"] for item in first},
                         {item["id"]: item["sha256"] for item in second})
        stored = json.loads((LIBRARY / "manifest.json").read_text())
        self.assertEqual(first, stored)

    def test_library_is_analysable_and_scenarios_preserve_facts(self):
        manifest = build_library()
        stored = json.loads((LIBRARY / "manifest.json").read_text())
        self.assertEqual(manifest, stored)
        self.assertTrue(all(set(item) == {"id", "file", "title", "description", "source", "expected", "sha256", "size_bytes", "packets"}
                            for item in manifest))
        # This library-relative mixed_enterprise.pcap is the legacy six-session
        # fixture. The server instead reads tests/fixtures/mixed_enterprise.pcap
        # (25 analyzed sessions). Both are shipped; do not substitute or rename.
        reports = {item["id"]: build_report(LIBRARY / item["file"], ml=False) for item in manifest}
        manifest_by_id = {item["id"]: item for item in manifest}
        self.assertEqual(reports["mixed_enterprise"].summary["sessions_total"], 6)
        expected = build_report("out/sample.pcap", ml=False)
        source_ids = {
            "clean_tls13": "s1", "legacy_downgrade": "s2", "cleartext_auth": "s3",
            "strip_attack": "s4", "expired_cert": "s5", "pq_ready": "s6",
        }
        for capture_id, session_id in source_ids.items():
            with self.subTest(capture_id=capture_id):
                actual = reports[capture_id].sessions[0]
                source = next(session for session in expected.sessions if session.id == session_id)
                actual_tls = actual.tls.to_dict()
                source_tls = source.tls.to_dict()
                for field in ("client_hello_frame", "server_hello_frame"):
                    actual_tls.pop(field)
                    source_tls.pop(field)
                self.assertEqual((actual.transition.verdict, actual_tls, actual.certificate.to_dict(),
                                  [item.rule_id for item in actual.findings]),
                                 (source.transition.verdict, source_tls, source.certificate.to_dict(),
                                  [item.rule_id for item in source.findings]))
                self.assertEqual(reports[capture_id].capture_health["skipped"], {})
                self.assertEqual(reports[capture_id].capture_health["frames"],
                                 manifest_by_id[capture_id]["packets"])
