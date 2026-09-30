"""The hex view must refuse to serve bytes from a file it cannot vouch for.

The packet view re-reads the capture from disk to show bytes. If that file is no
longer the one the report was produced from, the frame numbers the report
asserts do not address the same packets, and rendering them anyway would be a
confidently wrong answer in the one place we invite a reviewer to check us.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest

from sms.packet_view import CaptureChanged, packet_view
from sms.pipeline import run_pipeline

ROOT = Path(__file__).resolve().parents[1]


class CaptureIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.capture = Path(self.directory.name) / "capture.pcap"
        shutil.copyfile(ROOT / "out" / "sample.pcap", self.capture)
        self.report = run_pipeline(self.capture, ml=False)

    def test_unchanged_capture_is_served(self):
        view = packet_view(self.capture, self.report, "s4")
        self.assertTrue(view["frames"])
        self.assertTrue(view["evidence"])

    def test_changed_capture_is_refused(self):
        shutil.copyfile(ROOT / "out" / "multiclient.pcap", self.capture)
        with self.assertRaises(CaptureChanged) as caught:
            packet_view(self.capture, self.report, "s4")
        message = str(caught.exception)
        # The refusal must say what happened and name both digests, so an
        # operator can tell a changed file from a broken tool.
        self.assertIn("capture file has changed since analysis", message)
        self.assertIn(self.report["capture"]["sha256"], message)
        self.assertIn("Re-run the analysis", message)

    def test_single_flipped_byte_is_refused(self):
        """Not just a different file: any edit at all."""
        data = bytearray(self.capture.read_bytes())
        data[-1] ^= 0x01
        self.capture.write_bytes(bytes(data))
        with self.assertRaises(CaptureChanged):
            packet_view(self.capture, self.report, "s4")

    def test_report_without_a_capture_hash_is_refused(self):
        stripped = dict(self.report)
        stripped["capture"] = {key: value
                               for key, value in self.report["capture"].items()
                               if key != "sha256"}
        with self.assertRaises(CaptureChanged) as caught:
            packet_view(self.capture, stripped, "s4")
        self.assertIn("no capture SHA-256", str(caught.exception))

    def test_verification_precedes_the_session_lookup(self):
        """A changed file must be reported as changed, not as a missing session.

        The check runs before anything is read off disk, so the error names the
        real problem even when the session id is also wrong.
        """
        shutil.copyfile(ROOT / "out" / "multiclient.pcap", self.capture)
        with self.assertRaises(CaptureChanged):
            packet_view(self.capture, self.report, "no-such-session")

    def test_api_returns_409_and_explains(self):
        """The dashboard must see a refusal it can render, not a 500."""
        from fastapi.testclient import TestClient
        import server.app as app_module

        client = TestClient(app_module.app)
        created = client.post("/api/analyses",
                              json={"capture_id": "strip_attack", "ml": False})
        self.assertEqual(created.status_code, 200, created.text)
        analysis_id = created.json()["analysis_id"]
        with client.stream("GET", f"/api/analyses/{analysis_id}/events") as stream:
            for _ in stream.iter_lines():
                pass

        report = client.get(f"/api/analyses/{analysis_id}/report")
        self.assertEqual(report.status_code, 200, report.text)
        session_id = report.json()["sessions"][0]["id"]
        served = client.get(
            f"/api/analyses/{analysis_id}/sessions/{session_id}/packets")
        self.assertEqual(served.status_code, 200, served.text)

        # Now corrupt the registered capture underneath the completed analysis.
        analysis = app_module._analyses[analysis_id]
        path = app_module._capture_path(analysis.capture)
        original = path.read_bytes()
        self.addCleanup(path.write_bytes, original)
        path.write_bytes(original + b"\x00")
        refused = client.get(
            f"/api/analyses/{analysis_id}/sessions/{session_id}/packets")
        self.assertEqual(refused.status_code, 409, refused.text)
        self.assertIn("capture file has changed", refused.json()["error"])


if __name__ == "__main__":
    unittest.main()
