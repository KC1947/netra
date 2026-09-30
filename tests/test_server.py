import json
from pathlib import Path
import unittest

from fastapi.testclient import TestClient

from server.app import app
from sms.pipeline import run_pipeline


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def _analysis(self, capture_id="strip_attack", ml=False):
        response = self.client.post("/api/analyses", json={"capture_id": capture_id, "ml": ml})
        self.assertEqual(response.status_code, 200)
        return response.json()["analysis_id"]

    def _events(self, analysis_id):
        response = self.client.get(f"/api/analyses/{analysis_id}/events")
        self.assertEqual(response.status_code, 200)
        return [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith("data: ")]

    def test_health_and_captures(self):
        self.assertEqual(self.client.get("/api/health").json(), {
            "status": "ok", "engine": "securemailscope", "version": "0.2", "ml_available": True,
        })
        captures = self.client.get("/api/captures").json()
        self.assertTrue(any(item["id"] == "strip_attack" for item in captures))
        unsupported = next(item for item in captures if item["id"] == "pktap_unsupported")
        self.assertEqual(unsupported["file"], "unsupported_linktype_258.pcapng")
        self.assertEqual(unsupported["source"], "fixture")

    def test_analysis_report_sse_packets_exports_and_privacy(self):
        analysis_id = self._analysis()
        events = self._events(analysis_id)
        self.assertEqual([item["stage"] for item in events[:-1]],
                         ["M1", "M1", "M2", "M2", "M3", "M3", "M4", "M4", "M5", "M5", "M6", "M6", "P3", "P3", "M7", "M7", "M8", "M8", "M9", "M9"])
        self.assertEqual(events[-1]["stage"], "DONE")
        self.assertGreaterEqual(events[-1]["t_ms"], events[-2]["t_ms"])
        report = self.client.get(f"/api/analyses/{analysis_id}/report")
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.json(), run_pipeline("demo_captures/strip_attack.pcap", ml=False))
        packets = self.client.get(f"/api/analyses/{analysis_id}/sessions/s1/packets")
        self.assertEqual(packets.status_code, 200)
        self.assertTrue(any(item["rule_id"] == "CLEARTEXT-AUTH" for item in packets.json()["evidence"]))
        exported_json = self.client.get(f"/api/analyses/{analysis_id}/export?format=json")
        exported_html = self.client.get(f"/api/analyses/{analysis_id}/export?format=html")
        self.assertEqual((exported_json.status_code, exported_html.status_code), (200, 200))
        rendered = "".join((report.text, packets.text, exported_json.text, exported_html.text))
        for secret in ("supersecret", "AGxvZ2lu", "login"):
            self.assertNotIn(secret, rendered)

    def test_registered_unsupported_capture_declines_analysis(self):
        analysis_id = self._analysis("pktap_unsupported")
        self._events(analysis_id)
        response = self.client.get(f"/api/analyses/{analysis_id}/report")
        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual(report["capture_health"]["linktypes"], {"258": 2})
        self.assertEqual(report["capture_health"]["analysis_status"], "unsupported")
        self.assertFalse(report["summary"]["findings_assessed"])

    def test_non_pcap_upload_is_rejected(self):
        response = self.client.post("/api/captures/upload", files={"file": ("not-a-capture.txt", b"not pcap")})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(set(response.json()), {"error"})

    def test_pcap_upload_reports_packet_count(self):
        payload = Path("out/sample.pcap").read_bytes()
        response = self.client.post(
            "/api/captures/upload",
            files={"file": ("uploaded-sample.pcap", payload)},
        )
        self.assertEqual(response.status_code, 200)
        capture = response.json()
        self.assertEqual(capture["source"], "uploaded")
        self.assertEqual(capture["expected"], [])
        self.assertGreater(capture["packets"], 0)
