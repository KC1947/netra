import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout

from sms.cli import main
from sms.contracts import CertInfo, Session, TransitionInfo
from sms.m1_ingest import IngestStats
from sms.m8_score import score_sessions
from sms.m9_report import build_report, make_report, render_html


class ReportTests(unittest.TestCase):
    def test_report_json_is_canonical_and_deterministic(self):
        first = json.dumps(build_report("out/sample.pcap").to_dict(), sort_keys=True)
        second = json.dumps(build_report("out/sample.pcap").to_dict(), sort_keys=True)
        self.assertEqual(first, second)

    def test_report_shapes_match_canonical_contract(self):
        report = build_report("out/sample.pcap")
        data = report.to_dict()
        self.assertEqual(set(data.keys()), {"capture", "capture_health", "registry_version",
                                            "hndl", "summary", "sessions", "findings",
                                            "ml_summary", "servers", "observed_risk",
                                            "evidence_coverage", "deduced_coverage",
                                            "inferred_coverage"})
        self.assertEqual(data["hndl"], {
            "exposed_sessions": 5, "quantum_safe_sessions": 1,
            "total_sessions": 6, "unobservable_sessions": 0,
            "unobservable_sessions_excluded": 0, "percent": 83,
        })
        self.assertEqual(len(data["sessions"]), 6)
        self.assertEqual(data["summary"]["sessions_total"], 6)
        self.assertEqual(data["capture"]["filename"], "sample.pcap")
        self.assertEqual(len(data["capture"]["sha256"]), 64)
        session_mean_risk = round(
            sum(item["observed_risk"] for item in data["sessions"]) / len(data["sessions"])
        )
        self.assertNotEqual(data["observed_risk"], session_mean_risk)

    def test_report_coverage_is_pooled_not_mean_of_session_percentages(self):
        covered = Session("s1", {"server_port": 25}, protocol="smtp",
                          protocol_confidence="high")
        covered.transition = TransitionInfo(verdict="upgraded", confidence_band="certain")
        covered.tls.negotiated_version = "TLS1.2"
        covered.tls.forward_secrecy_status = "YES"
        covered.certificate = CertInfo(status="VALID", key_strength="VALID")
        for fact in (
            "protocol", "transition.verdict", "tls.negotiated_version",
            "tls.forward_secrecy", "certificate.status", "certificate.key_strength",
        ):
            covered.fact_tiers[fact] = "OBSERVED"
        thin = Session("s2", {"server_port": 25})
        sessions = score_sessions([covered, thin])
        mean = round(sum(item.evidence_coverage for item in sessions) / len(sessions))

        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "pooled.pcap"
            capture.write_bytes(b"pooled coverage fixture")
            report = make_report(
                capture, sessions, {"enabled": False}, IngestStats(), [],
            ).to_dict()

        self.assertEqual(mean, 50)
        self.assertEqual(report["evidence_coverage"], 75)
        self.assertNotEqual(report["evidence_coverage"], mean)

    def test_unsupported_link_type_is_not_reported_as_no_findings(self):
        report = build_report(
            "tests/fixtures/unsupported_linktype_258.pcapng"
        ).to_dict()

        self.assertEqual(report["capture_health"]["linktypes"], {"258": 2})
        self.assertEqual(report["capture_health"]["frames_decoded_pct"], 0.0)
        self.assertEqual(report["capture_health"]["analysis_status"], "unsupported")
        self.assertEqual(report["capture_health"]["unsupported_packets"]["count"], 2)
        self.assertFalse(report["summary"]["findings_assessed"])
        self.assertEqual(report["findings"], [])

    def test_html_is_self_contained_and_shows_the_hndl_banner(self):
        html = render_html(build_report("out/sample.pcap"))
        self.assertIn("83%", html)
        self.assertIn("5 exposed, 1 quantum-safe, and 0 unobservable sessions excluded", html)
        for banned in ("http://", "https://", "cdn."):
            self.assertNotIn(banned, html)

    def test_no_secret_or_credential_text_leaks_into_json_or_html(self):
        report = build_report("out/sample.pcap")
        rendered = json.dumps(report.to_dict()) + render_html(report)
        for secret in ("supersecret", "AGxvZ2lu", "login"):
            self.assertNotIn(secret, rendered)

    def test_cli_self_test_passes_all_six_sessions(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            exit_code = main(["analyse", "out/sample.pcap", "--self-test"])
        output = buffer.getvalue()
        self.assertEqual(exit_code, 0)
        for session_id in ("s1", "s2", "s3", "s4", "s5", "s6"):
            self.assertIn(f"{session_id}: PASS", output)
        self.assertIn("hndl: PASS", output)


if __name__ == "__main__":
    unittest.main()
