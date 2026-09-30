"""PDF delivery checks against the canonical report and rendered text."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pypdf import PdfReader

from sms.cli import main
from sms.delivery.pdf import render_pdf
from sms.pipeline import run_pipeline


def _text(pdf: bytes) -> str:
    reader = PdfReader(io.BytesIO(pdf))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


class PdfTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_pipeline("tests/fixtures/real_mail.pcap", ml=False)
        cls.pdf = render_pdf(cls.report)
        cls.text = _text(cls.pdf)

    def test_real_mail_pdf_opens_and_contains_required_sections_in_order(self):
        self.assertTrue(self.pdf.startswith(b"%PDF-"))
        reader = PdfReader(io.BytesIO(self.pdf))
        self.assertGreater(len(reader.pages), 0)

        headings = [
            "Capture health passport",
            "Servers and support matrices",
            "Findings and evidence",
            "Evidence coverage caveat",
        ]
        positions = [self.text.index(heading) for heading in headings]
        self.assertEqual(positions, sorted(positions))

    def test_real_mail_pdf_contains_support_matrix_findings_frames_and_tiers(self):
        self.assertIn("cipher:0xc02b", self.text)
        self.assertIn("DEMONSTRATED", self.text)
        self.assertIn("TLS-LEGACY-CLIENT", self.text)
        self.assertIn("tier OBSERVED", self.text)
        self.assertIn("frame ", self.text)

    def test_cli_writes_pdf_from_same_canonical_report(self):
        with TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            target = Path(directory) / "sample.pdf"
            report_target = Path(directory) / "sample.json"
            exit_code = main([
                "analyse", "out/sample.pcap", "--pdf", str(target),
                "--json", str(report_target), "--no-ml",
            ])
            pdf_text = _text(target.read_bytes())
            report = json.loads(report_target.read_text())
        self.assertEqual(exit_code, 0)
        self.assertIn(report["capture"]["sha256"], pdf_text)
        self.assertIn(report["servers"][0]["server_id"], pdf_text)


if __name__ == "__main__":
    unittest.main()
