import json
from pathlib import Path
import tempfile
import unittest

from sms.cli import main
from sms.m9_report import build_report
from sms.pipeline import run_pipeline


class PipelineTests(unittest.TestCase):
    def test_cli_json_is_byte_identical_to_the_pre_pipeline_report_path(self):
        for ml, flag in ((False, "--no-ml"), (True, "--ml")):
            with self.subTest(ml=ml), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "report.json"
                expected = json.dumps(build_report("out/sample.pcap", ml=ml).to_dict(),
                                      indent=2, sort_keys=True)
                self.assertEqual(main(["analyse", "out/sample.pcap", flag, "--json", str(path)]), 0)
                self.assertEqual(path.read_text(), expected)
                self.assertEqual(run_pipeline("out/sample.pcap", ml=ml), json.loads(expected))

    def test_events_bracket_real_stage_calls_in_order(self):
        events = []
        run_pipeline("out/sample.pcap", ml=False, on_stage=events.append)
        self.assertEqual([event["stage"] for event in events],
                         ["M1", "M1", "M2", "M2", "M3", "M3", "M4", "M4", "M5", "M5", "M6", "M6", "P3", "P3", "M7", "M7", "M8", "M8", "M9", "M9"])
        for start, end in zip(events[::2], events[1::2]):
            self.assertEqual(start["status"], "start")
            self.assertIn(end["status"], {"done", "skipped"})
            self.assertEqual(start["label"], end["label"])
            self.assertIsInstance(end["detail"], str)
            self.assertGreaterEqual(end["t_ms"], start["t_ms"])
        self.assertEqual(events[15]["status"], "skipped")
