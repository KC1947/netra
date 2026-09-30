"""Every emitted Wireshark display filter must resolve, in tshark, to the frame
it names.

This is the check that did not exist. ``packet_view`` used to emit the session's
position in our filtered mail list as ``tcp.stream``, which is correct only when
the capture contains nothing but mail. On ``out/haystack.pcap`` -- 5,024 TCP
flows, 24 of them mail -- every filter named a stream three or four digits below
the real one, ANDed it against an absolute frame number, and so resolved to
*zero packets*. Nothing failed, because nothing ran the filter.

So these tests run the emitted string through tshark and assert it selects
exactly the expected frame. An empty result is an explicit, loud failure.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import unittest

from sms.packet_view import packet_view
from sms.pipeline import run_pipeline

ROOT = Path(__file__).resolve().parents[1]
TSHARK = shutil.which("tshark")

# Every capture this repository ships, including the large mixed one that broke.
CAPTURES = (
    ROOT / "out" / "sample.pcap",
    ROOT / "out" / "anomaly_demo.pcap",
    ROOT / "out" / "multiclient.pcap",
    ROOT / "out" / "baseline.pcap",
    ROOT / "out" / "haystack.pcap",
    ROOT / "tests" / "fixtures" / "real_mail.pcap",
    ROOT / "tests" / "fixtures" / "mixed_enterprise.pcap",
    ROOT / "tests" / "fixtures" / "recorded_mail_ethernet.pcapng",
)
MINIMUM_FILTERS_PER_CAPTURE = 3
# Each session costs two tshark launches, and baseline.pcap has 240 of them.
# Check a bounded prefix per capture so the suite stays runnable on every commit;
# the bound is well above the three-per-capture floor the check requires.
MAX_SESSIONS_PER_CAPTURE = 8


def tshark_frames(capture: Path, display_filter: str) -> list[int]:
    """Return the frame numbers tshark selects for a display filter."""
    result = subprocess.run(
        [TSHARK, "-r", str(capture), "-n", "-Y", display_filter,
         "-T", "fields", "-e", "frame.number"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"tshark rejected the filter {display_filter!r} on {capture.name}: "
            f"{result.stderr.strip()[:200]}"
        )
    return [int(line) for line in result.stdout.split()]


def tshark_stream_of(capture: Path, frame: int) -> str:
    out = subprocess.run(
        [TSHARK, "-r", str(capture), "-n", "-Y", f"frame.number=={frame}",
         "-T", "fields", "-e", "tcp.stream"],
        capture_output=True, text=True, check=False,
    )
    return out.stdout.strip()


@unittest.skipIf(TSHARK is None,
                 "tshark not installed; install Wireshark to validate display filters")
class WiresharkFilterTests(unittest.TestCase):
    """Each capture is checked independently so a failure names the capture."""

    def _check_capture(self, capture: Path, limit: int = MAX_SESSIONS_PER_CAPTURE) -> int:
        if not capture.exists():
            self.skipTest(f"{capture.name} not generated; run the lab builders")
        report = run_pipeline(capture, ml=False)
        checked = 0
        # Prefer sessions that carry findings: those produce the paired
        # stream+frame filter, which is the shape that broke.
        ordered = sorted(report["sessions"], key=lambda item: not item["findings"])
        for session in ordered[:limit]:
            view = packet_view(capture, report, session["id"])
            display_filter = view["wireshark_filter"]
            with self.subTest(capture=capture.name, session=session["id"],
                              filter=display_filter):
                # The stream half must be Wireshark's own numbering.
                self.assertIsNotNone(
                    session["tcp_stream"],
                    "session carries no tcp.stream, so no filter can be built",
                )
                self.assertIn(f"tcp.stream eq {session['tcp_stream']}", display_filter)
                first_frame = session["packets"]["first"]
                self.assertEqual(
                    tshark_stream_of(capture, first_frame),
                    str(session["tcp_stream"]),
                    f"our tcp.stream disagrees with tshark for frame {first_frame}",
                )

                frames = tshark_frames(capture, display_filter)
                # A filter that selects nothing is the exact failure that shipped.
                self.assertNotEqual(
                    frames, [],
                    f"filter {display_filter!r} selected ZERO packets in "
                    f"{capture.name}; a filter a reviewer pastes into Wireshark "
                    f"must resolve",
                )
                if "frame.number ==" in display_filter:
                    expected = int(display_filter.split("frame.number ==")[1].strip())
                    self.assertEqual(
                        frames, [expected],
                        f"filter {display_filter!r} selected {frames}, not "
                        f"exactly the frame it names",
                    )
                    # That frame must be one the view actually shows, and must
                    # carry the evidence the filter was built from.
                    self.assertIn(expected, [item["frame"] for item in view["frames"]])
                    self.assertIn(expected, [item["frame"] for item in view["evidence"]])
                    checked += 1
        return checked

    def test_sample(self):
        self.assertGreaterEqual(self._check_capture(CAPTURES[0]),
                                MINIMUM_FILTERS_PER_CAPTURE)

    def test_anomaly_demo(self):
        # This capture carries no rule findings, so it exercises the
        # stream-only filter shape rather than the paired shape.
        self._check_capture(CAPTURES[1])

    def test_multiclient(self):
        self.assertGreaterEqual(self._check_capture(CAPTURES[2]),
                                MINIMUM_FILTERS_PER_CAPTURE)

    def test_baseline(self):
        self.assertGreaterEqual(self._check_capture(CAPTURES[3]),
                                MINIMUM_FILTERS_PER_CAPTURE)

    def test_haystack(self):
        """5,024 TCP flows, 24 of them mail. The capture the bug lived on."""
        self.assertGreaterEqual(self._check_capture(CAPTURES[4]),
                                MINIMUM_FILTERS_PER_CAPTURE)

    def test_real_mail(self):
        self.assertGreaterEqual(self._check_capture(CAPTURES[5]),
                                MINIMUM_FILTERS_PER_CAPTURE)

    def test_mixed_enterprise(self):
        self.assertGreaterEqual(self._check_capture(CAPTURES[6]),
                                MINIMUM_FILTERS_PER_CAPTURE)

    def test_recorded_mail_ethernet(self):
        self._check_capture(CAPTURES[7])

    def test_stream_index_counts_all_flows_not_retained_flows(self):
        """The regression itself, stated directly.

        On a capture where triage discards most flows, the highest tcp.stream
        must reflect the file's flow count, not the number of sessions kept.
        """
        capture = CAPTURES[4]
        if not capture.exists():
            self.skipTest("haystack not generated")
        report = run_pipeline(capture, ml=False)
        health = report["capture_health"]
        self.assertGreater(health["total_flows"], health["candidate_flows"],
                           "this assertion needs a capture with non-mail flows")
        streams = [s["tcp_stream"] for s in report["sessions"]]
        self.assertTrue(all(s is not None for s in streams))
        self.assertGreater(
            max(streams), len(report["sessions"]),
            "tcp.stream is still being numbered over retained sessions only",
        )

    def test_port_reuse_gives_each_session_its_own_stream_and_packets(self):
        """Two sessions can share a five-tuple; they must not share a view.

        tshark also splits a reused port into two streams, so the two must map
        to two different tcp.stream values and two disjoint frame sets.
        """
        import tempfile
        import warnings
        warnings.filterwarnings("ignore")
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw
        from scapy.utils import wrpcap

        client, server = "10.9.9.10", "10.9.9.20"

        def packet(src, dst, sport, dport, flags, seq, ack=0, payload=b"", when=0.0):
            frame = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            frame /= IP(src=src, dst=dst)
            frame /= TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
            if payload:
                frame /= Raw(payload)
            frame.time = when
            return frame

        frames = [
            packet(client, server, 44444, 25, "S", 1000, when=1.0),
            packet(server, client, 25, 44444, "SA", 5000, 1001, when=1.1),
            packet(client, server, 44444, 25, "A", 1001, 5001, when=1.2),
            packet(server, client, 25, 44444, "PA", 5001, 1001,
                   b"220 first.example ESMTP\r\n", when=1.3),
            packet(server, client, 25, 44444, "R", 5030, when=1.4),
            packet(client, server, 44444, 25, "S", 90000, when=2.0),
            packet(server, client, 25, 44444, "SA", 70000, 90001, when=2.1),
            packet(client, server, 44444, 25, "A", 90001, 70001, when=2.2),
            packet(server, client, 25, 44444, "PA", 70001, 90001,
                   b"220 second.example ESMTP\r\n", when=2.3),
        ]
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "reuse.pcap"
            wrpcap(str(capture), frames)
            report = run_pipeline(capture, ml=False)
            self.assertEqual(len(report["sessions"]), 2)
            streams, framesets = [], []
            for session in report["sessions"]:
                view = packet_view(capture, report, session["id"])
                streams.append(session["tcp_stream"])
                framesets.append({item["frame"] for item in view["frames"]})
                self.assertEqual(
                    tshark_stream_of(capture, session["packets"]["first"]),
                    str(session["tcp_stream"]),
                )
                self.assertNotEqual(tshark_frames(capture, view["wireshark_filter"]), [])
            self.assertEqual(len(set(streams)), 2, "both sessions share one tcp.stream")
            self.assertEqual(framesets[0] & framesets[1], set(),
                             "the two sessions were served overlapping frames")


if __name__ == "__main__":
    unittest.main()


class UiFilterDerivationTests(unittest.TestCase):
    """The dashboard does not copy the API filter verbatim.

    ``web/js/views/drawer.js`` rewrites the frame clause to whichever evidence
    row the reviewer clicked and reuses the stream clause as-is, so a wrong
    stream was amplified to every frame in the session rather than only the
    first. That derivation is exercised here through the real JavaScript, and
    the result is validated in tshark -- it is the string the reviewer actually
    pastes.
    """

    NODE = shutil.which("node")
    DRAWER = ROOT / "web" / "js" / "views" / "drawer.js"

    def ui_filter(self, api_filter: str, frame: int) -> str:
        """Run web/js's own wiresharkFilterForFrame, not a Python rewrite."""
        source = self.DRAWER.read_text()
        start = source.index("function wiresharkFilterForFrame(")
        end = source.index("\n}", start) + 2
        script = (
            source[start:end]
            + f"\nprocess.stdout.write(wiresharkFilterForFrame({api_filter!r}, {frame}));"
        )
        result = subprocess.run([self.NODE, "--input-type=module", "-e", script],
                                capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise AssertionError(f"node failed: {result.stderr.strip()[:200]}")
        return result.stdout

    @unittest.skipIf(TSHARK is None, "tshark not installed")
    @unittest.skipIf(shutil.which("node") is None, "node not installed")
    def test_ui_derived_filter_resolves_for_every_evidence_frame(self):
        capture = CAPTURES[4]          # haystack: the capture the bug lived on
        if not capture.exists():
            self.skipTest("haystack not generated")
        report = run_pipeline(capture, ml=False)
        checked = 0
        for session in report["sessions"]:
            if not session["findings"]:
                continue
            view = packet_view(capture, report, session["id"])
            for evidence in view["evidence"]:
                derived = self.ui_filter(view["wireshark_filter"], evidence["frame"])
                with self.subTest(session=session["id"], frame=evidence["frame"],
                                  derived=derived):
                    self.assertEqual(tshark_frames(capture, derived), [evidence["frame"]])
                    checked += 1
            if checked >= 6:
                break
        self.assertGreaterEqual(checked, MINIMUM_FILTERS_PER_CAPTURE)
