import unittest

from scapy.utils import RawPcapReader

from sms.contracts import PacketObservation
from sms.m1_ingest import _reassemble, ingest_pcap


class IngestTests(unittest.TestCase):
    def test_fixture_sessions_have_expected_ports_and_byte_provenance(self):
        sessions = ingest_pcap("out/sample.pcap")
        self.assertEqual([session.five_tuple["server_port"] for session in sessions],
                         [25, 25, 25, 25, 993, 465])
        self.assertEqual([(s.packets['first'], s.packets['last']) for s in sessions],
                         [(1, 9), (10, 18), (19, 23), (24, 28), (29, 33), (34, 37)])
        with RawPcapReader('out/sample.pcap') as reader:
            frames = [raw for raw, _ in reader]
        for session in sessions:
            for stream in (session.client_to_server, session.server_to_client):
                data = stream.contiguous_bytes()
                self.assertTrue(data)
                for source in stream.provenance_for(0, len(data)):
                    self.assertEqual(
                        data[source.stream_offset:source.stream_offset + source.byte_length],
                        frames[source.frame - 1][source.packet_byte_offset:
                                                  source.packet_byte_offset + source.byte_length],
                    )
        # The first frame's payload begins after Ethernet + IPv4 + TCP headers.
        source = sessions[0].server_to_client.provenance_for(0, 1)[0]
        self.assertEqual((source.frame, source.packet_byte_offset), (1, 54))

    def test_reassembly_deduplicates_retransmits_and_keeps_gaps_explicit(self):
        stream = _reassemble([
            PacketObservation(2, "client_to_server", 0.0, 103, b"def", 54),
            PacketObservation(1, "client_to_server", 0.0, 100, b"abc", 54),
            PacketObservation(3, "client_to_server", 0.0, 101, b"bcdef", 55),
        ])
        self.assertEqual(stream.contiguous_bytes(), b"abcdef")
        incomplete = _reassemble([
            PacketObservation(1, "client_to_server", 0.0, 100, b"abc", 54),
            PacketObservation(2, "client_to_server", 0.0, 105, b"f", 54),
        ])
        self.assertTrue(incomplete.has_gaps)
        with self.assertRaises(ValueError):
            incomplete.contiguous_bytes()


if __name__ == "__main__":
    unittest.main()
