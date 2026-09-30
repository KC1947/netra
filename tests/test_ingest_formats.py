"""Synthetic capture formats, flow generations and wire provenance for dpkt ingest."""

from pathlib import Path
import tempfile
import unittest

import dpkt
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from scapy.layers.l2 import ARP, CookedLinux, CookedLinuxV2, Dot1Q, Ether, Loopback, LoopbackOpenBSD
from scapy.packet import Raw
from scapy.utils import PcapWriter, wrpcapng

from sms.m1_ingest import (Budget, FlowTable, IngestStats, addr, ingest,
                           ingest_pcap, ingest_pcap_with_stats, network_layer,
                           open_reader)


CLIENT, SERVER = "192.0.2.10", "192.0.2.20"
CLIENT6, SERVER6 = "2001:db8::10", "2001:db8::20"
GREETING = b"220 mail.example ESMTP\r\n"
HELLO = b"EHLO client.example\r\n"


def ether():
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def packets(link, *, ipv6=False, extensions=False):
    client, server = (CLIENT6, SERVER6) if ipv6 else (CLIENT, SERVER)
    network = IPv6 if ipv6 else IP
    result = []
    for src, dst, sport, dport, seq, payload in (
        (server, client, 25, 44000, 5000, GREETING),
        (client, server, 44000, 25, 1000, HELLO),
    ):
        packet = network(src=src, dst=dst)
        if extensions:
            packet /= IPv6ExtHdrHopByHop()
        packet /= TCP(sport=sport, dport=dport, flags="PA", seq=seq) / Raw(payload)
        result.append(link.copy() / packet if link is not None else packet)
    return result


class IngestFormatTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "capture.data"

    def write(self, frames, *, linktype=1, pcapng=False, **options):
        for index, frame in enumerate(frames):
            if not isinstance(frame, bytes):
                frame.time = 1_700_000_000 + index
        if pcapng:
            wrpcapng(str(self.path), frames)
        else:
            with PcapWriter(str(self.path), linktype=linktype, **options) as writer:
                # Scapy's constructor treats LINKTYPE_NULL=0 as unspecified.
                # Set it explicitly before writing the raw packet records.
                writer.linktype = linktype
                writer.write_header(None)
                for index, frame in enumerate(frames):
                    writer.write_packet(bytes(frame), sec=1_700_000_000 + index, usec=0)
        return [bytes(frame) for frame in frames]

    def assert_provenance(self, sessions, frames):
        for session in sessions:
            for observation in session.packet_observations:
                start = observation.payload_packet_offset
                self.assertEqual(observation.payload,
                                 frames[observation.frame_no - 1][start:start + len(observation.payload)])
            for stream in (session.client_to_server, session.server_to_client):
                for data, sources in stream.iter_spans():
                    self.assertEqual(data, b"".join(
                        frames[source.frame - 1][source.packet_byte_offset:
                                                 source.packet_byte_offset + source.byte_length]
                        for source in sources))

    def assert_capture(self, frames, *, ipv6=False, offset=54, **options):
        raw = self.write(frames, **options)
        sessions = ingest_pcap(self.path)
        self.assertEqual(len(sessions), 1)
        session = sessions[0]
        self.assertEqual(session.packets, {"first": 1, "last": 2})
        self.assertEqual(session.client_to_server.contiguous_bytes(), HELLO)
        self.assertEqual(session.server_to_client.contiguous_bytes(), GREETING)
        self.assertEqual(session.five_tuple["client_ip"], CLIENT6 if ipv6 else CLIENT)
        self.assertEqual(session.five_tuple["server_ip"], SERVER6 if ipv6 else SERVER)
        self.assertEqual([item.payload_packet_offset for item in session.packet_observations], [offset, offset])
        self.assert_provenance(sessions, raw)
        table, stats = ingest(self.path)
        self.assertEqual((stats.frames, stats.tcp_segments, len(table.flows)), (2, 2, 1))
        self.assertEqual((stats.ipv4, stats.ipv6), (0, 2) if ipv6 else (2, 0))
        self.assertEqual(stats.skipped, {})

    def test_classic_pcap_microseconds_nanoseconds_and_byte_orders(self):
        for endian in ("<", ">"):
            for nano in (False, True):
                with self.subTest(endian=endian, nano=nano):
                    self.assert_capture(packets(ether()), endianness=endian, nano=nano)
                    with self.path.open("rb") as fh:
                        self.assertIsInstance(open_reader(fh), dpkt.pcap.Reader)

    def test_pcapng_is_selected_by_magic_not_extension(self):
        self.assert_capture(packets(ether()), pcapng=True)
        with self.path.open("rb") as fh:
            self.assertIsInstance(open_reader(fh), dpkt.pcapng.Reader)

    def test_vlan_and_qinq_offsets(self):
        self.assert_capture(packets(ether() / Dot1Q(vlan=20)), offset=58)
        self.assert_capture(packets(ether() / Dot1Q(vlan=20) / Dot1Q(vlan=30)), offset=62)

    def test_ipv6_addresses_and_provenance(self):
        self.assert_capture(packets(ether(), ipv6=True), ipv6=True, offset=74)

    def test_ipv6_extension_headers_are_not_payload(self):
        self.assert_capture(packets(ether(), ipv6=True, extensions=True), ipv6=True, offset=82)

    def test_linux_cooked_v1_and_v2(self):
        for link, linktype, offset in ((CookedLinux(), 113, 56), (CookedLinuxV2(), 276, 60)):
            with self.subTest(linktype=linktype):
                self.assert_capture(packets(link), linktype=linktype, offset=offset)

    def test_bsd_loopback_ipv4_and_ipv6(self):
        for link, linktype in ((Loopback(), 0), (LoopbackOpenBSD(), 108)):
            for ipv6 in (False, True):
                with self.subTest(linktype=linktype, ipv6=ipv6):
                    self.assert_capture(packets(link, ipv6=ipv6), linktype=linktype,
                                        ipv6=ipv6, offset=64 if ipv6 else 44)

    def test_raw_ip(self):
        for ipv6, linktype in ((False, 101), (True, 101), (False, 228), (True, 229)):
            with self.subTest(ipv6=ipv6, linktype=linktype):
                self.assert_capture(packets(None, ipv6=ipv6), ipv6=ipv6,
                                    linktype=linktype, offset=60 if ipv6 else 40)
                ip = network_layer(linktype, bytes(packets(None, ipv6=ipv6)[0]))
                self.assertEqual(addr(ip), (SERVER6, CLIENT6) if ipv6 else (SERVER, CLIENT))

    def test_padding_and_ip_tcp_options_preserve_byte_offsets(self):
        frames = packets(ether())
        for packet in frames:
            packet[IP].options = b"\x01" * 4
            packet[TCP].options = [("MSS", 1460)]
        raw = [bytes(packet) + b"\x00" * 12 for packet in frames]
        self.assert_capture(raw, offset=62)
        _, stats = ingest(self.path)
        self.assertEqual(stats.trimmed_padding, 24)

    def test_ipv4_fragments_are_counted_not_reassembled(self):
        frames = packets(ether())
        first = frames[0].copy()
        first[IP].flags = "MF"
        later = ether() / IP(src=SERVER, dst=CLIENT, proto=6, frag=2) / Raw(b"fragment")
        raw = self.write([first, later, frames[1]])
        table, stats = ingest(self.path)
        self.assertEqual((stats.frames, stats.fragments, stats.tcp_segments), (3, 2, 1))
        self.assertEqual(stats.as_dict()["ipv4_fragments"], 2)
        self.assertEqual(stats.skipped, {"ipv4_fragment": 2})
        self.assertEqual(len(table.flows), 1)
        sessions = ingest_pcap(self.path)
        self.assertEqual(sessions[0].packets, {"first": 3, "last": 3})
        self.assertEqual(sessions[0].server_to_client.contiguous_bytes(), b"")
        self.assert_provenance(sessions, raw)

    def test_corrupt_frame_in_middle_does_not_stop_ingest(self):
        frames = packets(ether())
        raw = self.write([frames[0], b"\x00", frames[1]])
        _, stats = ingest(self.path)
        self.assertEqual((stats.frames, stats.tcp_segments), (3, 2))
        self.assertEqual(stats.skipped, {"link_decode:NeedData": 1})
        sessions = ingest_pcap(self.path)
        self.assertEqual([item.frame_no for item in sessions[0].packet_observations], [1, 3])
        self.assertEqual(sessions[0].client_to_server.contiguous_bytes(), HELLO)
        self.assert_provenance(sessions, raw)

    def test_non_ip_non_tcp_and_truncated_frames_are_counted(self):
        self.write([ether() / ARP(), ether() / IP(src=CLIENT, dst=SERVER) / UDP(),
                    bytes(packets(ether())[0])[:-1], packets(ether())[1]])
        _, stats = ingest(self.path)
        self.assertEqual((stats.frames, stats.tcp_segments), (4, 1))
        self.assertEqual(stats.skipped, {"not_ip": 1, "not_tcp": 1, "truncated_ip": 1})

    def test_bad_capture_header_and_truncated_record_are_counted(self):
        self.path.write_bytes(b"\xd4\xc3\xb2\xa1\x02")
        _, stats = ingest(self.path)
        self.assertEqual(sum(stats.skipped.values()), 1)
        self.assertEqual(ingest_pcap(self.path), [])
        self.write(packets(ether()))
        with self.path.open("ab") as fh:
            fh.write(b"\x00")
        _, stats = ingest(self.path)
        self.assertEqual((stats.frames, stats.tcp_segments), (2, 2))
        self.assertEqual(stats.skipped, {"capture_record:NeedData": 1})

    def test_unsupported_linktype_and_port_filter_are_counted(self):
        self.write(packets(ether()), linktype=999)
        _, stats = ingest(self.path)
        self.assertEqual(stats.linktypes, {999: 2})
        self.assertEqual(stats.skipped, {"link_decode:ValueError": 2})
        passport = stats.as_dict()
        self.assertEqual(passport["snaplen"], 65535)
        self.assertEqual(passport["frames_decoded_pct"], 0.0)
        self.assertEqual(passport["analysis_status"], "unsupported")
        self.assertEqual(passport["unsupported_packets"], {
            "count": 2,
            "breakdown": {
                "link_type": 2, "malformed": 0,
                "non_tcp": 0, "truncated_header": 0,
            },
        })
        self.write(packets(ether()))
        table, stats = ingest(self.path, port_filter={993})
        self.assertEqual(stats.skipped, {"port_filtered": 2})
        self.assertFalse(table.flows)

    def test_capture_header_truncation_and_midstream_are_reported(self):
        frames = packets(ether())
        raw = bytes(frames[0])
        with PcapWriter(str(self.path), linktype=1) as writer:
            writer.write_header(None)
            writer.write_packet(raw[:-1], sec=1_700_000_000, usec=0,
                                caplen=len(raw) - 1, wirelen=len(raw))
        sessions, stats = ingest_pcap_with_stats(self.path)
        passport = stats.as_dict()
        self.assertTrue(passport["truncated"])
        self.assertEqual(passport["unsupported_packets"]["breakdown"]["truncated_header"], 1)
        self.assertEqual(sessions, [])

        self.write(frames)
        sessions, stats = ingest_pcap_with_stats(self.path)
        self.assertTrue(sessions[0].midstream)
        self.assertEqual(stats.as_dict()["midstream_sessions"], {"s1": True})

    def test_port_reuse_after_server_rst_and_retransmitted_syn(self):
        def packet(seq, flags, payload=b"", reverse=False):
            src, dst, sport, dport = (SERVER, CLIENT, 25, 44000) if reverse else (CLIENT, SERVER, 44000, 25)
            return ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, flags=flags) / Raw(payload)

        frames = [packet(1000, "S"), packet(1000, "S"), packet(5000, "SA", reverse=True),
                  packet(1001, "PA", HELLO), packet(5001, "PA", GREETING, reverse=True),
                  packet(5001 + len(GREETING), "R", reverse=True),
                  packet(9000, "S"), packet(9000, "S"), packet(15000, "SA", reverse=True),
                  packet(9001, "PA", HELLO), packet(9001, "PA", HELLO),
                  packet(15001, "PA", GREETING, reverse=True)]
        raw = self.write(frames)
        sessions = ingest_pcap(self.path)
        self.assertEqual([session.id for session in sessions], ["s1", "s2"])
        self.assertEqual([session.packets for session in sessions],
                         [{"first": 1, "last": 6}, {"first": 7, "last": 12}])
        for session in sessions:
            self.assertEqual(session.client_to_server.contiguous_bytes(), HELLO)
            self.assertEqual(session.server_to_client.contiguous_bytes(), GREETING)
        self.assert_provenance(sessions, raw)
        table, stats = ingest(self.path)
        self.assertEqual([key[-1] for key in table.flows], [1, 2])
        self.assertEqual(stats.tcp_segments, 12)

    def test_syn_payload_consumes_sequence_number_before_data(self):
        first = packets(ether())[1]
        first[TCP].flags = "S"
        second = first.copy()
        second[TCP].flags = "PA"
        second[TCP].seq += 1 + len(HELLO)
        raw = self.write([first, second])
        sessions = ingest_pcap(self.path)
        self.assertEqual(sessions[0].client_to_server.contiguous_bytes(), HELLO * 2)
        self.assert_provenance(sessions, raw)


class FlowBudgetTests(unittest.TestCase):
    def test_global_bytes_evict_lru_and_oversize_single_flow_is_truncated(self):
        stats = IngestStats()
        table = FlowTable(Budget(total_bytes=10, bytes_per_flow=20), stats)
        for index in range(3):
            key = table.key_for((CLIENT, 44000 + index, SERVER, 25), True, False, index)
            table.add(key, index, 0.0, index, b"x" * 6)
            self.assertLessEqual(table.total, 10)
        self.assertEqual((stats.flows_evicted, len(table.flows)), (2, 1))
        table.add(key, 4, 0.0, 4, b"x" * 5)
        table.add(key, 5, 0.0, 5, b"x" * 30)
        self.assertEqual(stats.flows_truncated, 1)
        self.assertEqual(table.total, 6)
        self.assertTrue(table.flows[key]["incomplete"])
        empty = FlowTable(Budget(total_bytes=0))
        empty.add(key, 1, 0.0, 1, b"x")
        self.assertEqual(empty.total, 0)
        self.assertEqual(empty.st.flows_truncated, 1)

    def test_per_flow_bytes_segments_and_generation_maps_are_bounded(self):
        table = FlowTable(Budget(bytes_per_flow=5, segments_per_flow=2, max_flows=2))
        for index in range(10):
            key = table.key_for((CLIENT, 44000 + index, SERVER, 25), True, False, index)
            table.add(key, index, 0.0, index, b"xx")
            table.add(key, index, 0.0, index, b"xx")
            table.add(key, index, 0.0, index, b"xx")
        self.assertEqual((len(table.flows), len(table.gen), len(table.isn)), (2, 2, 2))
        self.assertEqual((table.st.flows_evicted, table.st.flows_truncated), (8, 10))
        self.assertEqual(table.total, 8)
        controls = FlowTable(Budget(segments_per_flow=2))
        for frame in range(20):
            controls.add(key, frame, 0.0, 0, b"")
        self.assertEqual(len(controls.flows[key]["segs"]), 2)
        self.assertEqual(controls.st.flows_truncated, 1)

    def test_evicting_old_generation_does_not_forget_current_isn(self):
        table = FlowTable(Budget(max_flows=1))
        endpoints = (CLIENT, 44000, SERVER, 25)
        first = table.key_for(endpoints, True, False, 1000)
        table.add(first, 1, 0.0, 1000, b"")
        second = table.key_for(endpoints, True, False, 9000)
        table.add(second, 2, 0.0, 9000, b"")
        self.assertNotEqual(first, second)
        self.assertEqual(table.key_for(endpoints, True, False, 9000), second)
        reverse = (SERVER, 25, CLIENT, 44000)
        self.assertEqual(table.key_for(reverse, False, False, 3000), second)


if __name__ == "__main__":
    unittest.main()
