"""Small wire fixtures for capture formats and incomplete traffic, never real mail."""

from pathlib import Path
import tempfile
import unittest

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import CookedLinux, CookedLinuxV2, Dot1Q, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap, wrpcapng

from lab import tls_wire
from sms.m9_report import build_report


def _tcp(link, src, dst, sport, dport, seq, data):
    return link / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=seq) / Raw(data)


def _ether():
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def _smtp_packets(link):
    client, server = "198.51.100.10", "198.51.100.20"
    return [
        _tcp(link, server, client, 25, 44000, 5000, b"220 mail.example ESMTP\r\n"),
        _tcp(link, client, server, 44000, 25, 1000, b"EHLO client.example\r\n"),
    ]


class RobustnessTests(unittest.TestCase):
    def _report(self, packets, *, pcapng=False):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ("fixture.pcapng" if pcapng else "fixture.pcap")
            (wrpcapng if pcapng else wrpcap)(str(path), packets)
            return build_report(path, ml=False)

    def test_ipv6_vlan_and_pcapng_are_analysed(self):
        client, server = "2001:db8::10", "2001:db8::20"
        packets = [
            _ether() / Dot1Q(vlan=20) / IPv6(src=server, dst=client) /
            TCP(sport=25, dport=44000, flags="PA", seq=5000) / Raw(b"220 mail.example ESMTP\r\n"),
            _ether() / Dot1Q(vlan=20) / IPv6(src=client, dst=server) /
            TCP(sport=44000, dport=25, flags="PA", seq=1000) / Raw(b"EHLO client.example\r\n"),
        ]
        report = self._report(packets, pcapng=True)
        self.assertEqual([(session.protocol, session.five_tuple["server_ip"]) for session in report.sessions],
                         [("smtp", server)])

    def test_linux_sll_and_sll2_are_analysed(self):
        for link in (CookedLinux(), CookedLinuxV2()):
            with self.subTest(link=link.__class__.__name__):
                report = self._report(_smtp_packets(link))
                self.assertEqual([session.protocol for session in report.sessions], ["smtp"])

    def test_split_tls_record_and_retransmission_are_reassembled(self):
        client, server = "203.0.113.10", "203.0.113.20"
        hello = tls_wire.client_hello(random_bytes=lambda length: b"\x00" * length)
        split = 21
        first, second = hello[:split], hello[split:]
        packets = [
            _tcp(_ether(), client, server, 44000, 465, 1000, first),
            _tcp(_ether(), client, server, 44000, 465, 1000, first),  # retransmission
            _tcp(_ether(), client, server, 44000, 465, 1000 + len(first), second),
            _tcp(_ether(), server, client, 465, 44000, 5000,
                 tls_wire.server_hello(tls_wire.V_TLS13, 0x1301,
                                       group=tls_wire.G_X25519,
                                       random_bytes=lambda length: b"\x00" * length)),
        ]
        report = self._report(packets)
        self.assertEqual(len(report.sessions), 1)
        session = report.sessions[0]
        self.assertEqual((session.protocol, session.tls.offered_version, session.tls.negotiated_version),
                         ("smtp", "TLS1.3", "TLS1.3"))

    def test_non_mail_and_truncated_captures_do_not_crash_or_create_facts(self):
        non_mail = self._report([_tcp(_ether(), "192.0.2.10", "192.0.2.20", 44000, 443,
                                     1000, b"unrelated application bytes")])
        self.assertEqual(non_mail.summary["sessions_total"], 0)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "truncated.pcap"
            path.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04")
            report = build_report(path, ml=False)
        self.assertEqual((report.summary["sessions_total"], report.hndl["percent"]), (0, 0))
