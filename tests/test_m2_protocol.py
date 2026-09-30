import unittest

from sms.contracts import ByteSlice, ByteStream, PacketObservation, Session
from sms.m1_ingest import ingest_pcap
from sms.m2_protocol import classify_protocol, classify_protocols


def stream(data: bytes) -> ByteStream:
    return ByteStream([data], [ByteSlice(0, len(data), 1, 54)])


class ProtocolTests(unittest.TestCase):
    def test_fixture_protocols_are_grammar_first_with_implicit_tls_hints(self):
        sessions = classify_protocols(ingest_pcap("out/sample.pcap"))
        self.assertEqual([item.protocol for item in sessions],
                         ["smtp", "smtp", "smtp", "smtp", "imap", "smtp"])
        self.assertEqual([item.protocol_confidence for item in sessions],
                         ["high", "high", "high", "high", "medium", "medium"])
        self.assertEqual(sessions[4].protocol_reason, "implicit TLS; protocol inferred from port hint")
        self.assertEqual(sessions[5].protocol_reason, "implicit TLS; protocol inferred from port hint")
        # Serialized sessions expose neither banners nor internal notes.
        self.assertNotIn("mail.example.com", repr(sessions[0].to_dict()))
        self.assertNotIn("implicit", sessions[4].to_dict())

    def test_nonstandard_port_uses_banner_and_reverses_proven_server_direction(self):
        session = Session(
            "nonstandard",
            {"client_ip": "198.51.100.20", "client_port": 2525,
             "server_ip": "198.51.100.10", "server_port": 40000, "transport": "tcp"},
            client_to_server=stream(b"220 mx.example ESMTP\r\n"),
            server_to_client=stream(b"EHLO client.example\r\n"),
            packet_observations=[PacketObservation(1, "client_to_server", 0.0, 1, b"x", 54)],
        )
        classify_protocol(session)
        self.assertEqual((session.protocol, session.protocol_confidence), ("smtp", "high"))
        self.assertEqual((session.five_tuple["client_port"], session.five_tuple["server_port"]), (40000, 2525))
        self.assertEqual(session.packet_observations[0].direction, "server_to_client")

    def test_unhinted_implicit_tls_and_unrelated_text_stay_unknown(self):
        for server_bytes in (b"\x16\x03\x03\x00\x00", b"HELLO THERE\r\n"):
            session = Session("unknown", {"server_port": 4443}, server_to_client=stream(server_bytes))
            classify_protocol(session)
            self.assertEqual((session.protocol, session.protocol_confidence), ("unknown", "unknown"))


if __name__ == "__main__":
    unittest.main()
