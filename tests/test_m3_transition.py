import unittest

from sms.contracts import ByteSlice, ByteStream, Session, StreamGap
from sms.m1_ingest import ingest_pcap
from sms.m2_protocol import classify_protocols
from sms.m3_transition import analyse_transition


def stream(parts):
    """Build a contiguous private stream from (payload, frame) pairs."""
    chunks, slices, offset = [], [], 0
    for payload, frame in parts:
        chunks.append(payload)
        slices.append(ByteSlice(offset, len(payload), frame, 54))
        offset += len(payload)
    return ByteStream(chunks, slices)


def session(protocol, client, server):
    return Session(
        "unit", {"server_port": 25}, protocol=protocol,
        packets={"first": 1, "last": 99},
        client_to_server=stream(client), server_to_client=stream(server),
    )


TLS_RECORD = b"\x16\x03\x03\x00\x04\x01\x00\x00\x00"


class TransitionTests(unittest.TestCase):
    def test_fixture_transitions_and_redacted_evidence(self):
        sessions = classify_protocols(ingest_pcap("out/sample.pcap"))
        for item in sessions:
            analyse_transition(item)
        self.assertEqual([item.transition.verdict for item in sessions],
                         ["upgraded", "upgraded", "not_used", "suspected", "upgraded", "upgraded"])
        strip = next(item for item in sessions[3].findings
                     if item.rule_id == "STARTTLS-STRIP-SUSPECTED")
        self.assertEqual([(item.frame, item.byte_offset, item.byte_length, item.display)
                          for item in strip.evidence],
                         [(26, 96, 8, "250 XSNVVQRW"),
                          (27, 54, 37, "AUTH argument redacted")])
        rendered = repr([item.to_dict() for item in sessions])
        self.assertNotIn("supersecret", rendered)
        self.assertNotIn("AGxvZ2lu", rendered)

    def test_rejected_and_accepted_without_tls_are_distinct(self):
        rejected = session("smtp", [(b"STARTTLS\r\n", 2)], [(b"500 no\r\n", 3)])
        failed = session("smtp", [(b"STARTTLS\r\n", 2)], [(b"220 ready\r\n", 3)])
        analyse_transition(rejected)
        analyse_transition(failed)
        self.assertEqual(rejected.transition.verdict, "rejected")
        self.assertEqual(failed.transition.verdict, "failed")

    def test_fragmented_imap_and_pop3_upgrades(self):
        imap = session("imap", [(b"a1 STA", 2), (b"RTTLS\r\n", 3)],
                       [(b"a2 OK unrelated\r\n", 4), (b"a1 OK begin\r\n", 5), (TLS_RECORD, 6)])
        pop3 = session("pop3", [(b"STLS\r\n", 2)], [(b"+OK begin\r\n", 3), (TLS_RECORD, 4)])
        analyse_transition(imap)
        analyse_transition(pop3)
        self.assertEqual(imap.transition.verdict, "upgraded")
        self.assertEqual(pop3.transition.verdict, "upgraded")

    def test_auth_inside_smtp_data_and_gapped_commands_are_not_evidence(self):
        body = session("smtp", [(b"DATA\r\n", 2), (b"AUTH PLAIN secret\r\n", 3)],
                       [(b"250 PIPELINING\r\n", 1)])
        analyse_transition(body)
        self.assertFalse(body.findings)

        incomplete = session("smtp", [(b"AUTH", 3), (b" PLAIN secret\r\n", 4)],
                             [(b"250 PIPELINING\r\n", 1)])
        incomplete.client_to_server = ByteStream(
            [b"AUTH", b" PLAIN secret\r\n"],
            [ByteSlice(0, 4, 3, 54), ByteSlice(9, 15, 4, 54)],
            [StreamGap(4, 5, 4, 9)],
        )
        analyse_transition(incomplete)
        self.assertFalse(incomplete.findings)


if __name__ == "__main__":
    unittest.main()
