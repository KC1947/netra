"""Acceptance fixtures for passive TLS signal semantics."""

from __future__ import annotations

import struct
import unittest

from sms.contracts import ByteSlice, ByteStream, Session
from sms.m4_tls import analyse_tls
from sms.m6_rules import apply_rules
from sms.m8_score import score_session


def _u16(value: int) -> bytes:
    return struct.pack("!H", value)


def _u24(value: int) -> bytes:
    return struct.pack("!I", value)[1:]


def _extension(extension_type: int, data: bytes) -> bytes:
    return _u16(extension_type) + _u16(len(data)) + data


def _handshake(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + _u24(len(body)) + body


def _record(handshake: bytes) -> bytes:
    return b"\x16\x03\x01" + _u16(len(handshake)) + handshake


def _client_hello(*, versions=(0x0304, 0x0303), extensions=()) -> bytes:
    supported_versions = bytes([len(versions) * 2]) + b"".join(
        _u16(version) for version in versions
    )
    encoded_extensions = _extension(0x002B, supported_versions)
    encoded_extensions += b"".join(
        _extension(extension_type, data) for extension_type, data in extensions
    )
    cipher_suites = _u16(0x1301) + _u16(0xC02F)
    body = (
        _u16(0x0303)
        + bytes(32)
        + b"\x00"
        + _u16(len(cipher_suites))
        + cipher_suites
        + b"\x01\x00"
        + _u16(len(encoded_extensions))
        + encoded_extensions
    )
    return _record(_handshake(1, body))


def _server_hello(*, version: int, cipher: int, group: int | None = None,
                  extensions=()) -> bytes:
    encoded_extensions = b""
    if version == 0x0304:
        encoded_extensions += _extension(0x002B, _u16(version))
    if group is not None:
        encoded_extensions += _extension(0x0033, _u16(group) + _u16(1) + b"K")
    encoded_extensions += b"".join(
        _extension(extension_type, data) for extension_type, data in extensions
    )
    legacy_version = 0x0303 if version >= 0x0303 else version
    body = (
        _u16(legacy_version)
        + bytes(range(32))
        + b"\x00"
        + _u16(cipher)
        + b"\x00"
        + _u16(len(encoded_extensions))
        + encoded_extensions
    )
    return _record(_handshake(2, body))


def _stream(payload: bytes, frame: int) -> ByteStream:
    return ByteStream([payload], [ByteSlice(0, len(payload), frame, 54)])


def _session(client: bytes, server: bytes, session_id: str) -> Session:
    session = Session(
        session_id,
        {"server_port": 465},
        protocol="smtp",
        protocol_confidence="certain",
    )
    session.transition.verdict = "upgraded"
    session.transition.confidence_band = "certain"
    session.client_to_server = _stream(client, 1)
    session.server_to_client = _stream(server, 2)
    return analyse_tls(session)


class TlsSignalAcceptanceTests(unittest.TestCase):
    def test_tls13_psk_ke_without_key_share_has_no_forward_secrecy(self):
        # A minimal but structurally valid ClientHello pre_shared_key body.
        identity = _u16(1) + b"i" + bytes(4)
        binder = b"\x20" + bytes(32)
        offered_psk = _u16(len(identity)) + identity + _u16(len(binder)) + binder
        session = _session(
            _client_hello(extensions=((0x0029, offered_psk),)),
            _server_hello(
                version=0x0304,
                cipher=0x1301,
                group=None,
                extensions=((0x0029, _u16(0)),),
            ),
            "psk_ke",
        )

        self.assertTrue(session.tls.psk_offered)
        self.assertTrue(session.tls.psk_selected)
        self.assertEqual(session.tls.signal_facts()["forward_secrecy"], "NO")
        self.assertFalse(session.tls.forward_secrecy)  # v1 compatibility field

        apply_rules(session)
        finding = next(
            item for item in session.findings
            if item.rule_id == "TLS13-NO-FORWARD-SECRECY"
        )
        self.assertTrue(finding.evidence)

    def test_tls12_status_request_without_certificate_status_is_not_provided(self):
        # RFC 6066 status_request: type=ocsp, empty responder IDs/extensions.
        status_request = b"\x01\x00\x00\x00\x00"
        session = _session(
            _client_hello(versions=(0x0303,), extensions=((0x0005, status_request),)),
            _server_hello(version=0x0303, cipher=0xC02F),
            "ocsp_missing",
        )

        self.assertTrue(session.tls.status_request_sent)
        self.assertEqual(session.tls.ocsp_stapling, "requested_not_provided")

        apply_rules(session)
        finding = next(
            item for item in session.findings
            if item.rule_id == "TLS-NO-OCSP-STAPLING"
        )
        self.assertTrue(finding.evidence)

    def test_ech_lowers_coverage_without_raising_risk(self):
        server = _server_hello(version=0x0304, cipher=0x1301, group=0x001D)
        baseline = _session(_client_hello(), server, "baseline")
        ech = _session(
            _client_hello(extensions=((0xFE0D, b"\x00"),)),
            server,
            "ech",
        )
        for session in (baseline, ech):
            apply_rules(session)
            score_session(session)

        self.assertTrue(ech.tls.ech_offered)
        self.assertLess(ech.evidence_coverage, baseline.evidence_coverage)
        self.assertEqual(ech.observed_risk, baseline.observed_risk)
        self.assertEqual(ech.observed_risk, 0)
        ech_finding = next(
            item for item in ech.findings if item.rule_id == "TLS-ECH-IN-USE"
        )
        self.assertEqual(ech_finding.severity, "info")
        self.assertTrue(ech_finding.evidence)


if __name__ == "__main__":
    unittest.main()
