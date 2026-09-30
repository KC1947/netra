"""Passive TLS record and handshake parsing with exact packet provenance.

dpkt validates TLS record and hello framing. Bounded extension-body decoding
remains local. Unknown algorithm code points stay unknown and every offer list
preserves wire order.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct

import dpkt
import dpkt.ssl as ssl

from .contracts import ByteStream, Evidence, Session
from .judgement.epistemic import Tier
from .parsing.reader import Malformed, SafeReader, Truncated, u16_vector
from .registry import load as load_registry

# A package path preserves the sms.m4_tls API while exposing its signals submodule.
__path__ = [str(Path(__file__).with_suffix(""))]

from .m4_tls.signals import (  # noqa: E402  (requires module package path above)
    EXT_EARLY_DATA,
    EXT_ECH,
    EXT_PRE_SHARED_KEY,
    EXT_STATUS_REQUEST,
    client_signals,
    downgrade_flags,
    forward_secrecy as _signal_forward_secrecy,
    ocsp_stapling as _signal_ocsp_stapling,
)

_CT_CHANGE_CIPHER_SPEC = 0x14
_CT_HANDSHAKE = 0x16
_HS_CLIENT_HELLO = 0x01
_HS_SERVER_HELLO = 0x02
_HS_CERTIFICATE = 0x0B

_EXT_SUPPORTED_VERSIONS = 0x002B
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_KEY_SHARE = 0x0033
_EXT_SERVER_NAME = 0x0000

_VERSION_NAMES = {
    0x0300: "SSL3.0",
    0x0301: "TLS1.0",
    0x0302: "TLS1.1",
    0x0303: "TLS1.2",
    0x0304: "TLS1.3",
}

# RFC 8701 defines exactly these 16 values. The tempting bit mask matches 256.
GREASE = frozenset(((n << 12) | 0x0A00 | (n << 4) | 0x0A) for n in range(16))

DOWNGRADE_12 = bytes.fromhex("444F574E47524401")
DOWNGRADE_11 = bytes.fromhex("444F574E47524400")
HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
)

_DPKT_ERRORS = (
    dpkt.NeedData,
    dpkt.UnpackError,
    ssl.SSL3Exception,
    struct.error,
    IndexError,
    ValueError,
    TypeError,
)


def is_grease(value: int) -> bool:
    return value in GREASE


def classify_group(group: int | None) -> str:
    """Registry-backed group classification; unknown is never guessed."""
    return load_registry().classify_group(group)


def downgrade_finding(client: dict, server: dict) -> dict | None:
    """Compatibility API ported from the reference regression implementation."""
    if not server.get("downgrade_sentinel"):
        return None
    if 0x0304 in client.get("offered_versions", []):
        return {
            "rule_id": "TLS-DOWNGRADE-ANOMALY",
            "severity": "high",
            "tier": "OBSERVED",
            "what": "Client offered TLS 1.3, yet a 1.3-capable server negotiated lower.",
            "why": (
                "The ClientHello the server received may differ from the one observed "
                "here — consistent with interference between this capture point and "
                "the server. Not proof of an attacker."
            ),
        }
    return {
        "rule_id": "TLS-LEGACY-CLIENT",
        "severity": "info",
        "tier": "OBSERVED",
        "what": "A TLS 1.3-capable server served a client that did not offer 1.3.",
        "why": "Expected behaviour under RFC 8446 §4.1.3; recorded for inventory.",
    }


def forward_secrecy(server: dict, psk_modes_offered: list[int] | None) -> str:
    """Reference PSK-aware compatibility API returning YES, NO, or UNKNOWN."""
    del psk_modes_offered  # The observed server choice establishes the actual mode.
    if server.get("selected_version") == 0x0304:
        if server.get("psk_selected") and server.get("selected_group") is None:
            return "NO"
        return "YES"
    return "UNKNOWN"


@dataclass(frozen=True, repr=False)
class _HandshakeMessage:
    msg_type: int
    body: bytes
    body_offset: int


def _evidence(stream: ByteStream, start: int, length: int, field: str,
              display: str) -> list[Evidence]:
    if length <= 0:
        return []
    try:
        sources = stream.provenance_for(start, length)
    except ValueError:
        return []
    return [
        Evidence(source.frame, field, source.packet_byte_offset, source.byte_length, display)
        for source in sources
    ]


def _frame_at(stream: ByteStream, offset: int) -> int | None:
    try:
        sources = stream.provenance_for(offset, 1)
    except ValueError:
        return None
    return sources[0].frame if sources else None


def _find_first_tls_record(data: bytes) -> int:
    """Locate a complete handshake record; a bare 0x16 0x03 is not proof."""
    for candidate in range(0, max(0, len(data) - 4)):
        if data[candidate] != _CT_HANDSHAKE or data[candidate + 1] != 0x03:
            continue
        version_low = data[candidate + 2]
        length = int.from_bytes(data[candidate + 3:candidate + 5], "big")
        if version_low <= 4 and length > 0 and candidate + 5 + length <= len(data):
            return candidate
    return -1


def _iter_handshake_messages(stream: ByteStream) -> list[_HandshakeMessage]:
    """Frame complete TLS handshake records/messages without crossing TCP gaps."""
    for data, sources in stream.iter_spans():
        if not data or not sources:
            continue
        span_start = sources[0].stream_offset
        cursor = _find_first_tls_record(data)
        if cursor < 0:
            continue
        result: list[_HandshakeMessage] = []
        while cursor + 5 <= len(data):
            try:
                record = ssl.TLSRecord(data[cursor:])
            except _DPKT_ERRORS:
                break
            if (record.type == _CT_CHANGE_CIPHER_SPEC and record.length == 1
                    and cursor + 6 <= len(data) and result
                    and result[-1].msg_type == _HS_SERVER_HELLO
                    and result[-1].body[2:34] == HRR_RANDOM):
                # RFC 8446 D.4 middlebox compatibility: a dummy CCS follows a
                # HelloRetryRequest and the real ServerHello is still plaintext
                # after it. Any other CCS precedes encrypted records.
                cursor += 6
                continue
            if record.type != _CT_HANDSHAKE or record.version >> 8 != 0x03 or record.length == 0:
                break
            record_end = cursor + 5 + record.length
            if record_end > len(data):
                break
            if any(span_start + cursor <= offset < span_start + record_end
                   for offset in stream.disputed):
                # Retransmitted copies disagree inside this record; like a gap,
                # it and everything after it are not established handshake.
                break
            record_body = bytes(record.data)
            body_cursor = 0
            while body_cursor + 4 <= len(record_body):
                try:
                    handshake = ssl.TLSHandshake(record_body[body_cursor:])
                except _DPKT_ERRORS:
                    break
                message_end = body_cursor + 4 + handshake.length
                if message_end > len(record_body):
                    break
                message_body_offset = span_start + cursor + 5 + body_cursor + 4
                result.append(_HandshakeMessage(
                    handshake.type,
                    record_body[body_cursor + 4:message_end],
                    message_body_offset,
                ))
                body_cursor = message_end
            cursor = record_end
        return result
    return []


def _status(exc: Exception) -> str:
    return "truncated" if isinstance(exc, (dpkt.NeedData, Truncated)) else "malformed"


def _read_extensions(reader: SafeReader) -> list[dict]:
    if reader.remaining() == 0:
        return []
    total_length = reader.u16()
    extensions = reader.sub(total_length)
    reader.expect_end()
    result: list[dict] = []
    while extensions.remaining():
        type_offset = extensions.off
        extension_type = extensions.u16()
        # RFC 8446 §4.2: at most one extension of each type. With two, which
        # one a peer honours is unknowable and a conforming peer aborts.
        if any(item["type"] == extension_type for item in result):
            raise Malformed("duplicate extension")
        data_length = extensions.u16()
        data_offset = extensions.off
        data_reader = extensions.sub(data_length)
        result.append({
            "type": extension_type,
            "data": data_reader.buf[data_reader.off:data_reader.end],
            "type_offset": type_offset,
            "data_offset": data_offset,
            "data_length": data_length,
        })
    return result


def _client_layout(body: bytes) -> dict:
    reader = SafeReader(body)
    reader.u16()
    reader.sub(32)
    reader.sub(reader.u8())
    cipher_length = reader.u16()
    if cipher_length % 2:
        raise Malformed("odd-length cipher vector")
    cipher_start = reader.off
    ciphers = reader.sub(cipher_length)
    cipher_codes: list[int] = []
    cipher_offsets: list[int] = []
    while ciphers.remaining():
        cipher_offsets.append(ciphers.off)
        cipher_codes.append(ciphers.u16())
    reader.sub(reader.u8())
    return {
        "cipher_codes": cipher_codes,
        "cipher_offsets": cipher_offsets,
        "cipher_start": cipher_start,
        "cipher_length": cipher_length,
        "extensions": _read_extensions(reader),
    }


def _server_layout(body: bytes) -> dict:
    reader = SafeReader(body)
    reader.u16()
    reader.sub(32)
    reader.sub(reader.u8())
    cipher_offset = reader.off
    reader.u16()
    reader.u8()
    return {"cipher_offset": cipher_offset, "extensions": _read_extensions(reader)}


def _server_name(extension_data: bytes) -> tuple[str, int, int] | None:
    """Return the first valid DNS host_name and its extension-body range."""
    reader = SafeReader(extension_data)
    names = reader.sub(reader.u16())
    reader.expect_end()
    while names.remaining():
        name_type = names.u8()
        name_length = names.u16()
        name_offset = names.off
        encoded = bytes(names.sub(name_length).buf[name_offset:name_offset + name_length])
        if name_type != 0:
            continue
        try:
            hostname = encoded.decode("ascii").rstrip(".").lower()
        except UnicodeDecodeError:
            return None
        labels = hostname.split(".")
        if (not hostname or len(hostname) > 253
                or any(not label or len(label) > 63 for label in labels)
                or any(not all(character.isalnum() or character == "-" for character in label)
                       for label in labels)
                or any(label.startswith("-") or label.endswith("-") for label in labels)):
            return None
        return hostname, name_offset, name_length
    return None


def parse_client_hello(body: bytes) -> dict:
    """Parse the complete ordered client offer using dpkt hello framing."""
    output = {
        "offered_ciphers": [],
        "offered_versions": [],
        "offered_groups": [],
        "offered_cipher_offsets": {},
        "offered_version_offsets": {},
        "has_fallback_scsv": False,
        "legacy_version": None,
        "server_name": None,
        "supported_versions_present": False,
        "extensions": [],
        "extension_type_offsets": {},
        "parse_status": "complete",
        "parse_note": None,
    }
    try:
        hello = ssl.TLSClientHello(body)
        layout = _client_layout(body)
    except _DPKT_ERRORS + (Truncated, Malformed) as exc:
        output["parse_status"], output["parse_note"] = _status(exc), type(exc).__name__
        return output

    output["legacy_version"] = hello.version
    output["legacy_version_offset"] = 0
    output["cipher_vector_offset"] = layout["cipher_start"]
    output["cipher_vector_length"] = layout["cipher_length"]
    for code, offset in zip(layout["cipher_codes"], layout["cipher_offsets"]):
        if code == 0x5600:
            output["has_fallback_scsv"] = True
            output["has_fallback_scsv_offset"] = offset
        elif not is_grease(code):
            output["offered_ciphers"].append(code)
            output["offered_cipher_offsets"].setdefault(code, []).append(offset)

    extension_pairs: list[tuple[int, bytes]] = []
    for extension in layout["extensions"]:
        extension_type = extension["type"]
        extension_data = extension["data"]
        extension_pairs.append((extension_type, extension_data))
        output["extension_type_offsets"].setdefault(extension_type, []).append(
            extension["type_offset"]
        )
        try:
            if extension_type == _EXT_SUPPORTED_VERSIONS:
                output["supported_versions_present"] = True
                versions = u16_vector(extension_data, 1)
                output["offered_versions"] = [
                    version for version in versions if not is_grease(version)
                ]
                for index, version in enumerate(versions):
                    if not is_grease(version):
                        output["offered_version_offsets"].setdefault(version, []).append(
                            extension["data_offset"] + 1 + index * 2
                        )
                output["supported_versions_offset"] = extension["data_offset"] + 1
                output["supported_versions_length"] = extension_data[0]
            elif extension_type == _EXT_SUPPORTED_GROUPS:
                output["offered_groups"] = [
                    group for group in u16_vector(extension_data, 2)
                    if not is_grease(group)
                ]
                output["supported_groups_offset"] = extension["data_offset"] + 2
                output["supported_groups_length"] = int.from_bytes(extension_data[:2], "big")
            elif extension_type == _EXT_SERVER_NAME:
                parsed_name = _server_name(extension_data)
                if parsed_name is not None:
                    hostname, offset, length = parsed_name
                    output["server_name"] = hostname
                    output["server_name_offset"] = extension["data_offset"] + offset
                    output["server_name_length"] = length
        except (Truncated, Malformed) as exc:
            output["parse_status"], output["parse_note"] = _status(exc), str(exc)
            break
    output["extensions"] = extension_pairs
    return output


def parse_server_hello(body: bytes) -> dict:
    """Parse a ServerHello with structured truncated/malformed status."""
    output = {
        "legacy_version": None,
        "selected_cipher": None,
        "selected_version": None,
        "selected_group": None,
        "downgrade_sentinel": None,
        "is_hello_retry_request": False,
        "psk_selected": False,
        "extensions": [],
        "extension_type_offsets": {},
        "parse_status": "complete",
        "parse_note": None,
    }
    try:
        hello = ssl.TLSServerHello(body)
        layout = _server_layout(body)
    except _DPKT_ERRORS + (Truncated, Malformed) as exc:
        output["parse_status"], output["parse_note"] = _status(exc), type(exc).__name__
        return output

    output["legacy_version"] = hello.version
    output["legacy_version_offset"] = 0
    output["selected_cipher"] = hello.ciphersuite.code
    output["selected_cipher_offset"] = layout["cipher_offset"]
    random = hello.random
    if random == HRR_RANDOM:
        output["is_hello_retry_request"] = True
    if random[-8:] == DOWNGRADE_12:
        output["downgrade_sentinel"] = "settled_on_1.2"
        output["downgrade_sentinel_offset"] = 26
    elif random[-8:] == DOWNGRADE_11:
        output["downgrade_sentinel"] = "settled_on_1.1_or_lower"
        output["downgrade_sentinel_offset"] = 26

    extension_pairs: list[tuple[int, bytes]] = []
    try:
        for extension in layout["extensions"]:
            extension_type = extension["type"]
            extension_data = extension["data"]
            extension_pairs.append((extension_type, extension_data))
            output["extension_type_offsets"].setdefault(extension_type, []).append(
                extension["type_offset"]
            )
            reader = SafeReader(extension_data)
            if extension_type == _EXT_SUPPORTED_VERSIONS:
                output["selected_version"] = reader.u16()
                reader.expect_end()
                # RFC 8446 §4.2.1: a pre-1.3 version here makes the client abort.
                if output["selected_version"] < 0x0304:
                    raise Malformed("supported_versions selects a version below TLS 1.3")
                output["selected_version_offset"] = extension["data_offset"]
            elif extension_type == _EXT_KEY_SHARE:
                output["selected_group"] = reader.u16()
                output["selected_group_offset"] = extension["data_offset"]
            elif extension_type == EXT_PRE_SHARED_KEY:
                output["psk_selected"] = True
    except (Truncated, Malformed) as exc:
        output["parse_status"], output["parse_note"] = _status(exc), str(exc)

    output["extensions"] = extension_pairs
    if output["selected_version"] is None:
        output["selected_version"] = output["legacy_version"]
        output["selected_version_offset"] = output.get("legacy_version_offset", 0)
    return output


# Existing tests and callers use the private spellings.
_parse_client_hello = parse_client_hello
_parse_server_hello = parse_server_hello


def _parse_certificate(body: bytes) -> dict:
    """Read only the first certificate in a TLS 1.0/1.2 Certificate list."""
    if len(body) < 3:
        return {}
    list_length = int.from_bytes(body[0:3], "big")
    end = min(3 + list_length, len(body))
    if 6 > end:
        return {}
    certificate_length = int.from_bytes(body[3:6], "big")
    certificate_start, certificate_end = 6, 6 + certificate_length
    if certificate_end > end:
        return {}
    return {
        "der": body[certificate_start:certificate_end],
        "der_offset": certificate_start,
        "der_length": certificate_length,
    }


def _extension_evidence(stream: ByteStream, message: _HandshakeMessage | None,
                        parsed: dict, extension_type: int, field: str,
                        display: str) -> list[Evidence]:
    if message is None:
        return []
    offsets = parsed.get("extension_type_offsets", {}).get(extension_type, [])
    return [
        evidence
        for offset in offsets
        for evidence in _evidence(stream, message.body_offset + offset, 2, field, display)
    ]


def analyse_tls(session: Session) -> Session:
    """Populate TLS facts, passive signals, evidence, and private cert bytes."""
    client_messages = _iter_handshake_messages(session.client_to_server)
    server_messages = _iter_handshake_messages(session.server_to_client)
    client_hello = next((m for m in client_messages if m.msg_type == _HS_CLIENT_HELLO), None)
    # A HelloRetryRequest shares the ServerHello type but negotiates nothing:
    # it only asks for another key share. Only a real ServerHello selects.
    hello_retry = any(
        m.msg_type == _HS_SERVER_HELLO and m.body[2:34] == HRR_RANDOM
        for m in server_messages
    )
    server_hello = next((m for m in server_messages if m.msg_type == _HS_SERVER_HELLO
                         and m.body[2:34] != HRR_RANDOM), None)
    certificate_message = next(
        (m for m in server_messages if m.msg_type == _HS_CERTIFICATE), None
    )

    client = parse_client_hello(client_hello.body) if client_hello is not None else {}
    server = parse_server_hello(server_hello.body) if server_hello is not None else {}
    if server and hello_retry:
        # RFC 8446 §4.1.4/§4.2.8: the ServerHello must keep the HelloRetryRequest's
        # version, cipher suite and requested group, or the client aborts.
        retry = parse_server_hello(next(
            m for m in server_messages
            if m.msg_type == _HS_SERVER_HELLO and m.body[2:34] == HRR_RANDOM).body)
        if (retry.get("parse_status") != "complete"
                or retry.get("selected_version") != server.get("selected_version")
                or retry.get("selected_cipher") != server.get("selected_cipher")
                or retry.get("selected_group") not in (None, server.get("selected_group"))):
            server = {"parse_status": "malformed"}
    if server.get("parse_status", "complete") != "complete":
        # A client aborts on a ServerHello that fails validation, so none of
        # its partially parsed fields was negotiated.
        server = {}
    registry = load_registry()

    offered_ciphers = list(client.get("offered_ciphers", []))
    offered_versions = list(client.get("offered_versions", []))
    offered_groups = list(client.get("offered_groups", []))
    offered_code: int | None = None
    offered_evidence: list[Evidence] = []
    if client_hello is not None:
        if client.get("supported_versions_present"):
            if offered_versions:
                offered_code = max(offered_versions)
            if "supported_versions_offset" in client:
                offered_evidence = _evidence(
                    session.client_to_server,
                    client_hello.body_offset + client["supported_versions_offset"],
                    client.get("supported_versions_length", 0),
                    "tls.client_hello.supported_versions",
                    _VERSION_NAMES.get(offered_code, f"0x{offered_code:04x}")
                    if offered_code is not None else "unknown",
                )
        elif client.get("legacy_version") is not None:
            offered_code = client["legacy_version"]
            offered_evidence = _evidence(
                session.client_to_server,
                client_hello.body_offset,
                2,
                "tls.client_hello.legacy_version",
                _VERSION_NAMES.get(offered_code, f"0x{offered_code:04x}"),
            )
    offered_version = _VERSION_NAMES.get(offered_code)

    selected_code = server.get("selected_version")
    negotiated_version = _VERSION_NAMES.get(selected_code)
    negotiated_evidence: list[Evidence] = []
    cipher_code = server.get("selected_cipher")
    cipher_evidence: list[Evidence] = []
    group_code = server.get("selected_group")
    group_evidence: list[Evidence] = []
    if server_hello is not None:
        if selected_code is not None:
            selected_offset = server.get("selected_version_offset", 0)
            selected_field = (
                "tls.server_hello.supported_versions"
                if any(t == _EXT_SUPPORTED_VERSIONS for t, _ in server.get("extensions", []))
                else "tls.server_hello.legacy_version"
            )
            negotiated_evidence = _evidence(
                session.server_to_client,
                server_hello.body_offset + selected_offset,
                2,
                selected_field,
                negotiated_version or f"0x{selected_code:04x}",
            )
        if cipher_code is not None:
            cipher_evidence = _evidence(
                session.server_to_client,
                server_hello.body_offset + server["selected_cipher_offset"],
                2,
                "tls.server_hello.cipher_suite",
                f"0x{cipher_code:04x}",
            )
        if group_code is not None:
            group_evidence = _evidence(
                session.server_to_client,
                server_hello.body_offset + server["selected_group_offset"],
                2,
                "tls.server_hello.key_share.group",
                f"0x{group_code:04x}",
            )

    cipher_name = registry.cipher_name(cipher_code)
    cipher_is_cbc = registry.cipher_has(cipher_code, "cbc") is True
    cipher_has_no_fs = registry.cipher_has(cipher_code, "no_fs")
    group_name = registry.group_name(group_code)
    group_class = registry.classify_group(group_code)
    hybrid_pq_flag = registry.is_pq_hybrid(group_code)

    client_extensions = client.get("extensions", [])
    server_extensions = server.get("extensions", [])
    client_signal_values = client_signals(client_extensions)
    forward_secrecy_status = _signal_forward_secrecy(
        selected_code, server_extensions, cipher_has_no_fs
    )
    downgrade_values = downgrade_flags(
        offered_versions, server.get("downgrade_sentinel")
    )
    ocsp_stapling = (
        _signal_ocsp_stapling(
            client_extensions,
            server_extensions,
            [message.msg_type for message in server_messages],
            selected_code,
        )
        if client_hello is not None
        else "not_observable"
    )
    if ocsp_stapling == "requested_not_provided" and selected_code is None:
        # Only the server's own ServerHello can show it declined to staple; an
        # uncaptured or invalid one shows nothing either way.
        ocsp_stapling = "not_observable"

    delta_offers = offered_versions
    if not client.get("supported_versions_present") and offered_code is not None:
        delta_offers = [offered_code]
    # null when the offer or the selection is unknown: a gap between an unseen
    # version and a seen one is not zero.
    downgrade_delta = registry.downgrade_delta(delta_offers, selected_code)

    cert_der, cert_evidence, cert_visibility = None, [], "NOT_OBSERVABLE"
    if selected_code != 0x0304 and certificate_message is not None:
        parsed_certificate = _parse_certificate(certificate_message.body)
        if parsed_certificate.get("der"):
            cert_der = parsed_certificate["der"]
            cert_evidence = _evidence(
                session.server_to_client,
                certificate_message.body_offset + parsed_certificate["der_offset"],
                parsed_certificate["der_length"],
                "tls.certificate",
                "certificate DER",
            )
            cert_visibility = "OBSERVABLE"

    tls = session.tls
    tls.offered_version = offered_version
    tls.offered_ciphers = offered_ciphers
    tls.offered_versions = offered_versions
    tls.offered_groups = offered_groups
    tls.negotiated_version = negotiated_version
    tls.downgrade_delta = downgrade_delta
    tls.cipher = cipher_name
    tls.forward_secrecy_status = forward_secrecy_status
    # The v1 boolean follows the tri-state: an UNKNOWN is null, never "no FS".
    tls.forward_secrecy = {"YES": True, "NO": False}.get(forward_secrecy_status)
    tls.group = group_name
    tls.group_class = group_class
    tls.hybrid_pq_flag = hybrid_pq_flag
    tls.has_fallback_scsv = bool(client.get("has_fallback_scsv", False))
    tls.downgrade_sentinel = server.get("downgrade_sentinel")
    tls.psk_selected = bool(server.get("psk_selected", False))
    tls.is_hello_retry_request = hello_retry
    tls.client_hello_frame = (
        _frame_at(session.client_to_server, client_hello.body_offset)
        if client_hello is not None else None
    )
    tls.server_hello_frame = (
        _frame_at(session.server_to_client, server_hello.body_offset)
        if server_hello is not None else None
    )
    tls.ocsp_stapling = ocsp_stapling
    tls.status_request_sent = client_signal_values["status_request_sent"]
    tls.psk_offered = client_signal_values["psk_offered"]
    tls.ech_offered = client_signal_values["ech_offered"]
    tls.early_data_offered = client_signal_values["early_data_offered"]
    tls.downgrade_anomaly = downgrade_values["downgrade_anomaly"]
    tls.downgrade_legacy_client = downgrade_values["downgrade_legacy_client"]
    tls.cert_visibility = cert_visibility

    sni_evidence = []
    if client_hello is not None and client.get("server_name") is not None:
        sni_evidence = _evidence(
            session.client_to_server,
            client_hello.body_offset + client["server_name_offset"],
            client["server_name_length"],
            "tls.client_hello.server_name",
            client["server_name"],
        )
    session._sni_hostname = client.get("server_name")  # type: ignore[attr-defined]
    session._sni_evidence = sni_evidence  # type: ignore[attr-defined]
    session._correlation_tls = {  # type: ignore[attr-defined]
        "selected_version": selected_code,
        "selected_cipher": cipher_code,
        "selected_group": group_code,
        "selected_version_evidence": [item.to_dict() for item in negotiated_evidence],
        "selected_cipher_evidence": [item.to_dict() for item in cipher_evidence],
        "selected_group_evidence": [item.to_dict() for item in group_evidence],
        # A TLS 1.3 offer a server could accept needs a key share (RFC 8446
        # §9.2) and a TLS 1.3 suite; without both, choosing 1.2 excludes nothing.
        "tls13_offer_unusable": client_hello is not None and not (
            any(extension_type == _EXT_KEY_SHARE for extension_type, _ in client.get("extensions", []))
            and any(registry.cipher_has(code, "tls13") for code in offered_ciphers)
        ),
        "offered_version_evidence": {
            code: [
                item.to_dict()
                for offset in offsets
                for item in _evidence(
                    session.client_to_server,
                    client_hello.body_offset + offset,
                    2,
                    "tls.client_hello.supported_versions",
                    f"0x{code:04x}",
                )
            ]
            for code, offsets in client.get("offered_version_offsets", {}).items()
        } if client_hello is not None else {},
        "offered_cipher_evidence": {
            code: [
                item.to_dict()
                for offset in offsets
                for item in _evidence(
                    session.client_to_server,
                    client_hello.body_offset + offset,
                    2,
                    "tls.client_hello.cipher_suites",
                    f"0x{code:04x}",
                )
            ]
            for code, offsets in client.get("offered_cipher_offsets", {}).items()
        } if client_hello is not None else {},
    }

    fallback_evidence = []
    if client_hello is not None and "has_fallback_scsv_offset" in client:
        fallback_evidence = _evidence(
            session.client_to_server,
            client_hello.body_offset + client["has_fallback_scsv_offset"],
            2,
            "tls.client_hello.cipher_suites",
            "TLS_FALLBACK_SCSV",
        )
    sentinel_evidence = []
    if server_hello is not None and "downgrade_sentinel_offset" in server:
        sentinel_evidence = _evidence(
            session.server_to_client,
            server_hello.body_offset + server["downgrade_sentinel_offset"],
            8,
            "tls.server_hello.random.downgrade_sentinel",
            server["downgrade_sentinel"],
        )
    early_data_evidence = _extension_evidence(
        session.client_to_server, client_hello, client, EXT_EARLY_DATA,
        "tls.client_hello.extension_type", "early_data",
    )
    ech_evidence = _extension_evidence(
        session.client_to_server, client_hello, client, EXT_ECH,
        "tls.client_hello.extension_type", "encrypted_client_hello",
    )
    ocsp_evidence = _extension_evidence(
        session.client_to_server, client_hello, client, EXT_STATUS_REQUEST,
        "tls.client_hello.extension_type", "status_request",
    )
    psk_evidence = _extension_evidence(
        session.server_to_client, server_hello, server, EXT_PRE_SHARED_KEY,
        "tls.server_hello.extension_type", "pre_shared_key",
    )
    psk_offered_evidence = _extension_evidence(
        session.client_to_server, client_hello, client, EXT_PRE_SHARED_KEY,
        "tls.client_hello.extension_type", "pre_shared_key",
    )

    session.fact_tiers["tls.negotiated_version"] = (
        Tier.OBSERVED.value
        if negotiated_version is not None and negotiated_evidence
        else Tier.NOT_OBSERVABLE.value
    )
    session.fact_tiers["tls.forward_secrecy"] = (
        Tier.OBSERVED.value
        if forward_secrecy_status in {"YES", "NO"}
        and (group_evidence or cipher_evidence or psk_evidence)
        else Tier.NOT_OBSERVABLE.value
    )
    session.fact_tiers["tls.cipher"] = (
        Tier.OBSERVED.value if cipher_code is not None and cipher_evidence
        else Tier.NOT_OBSERVABLE.value
    )
    session.fact_tiers["tls.group"] = (
        Tier.OBSERVED.value if group_code is not None and group_evidence
        else Tier.NOT_OBSERVABLE.value
    )
    session.fact_tiers["tls.hybrid_pq_flag"] = (
        Tier.OBSERVED.value if group_code is not None and group_evidence
        else Tier.NOT_OBSERVABLE.value
    )
    session.fact_tiers["tls.ech_identity"] = (
        Tier.NOT_OBSERVABLE.value
        if client_signal_values["ech_offered"]
        else (Tier.OBSERVED.value if client_hello is not None
              else Tier.NOT_OBSERVABLE.value)
    )
    if client_signal_values["ech_offered"]:
        session.fact_reason_codes["tls.ech_identity"] = "ech_enabled"

    session._tls_evidence = {  # type: ignore[attr-defined]
        "offered_version": offered_evidence,
        "offered_versions": offered_evidence,
        "negotiated_version": negotiated_evidence,
        "cipher": cipher_evidence,
        "group": group_evidence,
        "cipher_is_cbc": cipher_is_cbc,
        "has_fallback_scsv": fallback_evidence,
        "downgrade_sentinel": sentinel_evidence,
        "downgrade_anomaly": offered_evidence + sentinel_evidence,
        "downgrade_legacy_client": offered_evidence + sentinel_evidence,
        "forward_secrecy": psk_evidence or group_evidence or cipher_evidence,
        "status_request_sent": ocsp_evidence,
        "psk_offered": psk_offered_evidence,
        "early_data_offered": early_data_evidence,
        "ech_offered": ech_evidence,
        "ocsp_stapling": ocsp_evidence + negotiated_evidence,
    }
    session._cert_der = cert_der  # type: ignore[attr-defined]
    session._cert_evidence = cert_evidence  # type: ignore[attr-defined]
    return session


analyze_tls = analyse_tls
