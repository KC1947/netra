"""Redacted, frame-by-frame proof views for the canonical report."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Any

from .m1_ingest import ingest_pcap
from .m2_protocol import classify_protocols


class CaptureChanged(Exception):
    """The capture on disk is not the one the report was produced from.

    Evidence views require the capture identified by the report's SHA-256.
    Bytes from a different file cannot substantiate its frame references,
    so a mismatch prevents serving packet evidence.
    """

_TLS_HANDSHAKES = {
    1: "ClientHello",
    2: "ServerHello",
    11: "Certificate",
}
_PRINTABLE = frozenset(range(32, 127))


def _data(report: Any) -> dict:
    return report.to_dict() if hasattr(report, "to_dict") else report


def _require_same_capture(pcap_path, report: dict) -> None:
    """Refuse to serve frames unless the file still hashes to the report's capture."""
    expected = (report.get("capture") or {}).get("sha256")
    if not expected:
        raise CaptureChanged(
            "report carries no capture SHA-256, so the bytes on disk cannot be "
            "matched to the analysis that produced this frame reference"
        )
    digest = hashlib.sha256(Path(pcap_path).read_bytes()).hexdigest()
    if digest != expected:
        raise CaptureChanged(
            f"capture file has changed since analysis: report was produced from "
            f"sha256 {expected}, the file on disk is sha256 {digest}. Re-run the "
            f"analysis; frame numbers from the old report do not apply to this file."
        )


def _target_session(report: dict, session_id: str) -> dict:
    for session in report["sessions"]:
        if session["id"] == session_id:
            return session
    raise KeyError(f"Unknown report session: {session_id}")


def _auth_line(payload: bytes, protocol: str) -> bool:
    upper = payload.upper()
    if protocol == "smtp":
        return bool(re.match(br"^AUTH(?:[ \t]|\r?\n)", upper))
    if protocol == "imap":
        return bool(re.match(br"^[^ \t\r\n]+[ \t]+AUTHENTICATE(?:[ \t]|\r?\n)", upper))
    if protocol == "pop3":
        return bool(re.match(br"^(?:AUTH|USER|PASS)(?:[ \t]|\r?\n)", upper))
    return False


def _is_tls(payload: bytes) -> bool:
    return len(payload) >= 5 and payload[0] in {0x14, 0x15, 0x16, 0x17} and payload[1] == 0x03


def _tls_summary(payload: bytes, direction: str, target: dict) -> str:
    content_type = payload[0]
    prefix = "C" if direction == "client_to_server" else "S"
    if content_type == 0x16 and len(payload) >= 6:
        handshake = _TLS_HANDSHAKES.get(payload[5], "handshake")
        if handshake == "ClientHello":
            offered = target["tls"]["offered_version"]
            return f"{prefix}: TLS ClientHello" + (f" (offers {offered})" if offered else "")
        if handshake == "ServerHello":
            version = target["tls"]["negotiated_version"]
            cipher = target["tls"]["cipher"]
            details = ", ".join(item for item in (version, cipher) if item)
            return f"{prefix}: TLS ServerHello" + (f" ({details})" if details else "")
        if handshake == "Certificate":
            return f"{prefix}: TLS Certificate (1 cert)"
        return f"{prefix}: TLS handshake"
    if content_type == 0x17:
        return f"TLS Application Data ({len(payload)} bytes)"
    return f"{prefix}: TLS record"


def _smtp_server_summary(payload: bytes) -> str:
    match = re.search(br"(?:^|\n)250[ -]([A-Z]{8})(?:\r?\n|$)", payload.upper())
    if match and match.group(1) == b"XSNVVQRW":
        return "S: 250 XSNVVQRW  (capability line)"
    status = re.match(br"^(\d{3})", payload)
    return f"S: {status.group(1).decode('ascii')} SMTP response" if status else "S: [protocol data, not displayed]"


def _frame_summary(payload: bytes, direction: str, target: dict, in_smtp_data: bool) -> tuple[str, str, bool]:
    """Return summary, layer, and updated SMTP-DATA state without copying content."""
    protocol = target["protocol"]
    if _is_tls(payload):
        return _tls_summary(payload, direction, target), "tls", in_smtp_data
    if direction == "client_to_server":
        if in_smtp_data:
            return f"C: [message body, {len(payload)} bytes, not displayed]", protocol, not payload.endswith((b"\r\n.\r\n", b"\n.\n"))
        if _auth_line(payload, protocol):
            return "C: AUTH PLAIN [REDACTED]", protocol, in_smtp_data
        upper = payload.upper()
        if protocol == "smtp" and re.match(br"^DATA(?:[ \t]|\r?\n)", upper):
            return "C: DATA", "smtp", True
        if protocol == "smtp" and re.match(br"^BDAT(?:[ \t]|\r?\n)", upper):
            return f"C: [message body, {len(payload)} bytes, not displayed]", "smtp", in_smtp_data
        if protocol == "smtp" and re.match(br"^EHLO(?:[ \t]|\r?\n)", upper):
            return "C: EHLO", "smtp", in_smtp_data
        if protocol == "smtp" and re.match(br"^STARTTLS(?:[ \t]|\r?\n)", upper):
            return "C: STARTTLS", "smtp", in_smtp_data
        return f"C: [{protocol} data, {len(payload)} bytes, not displayed]", protocol, in_smtp_data
    if protocol == "smtp":
        return _smtp_server_summary(payload), "smtp", in_smtp_data
    if protocol in {"imap", "pop3"}:
        return f"S: {protocol.upper()} response", protocol, in_smtp_data
    return f"TCP segment ({len(payload)} bytes)", "tcp", in_smtp_data


def _ascii(data: bytes) -> str:
    return "".join(chr(byte) if byte in _PRINTABLE else "." for byte in data)


# Evidence windows are built from allowlisted spans only. A window is never
# widened past the cited bytes: the old +/-16-byte neighbourhood copied
# whatever sat next to a span -- an SMTP error echoing a credential, a body
# line -- whenever the rule that produced the finding had no redaction of its
# own. Every decision below depends on the evidence field and the span's own
# grammar, never on the rule id.
#
# Binary TLS structure: the span bytes are public handshake framing and are
# shown in full. Key-share material is withheld even though it is public on
# the wire, because it is key material (API contract, Privacy).
_PUBLIC_BINARY_FIELDS = frozenset({
    "tls.record",
    "tls.certificate",
    "tls.client_hello.legacy_version",
    "tls.client_hello.supported_versions",
    "tls.client_hello.cipher_suites",
    "tls.client_hello.extension_type",
    "tls.client_hello.server_name",
    "tls.server_hello.legacy_version",
    "tls.server_hello.supported_versions",
    "tls.server_hello.cipher_suite",
    "tls.server_hello.extension_type",
    "tls.server_hello.random.downgrade_sentinel",
})
# Text fields whose span m2/m3 already cut to a single grammatical token; the
# span is shown only if it still matches that token grammar here.
_TOKEN_FIELDS = {
    "smtp.capability": re.compile(rb"[A-Z][A-Z0-9-]{0,31}"),
    "smtp.banner.hostname": re.compile(rb"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252}[A-Za-z0-9])?"),
}
# A cited protocol line may carry free text (error replies, client arguments).
# Only its leading status code or command verb -- drawn from a fixed set -- is
# shown; the remainder of the line is withheld.
_LINE_PREFIX = re.compile(
    rb"(?:[2-5][0-9][0-9](?=[ \t\r\n-]|$)"
    rb"|\+OK(?=[ \t\r\n]|$)|-ERR(?=[ \t\r\n]|$)"
    rb"|(?:EHLO|HELO|LHLO|STARTTLS|STLS|CAPA|QUIT|NOOP|RSET|DATA)(?=[ \t\r\n]|$))",
    re.IGNORECASE,
)


def _window(rule_id: str, evidence: dict, shown: bytes, withheld: int,
            ascii_override: str | None = None) -> dict:
    return {
        "rule_id": rule_id, "frame": evidence["frame"], "field": evidence["field"],
        "byte_offset": evidence["byte_offset"], "byte_length": evidence["byte_length"],
        "hex_window": " ".join(f"{byte:02x}" for byte in shown),
        "ascii_window": ascii_override if ascii_override is not None else _ascii(shown),
        "highlight": [0, len(shown)],
        "redacted": withheld > 0 or ascii_override is not None,
        "withheld_bytes": withheld,
    }


def _evidence_window(evidence: dict, payload: bytes, payload_offset: int, rule_id: str) -> dict:
    field = evidence["field"]
    length = evidence["byte_length"]
    if field == "cleartext-auth" or rule_id == "CLEARTEXT-AUTH":
        return _window(rule_id, evidence, b"", length, "AUTH PLAIN [REDACTED]")
    if "key_share" in field:
        return _window(rule_id, evidence, b"", length, "TLS key-share [not displayed]")
    start = evidence["byte_offset"] - payload_offset
    span = payload[start:start + length] if 0 <= start <= len(payload) else b""
    if len(span) != length:
        # The span does not lie inside this frame's payload; nothing is shown
        # rather than bytes from somewhere else in the packet.
        return _window(rule_id, evidence, b"", length, "[evidence bytes not displayed]")
    if field in _PUBLIC_BINARY_FIELDS:
        return _window(rule_id, evidence, span, 0)
    token = _TOKEN_FIELDS.get(field)
    if token is not None and token.fullmatch(span):
        return _window(rule_id, evidence, span, 0)
    if field == "protocol.line" and (start == 0 or payload[start - 1:start] == b"\n"):
        prefix = _LINE_PREFIX.match(span)
        if prefix:
            shown = span[:prefix.end()]
            return _window(rule_id, evidence, shown, length - len(shown))
    return _window(rule_id, evidence, b"", length, "[protocol text not displayed]")


def _filter_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def packet_view(pcap_path, report, session_id: str) -> dict:
    """Build the API-contract PacketView without exposing credentials or bodies."""
    data = _data(report)
    # Before anything is read off disk: the bytes must belong to this report.
    _require_same_capture(pcap_path, data)
    target = _target_session(data, session_id)
    # Match on the session id, never on the five-tuple: port reuse after RST
    # produces two sessions with an identical five-tuple, and matching by tuple
    # served the first one's packets for both. M1 assigns ids in first-frame
    # order and nothing downstream renumbers, so the ids are stable across a
    # re-ingest of the same file.
    all_sessions = classify_protocols(ingest_pcap(pcap_path))
    session = next(
        (candidate for candidate in all_sessions if candidate.id == session_id), None
    )
    if session is None:
        raise KeyError(session_id)

    rules_by_frame: dict[int, set[str]] = {}
    windows_by_frame: dict[int, list[tuple[str, dict]]] = {}
    for finding in target["findings"]:
        for evidence in finding["evidence"]:
            rules_by_frame.setdefault(evidence["frame"], set()).add(finding["rule_id"])
            windows_by_frame.setdefault(evidence["frame"], []).append((finding["rule_id"], evidence))

    observations = sorted(session.packet_observations, key=lambda item: item.frame_no)
    frames, evidence_windows = [], []
    in_smtp_data = False
    for observation in observations:
        summary, layer, in_smtp_data = _frame_summary(
            observation.payload, observation.direction, target, in_smtp_data,
        )
        frames.append({
            "frame": observation.frame_no,
            "t_ms": round((observation.ts - observations[0].ts) * 1000) if observations else 0,
            "dir": "c2s" if observation.direction == "client_to_server" else "s2c",
            "len": len(observation.payload), "layer": layer, "summary": summary,
            "evidence_rules": sorted(rules_by_frame.get(observation.frame_no, ())),
        })
        for rule_id, evidence in windows_by_frame.get(observation.frame_no, ()):
            evidence_windows.append(_evidence_window(
                evidence, observation.payload, observation.payload_packet_offset, rule_id,
            ))

    first_evidence_frame = evidence_windows[0]["frame"] if evidence_windows else None
    # The report carries M1's tcp.stream, counted over every TCP flow in the
    # file. Fall back to the re-ingested session for a report predating the
    # field; never to a positional index, which silently resolves to nothing.
    stream = target.get("tcp_stream")
    if stream is None:
        stream = session.tcp_stream
    # The filter is pasted into Wireshark verbatim. Only non-negative integers
    # are interpolated, so no report value can terminate or extend the
    # expression; anything else drops its clause instead of being quoted.
    if not _filter_int(stream):
        stream = None
    if not _filter_int(first_evidence_frame):
        first_evidence_frame = None
    wireshark_filter = "" if stream is None else f"tcp.stream eq {stream}"
    if first_evidence_frame is not None:
        wireshark_filter += (" && " if wireshark_filter else "")
        wireshark_filter += f"frame.number == {first_evidence_frame}"
    return {
        "session_id": session_id,
        "client": f"{target['five_tuple']['client_ip']}:{target['five_tuple']['client_port']}",
        "server": f"{target['five_tuple']['server_ip']}:{target['five_tuple']['server_port']}",
        "protocol": target["protocol"], "frames": frames, "evidence": evidence_windows,
        "wireshark_filter": wireshark_filter,
    }
