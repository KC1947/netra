"""Passive STARTTLS/STLS transition analysis.

Only cleartext protocol grammar before the first TLS record is inspected.  This
is deliberately a small state machine rather than a search over reassembled
payloads: searching past an upgrade could mistake encrypted application bytes
for commands, and would be unsafe for mail content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .contracts import ByteStream, Evidence, Finding, Session
from .judgement.epistemic import Tier, admit_finding


_TLS_PREFIX = b"\x16\x03"
_SMTP_KNOWN_CAPABILITIES = frozenset({
    "PIPELINING", "SIZE", "STARTTLS", "AUTH", "DSN", "ETRN", "8BITMIME",
    "SMTPUTF8", "CHUNKING", "ENHANCEDSTATUSCODES",
})


@dataclass(frozen=True, repr=False)
class _Line:
    direction: str
    start: int
    length: int
    value: bytes
    evidence: tuple[Evidence, ...]
    order: tuple[int, int]
    # Captured with conflicting copies: its content is not established.
    disputed: bool = False


def _evidence(stream: ByteStream, start: int, length: int, field: str,
              display: str = "redacted") -> tuple[Evidence, ...]:
    """Map a reassembled range back to exact captured-frame offsets."""
    return tuple(
        Evidence(source.frame, field, source.packet_byte_offset, source.byte_length, display)
        for source in stream.provenance_for(start, length)
    )


def _cleartext_lines(stream: ByteStream, direction: str, protocol: str) -> list[_Line]:
    """Return complete CRLF/LF lines before TLS, never bridging a TCP gap."""
    result: list[_Line] = []
    for data, sources in stream.iter_spans():
        if not data or not sources:
            continue
        # The start source gives the actual stream offset even after a gap.
        span_start = sources[0].stream_offset
        tls_at = data.find(_TLS_PREFIX)
        if tls_at >= 0:
            data = data[:tls_at]
        cursor = 0
        while cursor < len(data):
            newline = data.find(b"\n", cursor)
            if newline < 0:
                break                         # do not treat a fragment as a command
            end = newline + 1
            value = data[cursor:end]
            start = span_start + cursor
            try:
                evidence = _evidence(stream, start, len(value), "protocol.line")
            except ValueError:
                # A gap is inadequate proof for a protocol command.
                cursor = end
                continue
            result.append(_Line(direction, start, len(value), value, evidence,
                                (max(item.frame for item in evidence),
                                 max(item.byte_offset for item in evidence)),
                                any(start <= offset < start + len(value)
                                    for offset in stream.disputed)))
            cursor = end
            # SMTP DATA and BDAT introduce message content.  Its lines are not
            # protocol commands and must never be searched for AUTH.  A full
            # BDAT parser would need its declared byte count; stopping here is
            # the conservative passive choice.
            if direction == "client_to_server" and protocol == "smtp" and re.match(
                    br"^(?:DATA|BDAT)(?:[ \t]|\r?\n)", value.upper()):
                return result
        # Anything after a TLS record in this contiguous span is encrypted; a
        # later span cannot safely be assumed to resume cleartext either.
        if tls_at >= 0:
            break
    return result


def _first_tls_evidence(stream: ByteStream, field: str = "tls.record") -> tuple[Evidence, ...]:
    """Locate a captured TLS record header without inspecting its payload."""
    for data, sources in stream.iter_spans():
        if not data or not sources:
            continue
        index = -1
        for candidate in range(0, max(0, len(data) - 4)):
            if data[candidate:candidate + 2] != _TLS_PREFIX:
                continue
            # Require a complete TLS record framing envelope.  This prevents a
            # coincidental two-byte pattern in plaintext or an application body
            # from becoming encryption evidence.
            version = data[candidate + 2]
            length = int.from_bytes(data[candidate + 3:candidate + 5], "big")
            end = candidate + 5 + length
            if version <= 4 and length > 0 and end <= len(data):
                index = candidate
                break
        if index < 0:
            continue
        start = sources[0].stream_offset + index
        # Cite the complete validated record header, never just a coincidental
        # two-byte prefix.
        try:
            return _evidence(stream, start, 5, field, "TLS record")
        except ValueError:
            return ()
    return ()


def _is_auth(line: _Line, protocol: str) -> bool:
    upper = line.value.upper()
    if protocol == "smtp":
        return bool(re.match(br"^AUTH(?:[ \t]|\r?\n)", upper))
    if protocol == "imap":
        # IMAP commands start with a client-selected tag.
        return bool(re.match(br"^[^ \t\r\n]+[ \t]+AUTHENTICATE(?:[ \t]|\r?\n)", upper))
    if protocol == "pop3":
        return bool(re.match(br"^(?:AUTH|USER|PASS)(?:[ \t]|\r?\n)", upper))
    return False


def _request_kind(line: _Line, protocol: str) -> str | None:
    upper = line.value.upper()
    if protocol == "smtp" and re.match(br"^STARTTLS(?:[ \t]|\r?\n)", upper):
        return "STARTTLS"
    if protocol == "imap" and re.match(br"^([^ \t\r\n]+)[ \t]+STARTTLS(?:[ \t]|\r?\n)", upper):
        return "STARTTLS"
    if protocol == "pop3" and re.match(br"^STLS(?:[ \t]|\r?\n)", upper):
        return "STLS"
    return None


def _reply_status(line: _Line, protocol: str, request_tag: bytes | None = None) -> str | None:
    upper = line.value.upper()
    if protocol == "smtp":
        match = re.match(br"^(\d{3})(?:[ -]|\r?\n)", upper)
        if not match:
            return None
        return "accepted" if match.group(1) == b"220" else ("rejected" if match.group(1).startswith(b"5") else "other")
    if protocol == "imap":
        # The command tag is intentionally discarded after matching.
        match = re.match(br"^[^ \t\r\n]+[ \t]+(OK|NO|BAD)(?:[ \t]|\r?\n)", upper)
        if not match or request_tag is None:
            return None
        reply_tag = line.value.split(None, 1)[0]
        if reply_tag != request_tag:
            return None
        return "accepted" if match.group(1) == b"OK" else "rejected"
    if protocol == "pop3":
        if upper.startswith(b"+OK"):
            return "accepted"
        if upper.startswith(b"-ERR"):
            return "rejected"
    return None


def _smtp_capabilities(lines: Iterable[_Line], ehlo: _Line | None,
                       client_lines: Iterable[_Line]) -> tuple[bool | None, list[_Line]]:
    """Read only SMTP 250 capability grammar; no arbitrary server text."""
    offered: bool | None = None
    suspicious: list[_Line] = []
    complete = disputed = False
    if ehlo is None:
        return None, []
    next_client = min((line.order for line in client_lines if line.order > ehlo.order), default=None)
    for line in lines:
        if line.order <= ehlo.order or (next_client is not None and line.order >= next_client):
            continue
        match = re.match(br"^250([ -])([^ \t\r\n]+)", line.value.upper())
        if not match:
            continue
        if line.disputed:
            disputed = True
            continue
        token = match.group(2).decode("ascii", "ignore")
        if token == "STARTTLS":
            offered = True
        elif len(token) == 8 and token.isalpha() and token not in _SMTP_KNOWN_CAPABILITIES:
            suspicious.append(line)
        complete = complete or match.group(1) == b" "
    # Absence of STARTTLS is established only by the whole list: its final
    # "250 " line was captured and no line of it is disputed. A reply cut by a
    # gap or the end of the capture proves nothing about what was not seen.
    if offered is None and complete and not disputed:
        offered = False
    return offered, suspicious


def _without_pop3_retr_bodies(server_lines: Iterable[_Line],
                              client_lines: Iterable[_Line]) -> list[_Line]:
    """Exclude POP3 RETR message bodies from server-side grammar matching."""
    events = sorted((*server_lines, *client_lines), key=lambda item: item.order)
    result: list[_Line] = []
    in_body = False
    awaiting_body = False
    for line in events:
        if line.direction == "client_to_server":
            if re.match(br"^RETR(?:[ \t]|\r?\n)", line.value.upper()):
                awaiting_body = True
            continue
        if awaiting_body:
            # The positive status line belongs to POP3 grammar.  Its following
            # dot-terminated payload does not.
            result.append(line)
            if line.value.upper().startswith(b"+OK"):
                in_body = True
            awaiting_body = False
            continue
        if in_body:
            if line.value in (b".\r\n", b".\n"):
                in_body = False
            continue
        result.append(line)
    return result


def _cleartext_auth_finding(session: Session, auth_lines: list[_Line]) -> Finding:
    evidence: list[Evidence] = []
    for line in auth_lines:
        # The complete AUTH command is evidence, but its display is always a
        # constant.  No mechanism in this module retains its argument.
        evidence.extend(_evidence(
            session.client_to_server, line.start, line.length, "cleartext-auth", "AUTH argument redacted"
        ))
    return Finding(
        rule_id="CLEARTEXT-AUTH", tier=Tier.OBSERVED.value,
        confidence_band="certain", severity="critical", confidence=1.0,
        what="Authentication command was observed in cleartext.",
        why="Credentials sent before a TLS upgrade can be read from the capture.",
        fix="Require TLS before authentication and disable cleartext AUTH.",
        remediation_id="require_tls_before_auth", remediation_effort="one_line_reload",
        affected_sessions=[session.id], evidence=evidence, references=["RFC 8314"],
    )


def _first_line_after(order: tuple[int, int], *groups: list[_Line]) -> _Line | None:
    """First protocol line after a point. A failed upgrade is observed only when
    the session visibly went on in cleartext; a capture that ends, or loses the
    bytes after the request, shows no outcome at all."""
    return min((line for group in groups for line in group if line.order > order),
               key=lambda line: line.order, default=None)


def _set_transition(session: Session, verdict: str, band: str, evidence: Iterable[Evidence]) -> None:
    session.transition.verdict = verdict
    session.transition.confidence_band = band
    session.transition.evidence = list(evidence)
    session.fact_tiers["transition.verdict"] = (
        Tier.OBSERVED.value if band == "certain" else Tier.INFERRED.value
    )


def analyse_transition(session: Session) -> Session:
    """Analyse a classified email session in place and return it.

    Private facts retained for later rule/scoring stages are booleans and frame
    references only.  They contain no command text, mail data, or credentials.
    """
    client_tls = _first_tls_evidence(session.client_to_server)
    server_tls = _first_tls_evidence(session.server_to_client)
    all_tls = tuple(sorted(client_tls + server_tls, key=lambda item: (item.frame, item.byte_offset)))
    # Implicit TLS means the first payload is TLS. A captured SYN or bare ACK
    # carries none, so it must not turn an implicit-TLS session into not_used.
    first_packet = min((item.frame_no for item in session.packet_observations if item.payload),
                       default=session.packets.get("first"))
    implicit = bool(all_tls and first_packet is not None and all_tls[0].frame == first_packet)
    if implicit:
        _set_transition(session, "upgraded", "certain", all_tls[:1])
        session._transition_facts = {"implicit_tls": True, "starttls_offered": None, "auth_cleartext": False}  # type: ignore[attr-defined]
        return session

    protocol = session.protocol.lower()
    if protocol not in {"smtp", "imap", "pop3"}:
        _set_transition(session, "not_used", "inferred", ())
        session._transition_facts = {"implicit_tls": False, "starttls_offered": None, "auth_cleartext": False}  # type: ignore[attr-defined]
        return session

    client_lines = _cleartext_lines(session.client_to_server, "client_to_server", protocol)
    server_lines = _cleartext_lines(session.server_to_client, "server_to_client", protocol)
    if protocol == "pop3":
        server_lines = _without_pop3_retr_bodies(server_lines, client_lines)
    auth_lines = [line for line in client_lines if _is_auth(line, protocol)]
    ehlo = next((line for line in client_lines if re.match(br"^EHLO(?:[ \t]|\r?\n)", line.value.upper())), None)
    offered, suspicious_tokens = (_smtp_capabilities(server_lines, ehlo, client_lines)
                                  if protocol == "smtp" else (None, []))
    requests = [line for line in client_lines if _request_kind(line, protocol)]
    request = min(requests, key=lambda item: item.order) if requests else None
    facts = {"implicit_tls": False, "starttls_offered": offered,
             "auth_cleartext": bool(auth_lines), "upgrade_accepted": False}

    if request is not None:
        request_tag = request.value.split(None, 1)[0] if protocol == "imap" else None
        replies = [line for line in server_lines if line.order > request.order
                   and _reply_status(line, protocol, request_tag)]
        reply = min(replies, key=lambda item: item.order) if replies else None
        if reply is not None and _reply_status(reply, protocol, request_tag) == "rejected":
            _set_transition(session, "rejected", "certain", request.evidence + reply.evidence)
        elif reply is not None and _reply_status(reply, protocol, request_tag) == "accepted":
            facts["upgrade_accepted"] = True
            tls_after = tuple(item for item in all_tls if (item.frame, item.byte_offset) > reply.order)
            if tls_after:
                _set_transition(session, "upgraded", "certain", request.evidence + reply.evidence + tls_after[:1])
            else:
                later = _first_line_after(reply.order, client_lines, server_lines)
                _set_transition(session, "failed", "certain" if later else "inferred",
                                request.evidence + reply.evidence + (later.evidence if later else ()))
        else:
            later = _first_line_after(request.order, client_lines, server_lines)
            _set_transition(session, "failed", "certain" if later else "inferred",
                            request.evidence + (later.evidence if later else ()))
    elif protocol == "smtp" and offered is False and suspicious_tokens and any(
            line.order > suspicious_tokens[0].order for line in auth_lines):
        token_line = suspicious_tokens[0]
        token_match = re.match(br"^250[ -]([^ \t\r\n]+)", token_line.value.upper())
        # Point at the substituted capability itself, not the SMTP response
        # prefix or CRLF.  This makes the strip claim independently auditable.
        token_evidence = _evidence(
            session.server_to_client,
            token_line.start + (token_match.start(1) if token_match else 0),
            len(token_match.group(1)) if token_match else token_line.length,
            "smtp.capability", "250 " + (token_match.group(1).decode("ascii", "replace")
                                             if token_match else "capability"),
        )
        auth_line = min((line for line in auth_lines if line.order > token_line.order), key=lambda item: item.order)
        evidence = token_evidence + tuple(
            _evidence(session.client_to_server, auth_line.start, auth_line.length,
                      "cleartext-auth", "AUTH argument redacted")
        )
        _set_transition(session, "suspected", "inferred", evidence)
        admit_finding(session, Finding(
            rule_id="STARTTLS-STRIP-SUSPECTED", tier=Tier.INFERRED.value,
            confidence_band="inferred", severity="critical", confidence=0.5,
            what="STARTTLS capability removal is suspected.",
            why="An unknown eight-letter SMTP capability was followed by cleartext authentication.",
            fix="Require TLS before AUTH and investigate the mail path for capability modification.",
            remediation_id="require_tls_before_auth", remediation_effort="one_line_reload",
            affected_sessions=[session.id], evidence=list(evidence), references=["RFC 3207", "RFC 8314"],
        ))
    else:
        capability_evidence = next((line.evidence for line in server_lines
                                    if line.value.upper().startswith(b"250")), ())
        auth_evidence = tuple(item for line in auth_lines for item in _evidence(
            session.client_to_server, line.start, line.length, "cleartext-auth", "AUTH argument redacted"
        ))
        _set_transition(session, "not_used", "certain" if auth_lines else "inferred",
                        capability_evidence + auth_evidence)
        if protocol == "smtp" and offered is False and auth_lines:
            admit_finding(session, Finding(
                rule_id="STARTTLS-NOT-OFFERED", tier=Tier.OBSERVED.value,
                confidence_band="certain", severity="high", confidence=1.0,
                what="SMTP did not advertise STARTTLS before authentication.",
                why="The observed SMTP capability response lacks STARTTLS.",
                fix="Enable STARTTLS on the SMTP service.", remediation_id="enable_starttls",
                remediation_effort="one_line_reload", affected_sessions=[session.id],
                evidence=list(next((line.evidence for line in server_lines if line.value.upper().startswith(b"250")), ())),
                references=["RFC 3207"],
            ))

    if auth_lines:
        admit_finding(session, _cleartext_auth_finding(session, auth_lines))
    session._transition_facts = facts  # type: ignore[attr-defined]
    return session


# Both spellings remain available for pipeline and library API compatibility.
analyze_transition = analyse_transition
