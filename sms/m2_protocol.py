"""Conservative, grammar-first identification of mail transport protocols.

This module deliberately records only the protocol name and confidence.  Banner
and command bytes can carry private information, so they remain in the private
ingest streams and are never copied into a session or report field.
"""

from __future__ import annotations

from .contracts import PacketObservation, Session
from .judgement.epistemic import Tier


_TLS_RECORD_PREFIX = b"\x16\x03"
_IMPLICIT_TLS_PORT_PROTOCOLS = {993: "imap", 995: "pop3", 465: "smtp"}


def _first_span(session_stream) -> bytes:
    """Return the first captured contiguous span, without crossing TCP gaps."""
    for data, _sources in session_stream.iter_spans():
        return data
    return b""


def _cleartext_protocol(server_bytes: bytes, client_bytes: bytes) -> str | None:
    """Identify a cleartext protocol only from its specified opening grammar."""
    server_upper = server_bytes.upper()
    client_upper = client_bytes.upper()

    # SMTP's server banner must be a 220 greeting that identifies SMTP/ESMTP.
    # EHLO is also a sufficiently distinctive client grammar for an observed
    # session, including implementations that omit SMTP from a custom banner.
    if ((server_upper.startswith((b"220 ", b"220-"))
         and b"SMTP" in server_upper.split(b"\n", 1)[0])
            or client_upper.startswith(b"EHLO ")):
        return "smtp"
    # IMAP server greetings are untagged OK/PREAUTH responses.  Do not search
    # arbitrary bytes for "IMAP": a TLS ClientHello can legitimately contain
    # that substring in SNI and must never be mistaken for cleartext grammar.
    if server_upper.startswith((b"* OK", b"* PREAUTH")):
        return "imap"
    if server_upper.startswith(b"+OK"):
        return "pop3"
    return None


def _swap_roles(session: Session) -> None:
    """Repair ingest's deterministic fallback when a banner proves it backwards."""
    client_ip, client_port = session.five_tuple["client_ip"], session.five_tuple["client_port"]
    server_ip, server_port = session.five_tuple["server_ip"], session.five_tuple["server_port"]
    session.five_tuple = {
        "client_ip": server_ip,
        "client_port": server_port,
        "server_ip": client_ip,
        "server_port": client_port,
        "transport": session.five_tuple.get("transport", "tcp"),
    }
    session.client_to_server, session.server_to_client = (
        session.server_to_client,
        session.client_to_server,
    )
    session.packet_observations = [
        PacketObservation(
            item.frame_no,
            "server_to_client" if item.direction == "client_to_server" else "client_to_server",
            item.ts,
            item.sequence,
            item.payload,
            item.payload_packet_offset,
        )
        for item in session.packet_observations
    ]
    session.conflicts = [
        {
            **dict(item),
            "direction": ("server_to_client"
                          if item.get("direction") == "client_to_server"
                          else "client_to_server"),
        }
        for item in session.conflicts
    ]


def classify_protocol(session: Session) -> Session:
    """Classify one session in place and return it.

    Ports are used only after a server-originated TLS record establishes that
    the connection is implicit TLS.  A cleartext server banner observed on the
    client-labelled stream proves the ingest fallback chose roles backwards, so
    the private directional streams and five-tuple are normalized first.
    """
    server_bytes = _first_span(session.server_to_client)
    client_bytes = _first_span(session.client_to_server)

    # Do not infer role reversal from a client command alone: a command can be
    # partial or spoof-like capture noise, while a server greeting establishes
    # the direction unambiguously.
    if _cleartext_protocol(client_bytes, b"") is not None and _cleartext_protocol(server_bytes, b"") is None:
        _swap_roles(session)
        server_bytes, client_bytes = client_bytes, server_bytes

    if server_bytes.startswith(_TLS_RECORD_PREFIX):
        hinted = _IMPLICIT_TLS_PORT_PROTOCOLS.get(int(session.five_tuple["server_port"]))
        if hinted is not None:
            session.protocol = hinted
            session.protocol_confidence = "medium"
            session.protocol_reason = "implicit TLS; protocol inferred from port hint"
            session.fact_tiers["protocol"] = Tier.INFERRED.value
            # The observation is intentionally not serialized; later transition
            # analysis derives its own evidence from the wire.
            return session

    cleartext = _cleartext_protocol(server_bytes, client_bytes)
    if cleartext is not None:
        session.protocol = cleartext
        session.protocol_confidence = "high"
        session.fact_tiers["protocol"] = Tier.OBSERVED.value
        session.protocol_reason = {
            "smtp": "SMTP greeting or EHLO grammar",
            "imap": "IMAP greeting grammar",
            "pop3": "POP3 greeting grammar",
        }[cleartext]
    else:
        session.protocol = "unknown"
        session.protocol_confidence = "unknown"
        session.protocol_reason = "unrecognized protocol grammar"
        session.fact_tiers["protocol"] = Tier.NOT_OBSERVABLE.value
    return session


# The singular name used by pipeline callers.  ``classify_protocol`` remains a
# descriptive alias for direct use in tests and integrations.
identify_protocol = classify_protocol


def classify_protocols(sessions: list[Session]) -> list[Session]:
    """Classify sessions in deterministic input order."""
    for session in sessions:
        classify_protocol(session)
    return sessions
