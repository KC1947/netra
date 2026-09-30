"""Resolve capture-local server identities without network access."""

from __future__ import annotations

import re

from ..contracts import Evidence, Session


_SMTP_GREETING = re.compile(br"^220[ -]([^\s\r\n]+)")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _normalise_hostname(value: str) -> str | None:
    hostname = value.rstrip(".").lower()
    if not hostname or len(hostname) > 253:
        return None
    labels = hostname.split(".")
    if not all(_DNS_LABEL.fullmatch(label) for label in labels):
        return None
    return hostname


def _smtp_banner_identity(session: Session) -> tuple[str, list[Evidence]] | None:
    if session.protocol != "smtp":
        return None
    for data, sources in session.server_to_client.iter_spans():
        if not data or not sources:
            continue
        newline = data.find(b"\n")
        if newline < 0:
            return None
        line = data[:newline + 1]
        match = _SMTP_GREETING.match(line)
        if match is None:
            return None
        try:
            decoded = match.group(1).decode("ascii")
        except UnicodeDecodeError:
            return None
        hostname = _normalise_hostname(decoded)
        if hostname is None:
            return None
        start = sources[0].stream_offset + match.start(1)
        try:
            provenance = session.server_to_client.provenance_for(
                start, len(match.group(1))
            )
        except ValueError:
            return None
        evidence = [
            Evidence(
                item.frame,
                "smtp.banner.hostname",
                item.packet_byte_offset,
                item.byte_length,
                hostname,
            )
            for item in provenance
        ]
        return hostname, evidence
    return None


def endpoint_label(server_ip: str, server_port: int) -> str:
    address = f"[{server_ip}]" if ":" in server_ip else server_ip
    return f"{address}:{server_port}"


def resolve_identity(session: Session) -> tuple[tuple[str, int, str | None], dict]:
    """Return the grouping key and provenance for one observed server."""
    server_ip = str(session.five_tuple["server_ip"])
    server_port = int(session.five_tuple["server_port"])
    hostname = getattr(session, "_sni_hostname", None)
    evidence = list(getattr(session, "_sni_evidence", []))
    source = "tls_sni"
    if hostname is None:
        banner = _smtp_banner_identity(session)
        if banner is not None:
            hostname, evidence = banner
            source = "smtp_banner"
        else:
            source = "network_endpoint"

    resolution = {
        "session": session.id,
        "source": source,
        "tier": "OBSERVED",
        "hostname": hostname,
        "name_observed": hostname is not None,
        "reason": (None if hostname is not None else
                   "no server name was observed for this IP:port in the capture"),
        "endpoint": endpoint_label(server_ip, server_port),
        "evidence": [item.to_dict() for item in evidence],
    }
    return (server_ip, server_port, hostname), resolution
