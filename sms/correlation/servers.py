"""Assemble per-server P3 correlation summaries."""

from __future__ import annotations

from collections import defaultdict

from ..contracts import Session
from .cert_association import associate_certificates
from .constraints import (
    build_support_matrix,
    deduced_coverage,
    detect_preference_mode,
    find_contradictions,
)
from .identity import endpoint_label, resolve_identity


def _observation(session: Session) -> dict:
    private = getattr(session, "_correlation_tls", {})
    return {
        "id": session.id,
        "offered_ciphers": list(session.tls.offered_ciphers),
        "selected_cipher": private.get("selected_cipher"),
        "offered_versions": list(session.tls.offered_versions),
        "selected_version": private.get("selected_version"),
        "selected_group": private.get("selected_group"),
        "selected_cipher_evidence": list(private.get("selected_cipher_evidence", [])),
        "selected_group_evidence": list(private.get("selected_group_evidence", [])),
        "tls13_offer_unusable": bool(private.get("tls13_offer_unusable", False)),
        "selected_version_evidence": list(private.get("selected_version_evidence", [])),
        "offered_cipher_evidence": dict(private.get("offered_cipher_evidence", {})),
        "offered_version_evidence": dict(private.get("offered_version_evidence", {})),
    }


def _server_id(identity: tuple[str, int, str | None]) -> str:
    server_ip, server_port, hostname = identity
    endpoint = endpoint_label(server_ip, server_port)
    return f"{hostname}@{endpoint}" if hostname is not None else endpoint


def correlate_servers(sessions: list[Session]) -> list[dict]:
    """Group sessions by endpoint plus observed virtual-host identity."""
    resolved = []
    sni_by_endpoint: dict[tuple[str, int], set[str]] = defaultdict(set)
    for session in sessions:
        identity, resolution = resolve_identity(session)
        resolved.append((session, identity, resolution))
        if resolution["source"] == "tls_sni" and resolution["hostname"] is not None:
            sni_by_endpoint[identity[:2]].add(str(resolution["hostname"]))

    grouped: dict[tuple[str, int, str | None], list[Session]] = defaultdict(list)
    resolutions: dict[tuple[str, int, str | None], list[dict]] = defaultdict(list)
    for session, identity, resolution in resolved:
        endpoint = identity[:2]
        endpoint_names = sni_by_endpoint.get(endpoint, set())
        if identity[2] is None and len(endpoint_names) == 1:
            hostname = next(iter(endpoint_names))
            identity = (*endpoint, hostname)
            resolution = {
                **resolution,
                "source": "endpoint_sni_association",
                "tier": "DEDUCED",
                "hostname": hostname,
                "name_observed": False,
                "reason": (
                    "name was not observed in this session; another session for "
                    "the same IP:port presented this SNI"
                ),
            }
        grouped[identity].append(session)
        resolutions[identity].append(resolution)

    servers = []
    for identity in sorted(
            grouped, key=lambda item: (item[0], item[1], item[2] or "")):
        server_sessions = grouped[identity]
        observations = [_observation(session) for session in server_sessions]
        mode, mode_evidence = detect_preference_mode(observations)
        matrix = build_support_matrix(observations, mode)
        contradictions = find_contradictions(matrix)
        associate_certificates(server_sessions)
        for session in server_sessions:
            session.server_contradictions = contradictions  # type: ignore[attr-defined]
        servers.append({
            "server_id": _server_id(identity),
            "sessions": [session.id for session in server_sessions],
            "identity_evidence": resolutions[identity],
            "preference_mode": mode.value,
            "preference_mode_evidence": mode_evidence,
            "support_matrix": matrix,
            "contradictions": contradictions,
            "deduced_coverage": deduced_coverage(matrix),
        })
    return servers
