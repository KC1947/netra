"""Attach observed certificate context without changing session truth."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..contracts import Session


_RELATION = "same service identity; NOT proof for this session"


def _mapping_association(sessions: list[dict]) -> None:
    """Preserve the corrected reference API used by the regression fixture."""
    seen = [
        session
        for session in sessions
        if session.get("certificate", {}).get("status")
        not in (None, "NOT_OBSERVABLE")
    ]
    fingerprints = sorted({
        session["certificate"]["fingerprint"] for session in seen
    })
    for session in sessions:
        if session.get("certificate", {}).get("status") != "NOT_OBSERVABLE":
            continue
        session["certificate_seen_on_service"] = [
            {
                "fingerprint": source["certificate"]["fingerprint"],
                "source_session": source["id"],
                "source_frame": source["certificate"].get("frame"),
                "tier": "DEDUCED",
                "relation": _RELATION,
            }
            for source in seen
        ]
        session["certificate_ambiguous"] = len(fingerprints) > 1
        # The target certificate mapping is deliberately untouched.


def _session_association(sessions: list[Session]) -> None:
    observed: list[dict[str, Any]] = []
    for session in sessions:
        if session.certificate.status == "NOT_OBSERVABLE":
            continue
        fingerprint = getattr(session, "_certificate_fingerprint", None)
        if fingerprint is None:
            continue
        observed.append({
            "fingerprint": fingerprint,
            "source_session": session.id,
            "source_frame": getattr(session, "_certificate_frame", None),
            "tier": "DEDUCED",
            "relation": _RELATION,
        })

    if not observed:
        return
    fingerprints = sorted({item["fingerprint"] for item in observed})
    for session in sessions:
        if (session.tls.negotiated_version != "TLS1.3"
                or session.certificate.status != "NOT_OBSERVABLE"):
            continue
        session.certificate_seen_on_service = [dict(item) for item in observed]
        session.certificate_ambiguous = len(fingerprints) > 1
        # ``session.certificate`` remains the observation for this encrypted
        # session. Association is context and never replaces that object.


def associate_certificates(sessions: list[Session] | list[dict]) -> None:
    """Associate visible certificates within one resolved server identity.

    Callers must group sessions by the full P3 identity first. Certificates can
    rotate or vary by backend, SNI, or signature algorithm, so every observed
    fingerprint is retained as context and ambiguity is explicit.
    """
    if not sessions:
        return
    if isinstance(sessions[0], Mapping):
        _mapping_association(sessions)  # type: ignore[arg-type]
    else:
        _session_association(sessions)  # type: ignore[arg-type]
