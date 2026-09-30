"""Passive TLS signal classification from captured handshake metadata."""

from __future__ import annotations

EXT_STATUS_REQUEST = 0x0005
EXT_EARLY_DATA = 0x002A
EXT_PRE_SHARED_KEY = 0x0029
EXT_KEY_SHARE = 0x0033
EXT_ECH = 0xFE0D
EXT_PSK_KX_MODES = 0x002D
HANDSHAKE_CERTIFICATE_STATUS = 22


def _types(extensions):
    return {extension_type for extension_type, _ in (extensions or [])}


def client_signals(client_extensions) -> dict:
    extension_types = _types(client_extensions)
    return {
        "status_request_sent": EXT_STATUS_REQUEST in extension_types,
        "early_data_offered": EXT_EARLY_DATA in extension_types,
        "ech_offered": EXT_ECH in extension_types,
        "psk_offered": EXT_PRE_SHARED_KEY in extension_types,
    }


def ocsp_stapling(client_extensions, server_extensions, handshake_types,
                  negotiated_version) -> str:
    """Return not_requested, provided, requested_not_provided, or not_observable."""
    if EXT_STATUS_REQUEST not in _types(client_extensions):
        return "not_requested"
    if negotiated_version == 0x0304:
        return "not_observable"
    if HANDSHAKE_CERTIFICATE_STATUS in set(handshake_types or ()):
        return "provided"
    if EXT_STATUS_REQUEST in _types(server_extensions):
        return "provided"
    return "requested_not_provided"


def forward_secrecy(negotiated_version, server_extensions, cipher_has_no_fs) -> str:
    """Classify forward secrecy as YES, NO, or UNKNOWN."""
    extension_types = _types(server_extensions)
    if negotiated_version == 0x0304:
        if EXT_PRE_SHARED_KEY in extension_types and EXT_KEY_SHARE not in extension_types:
            return "NO"
        return "YES"
    if cipher_has_no_fs is None:
        return "UNKNOWN"
    return "NO" if cipher_has_no_fs else "YES"


def downgrade_flags(offered_versions, sentinel) -> dict:
    """Treat a downgrade sentinel as anomalous only after a TLS 1.3 offer."""
    if not sentinel:
        return {"downgrade_anomaly": False, "downgrade_legacy_client": False}
    offered_tls13 = 0x0304 in (offered_versions or [])
    return {
        "downgrade_anomaly": offered_tls13,
        "downgrade_legacy_client": not offered_tls13,
    }
