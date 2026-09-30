"""Passive X.509 certificate judgement: tri-state, capture-time only.

No network calls (no OCSP/CRL/DNS): validity is judged only from the DER
m4_tls captured off the wire.  A cert's window is always compared against
the CAPTURE timestamp, never ``datetime.now()`` -- the PCAP may be opened
long after it was recorded.
"""

from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

from .contracts import CertInfo, Session
from .judgement.epistemic import Tier


def _capture_time(session: Session) -> float | None:
    first_frame = session.packets.get("first")
    if first_frame is None:
        return None
    for item in session.packet_observations:
        if item.frame_no == first_frame:
            return item.ts
    return None


@dataclass(frozen=True)
class _PublicKeyInfo:
    key_type: str | None
    key_bits: int | None
    curve: str | None
    strength: str
    failure_reason: str | None = None


def _public_key_info(public_key) -> _PublicKeyInfo:
    """Classify an SPKI key from its parsed object, never from its bit count."""
    if isinstance(public_key, rsa.RSAPublicKey):
        bits = public_key.key_size
        weak = bits < 2048
        return _PublicKeyInfo(
            "RSA", bits, None, "INVALID" if weak else "VALID",
            f"weak key (RSA, {bits} bits; minimum 2048)" if weak else None,
        )
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        bits = public_key.curve.key_size
        weak = bits < 256
        return _PublicKeyInfo(
            "EC", bits, public_key.curve.name, "INVALID" if weak else "VALID",
            f"weak key (EC, {bits} bits; minimum 256)" if weak else None,
        )
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return _PublicKeyInfo("Ed25519", None, None, "VALID")
    if isinstance(public_key, ed448.Ed448PublicKey):
        return _PublicKeyInfo("Ed448", None, None, "VALID")
    return _PublicKeyInfo(None, None, None, "NOT_OBSERVABLE")


def _malformed(session: Session) -> Session:
    session.certificate = CertInfo(status="INDETERMINATE", reason="certificate DER could not be parsed")
    session.fact_tiers["certificate.status"] = Tier.NOT_OBSERVABLE.value
    session.fact_tiers["certificate.key_strength"] = Tier.NOT_OBSERVABLE.value
    session.fact_reason_codes["certificate.status"] = "malformed_certificate"
    session.fact_reason_codes["certificate.key_strength"] = "malformed_certificate"
    return session


def analyse_certificate(session: Session) -> Session:
    """Populate ``session.certificate`` from the DER m4_tls captured, if any."""
    der = getattr(session, "_cert_der", None)
    evidence = list(getattr(session, "_cert_evidence", []))
    session._certificate_fingerprint = (  # type: ignore[attr-defined]
        hashlib.sha256(der).hexdigest() if der is not None else None
    )
    session._certificate_frame = (  # type: ignore[attr-defined]
        evidence[0].frame if evidence else None
    )
    if der is None:
        tls13 = session.tls.negotiated_version == "TLS1.3"
        reason = ("certificate exchanged inside the encrypted TLS 1.3 handshake"
                   if tls13 else "no Certificate message observed in this capture")
        session.certificate = CertInfo(status="NOT_OBSERVABLE", reason=reason)
        session.fact_tiers["certificate.status"] = Tier.NOT_OBSERVABLE.value
        session.fact_tiers["certificate.key_strength"] = Tier.NOT_OBSERVABLE.value
        reason_code = ("tls13_encrypted_certificate" if tls13 else
                       "midstream_capture" if session.midstream else
                       "not_present_in_capture")
        session.fact_reason_codes["certificate.status"] = reason_code
        session.fact_reason_codes["certificate.key_strength"] = reason_code
        return session

    # ``cryptography`` parses subject, issuer, validity and signature fields
    # lazily: the loader can succeed and a later property access raise. Every
    # property is therefore read inside the same guard. The exception text is
    # discarded, never logged or copied into the reason -- it can quote the
    # offending capture bytes.
    try:
        cert = x509.load_der_x509_certificate(der)
        not_before, not_after = cert.not_valid_before_utc, cert.not_valid_after_utc
        self_signed = cert.issuer == cert.subject
        try:
            signature_hash = cert.signature_hash_algorithm
        except UnsupportedAlgorithm:
            signature_hash = None
        sig_alg = signature_hash.name if signature_hash else None
    except ValueError:
        return _malformed(session)
    try:
        key_info = _public_key_info(cert.public_key())
    except (TypeError, ValueError, UnsupportedAlgorithm):
        key_info = _PublicKeyInfo(None, None, None, "NOT_OBSERVABLE")

    capture_time = _capture_time(session)
    expired = None
    if capture_time is not None:
        capture_dt = datetime.datetime.fromtimestamp(capture_time, tz=datetime.timezone.utc)
        expired = capture_dt < not_before or capture_dt > not_after

    failures = []
    limitations = []
    if expired:
        failures.append("expired at capture time")
    if self_signed:
        failures.append("self-signed")
    if key_info.failure_reason:
        failures.append(key_info.failure_reason)
    if capture_time is None:
        limitations.append("capture time unknown")
    if key_info.strength == "NOT_OBSERVABLE":
        limitations.append("unsupported public-key type; key-strength check NOT_OBSERVABLE")

    if failures:
        status = "INVALID"
    elif limitations:
        # A missing capture time or unsupported key type leaves a check unrun;
        # that lowers coverage and never guesses an algorithm threshold.
        status = "INDETERMINATE"
    else:
        status = "VALID"

    session.certificate = CertInfo(
        status=status,
        reason="; ".join((*failures, *limitations)) or None,
        key_type=key_info.key_type,
        curve=key_info.curve,
        key_bits=key_info.key_bits,
        key_strength=key_info.strength,
        sig_alg=sig_alg,
        self_signed=self_signed,
        expired=expired,
        notBefore=not_before.isoformat(),
        notAfter=not_after.isoformat(),
    )
    session.fact_tiers["certificate.status"] = (
        Tier.OBSERVED.value
        if status in {"VALID", "INVALID"} else Tier.NOT_OBSERVABLE.value
    )
    session.fact_tiers["certificate.key_strength"] = (
        Tier.OBSERVED.value
        if key_info.strength in {"VALID", "INVALID"}
        else Tier.NOT_OBSERVABLE.value
    )
    if status == "INDETERMINATE":
        session.fact_reason_codes["certificate.status"] = (
            "not_present_in_capture" if capture_time is None else "unsupported_algorithm"
        )
    if key_info.strength == "NOT_OBSERVABLE":
        session.fact_reason_codes["certificate.key_strength"] = "unsupported_algorithm"
    return session


analyze_certificate = analyse_certificate


def associate_certificates(sessions):
    """Compatibility import for the reference regression API."""
    from .correlation.cert_association import associate_certificates as associate

    return associate(sessions)
