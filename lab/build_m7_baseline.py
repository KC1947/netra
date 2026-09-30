"""Rebuild the numeric-only M7 baseline from whole, offline captures.

Run with ``python -m lab.build_m7_baseline``. Generated PCAPs stay in out/;
the checked-in artifact contains feature values, session IDs and source hashes,
never addresses, credentials, message contents, or certificate material.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import random

import numpy as np
from scapy.utils import wrpcap

from lab.generate_corpus import CERTS, Session
from lab.generate_pcap import _VALID_ECDSA_P256_DER, _VALID_RSA_DER
from lab import tls_wire as wire
from sms.m7_anomaly import BASELINE, FEATURES, extract_features
from sms.m9_report import analyse_sessions

ROOT = Path(__file__).resolve().parents[1]
# Fixed before evaluation, from the enterprise answer key and generator:
# static RSA/CBC, expired legacy TLS, weak legacy cert, cleartext credentials,
# suspected stripping, and the TLS-1.3-offered downgrade-sentinel case.
ENTERPRISE_PLANTS = {
    "s3": "static RSA/CBC", "s8": "static RSA/CBC",
    "s19": "legacy TLS and expired certificate",
    "s21": "legacy TLS and weak self-signed certificate",
    "s23": "cleartext authentication", "s24": "suspected STARTTLS stripping",
    "s25": "downgrade sentinel with TLS 1.3 offered",
}


def generate_diverse(path: Path, seed: int, n: int = 40) -> None:
    """Independent benign configurations, not resampled real-capture rows."""
    rng = random.Random(seed)
    packets = []
    for index in range(n):
        starttls = rng.choice((True, False))
        tls12 = rng.choice((True, False))
        ec = rng.choice((True, False))
        port = 587 if starttls else rng.choice((465, 993, 995))
        session = Session(f"10.40.{seed % 200}.{index + 1}",
                          f"10.41.{seed % 200}.{1 + index % 3}", 43000 + index, port)
        if starttls:
            session.s("220 baseline.example ESMTP\r\n")
            session.c("EHLO baseline.example\r\n")
            session.s("250-baseline.example\r\n250 STARTTLS\r\n")
            session.c("STARTTLS\r\n")
            session.s("220 Ready for TLS\r\n")
        version = wire.V_TLS12 if tls12 else wire.V_TLS13
        offered = (version,) if rng.choice((True, False)) else (wire.V_TLS13, wire.V_TLS12)
        cipher = (0xc02b if ec else 0xc02f) if tls12 else rng.choice((0x1301, 0x1302))
        session.c(wire.client_hello(offered=offered, ciphers=(cipher,), random_bytes=rng.randbytes))
        group = None if tls12 else rng.choice((wire.G_X25519,) * 9 + (wire.G_X25519MLKEM768,))
        session.s(wire.server_hello(version, cipher, group, random_bytes=rng.randbytes))
        if tls12:
            der = _VALID_ECDSA_P256_DER if ec else rng.choice((
                _VALID_RSA_DER, (CERTS / "cert_A.der").read_bytes(),
            ))
            session.s(wire.certificate(der))
        # Vary normal connection lengths without synthesising message contents.
        for _ in range(rng.randint(2, 70)):
            getattr(session, rng.choice(("c", "s")))(
                wire.app_data(rng.randint(16, 128), random_bytes=rng.randbytes)
            )
        # Valid certificates at multiple ages, evaluated at capture time.
        age_offset = rng.randint(-120, 110) * 86400
        session_packets = list(session.packets(index))
        for packet in session_packets:
            packet.time += age_offset
        packets.extend(session_packets)
    path.parent.mkdir(parents=True, exist_ok=True)
    packets.sort(key=lambda packet: packet.time)
    wrpcap(str(path), packets)


def build() -> dict:
    sources = []
    for seed in (101, 102, 103, 104):
        path = ROOT / "out" / "m7_baseline" / f"benign_{seed}.pcap"
        generate_diverse(path, seed)
        sources.append((path, "synthetic benign variation", set()))
    sources.extend([
        (ROOT / "tests/fixtures/real_mail.pcap", "recorded mail; assumed benign", set()),
        (ROOT / "tests/fixtures/mixed_enterprise.pcap", "synthetic enterprise; planted risks excluded",
         set(ENTERPRISE_PLANTS)),
    ])
    captures = []
    for path, kind, excluded in sources:
        sessions = analyse_sessions(path)
        # Contextual fingerprint shares use the whole original capture, then
        # labels select baseline rows. Never recompute context on filtered rows.
        matrix = extract_features(sessions)
        retained = [(s, row) for s, row in zip(sessions, matrix) if s.id not in excluded]
        captures.append({
            "path": str(path.relative_to(ROOT)), "kind": kind,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "source_sessions": len(sessions), "excluded_session_ids": sorted(excluded),
            "session_ids": [s.id for s, _ in retained],
            "features": [[float(v) if np.isfinite(v) else None for v in row] for _, row in retained],
        })
    artifact = {"schema_version": "m7-baseline-v2", "features": list(FEATURES), "captures": captures}
    BASELINE.write_text(json.dumps(artifact, indent=2, allow_nan=False) + "\n")
    return artifact


if __name__ == "__main__":
    result = build()
    print(json.dumps({"captures": len(result["captures"]),
                      "sessions": sum(len(c["features"]) for c in result["captures"])}))
