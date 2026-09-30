"""Build the local, offline demo capture library and its API Capture manifest."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
import shutil

from scapy.utils import rdpcap

if __package__:
    from .generate_pcap import generate_scenarios
else:
    from generate_pcap import generate_scenarios

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "out"
LIBRARY = ROOT / "demo_captures"
GROUND_TRUTH = ROOT / "tests" / "ground_truth.json"
# Registry metadata describes this 25-session fixture, which the server resolves
# explicitly. Preserve demo_captures/mixed_enterprise.pcap: the library tests
# still read that separate legacy six-session capture by its existing name.
ENTERPRISE_FIXTURE = ROOT / "tests" / "fixtures" / "mixed_enterprise.pcap"

_SCENARIOS = {
    "s1": ("clean_tls13", "Clean TLS 1.3 SMTP", "STARTTLS completed with TLS 1.3 and forward secrecy."),
    "s2": ("legacy_downgrade", "Legacy TLS downgrade", "TLS 1.3 offer negotiated down to legacy TLS 1.0."),
    "s3": ("cleartext_auth", "Cleartext authentication", "SMTP authentication was observed before TLS."),
    "s4": ("strip_attack", "STARTTLS stripping attempt", "A mangled SMTP capability is followed by cleartext authentication."),
    "s5": ("expired_cert", "Expired IMAPS certificate", "Implicit TLS 1.2 with a certificate invalid at capture time."),
    "s6": ("pq_ready", "Hybrid PQ TLS 1.3", "Implicit TLS 1.3 uses the X25519MLKEM768 hybrid group."),
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def packet_count(path: Path) -> int:
    """Return the number of decoded packets in a capture."""
    return len(rdpcap(str(path)))


def _capture(capture_id: str, path: Path, title: str, description: str,
             source: str, expected: list[str]) -> dict:
    return {
        "id": capture_id,
        "file": path.name,
        "title": title,
        "description": description,
        "source": source,
        "expected": expected,
        "sha256": _sha256(path),
        "size_bytes": path.stat().st_size,
        "packets": packet_count(path),
    }


def _expected(facts: dict) -> list[str]:
    result = [f"verdict: {facts['transition_verdict']}"]
    if facts["negotiated_version"]:
        result.append(f"TLS: {facts['negotiated_version']}")
    if facts["cert_status"] != "NOT_OBSERVABLE":
        result.append(f"certificate: {facts['cert_status']}")
    if facts["expected_rule_ids"]:
        result.append(facts["expected_rule_ids"][0])
    return result


def enterprise_capture_record() -> dict:
    """Measure the checked-in enterprise fixture for its API description."""
    from sms.pipeline import run_pipeline

    report = run_pipeline(ENTERPRISE_FIXTURE, ml=False)
    frames = report["capture_health"]["frames"]
    sessions = report["summary"]["sessions_total"]
    identities = len(report["servers"])
    states = Counter(
        cell["state"]
        for server in report["servers"]
        for cell in server["support_matrix"].values()
    )
    resolved_modes = Counter(
        server["preference_mode"] for server in report["servers"]
    )
    hndl = report["hndl"]
    description = (
        f"{frames:,} measured frames; {sessions} mail sessions across "
        f"{identities} server identities; {states['EXCLUDED_FIRM']} firm "
        f"support exclusions; {resolved_modes['server_order']} server-order, "
        f"{resolved_modes['client_order']} client-order, and "
        f"{resolved_modes['unknown']} unknown preference modes; "
        f"HNDL {hndl['exposed_sessions']}/{hndl['total_sessions']} exposed."
    )
    return _capture(
        "mixed_enterprise",
        ENTERPRISE_FIXTURE,
        "Mixed enterprise mail traffic",
        description,
        "fixture",
        [
            f"{sessions} sessions",
            f"{identities} server identities",
            f"HNDL: {hndl['percent']}% exposed",
        ],
    )


def build_library() -> list[dict]:
    """Write derived captures and return stable contract-shaped metadata."""
    sample = OUT / "sample.pcap"
    anomaly = OUT / "anomaly_demo.pcap"
    if not sample.exists() or not anomaly.exists():
        raise FileNotFoundError("Build out/sample.pcap and out/anomaly_demo.pcap before the demo library")
    LIBRARY.mkdir(parents=True, exist_ok=True)
    truth = {item["id"]: item for item in json.loads(GROUND_TRUTH.read_text())["sessions"]}
    manifest = []

    manifest.append(enterprise_capture_record())

    scenario_paths = generate_scenarios(LIBRARY)
    for session_id, (capture_id, title, description) in _SCENARIOS.items():
        scenario = scenario_paths[session_id]
        manifest.append(_capture(capture_id, scenario, title, description, "synthetic", _expected(truth[session_id])))

    anomaly_target = LIBRARY / "anomaly_certswap.pcap"
    shutil.copyfile(anomaly, anomaly_target)
    manifest.append(_capture(
        "anomaly_certswap", anomaly_target, "Certificate swap anomaly",
        "One IMAPS server normally presents cert_A; one session presents cert_B.",
        "synthetic", ["cert_B unusual", "rules/AI disagreement expected"],
    ))

    real = ROOT / "tests" / "fixtures" / "real_mail.pcap"
    if real.exists():
        real_target = LIBRARY / "real_mail.pcap"
        shutil.copyfile(real, real_target)
        manifest.append(_capture(
            "real_mail", real_target, "Recorded mail traffic",
            "Locally recorded mail traffic; results depend on observable packets.",
            "real", ["facts depend on observed packets"],
        ))

    (LIBRARY / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


if __name__ == "__main__":
    build_library()
