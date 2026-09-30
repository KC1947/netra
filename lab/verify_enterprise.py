"""Verify the mixed-enterprise fixture against its immutable answer key."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sms.correlation.constraints import State  # noqa: E402
from sms.m9_report import build_report  # noqa: E402


FIXTURE = ROOT / "tests" / "fixtures" / "mixed_enterprise.pcap"
ANSWER_KEY = ROOT / "tests" / "enterprise_ground_truth.json"
# Take the state vocabulary from the engine rather than keeping a copy:
# a local list silently outlived the removal of EXCLUDED_LIKELY and printed it
# as a zero row, so this verifier contradicted the API contract about how many
# states exist. Importing it means the two cannot drift again.
MATRIX_STATES = tuple(state.value for state in State)


def _compare(disagreements, location, expected, actual):
    if expected != actual:
        disagreements.append({
            "location": location,
            "expected": expected,
            "actual": actual,
        })


def verify(fixture=FIXTURE, answer_key=ANSWER_KEY):
    truth = json.loads(Path(answer_key).read_text())
    started = time.perf_counter()
    report_object = build_report(fixture, ml=False)
    wall_seconds = time.perf_counter() - started
    report = report_object.to_dict()
    disagreements = []

    _compare(
        disagreements, "capture.sessions",
        truth["capture"]["expected_sessions"], report["summary"]["sessions_total"],
    )
    _compare(
        disagreements, "capture.server_identities",
        truth["capture"]["expected_server_identities"], len(report["servers"]),
    )
    _compare(
        disagreements, "capture.hndl",
        truth["capture"]["expected_hndl"], report["hndl"],
    )

    actual_servers = {server["server_id"]: server for server in report["servers"]}
    for expected_server in truth["servers"]:
        server_id = expected_server["server_id"]
        actual = actual_servers.get(server_id)
        if actual is None:
            disagreements.append({
                "location": f"servers.{server_id}",
                "expected": "present",
                "actual": "missing",
            })
            continue
        _compare(
            disagreements, f"servers.{server_id}.sessions",
            expected_server["session_ids"], actual["sessions"],
        )
        _compare(
            disagreements, f"servers.{server_id}.preference_mode",
            expected_server["expected_preference_mode"], actual["preference_mode"],
        )
        for prefix, key in (
            ("version:", "expected_version_states"),
            ("cipher:", "expected_cipher_states"),
        ):
            states = {
                capability: cell["state"]
                for capability, cell in actual["support_matrix"].items()
                if capability.startswith(prefix)
            }
            _compare(
                disagreements, f"servers.{server_id}.{key}",
                expected_server[key], states,
            )

    canonical_sessions = {session["id"]: session for session in report["sessions"]}
    object_sessions = {session.id: session for session in report_object.sessions}
    server_for_session = {
        session_id: server["server_id"]
        for server in report["servers"]
        for session_id in server["sessions"]
    }
    for expected_session in truth["sessions"]:
        session_id = expected_session["id"]
        actual = canonical_sessions.get(session_id)
        session_object = object_sessions.get(session_id)
        if actual is None or session_object is None:
            disagreements.append({
                "location": f"sessions.{session_id}",
                "expected": "present",
                "actual": "missing",
            })
            continue
        actual_values = {
            "server_id": server_for_session[session_id],
            "protocol": actual["protocol"],
            "transition_verdict": actual["transition"]["verdict"],
            "negotiated_version": actual["tls"]["negotiated_version"],
            "cipher": actual["tls"]["cipher"],
            "certificate_status": actual["certificate"]["status"],
            "certificate_key_type": session_object.certificate.key_type,
            "certificate_curve": session_object.certificate.curve,
            "certificate_key_bits": actual["certificate"]["key_bits"],
            "certificate_self_signed": actual["certificate"]["self_signed"],
            "has_fallback_scsv": actual["tls"]["has_fallback_scsv"],
            "downgrade_sentinel": actual["tls"]["downgrade_sentinel"],
            "group": actual["tls"]["group"],
            "hybrid_pq_flag": actual["tls"]["hybrid_pq_flag"],
            "expected_rule_ids": [
                finding["rule_id"] for finding in actual["findings"]
            ],
        }
        for key, expected in expected_session.items():
            if key in {"id", "hndl"}:
                continue
            _compare(
                disagreements, f"sessions.{session_id}.{key}",
                expected, actual_values[key],
            )

    counts = Counter(
        cell["state"]
        for server in report["servers"]
        for cell in server["support_matrix"].values()
    )
    return {
        "fixture": str(Path(fixture).resolve()),
        "answer_key": str(Path(answer_key).resolve()),
        "sha256": report["capture"]["sha256"],
        "frames": report["capture_health"]["frames"],
        "sessions": report["summary"]["sessions_total"],
        "server_identities": len(report["servers"]),
        "support_matrix_states": {
            state: counts[state] for state in MATRIX_STATES
        },
        "preference_modes": {
            server["server_id"]: server["preference_mode"]
            for server in report["servers"]
        },
        "hndl": report["hndl"],
        "analysis_wall_seconds": round(wall_seconds, 6),
        "disagreements": disagreements,
    }


def main():
    result = verify()
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(bool(result["disagreements"]))


if __name__ == "__main__":
    main()
