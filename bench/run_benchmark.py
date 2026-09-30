#!/usr/bin/env python3
"""Run the fixed SecureMailScope capture benchmark and write its JSON record."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
OUTPUT = ROOT / "docs" / "BENCHMARKS.json"
CAPTURES = (
    ROOT / "out" / "sample.pcap",
    ROOT / "out" / "multiclient.pcap",
    ROOT / "tests" / "fixtures" / "real_mail.pcap",
    ROOT / "out" / "haystack.pcap",
)
TRUTH = ROOT / "out" / "haystack.truth.json"

CONFIRMED_MAIL_SESSIONS_BASIS = (
    "sessions whose mail protocol is confirmed by payload grammar "
    "(session.protocol != 'unknown')"
)
RETAINED_MAIL_SESSIONS_BASIS = (
    "sessions retained for analysis: payload-grammar-confirmed mail sessions plus "
    "protocol-indeterminate sessions on known mail-service ports"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _flow_key(session: dict) -> str:
    flow = session["five_tuple"]
    endpoints = sorted((
        (flow["client_ip"], int(flow["client_port"])),
        (flow["server_ip"], int(flow["server_port"])),
    ))
    return "|".join(f"{ip}:{port}" for ip, port in endpoints)


def _peak_rss_bytes() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # macOS reports bytes; Linux and the other supported Unix runners report KiB.
    return int(value if sys.platform == "darwin" else value * 1024)


def _worker(capture: Path) -> int:
    from sms.pipeline import run_pipeline

    started = time.perf_counter()
    report = run_pipeline(capture, ml=False)
    elapsed = time.perf_counter() - started
    result = {
        "elapsed_seconds": elapsed,
        "peak_memory_bytes": _peak_rss_bytes(),
        "packets": report["capture_health"]["frames"],
        "mail_sessions_found": len(report["sessions"]),
        "confirmed_mail_sessions": report["capture_health"]["confirmed_mail_sessions"],
        "candidate_flows": report["capture_health"]["candidate_flows"],
        "total_flows": report["capture_health"]["total_flows"],
        "detected_flow_keys": sorted(_flow_key(session) for session in report["sessions"]),
    }
    print(json.dumps(result, sort_keys=True))
    return 0


def _run_once(capture: Path) -> dict:
    environment = dict(os.environ)
    environment["PYTHONHASHSEED"] = "0"
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--worker", str(capture)],
        cwd=ROOT,
        env=environment,
        check=True,
        text=True,
        capture_output=True,
    )
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"benchmark worker produced invalid output: {completed.stdout!r}") from exc


def _capture_result(capture: Path) -> tuple[dict, dict]:
    runs = [_run_once(capture) for _ in range(3)]
    elapsed = statistics.median(run["elapsed_seconds"] for run in runs)
    packets = runs[0]["packets"]
    size = capture.stat().st_size
    stable_fields = ("packets", "mail_sessions_found", "confirmed_mail_sessions",
                     "candidate_flows", "total_flows", "detected_flow_keys")
    for field in stable_fields:
        if any(run[field] != runs[0][field] for run in runs[1:]):
            raise RuntimeError(f"non-deterministic benchmark field {field!r} for {capture}")
    result = {
        "path": str(capture.relative_to(ROOT)),
        "sha256": _sha256(capture),
        "size_bytes": size,
        "packets": packets,
        "elapsed_seconds_median": round(elapsed, 6),
        "packets_per_second": round(packets / elapsed, 3) if elapsed else None,
        "mb_per_second": round((size / 1_000_000) / elapsed, 3) if elapsed else None,
        "peak_memory_bytes": max(run["peak_memory_bytes"] for run in runs),
        "mail_sessions_found": runs[0]["mail_sessions_found"],
        "mail_sessions_found_basis": RETAINED_MAIL_SESSIONS_BASIS,
        "confirmed_mail_sessions": runs[0]["confirmed_mail_sessions"],
        "confirmed_mail_sessions_basis": CONFIRMED_MAIL_SESSIONS_BASIS,
        "candidate_flows": runs[0]["candidate_flows"],
        "total_flows": runs[0]["total_flows"],
    }
    return result, runs[0]


def _haystack_accuracy(worker_result: dict) -> dict:
    truth = json.loads(TRUTH.read_text())
    haystack = ROOT / truth["haystack"]["path"]
    if _sha256(haystack) != truth["haystack"]["sha256"]:
        raise RuntimeError("haystack does not match its truth file; rebuild it first")
    expected = Counter(item["flow_key"] for item in truth["injected_flows"])
    detected = Counter(worker_result["detected_flow_keys"])
    true_positive = sum((expected & detected).values())
    false_positive = sum((detected - expected).values())
    false_negative = sum((expected - detected).values())
    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    return {
        "measurement_basis": (
            f"{truth['measurement_basis']} over retained mail sessions; "
            "payload-grammar confirmation is not required"
        ),
        "truth_file": str(TRUTH.relative_to(ROOT)),
        "injected_mail_sessions": truth["injected_mail_sessions"],
        "injected_mail_sessions_basis": (
            "mail sessions injected from the two deterministic needle captures, "
            "counted by canonical TCP endpoint pair"
        ),
        "true_positives": true_positive,
        "true_positives_basis": (
            "injected canonical TCP endpoint pairs present among retained mail sessions, "
            "including protocol-indeterminate sessions on known mail-service ports"
        ),
        "false_positives": false_positive,
        "false_negatives": false_negative,
        "precision": round(true_positive / precision_denominator, 6)
        if precision_denominator else 0.0,
        "recall": round(true_positive / recall_denominator, 6)
        if recall_denominator else 0.0,
        "recall_basis": "true_positives / injected_mail_sessions",
    }


def run_benchmark() -> dict:
    missing = [str(path.relative_to(ROOT)) for path in (*CAPTURES, TRUTH) if not path.exists()]
    if missing:
        raise FileNotFoundError(
            f"missing benchmark inputs: {', '.join(missing)}; run lab/scripts/build_haystack.sh"
        )
    captures = []
    haystack_worker = None
    for capture in CAPTURES:
        result, worker = _capture_result(capture)
        captures.append(result)
        if capture == ROOT / "out" / "haystack.pcap":
            haystack_worker = worker
    assert haystack_worker is not None
    git_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    git_dirty = bool(subprocess.check_output(
        ["git", "status", "--porcelain"], cwd=ROOT, text=True
    ).strip())
    document = {
        "schema_version": 1,
        "git_commit": git_commit,
        "git_dirty": git_dirty,
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "method": {
            "runs_per_capture": 3,
            "elapsed_statistic": "median",
            "peak_memory_statistic": "maximum process RSS across the three isolated runs",
            "ml_enabled": False,
            "megabyte_definition": 1_000_000,
        },
        "captures": captures,
        "haystack_accuracy": _haystack_accuracy(haystack_worker),
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.worker is not None:
        return _worker(args.worker.resolve())
    result = run_benchmark()
    print(f"Wrote {OUTPUT}")
    accuracy = result["haystack_accuracy"]
    print(
        "Haystack precision={precision:.3f} recall={recall:.3f} "
        "({true_positives} TP, {false_positives} FP, {false_negatives} FN)".format(
            **accuracy
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
