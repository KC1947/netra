"""Reproduce M7 capture-held-out metrics and AI on/off JSON diffs offline."""
from __future__ import annotations

import argparse
import copy
import difflib
import json
from pathlib import Path

import numpy as np

from lab.build_m7_baseline import ENTERPRISE_PLANTS
from sms.pipeline import run_pipeline

ROOT = Path(__file__).resolve().parents[1]


def _non_ml(report: dict) -> str:
    result = copy.deepcopy(report)
    result.pop("ml_summary")
    for session in result["sessions"]:
        session.pop("ml")
    return json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n"


def measure(output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    results = {}
    for name in ("real_mail", "mixed_enterprise"):
        path = ROOT / "tests" / "fixtures" / f"{name}.pcap"
        on = run_pipeline(path, ml=True)
        off = run_pipeline(path, ml=False)
        assert on == run_pipeline(path, ml=True), "non-deterministic ML report"
        for label, report in (("on", on), ("off", off)):
            (output / f"{name}.{label}.json").write_text(
                json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n"
            )
        diff = "".join(difflib.unified_diff(
            _non_ml(off).splitlines(keepends=True), _non_ml(on).splitlines(keepends=True),
            fromfile="AI off (ML fields removed)", tofile="AI on (ML fields removed)",
        ))
        (output / f"{name}.non_ml.diff").write_text(diff)
        assert not diff, "ML changed fields outside session.ml or report.ml_summary"
        sessions = on["sessions"]
        flags = [s for s in sessions if s["ml"]["is_anomaly"]]
        abstained = [s for s in sessions if s["ml"]["abstained"]]
        percentiles = [s["ml"]["anomaly_percentile"] for s in sessions if not s["ml"]["abstained"]]
        plants = set(ENTERPRISE_PLANTS) if name == "mixed_enterprise" else set()
        assert plants <= {s["id"] for s in sessions}
        normals = [s for s in sessions if s["id"] not in plants]
        false_alerts = sum(s["ml"]["is_anomaly"] for s in normals)
        # k fixed before measurement. Ties retain original capture session order.
        ranked = sorted((s for s in sessions if not s["ml"]["abstained"]),
                        key=lambda s: -s["ml"]["anomaly_score"])
        precision = {
            str(k): {"true_positives": sum(s["id"] in plants for s in ranked[:k]),
                     "k": k, "value": sum(s["id"] in plants for s in ranked[:k]) / k}
            for k in (5, 10)
        } if plants else None
        results[name] = {
            "sessions": len(sessions), "flagged": len(flags),
            "flag_rate": len(flags) / len(sessions), "flagged_session_ids": [s["id"] for s in flags],
            "abstained": len(abstained), "abstention_rate": len(abstained) / len(sessions),
            "percentiles": {"min": min(percentiles), "median": float(np.median(percentiles)),
                            "max": max(percentiles)} if percentiles else None,
            "normal_sessions": len(normals), "false_alerts": false_alerts,
            "false_alerts_per_1000": 1000 * false_alerts / len(normals),
            "label_basis": (
                "Enterprise answer-key planted risks; all other sessions treated as normal."
                if plants else "Assumed-benign recorded mail; no independent attack labels."
            ),
            "planted_anomalies": ENTERPRISE_PLANTS if plants else None,
            "precision_at_k": precision,
            "top_10_session_ids": [s["id"] for s in ranked[:10]],
            "non_ml_diff": diff, "deterministic": True,
            "calibration": on["ml_summary"]["calibration"],
        }
    (output / "metrics.json").write_text(json.dumps(results, indent=2, allow_nan=False) + "\n")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "out/m7_validation")
    args = parser.parse_args()
    print(json.dumps(measure(args.output), indent=2, allow_nan=False))
