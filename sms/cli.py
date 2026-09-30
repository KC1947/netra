"""SecureMailScope analysis and offline validation command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .delivery.cbom import build_cbom
from .delivery.pdf import render_pdf
from .m9_report import render_html
from .pipeline import run_pipeline

_GROUND_TRUTH_PATH = Path(__file__).resolve().parent.parent / "tests" / "ground_truth.json"
_FACT_KEYS = ("protocol", "transition_verdict", "offered_version", "negotiated_version",
              "downgrade_delta", "forward_secrecy", "hybrid_pq_flag", "cert_status")


def _risk_band(observed_risk: int) -> str:
    if observed_risk >= 85:
        return "critical"
    if observed_risk >= 50:
        return "high"
    if observed_risk >= 15:
        return "medium"
    return "low"


def _session_facts(session) -> dict:
    if isinstance(session, dict):
        return {
            "protocol": session["protocol"],
            "transition_verdict": session["transition"]["verdict"],
            "offered_version": session["tls"]["offered_version"],
            "negotiated_version": session["tls"]["negotiated_version"],
            "downgrade_delta": session["tls"]["downgrade_delta"],
            "forward_secrecy": session["tls"]["forward_secrecy"],
            "hybrid_pq_flag": session["tls"]["hybrid_pq_flag"],
            "cert_status": session["certificate"]["status"],
        }
    return {
        "protocol": session.protocol,
        "transition_verdict": session.transition.verdict,
        "offered_version": session.tls.offered_version,
        "negotiated_version": session.tls.negotiated_version,
        "downgrade_delta": session.tls.downgrade_delta,
        "forward_secrecy": session.tls.forward_secrecy,
        "hybrid_pq_flag": session.tls.hybrid_pq_flag,
        "cert_status": session.certificate.status,
    }


def run_self_test(report) -> bool:
    """Diff the analysed report against tests/ground_truth.json; never edit
    that file to force a pass -- fix the engine instead."""
    ground_truth = json.loads(_GROUND_TRUTH_PATH.read_text())
    expected_by_id = {item["id"]: item for item in ground_truth["sessions"]}

    all_passed = True
    sessions = report["sessions"] if isinstance(report, dict) else report.sessions
    for session in sessions:
        session_id = session["id"] if isinstance(session, dict) else session.id
        expected = expected_by_id.get(session_id)
        if expected is None:
            continue
        actual = _session_facts(session)
        expected_facts = {key: expected[key] for key in _FACT_KEYS}
        rule_ids = ({finding["rule_id"] for finding in session["findings"]}
                    if isinstance(session, dict) else {finding.rule_id for finding in session.findings})
        expected_rule_ids = set(expected["expected_rule_ids"])
        observed_risk = session["observed_risk"] if isinstance(session, dict) else session.observed_risk
        band = _risk_band(observed_risk)

        passed = actual == expected_facts and rule_ids == expected_rule_ids and band == expected["risk_band"]
        all_passed = all_passed and passed
        print(f"{session_id}: {'PASS' if passed else 'FAIL'}")
        if not passed:
            if actual != expected_facts:
                print(f"    facts:     expected={expected_facts}")
                print(f"               actual  ={actual}")
            if rule_ids != expected_rule_ids:
                print(f"    rule_ids:  expected={sorted(expected_rule_ids)} actual={sorted(rule_ids)}")
            if band != expected["risk_band"]:
                print(f"    risk_band: expected={expected['risk_band']} actual={band} "
                      f"(observed_risk={observed_risk})")

    hndl_expected = ground_truth["capture"]["hndl_percent_expected"]
    hndl_actual = report["hndl"]["percent"] if isinstance(report, dict) else report.hndl["percent"]
    hndl_passed = hndl_actual == hndl_expected
    all_passed = all_passed and hndl_passed
    print(f"hndl: {'PASS' if hndl_passed else 'FAIL'} (expected={hndl_expected} actual={hndl_actual})")

    return all_passed


def _capture_summary(report: dict) -> str:
    health = report["capture_health"]
    skipped = sum(health["skipped"].values())
    return (f"capture: {health['frames']} frames, {health['candidate_flows']}/"
            f"{health['total_flows']} candidate flows, "
            f"{health['confirmed_mail_sessions']} confirmed mail sessions, "
            f"{skipped} skipped, {health['sessions_incomplete']} incomplete")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sms.cli")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyse = subparsers.add_parser("analyse", aliases=["analyze"])
    analyse.add_argument("pcap")
    analyse.add_argument("--json", dest="json_path")
    analyse.add_argument("--html", dest="html_path")
    analyse.add_argument("--cbom", dest="cbom_path")
    analyse.add_argument("--pdf", dest="pdf_path")
    analyse.add_argument("--self-test", action="store_true")

    ml_flags = analyse.add_mutually_exclusive_group()
    ml_flags.add_argument("--ml", dest="ml", action="store_true")
    ml_flags.add_argument("--no-ml", dest="ml", action="store_false")
    analyse.set_defaults(ml=None)

    validate_anomaly = subparsers.add_parser("validate-anomaly")
    validate_anomaly.add_argument("--captures", required=True)

    args = parser.parse_args(argv)
    if args.command == "validate-anomaly":
        from ml.validate_anomaly import validate_capture_directory

        try:
            metrics = validate_capture_directory(args.captures)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        print(json.dumps(metrics, indent=2, sort_keys=True))
        return 0

    from .m7_anomaly import BASELINE
    report = run_pipeline(args.pcap, ml=BASELINE.exists() if args.ml is None else args.ml)
    canonical_json = json.dumps(report, indent=2, sort_keys=True)

    if args.json_path:
        Path(args.json_path).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_path).write_text(canonical_json)
    if args.html_path:
        Path(args.html_path).write_text(render_html(report))
    if args.cbom_path:
        Path(args.cbom_path).parent.mkdir(parents=True, exist_ok=True)
        Path(args.cbom_path).write_text(
            json.dumps(build_cbom(report), indent=2, sort_keys=True)
        )
    if args.pdf_path:
        Path(args.pdf_path).parent.mkdir(parents=True, exist_ok=True)
        Path(args.pdf_path).write_bytes(render_pdf(report))

    # Preserve canonical JSON on stdout when no output file was requested.
    summary_stream = (sys.stderr if not args.json_path and not args.html_path
                      and not args.cbom_path
                      and not args.pdf_path
                      and not args.self_test else sys.stdout)
    print(_capture_summary(report), file=summary_stream)

    if args.self_test:
        return 0 if run_self_test(report) else 1

    if (not args.json_path and not args.html_path and not args.cbom_path
            and not args.pdf_path):
        print(canonical_json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
