"""The sole execution path used by the command line and web service."""

from __future__ import annotations

from pathlib import Path
import time
from typing import Callable

from .m1_ingest import MAIL_SERVER_PORTS, ingest_pcap_with_stats
from .m2_protocol import classify_protocols
from .m3_transition import analyse_transition
from .m4_tls import analyse_tls
from .m5_x509 import analyse_certificate
from .m6_rules import apply_rules, apply_server_rules
from .correlation import correlate_servers
from .m7_anomaly import apply_anomalies
from .m8_score import score_sessions
from .m9_report import make_report

StageCallback = Callable[[dict], None]

_STAGES = (
    ("M1", "Ingest & TCP reassembly"),
    ("M2", "Protocol identification"),
    ("M3", "STARTTLS state machine"),
    ("M4", "TLS handshake analysis"),
    ("M5", "X.509 certificate checks"),
    ("M6", "Rule engine"),
    ("P3", "Server correlation"),
    ("M7", "AI anomaly layer"),
    ("M8", "Scoring & HNDL"),
    ("M9", "Report"),
)


def run_pipeline(pcap_path: str | Path, ml: bool = True, on_stage: StageCallback | None = None) -> dict:
    """Analyse one capture offline and return canonical report JSON.

    Events bracket real module calls; they are deliberately not progress timers.
    Their timings are diagnostic transport metadata and are never report data.
    """
    started = time.perf_counter()

    def event(stage: str, status: str, detail: str = "") -> None:
        if on_stage is not None:
            label = dict(_STAGES).get(stage)
            payload = {"stage": stage, "status": status, "detail": detail,
                       "t_ms": round((time.perf_counter() - started) * 1000)}
            if label is not None:
                payload["label"] = label
            on_stage(payload)

    event("M1", "start")
    sessions, ingest_stats = ingest_pcap_with_stats(pcap_path)
    # Ingest timing and memory are diagnostic transport metadata, exactly like
    # every other t_ms on this stream, and never report data.
    event(
        "M1", "done",
        f"{ingest_stats.candidate_flows}/{ingest_stats.total_flows} candidate flows"
        f" in {ingest_stats.elapsed_time_ms:.0f} ms,"
        f" {ingest_stats.peak_memory_bytes / 1_048_576:.1f} MiB traced peak",
    )

    event("M2", "start")
    sessions = classify_protocols(sessions)
    ingest_stats.confirmed_mail_sessions = sum(
        session.protocol != "unknown" for session in sessions
    )
    sessions = [session for session in sessions if session.protocol != "unknown" or
                int(session.five_tuple["server_port"]) in MAIL_SERVER_PORTS]
    event("M2", "done", f"{len(sessions)} mail sessions or indeterminate mail-port sessions")

    event("M3", "start")
    for session in sessions:
        analyse_transition(session)
    event("M3", "done", f"{len(sessions)} transitions analysed")

    event("M4", "start")
    for session in sessions:
        analyse_tls(session)
    event("M4", "done", f"{sum(s.tls.negotiated_version is not None for s in sessions)} TLS handshakes observed")

    event("M5", "start")
    for session in sessions:
        analyse_certificate(session)
    event("M5", "done", f"{sum(s.certificate.status in {'VALID', 'INVALID'} for s in sessions)} certificates checked")

    event("M6", "start")
    for session in sessions:
        apply_rules(session)
    event("M6", "done", f"{sum(len(s.findings) for s in sessions)} rule findings")

    event("P3", "start")
    servers = correlate_servers(sessions)
    apply_server_rules(sessions, servers)
    event("P3", "done", f"{len(servers)} server identities correlated")

    event("M7", "start")
    ml_summary = apply_anomalies(sessions, enabled=ml, capture_path=pcap_path)
    if ml:
        event("M7", "done", f"{ml_summary.get('anomalies', 0)} unusual sessions")
    else:
        event("M7", "skipped", "ML disabled")

    event("M8", "start")
    score_sessions(sessions)
    event("M8", "done", f"{len(sessions)} scores; HNDL computed")

    event("M9", "start")
    report = make_report(
        pcap_path, sessions, ml_summary, ingest_stats, servers,
    ).to_dict()
    event("M9", "done", f"{len(sessions)} sessions, {len(report['findings'])} findings")
    return report
