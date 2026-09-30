"""Assemble the canonical Report and render the offline HTML demo page.

Canonical JSON (``Report.to_dict()``) is the source of truth; the HTML is a
pure rendering of it -- no finding, score, or fact is computed here.
"""

from __future__ import annotations

import datetime
import hashlib
from pathlib import Path

import jinja2

from .contracts import Report, Session
from .correlation import correlate_servers
from .m1_ingest import IngestStats, MAIL_SERVER_PORTS, ingest_pcap, ingest_pcap_with_stats
from .m2_protocol import classify_protocols
from .m3_transition import analyse_transition
from .m4_tls import analyse_tls
from .m5_x509 import analyse_certificate
from .m6_rules import apply_rules, apply_server_rules
from .m8_score import compute_hndl, is_cleartext, is_encrypted, score_report, score_sessions
from .registry import load as load_registry

_EFFORT_ORDER = {"one_line_reload": 0, "cert_reissue": 1, "software_upgrade": 2}
_TEMPLATE_PATH = Path(__file__).resolve().parent / "report_template.html"


def _iso(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()


def _prepare_sessions(sessions: list[Session],
                      ingest_stats: IngestStats | None = None) -> tuple[list[Session], list[dict]]:
    """Run m2-m6, P3 and m8 over sessions already produced by M1."""
    sessions = classify_protocols(sessions)
    if ingest_stats is not None:
        ingest_stats.confirmed_mail_sessions = sum(
            session.protocol != "unknown" for session in sessions
        )
    # Ignore non-mail conversations, while retaining traffic on a mail port
    # that is genuinely indeterminate (for example, a capture beginning in the
    # middle of an encrypted exchange). Ports are only a retention hint; the
    # protocol field is still grammar-derived and may remain "unknown".
    sessions = [session for session in sessions if session.protocol != "unknown" or
                int(session.five_tuple["server_port"]) in MAIL_SERVER_PORTS]
    for session in sessions:
        analyse_transition(session)
        analyse_tls(session)
        analyse_certificate(session)
        apply_rules(session)
    servers = correlate_servers(sessions)
    apply_server_rules(sessions, servers)
    return score_sessions(sessions), servers


def _analyse_sessions(sessions: list[Session]) -> list[Session]:
    """Compatibility helper returning analysed sessions without report blocks."""
    return _prepare_sessions(sessions)[0]


def analyse_sessions(pcap_path: str | Path) -> list[Session]:
    """Run the full passive pipeline (m1-m6, m8) over one PCAP."""
    return _analyse_sessions(ingest_pcap(pcap_path))


def make_report(pcap_path: str | Path, sessions: list[Session], ml_summary: dict,
                ingest_stats: IngestStats, servers: list[dict] | None = None) -> Report:
    """Turn fully analysed sessions into the canonical report without analysis."""
    path = Path(pcap_path)
    all_ts = [item.ts for session in sessions for item in session.packet_observations]
    capture = {
        "filename": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "packets": sum(len(session.packet_observations) for session in sessions),
        "first_ts": _iso(min(all_ts)) if all_ts else None,
        "last_ts": _iso(max(all_ts)) if all_ts else None,
    }

    findings = [finding for session in sessions for finding in session.findings]
    findings_by_severity: dict[str, int] = {}
    for finding in findings:
        findings_by_severity[finding.severity] = findings_by_severity.get(finding.severity, 0) + 1
    # Three disjoint counts. A session that is neither established TLS nor
    # established cleartext (an incomplete handshake, mid-stream traffic) is
    # NOT_OBSERVABLE; counting it as cleartext claims an exposure nobody saw.
    encrypted = sum(1 for session in sessions if is_encrypted(session))
    cleartext = sum(1 for session in sessions if is_cleartext(session))
    capture_health = ingest_stats.as_dict()
    summary = {
        "sessions_total": len(sessions),
        "encrypted": encrypted,
        "cleartext": cleartext,
        "not_observable": len(sessions) - encrypted - cleartext,
        "findings_by_severity": findings_by_severity,
        "findings_assessed": capture_health["analysis_status"] not in {
            "unsupported", "unreadable",
        },
    }
    capture_scores = score_report(sessions)

    return Report(capture=capture, capture_health=capture_health,
                   registry_version=load_registry().version,
                   **capture_scores,
                   hndl=compute_hndl(sessions), summary=summary,
                   sessions=sessions, findings=findings, ml_summary=ml_summary,
                   servers=servers or [])


def build_report(pcap_path: str | Path, ml: bool = False) -> Report:
    """Compatibility API for library callers. CLI and server use run_pipeline."""
    sessions, ingest_stats = ingest_pcap_with_stats(pcap_path)
    sessions, servers = _prepare_sessions(sessions, ingest_stats)
    from .m7_anomaly import apply_anomalies
    return make_report(
        pcap_path, sessions, apply_anomalies(sessions, enabled=ml, capture_path=pcap_path), ingest_stats,
        servers,
    )


def render_html(report: Report | dict) -> str:
    """One self-contained offline HTML page: inline CSS, no CDN, no script deps."""
    data = report.to_dict() if isinstance(report, Report) else report
    sessions = data["sessions"]

    protocol_counts: dict[str, int] = {}
    for session in sessions:
        protocol_counts[session["protocol"]] = protocol_counts.get(session["protocol"], 0) + 1
    overview = {
        "avg_observed_risk": round(sum(s["observed_risk"] for s in sessions) / len(sessions)) if sessions else 0,
        "avg_evidence_coverage": round(sum(s["evidence_coverage"] for s in sessions) / len(sessions)) if sessions else 0,
        "avg_deduced_coverage": round(sum(s["deduced_coverage"] for s in sessions) / len(sessions)) if sessions else 0,
        "avg_inferred_coverage": round(sum(s["inferred_coverage"] for s in sessions) / len(sessions)) if sessions else 0,
        "protocol_counts": protocol_counts,
    }
    findings = data["findings"]
    findings_by_effort = sorted(
        (item.to_dict() if hasattr(item, "to_dict") else item for item in findings),
        key=lambda item: _EFFORT_ORDER.get(item["remediation_effort"], 99),
    )

    env = jinja2.Environment(autoescape=True)
    template = env.from_string(_TEMPLATE_PATH.read_text())
    return template.render(
        report=data, overview=overview,
        findings_by_effort=findings_by_effort,
    )
