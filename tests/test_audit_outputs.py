from copy import deepcopy
import datetime
import io
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest
from pypdf import PdfReader

from audit_support import Capture, client_hello, server_hello, with_extensions, wire
from sms.pipeline import run_pipeline
from sms.m9_report import render_html
from sms.delivery.pdf import render_pdf
from sms.delivery.cbom import build_cbom


@pytest.fixture
def inventory_report(tmp_path):
    cap = Capture()
    cap.add("c", client_hello(offered=(0x304,), ciphers=(0x1301,), groups=(0x11ed,)))
    cap.add("s", server_hello(group=0x11ed))
    cap.add("c", client_hello(offered=(0x303,), ciphers=(0xc02f,)), port=40001)
    cap.add("s", server_hello(wire.V_TLS12, 0xc02f, None), port=40001)
    return run_pipeline(cap.write(tmp_path / "two-versions.pcap"), ml=False)


def test_outputs_use_canonical_scores(inventory_report, monkeypatch, tmp_path):
    import sms.m9_report as renderer
    import sms.pipeline as pipeline
    def forbidden(*args, **kwargs):
        raise AssertionError("export called the analysis/scoring pipeline")
    for name in ("score_report", "score_sessions", "compute_hndl", "analyse_sessions"):
        monkeypatch.setattr(renderer, name, forbidden)
    monkeypatch.setattr(pipeline, "run_pipeline", forbidden)
    data = deepcopy(inventory_report)
    data.update(observed_risk=91, evidence_coverage=13, deduced_coverage=29, inferred_coverage=31)
    data["hndl"]["percent"] = 73
    data["capture"]["filename"] = "audit-canonical-source.pcap"
    contexts = []
    rendered_reports = []
    original_render = renderer.jinja2.Template.render
    def spy(template, *args, **kwargs):
        contexts.append(kwargs["overview"])
        rendered_reports.append(deepcopy(kwargs["report"]))
        return original_render(template, *args, **kwargs)
    monkeypatch.setattr(renderer.jinja2.Template, "render", spy)
    before = deepcopy(data)
    html = render_html(data)
    pdf = render_pdf(data)
    text = "\n".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(pdf)).pages)
    cbom = build_cbom(data)
    # Keep one offline export for read-only page rendering during the audit.
    Path("/private/tmp/netra-audit-output.pdf").write_bytes(pdf)
    Path("/private/tmp/netra-audit-output.html").write_text(html)
    labels = {"Observed risk": 91, "Evidence coverage": 13,
              "Deduced coverage": 29, "Inferred coverage": 31}
    for label, value in labels.items():
        assert re.search(re.escape(label) + r"</div>\s*<div class=\"value\">" + str(value), html)
    assert "73%" in html
    assert rendered_reports == [data, data]
    assert data["capture"]["sha256"] in text
    assert "PQ-HYBRID-OBSERVED" in text
    assert data == before
    print("canonical score sentinels appear in HTML and PDF render input: " + json.dumps(labels, sort_keys=True) + "; HNDL=73%")
    print("PDF print CSS hides risk/coverage/HNDL cards; extracted metric labels=" + str([label for label in labels if label.lower() in text.lower()]))
    print("renderer actually computed unused averages/protocol counts: " + json.dumps(contexts[0], sort_keys=True))
    print(f"PDF pages={len(PdfReader(io.BytesIO(pdf)).pages)}; CBOM components={len(cbom['components'])}; source unchanged=True; scorer calls=0")


def test_cbom_preserves_version_cipher_pairs(inventory_report):
    cbom = build_cbom(inventory_report)
    actual = {}
    for component in cbom["components"]:
        props = component["cryptoProperties"]
        if props["assetType"] == "protocol":
            actual[props["protocolProperties"]["version"]] = [s["name"] for s in props["protocolProperties"]["cipherSuites"]]
    pairs = [(s["tls"]["negotiated_version"], s["tls"]["cipher"]) for s in inventory_report["sessions"]]
    print("canonical version/cipher pairs: " + json.dumps(pairs))
    print("CBOM version/cipher pairs: " + json.dumps(actual, sort_keys=True))
    assert actual == {"1.3": ["TLS_AES_128_GCM_SHA256"], "1.2": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]}


def test_cbom_includes_observed_pq_group(inventory_report):
    cbom = build_cbom(inventory_report)
    groups = [s["tls"]["group"] for s in inventory_report["sessions"] if s["tls"]["group"]]
    matrix = inventory_report["servers"][0]["support_matrix"]
    names = [c["name"] for c in cbom["components"]]
    print("observed groups: " + json.dumps(groups))
    print("matrix group keys: " + json.dumps([key for key in matrix if key.startswith("group:")]))
    print("CBOM component names: " + json.dumps(names))
    assert any("MLKEM" in name.upper().replace("-", "") or "ML_KEM" in name.upper() for name in names)


def test_pq_finding_names_actual_group(inventory_report):
    s = inventory_report["sessions"][0]
    finding = next(f for f in s["findings"] if f["rule_id"] == "PQ-HYBRID-OBSERVED")
    print("PQ identity disagreement: " + json.dumps({"canonical_group": s["tls"]["group"],
          "finding_what": finding["what"], "tier": finding["tier"],
          "evidence": finding["evidence"]}, sort_keys=True))
    assert s["tls"]["group"] in finding["what"]


def test_certificate_uses_capture_year_not_wall_clock(tmp_path, monkeypatch):
    import sms.m5_x509 as x509_stage
    class NoWallClock(datetime.datetime):
        @classmethod
        def now(cls, *args, **kwargs):
            raise AssertionError("wall clock consulted")
        @classmethod
        def utcnow(cls):
            raise AssertionError("wall clock consulted")
    monkeypatch.setattr(x509_stage, "datetime", SimpleNamespace(datetime=NoWallClock, timezone=datetime.timezone))
    der = Path("lab/certs/corpus/cert_A.der").read_bytes()
    results = {}
    for year in (2026, 2036):
        stamp = datetime.datetime(year, 9, 1, tzinfo=datetime.timezone.utc).timestamp()
        cap = Capture(stamp).hello(version=wire.V_TLS12, cipher=0xc02f, group=None)
        cap.add("s", wire.certificate(der))
        report = run_pipeline(cap.write(tmp_path / f"cert-{year}.pcap"), ml=False)
        c = report["sessions"][0]["certificate"]
        results[year] = {key: c[key] for key in ("status", "expired", "notBefore", "notAfter")}
    print("certificate by capture year (wall clock forbidden): " + json.dumps(results, sort_keys=True))
    assert results[2026]["status"] == "VALID"
    assert results[2026]["expired"] is False
    assert results[2036]["status"] == "INVALID"
    assert results[2036]["expired"] is True


def test_sibling_certificate_cannot_clear_session_truth(tmp_path):
    from sms.m1_ingest import ingest_pcap
    from sms.m2_protocol import classify_protocols
    from sms.m3_transition import analyse_transition
    from sms.m4_tls import analyse_tls
    from sms.m5_x509 import analyse_certificate
    from sms.m6_rules import apply_rules
    from sms.correlation import correlate_servers
    from sms.m8_score import score_session
    stamp = datetime.datetime(2026, 9, 1, tzinfo=datetime.timezone.utc).timestamp()
    cap = Capture(stamp).hello(version=wire.V_TLS12, cipher=0xc02f, group=None)
    cap.add("s", wire.certificate(Path("lab/certs/corpus/cert_A.der").read_bytes()))
    ch = with_extensions(client_hello(), wire._ext(43, b"\x04\x03\x04\x03\x03") + wire._ext(42, b""))
    cap.add("c", ch, port=40001).add("s", server_hello(), port=40001)
    # Even a plaintext Certificate stuffed after TLS1.3 must not become its certificate.
    cap.add("s", wire.certificate(Path("lab/certs/corpus/cert_B.der").read_bytes()), port=40001)
    path = cap.write(tmp_path / "sibling-certificates.pcap")
    sessions = classify_protocols(ingest_pcap(path))
    for s in sessions:
        analyse_transition(s)
        analyse_tls(s)
        analyse_certificate(s)
        apply_rules(s)
        score_session(s)
    target = sessions[1]
    before = (target.certificate.to_dict(), [f.to_dict() for f in target.findings], target.observed_risk)
    correlate_servers(sessions)
    score_session(target)
    after = (target.certificate.to_dict(), [f.to_dict() for f in target.findings], target.observed_risk)
    print("sibling association: " + json.dumps({"certificate": target.certificate.status,
          "certificate_tier": target.fact_tiers["certificate.status"],
          "reason": target.fact_reason_codes["certificate.status"],
          "source": target.certificate_seen_on_service[0]["source_session"],
          "source_frame": target.certificate_seen_on_service[0]["source_frame"],
          "risk_before_after": [before[2], after[2]],
          "findings": [f.rule_id for f in target.findings]}, sort_keys=True))
    assert target.certificate.status == "NOT_OBSERVABLE"
    assert target.fact_reason_codes["certificate.status"] == "tls13_encrypted_certificate"
    assert before == after
    assert target._cert_der is None
    assert target.certificate_seen_on_service[0]["source_session"] == sessions[0].id
