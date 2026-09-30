"""Loopback-only API service. Analyses remain local and fully passive."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
import hashlib
import json
from pathlib import Path
from queue import Empty, Queue
import threading
import time
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from lab.build_demo_library import LIBRARY, build_library, packet_count
from sms.delivery.cbom import build_cbom
from sms.delivery.pdf import render_pdf
from sms.m1_ingest import open_reader
from sms.m7_anomaly import BASELINE
from sms.m9_report import render_html
from sms.packet_view import CaptureChanged, packet_view
from sms.pipeline import run_pipeline

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = LIBRARY / "manifest.json"
# The API serves the current 25-session enterprise fixture. The same-named
# demo_captures file is a distinct six-session fixture required by library tests.
ENTERPRISE_CAPTURE = ROOT / "tests" / "fixtures" / "mixed_enterprise.pcap"
UNSUPPORTED_CAPTURE = ROOT / "tests" / "fixtures" / "unsupported_linktype_258.pcapng"
RECORDED_CAPTURE = ROOT / "tests" / "fixtures" / "real_mail.pcap"
UPLOADS = LIBRARY / "uploads"
MAX_UPLOAD_BYTES = 200 * 1024 * 1024
PCAP_SIGNATURES = frozenset({
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a",
})

app = FastAPI(title="SecureMailScope", version="0.2")
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(?::\d+)?$",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@dataclass
class _Analysis:
    analysis_id: str
    capture: dict
    ml: bool
    events: Queue = field(default_factory=Queue)
    report: dict | None = None
    error: str | None = None
    complete: bool = False
    last_t_ms: int = 0


_analyses: dict[str, _Analysis] = {}
_uploaded: dict[str, dict] = {}
_lock = threading.Lock()
_sequence = 0


def _error(status_code: int, message: str):
    return JSONResponse(status_code=status_code, content={"error": message})


def _ensure_library() -> None:
    if not MANIFEST.exists():
        build_library()


def _capture_record_count(path: Path) -> int:
    with path.open("rb") as capture:
        return sum(1 for _ in open_reader(capture))


def _captures() -> list[dict]:
    _ensure_library()
    captures = json.loads(MANIFEST.read_text())
    captures = [
        ({**capture, "category": "enterprise"}
         if capture.get("id") == "mixed_enterprise" else capture)
        for capture in captures
    ]
    if UNSUPPORTED_CAPTURE.exists():
        captures.append({
            "id": "pktap_unsupported",
            "file": UNSUPPORTED_CAPTURE.name,
            "title": "Unsupported capture",
            "description": (
                "Unsupported link type 258; capture health is reported "
                "without assessing findings."
            ),
            "source": "fixture",
            "expected": ["unsupported link type is reported"],
            "sha256": hashlib.sha256(UNSUPPORTED_CAPTURE.read_bytes()).hexdigest(),
            "size_bytes": UNSUPPORTED_CAPTURE.stat().st_size,
            "packets": _capture_record_count(UNSUPPORTED_CAPTURE),
        })
    return [_measured_capture(capture) for capture in
            captures + [item["capture"] for _, item in sorted(_uploaded.items())]]


@lru_cache(maxsize=128)
def _capture_measurements(path: Path, modified_ns: int, size: int) -> dict:
    """Registry counts come from the same passive pipeline, cached per file revision."""
    report = run_pipeline(path, ml=False)
    return {
        "frames": report["capture_health"]["frames"],
        "sessions": report["summary"]["sessions_total"],
        "analysis_status": report["capture_health"]["analysis_status"],
    }


def _measured_capture(capture: dict) -> dict:
    path = _capture_path(capture)
    stat = path.stat()
    measured = _capture_measurements(path, stat.st_mtime_ns, stat.st_size)
    category = capture.get("category") or (
        "unsupported" if measured["analysis_status"] in {"unsupported", "unreadable"}
        else "constructed" if capture["source"] in {"synthetic", "fixture"}
        else "recorded"
    )
    return {**capture, **measured, "category": category,
            "packets": measured["frames"], "size_bytes": stat.st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def _capture_path(capture: dict) -> Path:
    if capture["source"] == "uploaded":
        return _uploaded[capture["id"]]["path"]
    if capture["id"] == "mixed_enterprise":
        return ENTERPRISE_CAPTURE
    if capture["id"] == "pktap_unsupported":
        return UNSUPPORTED_CAPTURE
    if capture["id"] == "real_mail":
        return RECORDED_CAPTURE
    return LIBRARY / capture["file"]


def _analysis(analysis_id: str) -> _Analysis:
    try:
        return _analyses[analysis_id]
    except KeyError as error:
        raise HTTPException(status_code=404, detail="analysis not found") from error


def _run(analysis: _Analysis) -> None:
    try:
        def stage(event: dict) -> None:
            analysis.last_t_ms = event["t_ms"]
            analysis.events.put(event)

        analysis.report = run_pipeline(_capture_path(analysis.capture), ml=analysis.ml, on_stage=stage)
        # The upload store uses a digest-based filename, but the canonical
        # report must retain the capture filename presented through the API.
        analysis.report["capture"]["filename"] = analysis.capture["file"]
        analysis.complete = True
        analysis.events.put({
            "stage": "DONE", "status": "done", "analysis_id": analysis.analysis_id,
            "t_ms": analysis.last_t_ms,
        })
    except Exception:
        # Never put parser data or capture content into an API error response.
        analysis.error = "analysis failed"
        analysis.complete = True
        analysis.events.put({"stage": "ERROR", "status": "error", "message": analysis.error})


@app.get("/api/health")
def health():
    return {"status": "ok", "engine": "securemailscope", "version": "0.2", "ml_available": BASELINE.exists()}


@app.get("/api/captures")
def captures():
    return _captures()


@app.post("/api/captures/upload")
async def upload_capture(file: UploadFile = File(...)):
    UPLOADS.mkdir(parents=True, exist_ok=True)
    first = await file.read(4)
    if first not in PCAP_SIGNATURES:
        return _error(400, "file is not a pcap or pcapng capture")
    digest = hashlib.sha256()
    digest.update(first)
    content = bytearray(first)
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        content.extend(chunk)
        digest.update(chunk)
        if len(content) > MAX_UPLOAD_BYTES:
            return _error(400, "capture exceeds 200 MB")
    capture_id = f"upload_{digest.hexdigest()[:12]}"
    suffix = ".pcapng" if first == b"\x0a\x0d\x0d\x0a" else ".pcap"
    target = UPLOADS / f"{capture_id}{suffix}"
    try:
        target.write_bytes(bytes(content))
        packets = packet_count(target)
    except Exception:
        # A known magic number is not sufficient proof that Scapy can decode
        # the capture.  Avoid retaining an unreadable user upload.
        target.unlink(missing_ok=True)
        return _error(400, "file is not a readable pcap or pcapng capture")
    capture = {
        "id": capture_id,
        "file": Path(file.filename or target.name).name,
        "title": f"Uploaded capture {capture_id}",
        "description": "User-uploaded capture; conclusions depend on observable packets.",
        "source": "uploaded", "expected": [], "sha256": digest.hexdigest(),
        "size_bytes": len(content), "packets": packets,
    }
    _uploaded[capture_id] = {"capture": capture, "path": target}
    return _measured_capture(capture)


@app.post("/api/analyses")
def start_analysis(payload: dict):
    capture_id = payload.get("capture_id")
    ml = payload.get("ml", True)
    if not isinstance(capture_id, str) or not isinstance(ml, bool):
        return _error(400, "capture_id must be a string and ml must be a boolean")
    capture = next((item for item in _captures() if item["id"] == capture_id), None)
    if capture is None:
        return _error(404, "capture not found")
    global _sequence
    with _lock:
        _sequence += 1
        analysis_id = f"a_{_sequence:06d}"
        analysis = _Analysis(analysis_id, capture, ml)
        _analyses[analysis_id] = analysis
    threading.Thread(target=_run, args=(analysis,), daemon=True).start()
    return {"analysis_id": analysis_id}


@app.get("/api/analyses/{analysis_id}/events")
def events(analysis_id: str):
    analysis = _analysis(analysis_id)

    def stream():
        while True:
            try:
                event = analysis.events.get(timeout=0.25)
            except Empty:
                if analysis.complete:
                    return
                continue
            yield f"data: {json.dumps(event, sort_keys=True, separators=(',', ':'))}\n\n"
            if event["stage"] in {"DONE", "ERROR"}:
                return

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.get("/api/analyses/{analysis_id}/report")
def report(analysis_id: str):
    analysis = _analysis(analysis_id)
    if not analysis.complete:
        return _error(409, "analysis is still running")
    if analysis.error:
        return _error(500, analysis.error)
    return analysis.report


@app.get("/api/analyses/{analysis_id}/sessions/{session_id}/packets")
def packets(analysis_id: str, session_id: str):
    analysis = _analysis(analysis_id)
    if not analysis.complete:
        return _error(409, "analysis is still running")
    if analysis.error:
        return _error(500, analysis.error)
    try:
        return packet_view(_capture_path(analysis.capture), analysis.report, session_id)
    except CaptureChanged as changed:
        # A mismatched capture cannot substantiate the report's frame references (409).
        return _error(409, str(changed))
    except KeyError:
        return _error(404, "session not found")


@app.get("/api/analyses/{analysis_id}/export")
def export(analysis_id: str, format: str = "json"):
    analysis = _analysis(analysis_id)
    if not analysis.complete:
        return _error(409, "analysis is still running")
    if analysis.error:
        return _error(500, analysis.error)
    if format == "json":
        return JSONResponse(
            analysis.report,
            headers={"Content-Disposition": f'attachment; filename="{analysis_id}.json"'},
        )
    if format == "html":
        return HTMLResponse(
            render_html(analysis.report),
            headers={"Content-Disposition": f'attachment; filename="{analysis_id}.html"'},
        )
    if format == "cbom":
        return JSONResponse(
            build_cbom(analysis.report),
            headers={
                "Content-Disposition":
                    f'attachment; filename="{analysis_id}.cdx.json"'
            },
        )
    if format == "pdf":
        return Response(
            content=render_pdf(analysis.report),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{analysis_id}.pdf"'
            },
        )
    return _error(400, "format must be json, html, cbom or pdf")


WEB = ROOT / "web"
if WEB.exists():
    app.mount("/", StaticFiles(directory=WEB, html=True), name="web")
else:
    @app.get("/", response_class=HTMLResponse)
    def index():
        return "<h1>SecureMailScope</h1><p>/api/health · /api/captures · /api/analyses</p>"


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("server.app:app", host="127.0.0.1", port=8000)
