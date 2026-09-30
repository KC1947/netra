"""Offline PDF delivery rendered from the canonical JSON report."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from weasyprint import HTML

from ..m9_report import render_html


_BASE_URL = Path(__file__).resolve().parent.parent


def render_pdf(report: Mapping) -> bytes:
    """Render the canonical report JSON through the existing HTML template."""
    if not isinstance(report, Mapping):
        raise TypeError("PDF export requires the canonical report mapping")
    html = render_html(dict(report))
    return HTML(string=html, base_url=str(_BASE_URL)).write_pdf()
