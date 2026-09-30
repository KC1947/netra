"""Canonical report contracts and private ingest-side data structures.

Only the explicit ``to_dict`` methods in this module define the JSON contract.
The byte streams used while analysing a capture are deliberately excluded: they
can contain mail traffic and must never reach a report, log, or repr.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping, Sequence


NOT_OBSERVABLE_REASON_CODES = frozenset({
    "tls13_encrypted_certificate",
    "midstream_capture",
    "ech_enabled",
    "not_present_in_capture",
    "unsupported_link_type",
    "malformed_certificate",
    "unsupported_algorithm",
})


@dataclass(frozen=True)
class Evidence:
    """A precise, zero-based location in a captured frame."""

    frame: int
    field: str
    byte_offset: int
    byte_length: int
    display: str = "redacted"

    def to_dict(self) -> dict[str, Any]:
        return {
            "frame": self.frame,
            "field": self.field,
            "byte_offset": self.byte_offset,
            "byte_length": self.byte_length,
            "display": self.display,
        }


@dataclass
class Finding:
    rule_id: str
    confidence_band: str
    severity: str
    confidence: float
    what: str
    why: str
    fix: str
    remediation_id: str
    remediation_effort: str
    tier: str | None = None
    affected_sessions: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "tier": self.tier,
            "confidence_band": self.confidence_band,
            "severity": self.severity,
            "confidence": self.confidence,
            "what": self.what,
            "why": self.why,
            "fix": self.fix,
            "remediation_id": self.remediation_id,
            "remediation_effort": self.remediation_effort,
            "affected_sessions": list(self.affected_sessions),
            "evidence": [item.to_dict() for item in self.evidence],
            "references": list(self.references),
        }


@dataclass
class TransitionInfo:
    verdict: str | None = None
    confidence_band: str | None = None
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence_band": self.confidence_band,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass
class TlsInfo:
    offered_version: str | None = None
    offered_ciphers: list[int] = field(default_factory=list)
    offered_versions: list[int] = field(default_factory=list)
    offered_groups: list[int] = field(default_factory=list)
    negotiated_version: str | None = None
    downgrade_delta: int | None = None
    cipher: str | None = None
    forward_secrecy: bool | None = None
    forward_secrecy_status: str = "UNKNOWN"
    group: str | None = None
    group_class: str = "NOT_OBSERVABLE"
    hybrid_pq_flag: bool = False
    has_fallback_scsv: bool = False
    downgrade_sentinel: str | None = None
    psk_selected: bool = False
    is_hello_retry_request: bool = False
    client_hello_frame: int | None = None
    server_hello_frame: int | None = None
    ocsp_stapling: str = "not_observable"
    status_request_sent: bool = False
    psk_offered: bool = False
    ech_offered: bool = False
    early_data_offered: bool = False
    downgrade_anomaly: bool = False
    downgrade_legacy_client: bool = False
    cert_visibility: str = "NOT_OBSERVABLE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "offered_version": self.offered_version,
            "offered_ciphers": list(self.offered_ciphers),
            "offered_versions": list(self.offered_versions),
            "offered_groups": list(self.offered_groups),
            "negotiated_version": self.negotiated_version,
            "downgrade_delta": self.downgrade_delta,
            "cipher": self.cipher,
            "forward_secrecy": self.forward_secrecy,
            "forward_secrecy_status": self.forward_secrecy_status,
            "group": self.group,
            "group_class": self.group_class,
            "hybrid_pq_flag": self.hybrid_pq_flag,
            "has_fallback_scsv": self.has_fallback_scsv,
            "downgrade_sentinel": self.downgrade_sentinel,
            "psk_selected": self.psk_selected,
            "is_hello_retry_request": self.is_hello_retry_request,
            "client_hello_frame": self.client_hello_frame,
            "server_hello_frame": self.server_hello_frame,
            "ocsp_stapling": self.ocsp_stapling,
            "status_request_sent": self.status_request_sent,
            "psk_offered": self.psk_offered,
            "ech_offered": self.ech_offered,
            "early_data_offered": self.early_data_offered,
            "downgrade_anomaly": self.downgrade_anomaly,
            "downgrade_legacy_client": self.downgrade_legacy_client,
            "cert_visibility": self.cert_visibility,
        }

    def signal_facts(self) -> dict[str, bool | str]:
        """The nine passive signal facts, with tri-state FS kept explicit."""
        return {
            "has_fallback_scsv": self.has_fallback_scsv,
            "status_request_sent": self.status_request_sent,
            "psk_offered": self.psk_offered,
            "ocsp_stapling": self.ocsp_stapling,
            "ech_offered": self.ech_offered,
            "early_data_offered": self.early_data_offered,
            "forward_secrecy": self.forward_secrecy_status,
            "downgrade_anomaly": self.downgrade_anomaly,
            "downgrade_legacy_client": self.downgrade_legacy_client,
        }


@dataclass
class CertInfo:
    status: str = "INDETERMINATE"
    reason: str | None = None
    # Parsed from SubjectPublicKeyInfo via cryptography's public-key object.
    # These analysis facts are intentionally kept out of the frozen v1 JSON
    # contract until its frontend counterpart is versioned.
    key_type: str | None = None
    curve: str | None = None
    key_bits: int | None = None
    key_strength: str = "NOT_OBSERVABLE"
    sig_alg: str | None = None
    self_signed: bool | None = None
    expired: bool | None = None
    notBefore: str | None = None
    notAfter: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "key_bits": self.key_bits,
            "sig_alg": self.sig_alg,
            "self_signed": self.self_signed,
            "expired": self.expired,
            "notBefore": self.notBefore,
            "notAfter": self.notAfter,
        }


@dataclass(frozen=True, repr=False)
class ByteSlice:
    """Provenance for a contiguous part of a reassembled stream."""

    stream_offset: int
    byte_length: int
    frame: int
    packet_byte_offset: int

    def evidence(self, field: str, display: str = "redacted") -> Evidence:
        return Evidence(self.frame, field, self.packet_byte_offset, self.byte_length, display)


@dataclass(frozen=True, repr=False)
class StreamGap:
    """A missing TCP sequence range.  It is never represented as joined bytes."""

    stream_offset: int
    byte_length: int
    sequence_start: int
    sequence_end: int


@dataclass(frozen=True, repr=False)
class PacketObservation:
    frame_no: int
    direction: str
    ts: float
    sequence: int
    payload: bytes
    payload_packet_offset: int


@dataclass(repr=False)
class ByteStream:
    """TCP data with byte-to-frame provenance and explicit missing ranges."""

    _chunks: list[bytes] = field(default_factory=list)
    _slices: list[ByteSlice] = field(default_factory=list)
    gaps: list[StreamGap] = field(default_factory=list)
    # Stream offsets captured with more than one value: which copy the
    # endpoint accepted is unknown, so their content is not established.
    disputed: tuple[int, ...] = ()

    @property
    def has_gaps(self) -> bool:
        return bool(self.gaps)

    @property
    def length(self) -> int:
        return sum(len(chunk) for chunk in self._chunks)

    def contiguous_bytes(self) -> bytes:
        """Return all bytes only when the TCP stream has no missing sequence range."""
        if self.has_gaps:
            raise ValueError("TCP stream has gaps; use iter_spans() and inspect gaps")
        return b"".join(self._chunks)

    def iter_spans(self) -> Iterator[tuple[bytes, Sequence[ByteSlice]]]:
        """Yield captured contiguous data segments without bridging a stream gap."""
        if not self.gaps:
            yield b"".join(self._chunks), tuple(self._slices)
            return
        # Gaps use stream offsets including omitted bytes.  Split chunks around them.
        stream_offset = 0
        next_gap = iter(self.gaps)
        gap = next(next_gap, None)
        span_chunks: list[bytes] = []
        span_slices: list[ByteSlice] = []
        for chunk, source in zip(self._chunks, self._slices):
            if gap is not None and stream_offset >= gap.stream_offset:
                if span_chunks:
                    yield b"".join(span_chunks), tuple(span_slices)
                    span_chunks, span_slices = [], []
                stream_offset += gap.byte_length
                gap = next(next_gap, None)
            span_chunks.append(chunk)
            span_slices.append(source)
            stream_offset += len(chunk)
        if span_chunks:
            yield b"".join(span_chunks), tuple(span_slices)

    def provenance_for(self, start: int, length: int) -> list[ByteSlice]:
        """Return source slices for a captured stream range; reject ranges over gaps."""
        if start < 0 or length < 0:
            raise ValueError("stream range must be non-negative")
        end = start + length
        result: list[ByteSlice] = []
        for source in self._slices:
            source_end = source.stream_offset + source.byte_length
            left, right = max(start, source.stream_offset), min(end, source_end)
            if left < right:
                result.append(ByteSlice(
                    left, right - left, source.frame,
                    source.packet_byte_offset + (left - source.stream_offset),
                ))
        if sum(item.byte_length for item in result) != length:
            raise ValueError("requested range contains uncaptured TCP bytes")
        return result


@dataclass
class Session:
    id: str
    five_tuple: Mapping[str, Any]
    # Wireshark's ``tcp.stream`` for this flow, counted by M1 over EVERY TCP
    # flow in the capture. It is not this session's position in the report:
    # triage drops non-mail flows, so the two diverge on any mixed capture and
    # a display filter built from the wrong one resolves to nothing.
    tcp_stream: int | None = None
    protocol: str = "unknown"
    protocol_confidence: str = "unknown"
    # Analysis-only classification rationale.  It must remain static text: do
    # not retain raw banners, commands, credentials, or message content here.
    protocol_reason: str = field(default="unrecognized protocol grammar", repr=False)
    packets: Mapping[str, int | None] = field(default_factory=lambda: {"first": None, "last": None})
    transition: TransitionInfo = field(default_factory=TransitionInfo)
    tls: TlsInfo = field(default_factory=TlsInfo)
    certificate: CertInfo = field(default_factory=CertInfo)
    observed_risk: int = 0
    evidence_coverage: int = 0
    deduced_coverage: int = 0
    inferred_coverage: int = 0
    findings: list[Finding] = field(default_factory=list)
    fact_tiers: dict[str, str] = field(default_factory=lambda: {
        "protocol": "NOT_OBSERVABLE",
        "transition.verdict": "NOT_OBSERVABLE",
        "tls.negotiated_version": "NOT_OBSERVABLE",
        "tls.forward_secrecy": "NOT_OBSERVABLE",
        "tls.cipher": "NOT_OBSERVABLE",
        "tls.group": "NOT_OBSERVABLE",
        "tls.hybrid_pq_flag": "NOT_OBSERVABLE",
        "tls.ech_identity": "NOT_OBSERVABLE",
        "certificate.status": "NOT_OBSERVABLE",
        "certificate.key_strength": "NOT_OBSERVABLE",
    })
    fact_reason_codes: dict[str, str] = field(default_factory=lambda: {
        "protocol": "not_present_in_capture",
        "transition.verdict": "not_present_in_capture",
        "tls.negotiated_version": "not_present_in_capture",
        "tls.forward_secrecy": "not_present_in_capture",
        "tls.cipher": "not_present_in_capture",
        "tls.group": "not_present_in_capture",
        "tls.hybrid_pq_flag": "not_present_in_capture",
        "tls.ech_identity": "not_present_in_capture",
        "certificate.status": "not_present_in_capture",
        "certificate.key_strength": "not_present_in_capture",
    })
    certificate_seen_on_service: list[Mapping[str, Any]] = field(default_factory=list)
    certificate_ambiguous: bool = False
    ml: dict | None = None
    # Reassembly diagnostics are serialized only for incomplete sessions so a
    # clean capture retains the stable v1 report shape. Conflict records carry
    # sequence offsets and frame numbers, never captured payload bytes.
    incomplete: bool = False
    holes: int = 0
    conflicts: list[Mapping[str, Any]] = field(default_factory=list)
    # Analysis-only fields: intentionally omitted from repr and serialization.
    client_to_server: ByteStream = field(default_factory=ByteStream, repr=False)
    server_to_client: ByteStream = field(default_factory=ByteStream, repr=False)
    packet_observations: list[PacketObservation] = field(default_factory=list, repr=False)
    midstream: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        if self.midstream:
            for fact in self.fact_reason_codes:
                self.fact_reason_codes[fact] = "midstream_capture"

    def to_dict(self) -> dict[str, Any]:
        for fact, reason in self.fact_reason_codes.items():
            if reason not in NOT_OBSERVABLE_REASON_CODES:
                raise ValueError(
                    f"fact {fact!r} has reason code outside the closed vocabulary"
                )
        reasons = {}
        for fact, tier in self.fact_tiers.items():
            if tier != "NOT_OBSERVABLE":
                continue
            reason = self.fact_reason_codes.get(fact)
            if reason not in NOT_OBSERVABLE_REASON_CODES:
                raise ValueError(f"NOT_OBSERVABLE fact {fact!r} requires a reason code")
            reasons[fact] = reason
        result = {
            "id": self.id,
            "ml": self.ml,
            "five_tuple": dict(self.five_tuple),
            "tcp_stream": self.tcp_stream,
            "protocol": self.protocol,
            "protocol_confidence": self.protocol_confidence,
            "packets": dict(self.packets),
            "transition": self.transition.to_dict(),
            "tls": self.tls.to_dict(),
            "certificate": self.certificate.to_dict(),
            "observed_risk": self.observed_risk,
            "evidence_coverage": self.evidence_coverage,
            "deduced_coverage": self.deduced_coverage,
            "inferred_coverage": self.inferred_coverage,
            "fact_tiers": dict(self.fact_tiers),
            "fact_reason_codes": reasons,
            "findings": [item.to_dict() for item in self.findings],
        }
        if self.incomplete:
            result.update({
                "incomplete": True,
                "holes": self.holes,
                "conflicts": [dict(item) for item in self.conflicts],
            })
        if self.certificate_seen_on_service:
            result.update({
                "certificate_seen_on_service": [
                    dict(item) for item in self.certificate_seen_on_service
                ],
                "certificate_ambiguous": self.certificate_ambiguous,
            })
        return result


@dataclass
class Report:
    ml_summary: Mapping[str, Any] = field(default_factory=lambda: {"enabled": False}, kw_only=True)
    capture: Mapping[str, Any]
    capture_health: Mapping[str, Any]
    registry_version: str
    observed_risk: int = 0
    evidence_coverage: int = 0
    deduced_coverage: int = 0
    inferred_coverage: int = 0
    hndl: Mapping[str, Any] = field(default_factory=lambda: {
        "exposed_sessions": 0, "quantum_safe_sessions": 0,
        "total_sessions": 0, "unobservable_sessions": 0,
        "unobservable_sessions_excluded": 0, "percent": 0,
    })
    summary: Mapping[str, Any] = field(default_factory=lambda: {
        "sessions_total": 0, "encrypted": 0, "cleartext": 0, "not_observable": 0,
        "findings_by_severity": {},
    })
    sessions: list[Session] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    servers: list[Mapping[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "capture": dict(self.capture),
            "capture_health": dict(self.capture_health),
            "registry_version": self.registry_version,
            "observed_risk": self.observed_risk,
            "evidence_coverage": self.evidence_coverage,
            "deduced_coverage": self.deduced_coverage,
            "inferred_coverage": self.inferred_coverage,
            "ml_summary": dict(self.ml_summary),
            "hndl": dict(self.hndl),
            "summary": dict(self.summary),
            "sessions": [item.to_dict() for item in self.sessions],
            "findings": [item.to_dict() for item in self.findings],
            "servers": [dict(item) for item in self.servers],
        }
