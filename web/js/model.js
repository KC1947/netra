/**
 * model.js — the ONLY place that reads report.json field names.
 * Maps API snake_case fields to camelCase view models.
 * Missing fields use defensive fallbacks.
 */

const DASH = '—';

// ── helpers ──────────────────────────────────────────────────────────────
function str(v, fallback) { return v != null && v !== '' ? String(v) : (fallback ?? DASH); }
function num(v, fallback) { return typeof v === 'number' ? v : (fallback ?? 0); }
function nullableNum(v) { return typeof v === 'number' ? v : null; }
function arr(v) { return Array.isArray(v) ? v : []; }
function bool(v) { return !!v; }
function object(v) { return v && typeof v === 'object' && !Array.isArray(v) ? v : {}; }

// ── severity / cert colours ──────────────────────────────────────────────
const SEV_COLORS = {
  critical: '#E05648',
  high:     '#F08A3C',
  medium:   '#E8B33A',
  low:      '#02C39A',
  info:     '#6C8EBF'
};
const CERT_COLORS = {
  VALID:          '#02C39A',
  INVALID:        '#E05648',
  INDETERMINATE:  '#E8B33A',
  NOT_OBSERVABLE: '#8FA3B8'
};
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const EFFORT_ORDER = ['one_line_reload', 'cert_reissue', 'software_upgrade'];

export function severityColor(sev) { return SEV_COLORS[(sev || '').toLowerCase()] || '#6C8EBF'; }
export function certStatusColor(st) { return CERT_COLORS[(st || '').toUpperCase()] || '#8FA3B8'; }
export function severityRank(sev) { const i = SEV_ORDER.indexOf((sev||'').toLowerCase()); return i >= 0 ? i : 99; }
export function effortRank(eff) { const i = EFFORT_ORDER.indexOf(eff); return i >= 0 ? i : 99; }
export function effortLabel(eff) {
  switch (eff) {
    case 'one_line_reload': return 'Config change + reload';
    case 'cert_reissue': return 'Certificate reissue';
    case 'software_upgrade': return 'Software upgrade';
    default: return str(eff);
  }
}

export function mapReport(raw) {
  if (!raw) raw = {};

  const c  = raw.capture  || {};
  const sm = raw.summary  || {};
  const h  = raw.hndl     || {};
  const ch = raw.capture_health || {};
  const fbs = sm.findings_by_severity || sm.findingsBySeverity || {};

  const mlSumRaw = raw.ml_summary || raw.mlSummary || null;

  const sessions = arr(raw.sessions).map(mapSession);
  const findings = arr(raw.findings).map(mapFinding);

  const unobs = nullableNum(h.unobservable_sessions_excluded ?? h.unobservable_sessions);
  const totalSess = nullableNum(h.total_sessions);

  return {
    capture: {
      filename: str(c.filename),
      sha256:   str(c.sha256),
      packets:  num(c.packets),
      firstTs:  str(c.first_ts || c.firstTs),
      lastTs:   str(c.last_ts  || c.lastTs)
    },
    captureHealth: {
      fileFormat: str(ch.file_format, 'Absent: capture_health.file_format'),
      analysisStatus: str(ch.analysis_status, 'unknown'),
      frames: nullableNum(ch.frames),
      tcpSegments: nullableNum(ch.tcp_segments),
      linktypes: Object.entries(object(ch.linktypes)).map(([type, count]) => ({
        type,
        count: nullableNum(count)
      })),
      skipped: Object.entries(object(ch.skipped)).map(([reason, count]) => ({
        reason,
        count: nullableNum(count)
      })),
      flowsTruncated: nullableNum(ch.flows_truncated),
      sessionsWithHoles: nullableNum(ch.sessions_with_holes),
      sessionsIncomplete: nullableNum(ch.sessions_incomplete),
      snaplen: nullableNum(ch.snaplen),
      truncated: ch.truncated,
      decodedPercent: nullableNum(ch.frames_decoded_pct),
      midstreamSessions: object(ch.midstream_sessions),
      unsupportedPackets: object(ch.unsupported_packets)
    },
    summary: {
      sessionsTotal: num(sm.sessions_total),
      findingsAssessed: sm.findings_assessed === true,
      cleartext:     num(sm.cleartext),
      encrypted:     num(sm.encrypted),
      findingsBySeverity: {
        critical: num(fbs.critical),
        high:     num(fbs.high),
        medium:   num(fbs.medium),
        low:      num(fbs.low),
        info:     num(fbs.info)
      }
    },
    hndl: {
      percent:              nullableNum(h.percent),
      exposedSessions:      nullableNum(h.exposed_sessions),
      quantumSafeSessions:  nullableNum(h.quantum_safe_sessions),
      totalSessions:        totalSess,
      unobservableSessions: unobs,
      observableSessions:   totalSess
    },
    scores: {
      observedRisk: nullableNum(raw.observed_risk),
      evidenceCoverage: nullableNum(raw.evidence_coverage),
      deducedCoverage: nullableNum(raw.deduced_coverage),
      inferredCoverage: nullableNum(raw.inferred_coverage)
    },
    sessions,
    findings,
    servers: arr(raw.servers).map(mapServer),
    mlSummary: mlSumRaw ? {
      enabled:             bool(mlSumRaw.enabled),
      model:               str(mlSumRaw.model),
      baselineSessions:    num(mlSumRaw.baseline_sessions || mlSumRaw.baselineSessions),
      anomalies:           num(mlSumRaw.anomalies),
      thresholdPercentile: num(mlSumRaw.threshold_percentile || mlSumRaw.thresholdPercentile)
    } : null
  };
}

export function mapSession(raw) {
  if (!raw) raw = {};
  const tr   = raw.transition   || {};
  const tls  = raw.tls          || {};
  const cert = raw.certificate  || {};
  const ft   = raw.five_tuple   || raw.fiveTuple || {};
  const mlR  = raw.ml || null;

  const client = ft.client_ip ? `${ft.client_ip}:${ft.client_port}` : str(raw.client);
  const server = ft.server_ip ? `${ft.server_ip}:${ft.server_port}` : str(raw.server);

  return {
    id:                 str(raw.id),
    protocol:           str(raw.protocol),
    protocolConfidence: str(raw.protocol_confidence || raw.protocolConfidence),
    client,
    server,
    transition: {
      verdict:        str(tr.verdict),
      confidenceBand: str(tr.confidence_band || tr.confidenceBand)
    },
    tls: {
      offeredVersion:    str(tls.offered_version    || tls.offeredVersion),
      negotiatedVersion: str(tls.negotiated_version || tls.negotiatedVersion),
      cipher:            str(tls.cipher),
      forwardSecrecy:    bool(tls.forward_secrecy ?? tls.forwardSecrecy),
      forwardSecrecyStatus: str(tls.forward_secrecy_status, 'UNKNOWN'),
      downgradeDelta:    nullableNum(tls.downgrade_delta ?? tls.downgradeDelta),
      hasFallbackScsv:   bool(tls.has_fallback_scsv),
      downgradeSentinel: tls.downgrade_sentinel == null ? null : str(tls.downgrade_sentinel),
      downgradeAnomaly:  bool(tls.downgrade_anomaly),
      downgradeLegacyClient: bool(tls.downgrade_legacy_client),
      clientHelloFrame:  nullableNum(tls.client_hello_frame),
      serverHelloFrame:  nullableNum(tls.server_hello_frame),
      group:             str(tls.group),
      hybridPq:          bool(tls.hybrid_pq_flag ?? tls.hybridPq)
    },
    certificate: {
      status:     str(cert.status),
      keyBits:    cert.key_bits ?? cert.keyBits ?? null,
      sigAlg:     str(cert.sig_alg    || cert.sigAlg),
      expired:    cert.expired,          // tri-state: true/false/null
      selfSigned: cert.self_signed ?? cert.selfSigned,  // tri-state
      notBefore:  str(cert.notBefore),
      notAfter:   str(cert.notAfter),
      reason:     str(cert.reason)
    },
    observedRisk:     num(raw.observed_risk     ?? raw.observedRisk),
    evidenceCoverage: num(raw.evidence_coverage ?? raw.evidenceCoverage),
    deducedCoverage:  num(raw.deduced_coverage),
    inferredCoverage: num(raw.inferred_coverage),
    factTiers: Object.entries(object(raw.fact_tiers)).map(([fact, tier]) => ({
      fact,
      tier: str(tier),
      reasonCode: raw.fact_reason_codes?.[fact] ?? null
    })),
    findings:         arr(raw.findings).map(mapFinding),
    ml: mlR ? {
      anomalyScore:       num(mlR.anomaly_score      || mlR.anomalyScore),
      anomalyPercentile:  num(mlR.anomaly_percentile  || mlR.anomalyPercentile),
      isAnomaly:          bool(mlR.is_anomaly ?? mlR.isAnomaly),
      topFactors:         arr(mlR.top_factors || mlR.topFactors).map(item => ({
        feature: str(item.feature),
        value: item.value == null ? DASH : item.value,
        baselineTypical: item.baseline_typical ?? item.baselineTypical ?? DASH,
        baselineSharePct: item.baseline_share_pct ?? item.baselineSharePct ?? null
      })),
      disagreesWithRules: bool(mlR.disagrees_with_rules ?? mlR.disagreesWithRules),
      model:              str(mlR.model)
    } : null
  };
}

export function mapFinding(raw) {
  if (!raw) raw = {};
  return {
    ruleId:            str(raw.rule_id           || raw.ruleId),
    severity:          str(raw.severity, 'info'),
    what:              str(raw.what),
    why:               str(raw.why),
    fix:               str(raw.fix),
    confidence:        num(raw.confidence),
    tier:              str(raw.tier),
    confidenceBand:    str(raw.confidence_band    || raw.confidenceBand),
    remediationEffort: str(raw.remediation_effort || raw.remediationEffort),
    remediationId:     str(raw.remediation_id     || raw.remediationId),
    references:        arr(raw.references),
    affectedSessions:  arr(raw.affected_sessions  || raw.affectedSessions),
    evidence:          arr(raw.evidence).map(mapEvidence)
  };
}

export function mapServer(raw) {
  if (!raw) raw = {};
  const preferenceEvidence = raw.preference_mode_evidence || {};
  const coverage = raw.deduced_coverage || {};

  return {
    serverId: str(raw.server_id),
    sessions: arr(raw.sessions),
    preferenceMode: str(raw.preference_mode, 'unknown'),
    preferenceReason: str(preferenceEvidence.reason, 'The evidence does not rule out the alternative.'),
    deducedCoverage: {
      settled: nullableNum(coverage.settled),
      applicable: nullableNum(coverage.applicable),
      percent: nullableNum(coverage.percent)
    },
    identityEvidence: arr(raw.identity_evidence).map(item => ({
      sessionId: str(item.session),
      source: str(item.source),
      tier: str(item.tier),
      hostname: item.hostname == null ? null : str(item.hostname),
      endpoint: str(item.endpoint),
      evidence: arr(item.evidence).map(mapEvidence)
    })),
    supportMatrix: Object.entries(object(raw.support_matrix)).map(([algorithm, cell]) => ({
      algorithm,
      state: str(cell.state, 'UNDETERMINED'),
      tier: str(cell.tier),
      positiveEvidence: arr(cell.positive_evidence),
      negativeEvidence: arr(cell.negative_evidence),
      establishingEvidence: arr(cell.establishing_evidence).map(item => ({
        sessionId: str(item.session), frame: nullableNum(item.frame),
        byteOffset: nullableNum(item.byte_offset), byteLength: nullableNum(item.byte_length),
        kind: str(item.kind)
      })),
      reasonCode: cell.reason_code ?? null
    })),
    contradictions: arr(raw.contradictions)
  };
}

function mapEvidence(raw) {
  if (!raw) raw = {};
  return {
    frame: nullableNum(raw.frame),
    field: str(raw.field),
    byteOffset: nullableNum(raw.byte_offset),
    byteLength: nullableNum(raw.byte_length),
    display: str(raw.display)
  };
}

export function tierFor(session, fact) {
  const entry = (session?.factTiers || []).find(item => item.fact === fact);
  return entry || null;
}

export function mapPacketView(raw) {
  if (!raw) raw = {};

  if (raw.unavailable) {
    return {
      unavailable: true,
      unavailableMessage: raw.message || 'Packet view available with live engine',
      sessionId: DASH, client: DASH, server: DASH, protocol: DASH,
      frames: [], evidence: [], wiresharkFilter: DASH
    };
  }

  return {
    sessionId: str(raw.session_id || raw.sessionId),
    client:    str(raw.client),
    server:    str(raw.server),
    protocol:  str(raw.protocol),
    frames: arr(raw.frames).map(f => ({
      frame:         num(f.frame),
      tMs:           num(f.t_ms ?? f.tMs),
      dir:           str(f.dir),
      len:           num(f.len),
      layer:         str(f.layer),
      summary:       str(f.summary),
      evidenceRules: arr(f.evidence_rules || f.evidenceRules)
    })),
    evidence: arr(raw.evidence).map(e => ({
      ruleId:     str(e.rule_id     || e.ruleId),
      frame:      num(e.frame),
      field:      str(e.field),
      byteOffset: num(e.byte_offset  || e.byteOffset),
      byteLength: num(e.byte_length  || e.byteLength),
      hexWindow:  e.hex_window ?? e.hexWindow ?? '',
      asciiWindow:e.ascii_window ?? e.asciiWindow ?? '',
      highlight:  arr(e.highlight),      // [start, end) byte indices
      redacted:   bool(e.redacted),
      withheldBytes: nullableNum(e.withheld_bytes ?? e.withheldBytes),
      reason:     str(e.reason, '')
    })),
    wiresharkFilter: str(raw.wireshark_filter || raw.wiresharkFilter),
    unavailable: false,
    unavailableMessage: ''
  };
}
