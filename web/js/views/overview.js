/**
 * overview.js — Report metadata, capture health, HNDL, scores, and support matrices
 */

import { exportUrl } from '../api.js';

let chartInstances = [];
let supportEvidenceCallback = null;

export function onSupportEvidenceClick(callback) {
  supportEvidenceCallback = callback;
}

export function render(report, analysisId) {
  const content = document.getElementById('overview-content');
  const empty = document.getElementById('overview-empty');
  if (content) content.hidden = false;
  if (empty) empty.hidden = true;

  renderExportActions(analysisId);
  renderTransparencyStrip(report, analysisId);
  renderCaptureHealth(report.captureHealth);
  renderHndl(report.hndl);
  renderScores(report);
  renderCharts(report);
  renderSupportMatrices(report);
  for (const id of ['hndl-banner', 'kpi-grid', 'charts-grid', 'support-matrices']) {
    document.getElementById(id).hidden = !report.summary.findingsAssessed;
  }
  document.querySelector('.kpi-explanation').hidden = !report.summary.findingsAssessed;
}

function renderExportActions(analysisId) {
  const actions = document.getElementById('overview-export-actions');
  const jsonButton = document.getElementById('overview-export-json-btn');
  const htmlButton = document.getElementById('overview-export-html-btn');
  const cbomButton = document.getElementById('overview-export-cbom-btn');
  const pdfButton = document.getElementById('overview-export-pdf-btn');
  if (!actions || !jsonButton || !htmlButton || !cbomButton || !pdfButton || !analysisId) return;

  jsonButton.href = exportUrl(analysisId, 'json');
  htmlButton.href = exportUrl(analysisId, 'html');
  cbomButton.href = exportUrl(analysisId, 'cbom');
  cbomButton.hidden = false;
  pdfButton.href = exportUrl(analysisId, 'pdf');
  pdfButton.hidden = false;
  actions.hidden = false;
}

function renderTransparencyStrip(report, analysisId) {
  const strip = document.getElementById('transparency-strip');
  if (!strip) return;

  const capture = report.capture || {};
  const aiOn = !!report.mlSummary?.enabled;
  const first = capture.firstTs !== '—' ? formatTimestamp(capture.firstTs) : '—';
  const last = capture.lastTs !== '—' ? formatTimestamp(capture.lastTs) : '—';
  const time = first !== '—' && last !== '—' ? `${first} — ${last}` : '—';

  strip.innerHTML = `
    <div class="ts-item"><span class="ts-label">Capture file</span><span class="ts-value">${escapeHtml(capture.filename)}</span></div>
    <div class="ts-item">
      <span class="ts-label">SHA-256</span>
      <span class="ts-value"><span id="ts-sha-full">${escapeHtml(capture.sha256)}</span><button class="copy-btn" id="copy-sha-btn" title="Copy full SHA-256" aria-label="Copy SHA-256">Copy</button></span>
    </div>
    <div class="ts-item"><span class="ts-label">Analysis ID</span><span class="ts-value">${escapeHtml(analysisId)}</span></div>
    <div class="ts-item"><span class="ts-label">Capture time</span><span class="ts-value">${escapeHtml(time)}</span></div>
    <div class="ts-item"><span class="ts-label">AI layer</span><span class="ts-value">${aiOn ? 'ON' : 'OFF'}</span></div>
  `;

  strip.querySelector('#copy-sha-btn')?.addEventListener('click', async event => {
    if (!capture.sha256 || capture.sha256 === '—') return;
    const button = event.currentTarget;
    try { await navigator.clipboard.writeText(capture.sha256); button.textContent = 'Copied'; }
    catch (_) { button.textContent = 'Copy unavailable'; }
  });
}

function renderCaptureHealth(health = {}) {
  const container = document.getElementById('capture-health-passport');
  if (!container) return;

  const skipped = health.skipped || [];
  const warning = health.analysisStatus !== 'complete' || health.truncated || (health.decodedPercent != null && health.decodedPercent < 100) || skipped.length > 0;
  const healthState = (health.analysisStatus || 'unknown').toUpperCase();
  const healthTitle = warning
    ? 'Capture limitations need review'
    : health.decodedPercent == null
      ? 'Capture health is partially reported'
      : 'Capture decoded without reported limitations';
  const linktypes = (health.linktypes || []).length
    ? health.linktypes.map(item => `${item.type} (${displayNumber(item.count)} frame${item.count === 1 ? '' : 's'})`).join(', ')
    : 'No link type reported';
  const skippedText = skipped.length
    ? skipped.map(item => `${item.reason}: ${displayNumber(item.count)}`).join(', ')
    : '0 reported';

  container.className = `capture-health-passport${warning ? ' warning' : ''}`;
  container.innerHTML = `
    <div class="passport-heading">
      <div><span class="passport-kicker">Capture Health Passport</span><h3>${healthTitle}</h3></div>
      <span class="passport-status">${healthState}</span>
    </div>
    <div class="passport-items">
      ${passportItem('Link type · file format', `${linktypes} · ${health.fileFormat}`)}
      ${passportItem('Snaplen · truncation', `${missingOrValue(health.snaplen)} bytes · ${health.truncated === true ? 'packets truncated' : health.truncated === false ? 'no packet truncation' : 'truncated field absent'} · ${displayNumber(health.flowsTruncated)} flows truncated`)}
      ${passportItem('Frames decoded', `${displayNumber(health.decodedPercent)}% · ${displayNumber(health.tcpSegments)} / ${displayNumber(health.frames)} frames`)}
      ${passportItem('Sequence gaps · mid-stream', `${displayNumber(health.sessionsWithHoles)} sessions with gaps · ${Object.entries(health.midstreamSessions || {}).filter(([, value]) => value).map(([id]) => id).join(', ') || 'none'} flagged mid-stream (first packet not SYN; no probability supplied)`)}
      ${passportItem('Unsupported / skipped packets', `${health.unsupportedPackets?.count ?? 'Unreported'} unsupported · ${skippedText}`)}
      ${passportItem('Analysis status', `${healthState} · ${displayNumber(health.sessionsIncomplete)} incomplete sessions`)}
    </div>
  `;
}

function passportItem(label, value) {
  return `<div class="passport-item"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function renderHndl(hndl = {}) {
  const container = document.getElementById('hndl-banner');
  if (!container) return;

  container.className = 'hndl-banner';
  container.innerHTML = `
    <div class="hndl-title">
      <span>Harvest-now-decrypt-later exposure</span>
      <strong>${displayNumber(hndl.percent)}%</strong>
      <small>${displayNumber(hndl.exposedSessions)} / ${displayNumber(hndl.totalSessions)} observable sessions</small>
    </div>
    <div class="hndl-counts">
      ${hndlCount('Exposed', hndl.exposedSessions, 'exposed_sessions')}
      ${hndlCount('Quantum-safe', hndl.quantumSafeSessions, 'quantum_safe_sessions')}
      ${hndlCount('Unobservable · excluded', hndl.unobservableSessions, 'unobservable_sessions_excluded')}
    </div>
    <p>Sessions whose key exchange was not observable are excluded from both sides of the ratio and counted separately.</p>
  `;
}

function hndlCount(label, value, key) {
  const missing = value == null;
  return `<div class="hndl-count${missing ? ' data-missing' : ''}"><strong>${missing ? '—' : value}</strong><span>${escapeHtml(label)}</span>${missing ? `<small>Absent: hndl.${key}</small>` : ''}</div>`;
}

function renderScores(report) {
  const grid = document.getElementById('kpi-grid');
  if (!grid) return;
  const scores = report.scores || {};

  grid.innerHTML = `
    ${scoreCard('Observed risk', scores.observedRisk, 'Risk from observed and deduced evidence only.')}
    ${scoreCard(
      'Evidence coverage',
      scores.evidenceCoverage,
      'Missing evidence lowers coverage, never risk.',
      `<div class="coverage-breakdown"><span>Deduced <strong>${displayScore(scores.deducedCoverage)}</strong></span><span>Inferred <strong>${displayScore(scores.inferredCoverage)}</strong></span></div>`
    )}
  `;
}

function scoreCard(label, value, explanation, extra = '') {
  const missing = value == null;
  return `
    <div class="kpi-card score-card${missing ? ' data-missing' : ''}">
      <div class="kpi-label">${escapeHtml(label)}</div>
      <div class="kpi-number">${missing ? '—' : value}${missing ? '' : label.includes('coverage') ? '%' : ''}</div>
      ${missing ? `<div class="missing-field">Absent: ${label === 'Observed risk' ? 'observed_risk' : 'evidence_coverage'}</div>` : ''}
      <p>${escapeHtml(explanation)}</p>
      ${extra}
    </div>
  `;
}

function renderSupportMatrices(report) {
  const container = document.getElementById('support-matrices');
  if (!container) return;
  const servers = report.servers || [];

  if (!servers.length) {
    container.innerHTML = '<div class="support-empty"><h3>Server support matrix</h3><p>No correlated server identities were provided by the report.</p></div>';
    return;
  }

  container.innerHTML = `<div class="subsection-heading"><h3>Server support matrix</h3><p>Capabilities are shown exactly as reported for each correlated server identity.</p></div>`;

  for (const server of servers) {
    const panel = document.createElement('section');
    panel.className = 'support-panel';
    const modeReason = server.preferenceMode === 'unknown'
      ? `<p class="preference-reason">${escapeHtml(server.preferenceReason || 'The evidence does not rule out the alternative.')}</p>`
      : '';
    const rows = server.supportMatrix.length
      ? server.supportMatrix.map(cell => supportRow(cell)).join('')
      : '<tr><td colspan="4" class="table-empty">No algorithm support facts were provided for this identity.</td></tr>';

    panel.innerHTML = `
      <div class="support-header">
        <div><h4>${escapeHtml(server.serverId)}</h4><p>${server.sessions.length} report session(s)</p></div>
        <div class="preference-mode"><span>Cipher preference</span><strong>${escapeHtml(server.preferenceMode)}</strong>${modeReason}</div>
      </div>
      <div class="support-table-wrap">
        <table class="support-table">
          <thead><tr><th>Algorithm</th><th>State</th><th>Tier</th><th>Evidence</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    `;

    panel.querySelectorAll('[data-support-session]').forEach(button => {
      button.addEventListener('click', () => {
        supportEvidenceCallback?.({
          sessionId: button.dataset.supportSession,
          frame: Number(button.dataset.frame),
          algorithm: button.dataset.algorithm,
          state: button.dataset.state
        });
      });
    });
    container.appendChild(panel);
  }
}

function supportRow(cell) {
  const refs = cell.establishingEvidence || [];
  const clickable = cell.state !== 'UNDETERMINED' && refs.length;
  const evidence = clickable
    ? refs.map(ref => `<button class="support-evidence-link" data-support-session="${escapeHtml(ref.sessionId)}" data-frame="${ref.frame}" data-algorithm="${escapeHtml(cell.algorithm)}" data-state="${escapeHtml(cell.state)}">${escapeHtml(ref.sessionId)} · frame ${ref.frame} · ${escapeHtml(ref.kind)}</button>`).join(' ')
    : `<span class="muted">${escapeHtml(cell.reasonCode || 'Establishing evidence absent')} — no captured bytes establish this cell.</span>`;
  return `
    <tr>
      <td><code>${escapeHtml(cell.algorithm)}</code></td>
      <td><span class="support-state state-${cell.state.toLowerCase()}">${escapeHtml(cell.state)}</span></td>
      <td>${tierBadge(cell.tier, cell.reasonCode)}</td>
      <td>${evidence}</td>
    </tr>
  `;
}

function tierBadge(tier, reason) {
  if (!tier || tier === '—') return '<span class="muted">—</span>';
  const css = tier.toLowerCase().replace(/_/g, '-');
  const title = tier === 'NOT_OBSERVABLE' ? ` title="${escapeHtml(reason || 'reason_code absent')}"` : '';
  return `<span class="tier-badge tier-${css}"${title}>${escapeHtml(tier)}</span>`;
}

function renderCharts(report) {
  chartInstances.forEach(chart => chart?.destroy?.());
  chartInstances = [];

  const tlsPanel = document.getElementById('chart-tls')?.closest('.chart-panel');
  const verdictPanel = document.getElementById('chart-verdicts')?.closest('.chart-panel');
  if (tlsPanel) tlsPanel.hidden = true;
  if (verdictPanel) verdictPanel.hidden = true;
  if (typeof Chart === 'undefined') return;

  const canvas = document.getElementById('chart-severity');
  if (!canvas) return;
  const counts = report.summary.findingsBySeverity;
  const chart = new Chart(canvas, {
    type: 'bar',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
      datasets: [{
        data: [counts.critical, counts.high, counts.medium, counts.low, counts.info],
        backgroundColor: ['#D9534F', '#E8913A', '#E8C547', '#5CB85C', '#6C8EBF'],
        borderColor: '#1A1A1A',
        borderWidth: 1.5
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, ticks: { stepSize: 1, precision: 0 } }, x: { grid: { display: false } } }
    }
  });
  chartInstances.push(chart);
}

function formatTimestamp(value) {
  try {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toUTCString().replace('GMT', 'UTC');
  } catch (_) {
    return value;
  }
}

function missingOrValue(value) {
  return value == null ? 'Field absent' : String(value);
}

function displayNumber(value) {
  return value == null ? '—' : value;
}

function displayScore(value) {
  return value == null ? 'Not provided' : `${value}%`;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  })[char]);
}
