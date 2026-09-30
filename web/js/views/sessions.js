/**
 * sessions.js — Sessions table view with sorting and filters
 */

import { severityColor, severityRank, tierFor } from '../model.js';
import { anomalyPresentation, sentinelLabel } from '../presentation.js';

let rowClickCb = null;
let currentReport = null;
let activeSeverityFilter = null; // null for All, or 'critical'|'high'|'medium'|'low'|'info'
let activeVerdictFilter = null;  // null for All, or an engine transition verdict
let sortCol = 'id';
let sortAsc = true;

const LOCK_SVG = `<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" style="vertical-align:middle;margin-right:2px"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zM9 8V6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9z"/></svg>`;

export function onRowClick(callback) {
  rowClickCb = callback;
}

export function render(report) {
  currentReport = report;
  activeSeverityFilter = null;
  activeVerdictFilter = null;

  const content = document.getElementById('sessions-content');
  const empty = document.getElementById('sessions-empty');

  if (!report || !report.sessions || report.sessions.length === 0) {
    if (content) content.hidden = true;
    if (empty) empty.hidden = false;
    document.getElementById('sessions-tbody').replaceChildren();
    if (empty) empty.querySelector('p').textContent = !report ? 'No session report loaded.' : !report.summary.findingsAssessed ? 'NOT ANALYSED — no session assessment is available.' : 'No mail sessions identified in this capture.';
    return;
  }

  if (content) content.hidden = false;
  if (empty) empty.hidden = true;

  renderFilterChips();
  setupTableSortHeaders();
  renderTableRows();
}

function renderFilterChips() {
  const container = document.getElementById('sessions-filters');
  if (!container) return;

  container.innerHTML = `
    <span style="font-size:0.8rem;font-weight:700;color:var(--text-muted);align-self:center;">Severity:</span>
    <button class="filter-chip ${activeSeverityFilter === null ? 'active' : ''}" data-sev="all">All</button>
    <button class="filter-chip ${activeSeverityFilter === 'critical' ? 'active' : ''}" data-sev="critical" style="color:var(--sev-critical)">Critical</button>
    <button class="filter-chip ${activeSeverityFilter === 'high' ? 'active' : ''}" data-sev="high" style="color:var(--sev-high)">High</button>
    <button class="filter-chip ${activeSeverityFilter === 'medium' ? 'active' : ''}" data-sev="medium" style="color:var(--sev-medium)">Medium</button>
    <button class="filter-chip ${activeSeverityFilter === 'low' ? 'active' : ''}" data-sev="low" style="color:var(--sev-low)">Low</button>
    <button class="filter-chip ${activeSeverityFilter === 'info' ? 'active' : ''}" data-sev="info" style="color:var(--sev-info)">Info</button>

    <span style="font-size:0.8rem;font-weight:700;color:var(--text-muted);align-self:center;margin-left:12px;">Verdict:</span>
    <button class="filter-chip ${activeVerdictFilter === null ? 'active' : ''}" data-verdict="all">All</button>
    <button class="filter-chip ${activeVerdictFilter === 'upgraded' ? 'active' : ''}" data-verdict="upgraded">Upgraded</button>
    <button class="filter-chip ${activeVerdictFilter === 'not_used' ? 'active' : ''}" data-verdict="not_used">Not Used</button>
    <button class="filter-chip ${activeVerdictFilter === 'suspected' ? 'active' : ''}" data-verdict="suspected">Suspected</button>
    <button class="filter-chip ${activeVerdictFilter === 'failed' ? 'active' : ''}" data-verdict="failed">Failed</button>
    <button class="filter-chip ${activeVerdictFilter === 'rejected' ? 'active' : ''}" data-verdict="rejected">Rejected</button>
  `;

  container.querySelectorAll('[data-sev]').forEach(btn => {
    btn.addEventListener('click', () => {
      const sev = btn.dataset.sev;
      activeSeverityFilter = (sev === 'all') ? null : sev;
      renderFilterChips();
      renderTableRows();
    });
  });

  container.querySelectorAll('[data-verdict]').forEach(btn => {
    btn.addEventListener('click', () => {
      const v = btn.dataset.verdict;
      activeVerdictFilter = (v === 'all') ? null : v;
      renderFilterChips();
      renderTableRows();
    });
  });
}

function getSessionWorstSeverity(session) {
  if (!session.findings || session.findings.length === 0) return 'info';
  let worstRank = 99;
  let worstSev = 'info';

  for (const f of session.findings) {
    const r = severityRank(f.severity);
    if (r < worstRank) {
      worstRank = r;
      worstSev = f.severity;
    }
  }
  return worstSev;
}

function setupTableSortHeaders() {
  const ths = document.querySelectorAll('#sessions-table thead th[data-sort]');
  ths.forEach(th => {
    th.tabIndex = 0;
    th.onkeydown = event => {
      if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); th.click(); }
    };
    th.onclick = () => {
      const col = th.dataset.sort;
      if (sortCol === col) {
        sortAsc = !sortAsc;
      } else {
        sortCol = col;
        sortAsc = true;
      }
      updateSortIndicators();
      renderTableRows();
    };
  });
  updateSortIndicators();
}

function updateSortIndicators() {
  const ths = document.querySelectorAll('#sessions-table thead th[data-sort]');
  ths.forEach(th => {
    const col = th.dataset.sort;
    th.setAttribute('aria-sort', sortCol === col ? (sortAsc ? 'ascending' : 'descending') : 'none');
    const cleanText = th.textContent.replace(/[▲▼]/g, '').trim();
    if (sortCol === col) {
      th.innerHTML = `${cleanText} <span class="sort-arrow">${sortAsc ? '▲' : '▼'}</span>`;
    } else {
      th.innerHTML = cleanText;
    }
  });
}

function renderTableRows() {
  const tbody = document.getElementById('sessions-tbody');
  if (!tbody || !currentReport || !currentReport.sessions) return;

  tbody.innerHTML = '';

  let filtered = [...currentReport.sessions];

  if (activeSeverityFilter) {
    filtered = filtered.filter(s => getSessionWorstSeverity(s).toLowerCase() === activeSeverityFilter);
  }
  if (activeVerdictFilter) {
    filtered = filtered.filter(s => (s.transition.verdict || '').toLowerCase() === activeVerdictFilter);
  }

  filtered.sort((a, b) => {
    let valA, valB;
    switch (sortCol) {
      case 'id':
        valA = a.id; valB = b.id; break;
      case 'protocol':
        valA = a.protocol; valB = b.protocol; break;
      case 'endpoints':
        valA = `${a.client} ${a.server}`; valB = `${b.client} ${b.server}`; break;
      case 'verdict':
        valA = a.transition.verdict; valB = b.transition.verdict; break;
      case 'tls':
        valA = a.tls.negotiatedVersion || ''; valB = b.tls.negotiatedVersion || ''; break;
      case 'downgrade':
        valA = a.tls.downgradeDelta || 0; valB = b.tls.downgradeDelta || 0; break;
      case 'cert':
        valA = a.certificate.status || ''; valB = b.certificate.status || ''; break;
      case 'risk':
        valA = a.observedRisk; valB = b.observedRisk; break;
      case 'coverage':
        valA = a.evidenceCoverage; valB = b.evidenceCoverage; break;
      case 'ai':
        valA = a.ml ? a.ml.anomalyPercentile : -1;
        valB = b.ml ? b.ml.anomalyPercentile : -1;
        break;
      default:
        valA = a.id; valB = b.id;
    }

    if (typeof valA === 'string') {
      const cmp = valA.localeCompare(valB, 'en', { numeric: true });
      return sortAsc ? cmp : -cmp;
    }
    return sortAsc ? (valA - valB) : (valB - valA);
  });

  if (filtered.length === 0) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td colspan="10" style="text-align:center;padding:24px;color:var(--text-muted)">No sessions match the selected filters</td>`;
    tbody.appendChild(tr);
    return;
  }

  filtered.forEach(session => {
    const tr = document.createElement('tr');
    tr.tabIndex = 0; // keyboard navigable
    tr.dataset.sessionId = session.id;
    tr.setAttribute('aria-label', `Open session ${session.id}`);

    const worstSev = getSessionWorstSeverity(session);
    const barColor = severityColor(worstSev);

    const verdict = session.transition.verdict || '—';
    const verdictClass = verdict.toLowerCase().replace(/[\s-]/g, '_');
    const band = (session.transition.confidenceBand || 'certain').toLowerCase();

    let tlsStr = '—';
    if (session.tls.negotiatedVersion && session.tls.negotiatedVersion !== '—') {
      if (session.tls.offeredVersion && session.tls.offeredVersion !== '—' && session.tls.offeredVersion !== session.tls.negotiatedVersion) {
        tlsStr = `${session.tls.offeredVersion} → ${session.tls.negotiatedVersion}`;
      } else {
        tlsStr = session.tls.negotiatedVersion;
      }
    }

    // null means the offered or negotiated version is unknown: show a dash, not 0.
    const downgradeDelta = session.tls.downgradeDelta;
    const downgradeSignals = [];
    if (session.tls.hasFallbackScsv) downgradeSignals.push('Fallback SCSV 0x5600');
    if (session.tls.downgradeSentinel) downgradeSignals.push(sentinelLabel(session.tls));
    const downgradeDisplay = downgradeDelta > 0 || downgradeSignals.length
      ? `<div><span class="${downgradeDelta > 0 ? 'downgrade-highlight' : ''}">Δ ${downgradeDelta ?? '—'}</span>${session.tls.downgradeAnomaly ? '<span class="composite-signal">Engine-reported downgrade anomaly</span>' : ''}${downgradeSignals.map(signal => `<small>${signal}</small>`).join('')}</div>`
      : (downgradeDelta == null ? '—' : '0');

    const certStatus = session.certificate.status || 'NOT_OBSERVABLE';
    const certHtml = `<div class="fact-with-tier"><span class="cert-badge cert-${certStatus.toLowerCase()}">${LOCK_SVG} ${certStatus}</span>${renderTier(tierFor(session, 'certificate.status'))}</div>`;

    // The existing engine percentile is bounded; raw z-score is tooltip-only.
    let aiDisplay = '—';
    if (session.ml && session.ml.anomalyPercentile != null) {
      const display = anomalyPresentation(session.ml);
      aiDisplay = `
        <div style="font-weight:600;" title="${display.tooltip}">${display.label}</div>
      `;
    }

    tr.innerHTML = `
      <td class="td-id" style="position:relative;padding-left:16px;">
        <div class="sev-bar" style="background:${barColor};"></div>
        ${session.id}
      </td>
      <td class="td-protocol"><div class="fact-with-tier">${session.protocol}${renderTier(tierFor(session, 'protocol'))}</div></td>
      <td class="td-endpoints"><span>${session.client}</span><span>→ ${session.server}</span></td>
      <td>
        <span class="verdict-badge ${verdictClass}">
          <span class="confidence-dot ${band}"></span>
          ${verdict}
        </span>
        ${renderTier(tierFor(session, 'transition.verdict'))}
      </td>
      <td style="font-family:var(--mono);font-size:0.78rem;"><div class="fact-with-tier">${tlsStr}${renderTier(tierFor(session, 'tls.negotiated_version'))}</div></td>
      <td style="font-family:var(--mono);">${downgradeDisplay}</td>
      <td>${certHtml}</td>
      <td style="font-family:var(--mono);font-weight:700;color:${session.observedRisk > 50 ? 'var(--sev-critical)' : 'var(--text)'}">${session.observedRisk}</td>
      <td style="font-family:var(--mono);"><strong>${session.evidenceCoverage}%</strong><small class="coverage-row-breakdown">Deduced ${session.deducedCoverage}% · Inferred ${session.inferredCoverage}%</small></td>
      <td style="font-family:var(--mono);">${aiDisplay}</td>
    `;

    tr.addEventListener('click', () => {
      if (rowClickCb) rowClickCb(session);
    });

    tr.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        if (rowClickCb) rowClickCb(session);
      }
    });

    tbody.appendChild(tr);
  });
}

function renderTier(entry) {
  if (!entry || !entry.tier || entry.tier === '—') return '';
  const css = entry.tier.toLowerCase().replace(/_/g, '-');
  const tooltip = entry.tier === 'NOT_OBSERVABLE'
    ? (entry.reasonCode || 'Absent: fact_reason_codes entry')
    : entry.tier;
  return `<span class="tier-badge tier-${css}" title="${escapeAttribute(tooltip)}">${entry.tier}</span>`;
}

function escapeAttribute(value) {
  // Quoted HTML attributes require escaping quotes as well as markup.
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}
