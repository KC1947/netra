/**
 * fixfirst.js — Fix-first Priorities, AI Review Queue, and Export views
 */

import { severityColor, severityRank, effortRank, effortLabel } from '../model.js';
import { exportUrl } from '../api.js';
import { anomalyPresentation, baselineShareLabel } from '../presentation.js';

let findingClickCallback = null;
let aiSessionClickCallback = null;

export function onFindingClick(callback) {
  findingClickCallback = callback;
}

export function onAISessionClick(callback) {
  aiSessionClickCallback = callback;
}

export function renderFixFirst(report) {
  const content = document.getElementById('fixfirst-content');
  const empty = document.getElementById('fixfirst-empty');

  if (!content || !empty) return;

  if (!report || !report.findings || report.findings.length === 0) {
    content.hidden = true;
    empty.hidden = false;
    empty.querySelector('p').textContent = !report ? 'No findings report loaded.' : !report.summary.findingsAssessed ? 'NOT ANALYSED — findings were not assessed.' : 'No findings reported in the observable evidence.';
    return;
  }

  const nonInfoFindings = report.findings.filter(f => (f.severity || '').toLowerCase() !== 'info');

  if (nonInfoFindings.length === 0) {
    content.hidden = true;
    empty.hidden = false;
    empty.querySelector('p').textContent = 'No non-informational findings reported in the observable evidence.';
    return;
  }

  content.hidden = false;
  empty.hidden = true;

  // Sort: 1) severity (critical first), 2) effort (one_line_reload < cert_reissue < software_upgrade)
  const sorted = [...nonInfoFindings].sort((a, b) => {
    const sA = severityRank(a.severity);
    const sB = severityRank(b.severity);
    if (sA !== sB) return sA - sB;

    const eA = effortRank(a.remediationEffort);
    const eB = effortRank(b.remediationEffort);
    return eA - eB;
  });

  let cardsHtml = '<div class="fixfirst-list">';
  sorted.forEach(f => {
    const sev = f.severity || 'info';
    const col = severityColor(sev);
    const sessionsTags = (f.affectedSessions || []).map(sid => `<span class="finding-session-tag">${sid}</span>`).join(' ');

    cardsHtml += `
      <div class="fixfirst-card clickable" style="border-left-color:${col}" role="button" tabindex="0" data-session-id="${f.affectedSessions?.[0] || ''}" data-rule-id="${f.ruleId}">
        <div class="fixfirst-header">
          <span class="severity-chip ${sev.toLowerCase()}">${sev}</span>
          <span class="rule-id-label">${f.ruleId}</span>
          <span class="effort-badge">${effortLabel(f.remediationEffort)}</span>
          <div style="margin-left:auto;display:flex;align-items:center;gap:4px;">
            <span style="font-size:0.75rem;color:var(--text-muted)">Affected:</span>
            ${sessionsTags || '—'}
          </div>
        </div>
        <p style="font-size:0.9rem;font-weight:600;color:var(--text);margin-bottom:6px;">
          ${f.fix}
        </p>
        <p style="font-size:0.8rem;color:var(--text-muted);">
          ${f.what}
        </p>
      </div>
    `;
  });
  cardsHtml += '</div>';

  content.innerHTML = cardsHtml;

  content.querySelectorAll('.fixfirst-card[data-session-id]').forEach(card => {
    const activate = () => findingClickCallback?.(card.dataset.sessionId, card.dataset.ruleId);
    card.addEventListener('click', activate);
    card.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        activate();
      }
    });
  });
}

export function renderAIQueue(report) {
  const content = document.getElementById('aiqueue-content');
  if (!content) return;

  if (!report || !report.summary.findingsAssessed) {
    content.textContent = report ? 'NOT ANALYSED — no AI assessment is available.' : 'No AI assessment loaded.';
    return;
  }

  const mlSum = report ? report.mlSummary : null;

  if (!mlSum || !mlSum.enabled) {
    content.innerHTML = `
      <div class="ai-disabled-msg">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5" style="margin-bottom:12px;">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <p style="font-weight:600;color:var(--text);margin-bottom:6px;">AI Anomaly Layer is disabled</p>
        <p style="font-size:0.85rem;max-width:620px;margin:0 auto 8px;">The review queue requires an analysis with the AI layer enabled.</p>
        <p class="ai-isolation-note">Findings and scores are byte-identical when the AI layer is off.</p>
      </div>
    `;
    return;
  }

  // The engine-provided disagreement flag is authoritative; the UI does not
  // recalculate finding severity or infer disagreement from rule output.
  const mlSessions = (report.sessions || []).filter(s =>
    s.ml && s.ml.isAnomaly && s.ml.disagreesWithRules
  );

  if (mlSessions.length === 0) {
    content.innerHTML = `
      <p class="ai-isolation-note">Findings and scores are byte-identical when the AI layer is off.</p>
      <p style="color:var(--text-muted);text-align:center;padding:32px;">No report session is marked both anomalous and in disagreement with the rules.</p>
    `;
    return;
  }

  const renderQueueList = () => {
    let list = [...mlSessions];

    list.sort((a, b) => (b.ml.anomalyPercentile || 0) - (a.ml.anomalyPercentile || 0));

    let listHtml = '';
    list.forEach(s => {
      const ml = s.ml;
      const pct = ml.anomalyPercentile || 0;
      const display = anomalyPresentation(ml);
      const isAnomaly = ml.isAnomaly;
      const fillColor = isAnomaly ? 'var(--sev-critical)' : (pct > 70 ? 'var(--sev-high)' : 'var(--teal)');

      let factorsHtml = '';
      if (ml.topFactors && ml.topFactors.length > 0) {
        factorsHtml = '<ul class="ai-factors" style="margin-top:8px;list-style:none;padding:0;">';
        ml.topFactors.forEach(tf => {
          const typical = tf.baselineTypical;
          factorsHtml += `
            <li>
              <span style="font-family:var(--mono);color:var(--text);">${tf.feature}</span> = <span style="font-family:var(--mono);">${tf.value}</span>
              &mdash; ${baselineShareLabel(tf.baselineSharePct)} (typical ${typical})
            </li>
          `;
        });
        factorsHtml += '</ul>';
      }

      listHtml += `
        <div class="ai-session-card clickable" role="button" tabindex="0" data-session-id="${s.id}">
          <div class="ai-session-header" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
            <div>
              <span style="font-family:var(--mono);font-weight:700;font-size:1rem;">${s.id}</span>
              <span class="pill pill-passive" style="text-transform:uppercase;margin-left:6px;">${s.protocol}</span>
              <span style="font-family:var(--mono);font-size:0.8rem;color:var(--text-muted);margin-left:8px;">${s.client} &rarr; ${s.server}</span>
            </div>
            ${ml.disagreesWithRules ? '<span class="ai-disagrees">AI disagrees with rules</span>' : ''}
            <div class="percentile-bar" style="max-width:180px;margin-left:auto;">
              <div class="percentile-fill" style="width:${pct}%;background:${fillColor}"></div>
            </div>
            <div class="percentile-value" style="color:${fillColor};text-align:right;" title="${display.tooltip}">
              <div>${display.label}</div>
            </div>
          </div>
          ${factorsHtml}
        </div>
      `;
    });

    const queueContainer = document.getElementById('ai-queue-items');
    if (queueContainer) {
      queueContainer.innerHTML = listHtml || `<p style="color:var(--text-muted);padding:24px;text-align:center;">No sessions match the filter.</p>`;
    }
  };

  content.innerHTML = `
    <p class="ai-isolation-note">Findings and scores are byte-identical when the AI layer is off.</p>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
      <div style="font-size:0.85rem;color:var(--text-muted)">
        Baseline: <strong>${mlSum.baselineSessions} sessions</strong> | Model: <strong>${mlSum.model}</strong> | Anomalies detected: <strong>${mlSum.anomalies}</strong>
      </div>
    </div>
    <div id="ai-queue-items"></div>
  `;

  renderQueueList();

  content.querySelectorAll('.ai-session-card[data-session-id]').forEach(card => {
    const activate = () => aiSessionClickCallback?.(card.dataset.sessionId);
    card.addEventListener('click', activate);
    card.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        activate();
      }
    });
  });
}

export function renderExport(analysisId) {
  const content = document.getElementById('export-content');
  const empty = document.getElementById('export-empty');

  if (!content || !empty) return;

  if (!analysisId) {
    content.hidden = true;
    empty.hidden = false;
    return;
  }

  content.hidden = false;
  empty.hidden = true;

  const jsonBtn = document.getElementById('export-json-btn');
  const htmlBtn = document.getElementById('export-html-btn');
  const cbomBtn = document.getElementById('export-cbom-btn');
  const pdfBtn = document.getElementById('export-pdf-btn');

  if (jsonBtn) jsonBtn.href = exportUrl(analysisId, 'json');
  if (htmlBtn) htmlBtn.href = exportUrl(analysisId, 'html');
  if (cbomBtn) {
    cbomBtn.href = exportUrl(analysisId, 'cbom');
    cbomBtn.hidden = false;
  }
  if (pdfBtn) {
    pdfBtn.href = exportUrl(analysisId, 'pdf');
    pdfBtn.hidden = false;
  }

}
