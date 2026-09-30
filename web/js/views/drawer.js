/**
 * drawer.js — Session detail drawer & Evidence viewer modal
 */

import { mapPacketView, severityColor, effortLabel, tierFor } from '../model.js';
import * as api from '../api.js';
import { sentinelLabel } from '../presentation.js';

let currentSession = null;
let currentAnalysisId = null;
let packetData = null;
let pendingFocus = null;
let closeTimer = null;

const LOCK_SVG = `<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" style="vertical-align:middle;margin-right:4px"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zM9 8V6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9z"/></svg>`;

export async function open(session, analysisId, focus = null) {
  clearTimeout(closeTimer);
  currentSession = session;
  currentAnalysisId = analysisId;
  packetData = null;
  pendingFocus = focus;

  const drawer = document.getElementById('session-drawer');
  const overlay = document.getElementById('drawer-overlay');

  if (!drawer || !overlay) return;

  drawer.hidden = false;
  overlay.hidden = false;

  requestAnimationFrame(() => {
    drawer.classList.add('open');
    overlay.classList.add('visible');
  });

  renderHeader();
  renderBody();
  document.getElementById('drawer-body').scrollTop = 0;
  document.getElementById('drawer-close').focus();
  await loadAndRenderPacketLadder();
}

export function close() {
  currentSession = null;
  pendingFocus = null;
  closeEvidence();
  const drawer = document.getElementById('session-drawer');
  const overlay = document.getElementById('drawer-overlay');

  if (!drawer || !overlay) return;

  drawer.classList.remove('open');
  overlay.classList.remove('visible');

  closeTimer = setTimeout(() => {
    drawer.hidden = true;
    overlay.hidden = true;
  }, 250);
}

// Setup close triggers once
export function setupListeners() {
  const closeBtn = document.getElementById('drawer-close');
  if (closeBtn) closeBtn.onclick = close;

  const overlay = document.getElementById('drawer-overlay');
  if (overlay) overlay.onclick = close;

  const evClose = document.getElementById('evidence-close');
  if (evClose) evClose.onclick = closeEvidence;

  const evOverlay = document.getElementById('evidence-overlay');
  if (evOverlay) {
    evOverlay.onclick = (e) => {
      if (e.target === evOverlay) closeEvidence();
    };
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      const evModal = document.getElementById('evidence-overlay');
      if (evModal && !evModal.hidden) {
        closeEvidence();
      } else {
        close();
      }
    }
  });
}

function renderHeader() {
  const header = document.getElementById('drawer-header');
  if (!header || !currentSession) return;

  const s = currentSession;
  const verdict = s.transition.verdict || '—';
  const band = s.transition.confidenceBand || 'certain';
  const vClass = verdict.toLowerCase().replace(/[\s-]/g, '_');

  header.innerHTML = `
    <div style="flex:1;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
        <span style="font-family:var(--mono);font-size:1.1rem;font-weight:700;">${s.id}</span>
        <span class="pill pill-passive" style="text-transform:uppercase;">${s.protocol}</span>
        <span class="verdict-badge ${vClass}">
          <span class="confidence-dot ${band.toLowerCase()}"></span>
          ${verdict}
        </span>
      </div>
      <div style="font-family:var(--mono);font-size:0.82rem;color:var(--text-muted);">
        ${s.client} &rarr; ${s.server}
      </div>
    </div>

    <div class="score-gauges">
      <div class="score-gauge">
        <div class="score-gauge-bar score-risk">
          <span class="score-gauge-fill" style="width:${s.observedRisk}%"></span>
          <span class="score-gauge-value">${s.observedRisk}</span>
        </div>
        <span class="score-gauge-label">Risk</span>
      </div>
      <div class="score-gauge">
        <div class="score-gauge-bar score-coverage">
          <span class="score-gauge-fill" style="width:${s.evidenceCoverage}%"></span>
          <span class="score-gauge-value">${s.evidenceCoverage}%</span>
        </div>
        <span class="score-gauge-label">Coverage</span>
        <span class="score-gauge-detail">Deduced ${s.deducedCoverage}% · Inferred ${s.inferredCoverage}%</span>
      </div>
    </div>

    <button class="drawer-close" id="drawer-close" aria-label="Close drawer">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <line x1="18" y1="6" x2="6" y2="18"/>
        <line x1="6" y1="6" x2="18" y2="18"/>
      </svg>
    </button>
  `;

  const newClose = header.querySelector('#drawer-close');
  if (newClose) newClose.onclick = close;
}

function renderBody() {
  const body = document.getElementById('drawer-body');
  if (!body || !currentSession) return;

  const s = currentSession;
  const tls = s.tls || {};
  const cert = s.certificate || {};

  // 1. TLS facts panel
  const tlsHtml = `
    <div class="drawer-panel">
      <h3>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        TLS Facts
      </h3>
      <div class="detail-row">
        <div class="detail-item">
          <span class="detail-label">Offered &rarr; Negotiated</span>
          <span class="detail-value" style="font-family:var(--mono)">
            ${tls.offeredVersion || '—'} &rarr; ${tls.negotiatedVersion || '—'}
            ${renderTier(tierFor(s, 'tls.negotiated_version'))}
          </span>
        </div>
        <div class="detail-item">
          <span class="detail-label">Cipher Suite</span>
          <span class="detail-value" style="font-family:var(--mono);font-size:0.8rem">${tls.cipher || '—'} ${renderTier(tierFor(s, 'tls.cipher'))}</span>
        </div>
        <div class="detail-item">
          <span class="detail-label">Forward Secrecy</span>
          <span class="detail-value" style="font-weight:700;">
            ${tls.forwardSecrecyStatus || 'UNKNOWN'} ${renderTier(tierFor(s, 'tls.forward_secrecy'))}
          </span>
        </div>
        <div class="detail-item">
          <span class="detail-label">Key Exchange Group</span>
          <span class="detail-value" style="font-family:var(--mono)">${tls.group || '—'} ${renderTier(tierFor(s, 'tls.group'))}</span>
        </div>
        <div class="detail-item">
          <span class="detail-label">Post-Quantum Hybrid</span>
          <span class="detail-value" style="color:${tls.hybridPq ? 'var(--sev-low)' : 'var(--text-muted)'};font-weight:700;">
            ${tierFor(s, 'tls.hybrid_pq_flag')?.tier === 'NOT_OBSERVABLE' ? 'Unknown' : tls.hybridPq ? (tls.group && tls.group !== '—' ? `Yes (${escapeHtml(tls.group)})` : 'Yes') : 'No'} ${renderTier(tierFor(s, 'tls.hybrid_pq_flag'))}
          </span>
        </div>
      </div>
    </div>
  `;

  const downgradeHtml = tls.downgradeDelta > 0 || tls.hasFallbackScsv || tls.downgradeSentinel ? renderDowngradeEvidence(tls) : '';

  // 2. Certificate panel
  const certStatus = cert.status || 'NOT_OBSERVABLE';
  let certDetails = '';

  if (certStatus === 'NOT_OBSERVABLE') {
    certDetails = `
      <p style="font-size:0.85rem;color:var(--text-muted);font-style:italic;margin-top:8px;">
        ${escapeHtml(tls.negotiatedVersion === 'TLS1.3' ? 'TLS 1.3 encrypts the certificate. A passive tool cannot see it.' : cert.reason)}
      </p>
    `;
  } else {
    certDetails = `
      <div class="detail-row" style="margin-top:12px;">
        <div class="detail-item">
          <span class="detail-label">Public Key Bits</span>
          <span class="detail-value" style="font-family:var(--mono)">${cert.keyBits ? `${cert.keyBits} bits` : '—'}</span>
        </div>
        <div class="detail-item">
          <span class="detail-label">Signature Algorithm</span>
          <span class="detail-value" style="font-family:var(--mono)">${cert.sigAlg || '—'}</span>
        </div>
        <div class="detail-item">
          <span class="detail-label">Self-Signed</span>
          <span class="detail-value" style="color:${cert.selfSigned ? 'var(--sev-high)' : 'var(--text)'}">
            ${cert.selfSigned != null ? (cert.selfSigned ? 'Yes' : 'No') : '—'}
          </span>
        </div>
        <div class="detail-item">
          <span class="detail-label">Expired</span>
          <span class="detail-value" style="color:${cert.expired ? 'var(--sev-critical)' : 'var(--text)'}">
            ${cert.expired != null ? (cert.expired ? 'Yes (at capture time)' : 'No') : '—'}
          </span>
        </div>
      </div>
      <div class="detail-row" style="margin-top:8px;">
        <div class="detail-item">
          <span class="detail-label">Not Before</span>
          <span class="detail-value" style="font-family:var(--mono);font-size:0.8rem">${cert.notBefore || '—'}</span>
        </div>
        <div class="detail-item">
          <span class="detail-label">Not After</span>
          <span class="detail-value" style="font-family:var(--mono);font-size:0.8rem">${cert.notAfter || '—'}</span>
        </div>
      </div>
    `;
  }

  const certHtml = `
    <div class="drawer-panel">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <h3>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="7"/><polyline points="8.21 13.89 7 23 12 20 17 23 15.79 13.88"/></svg>
          Certificate
        </h3>
        <span class="cert-badge cert-${certStatus.toLowerCase()}">
          ${LOCK_SVG} ${certStatus}
        </span>
        ${renderTier(tierFor(s, 'certificate.status'))}
      </div>
      ${certDetails}
    </div>
  `;

  const tiersHtml = `
    <div class="drawer-panel">
      <h3>Epistemic fact tiers</h3>
      <div class="fact-tier-list">
        ${(s.factTiers || []).map(entry => `<div><code>${entry.fact}</code>${renderTier(entry)}</div>`).join('') || '<p class="muted">No fact tiers were provided by the report.</p>'}
      </div>
    </div>
  `;

  // 3. Findings panel
  let findingsListHtml = '';
  if (!s.findings || s.findings.length === 0) {
    findingsListHtml = `<p style="color:var(--text-muted);font-size:0.85rem">No findings for this session.</p>`;
  } else {
    findingsListHtml = s.findings.map((f, index) => {
      const sev = f.severity || 'info';
      const col = severityColor(sev);
      const refsHtml = f.references && f.references.length
        ? `<div class="finding-refs">${f.references.map(r => `<span class="finding-ref">${escapeHtml(r)}</span>`).join('')}</div>`
        : '';

      return `
        <div class="finding-card clickable" style="border-left-color:${col}" data-rule-id="${escapeHtml(f.ruleId)}" data-finding-index="${index}" role="button" tabindex="0">
          <div class="finding-header">
            <span class="rule-id-label">${escapeHtml(f.ruleId)}</span>
            ${renderTier({ tier: f.tier, reasonCode: null })}
            <span class="band-label">(${escapeHtml(f.confidenceBand)})</span>
          </div>
          <div class="finding-body">
            <div class="finding-section">
              <div class="finding-section-label">What</div>
              <p>${escapeHtml(f.what)}</p>
            </div>
            <div class="finding-section">
              <div class="finding-section-label">Why</div>
              <p>${escapeHtml(f.why)}</p>
            </div>
            <div class="finding-section">
              <div class="finding-section-label">Severity</div>
              <span class="severity-chip ${escapeHtml(sev.toLowerCase())}">${escapeHtml(sev)}</span>
            </div>
            <div class="finding-section">
              <div class="finding-section-label">Fix</div>
              <p style="color:var(--text);font-weight:600;">${escapeHtml(f.fix)}</p>
            </div>
            <div class="finding-effort">
              Remediation effort: <strong>${escapeHtml(effortLabel(f.remediationEffort))}</strong>
            </div>
            ${refsHtml}
          </div>
        </div>
      `;
    }).join('');
  }

  const findingsHtml = `
    <div class="drawer-panel">
      <h3>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        Findings (${s.findings ? s.findings.length : 0})
      </h3>
      <div class="findings-list">
        ${findingsListHtml}
      </div>
    </div>
  `;

  // 4. Packet Ladder container
  const ladderHtml = `
    <div class="drawer-panel">
      <h3>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/><polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/><line x1="4" y1="4" x2="9" y2="9"/></svg>
        Packet Ladder
      </h3>
      <div id="packet-ladder-container">
        <div class="loading-indicator"><div class="spinner"></div><span>Loading packets…</span></div>
      </div>
    </div>
  `;

  const focusNotice = pendingFocus?.algorithm
    ? `<div class="drawer-focus-notice">${escapeHtml(pendingFocus.state)} · <code>${escapeHtml(pendingFocus.algorithm)}</code> · establishing frame ${pendingFocus.frame} in ${s.id}. The establishing packet is highlighted below.</div>`
    : '';
  body.innerHTML = `${focusNotice}${tlsHtml}${downgradeHtml}${certHtml}${tiersHtml}${findingsHtml}${ladderHtml}`;

  // A finding opens its exact evidence path. If packets are still loading,
  // the focus is applied as soon as the packet view arrives.
  body.querySelectorAll('.finding-card[data-rule-id]').forEach(card => {
    const activate = () => {
      const finding = s.findings[Number(card.dataset.findingIndex)];
      openFindingEvidence(finding);
    };
    card.addEventListener('click', activate);
    card.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        activate();
      }
    });
  });
}

async function loadAndRenderPacketLadder() {
  const container = document.getElementById('packet-ladder-container');
  if (!container || !currentSession) return;

  const requestedSessionId = currentSession.id;
  const requestedAnalysisId = currentAnalysisId;

  try {
    const raw = await api.getPackets(requestedAnalysisId, requestedSessionId);
    // A later drawer open may have replaced this request while it was in flight.
    if (!currentSession || currentSession.id !== requestedSessionId || currentAnalysisId !== requestedAnalysisId) return;

    packetData = mapPacketView(raw);

    if (packetData.unavailable) {
      renderLadderUnavailable(container, packetData.unavailableMessage);
      return;
    }

    renderLadder(container, packetData);
    applyPendingFocus();
  } catch (e) {
    if (!currentSession || currentSession.id !== requestedSessionId || currentAnalysisId !== requestedAnalysisId) return;
    renderLadderUnavailable(container, `Error loading packets: ${e.message}`);
  }
}

function renderLadderUnavailable(container, message) {
  const notice = document.createElement('div');
  notice.className = 'ladder-unavailable';
  notice.textContent = message;
  container.replaceChildren(notice);
}

function renderLadder(container, pData) {
  if (!pData.frames || pData.frames.length === 0) {
    container.innerHTML = `<div class="ladder-unavailable">No frames available</div>`;
    return;
  }

  let html = `
    <div class="packet-ladder">
      <div class="ladder-header">
        <span>CLIENT (${escapeHtml(pData.client)})</span>
        <span>SERVER (${escapeHtml(pData.server)})</span>
      </div>
      <div class="ladder-lanes">
  `;

  pData.frames.forEach(f => {
    const isC2S = f.dir === 'c2s';
    const layerClass = `layer-${(f.layer || 'tcp').toLowerCase()}`;
    const hasEvidence = f.evidenceRules && f.evidenceRules.length > 0;
    const rulesStr = (f.evidenceRules || []).join(',');

    let ruleTags = '';
    let borderStyle = '';
    if (hasEvidence) {
      f.evidenceRules.forEach(r => {
        ruleTags += `<span class="rule-tag evidence-rule">${r}</span>`;
      });
      borderStyle = `border-color:var(--text);background:var(--highlight);`;
    }

    const arrowSymbol = isC2S ? '&rarr;' : '&larr;';
    const arrowContent = isC2S
      ? `<span class="arrow-line ${layerClass}"></span><span class="arrow-label" style="${borderStyle}">#${f.frame} +${f.tMs}ms ${escapeHtml(f.summary)} ${arrowSymbol} ${ruleTags}</span>`
      : `<span class="arrow-label" style="${borderStyle}">${arrowSymbol} #${f.frame} +${f.tMs}ms ${escapeHtml(f.summary)} ${ruleTags}</span><span class="arrow-line ${layerClass}"></span>`;

    html += `
      <div class="ladder-frame ${isC2S ? 'c2s' : 's2c'} ${hasEvidence ? 'evidence' : ''}"
           data-frame="${f.frame}"
           data-rules="${rulesStr}"
           title="Length: ${f.len} bytes | Layer: ${f.layer}">
        <div class="arrow-container">
          ${arrowContent}
        </div>
      </div>
    `;
  });

  html += `
      </div>
    </div>
  `;

  container.innerHTML = html;

  container.querySelectorAll('.ladder-frame.evidence').forEach(el => {
    el.style.cursor = 'pointer';
    el.tabIndex = 0;
    el.setAttribute('role', 'button');
    el.onkeydown = event => {
      if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); el.click(); }
    };
    el.addEventListener('click', () => {
      const frameNum = parseInt(el.dataset.frame, 10);
      const evObj = pData.evidence.find(e => e.frame === frameNum);
      if (evObj) {
        const finding = currentSession?.findings?.find(item => item.ruleId === evObj.ruleId) || null;
        openEvidence(evObj, pData.wiresharkFilter, finding);
      }
    });
  });
}

function highlightEvidenceFrames(ruleId) {
  const container = document.getElementById('packet-ladder-container');
  if (!container) return;

  const frames = container.querySelectorAll(`.ladder-frame[data-rules*="${ruleId}"]`);
  if (frames.length > 0) {
    frames[0].scrollIntoView({ behavior: 'smooth', block: 'center' });
    frames.forEach(f => {
      f.classList.remove('glow');
      void f.offsetWidth; // re-flow
      f.classList.add('glow');
    });
  }
}

function openFindingEvidence(finding) {
  if (!finding) return;
  if (!packetData) {
    pendingFocus = { ruleId: finding.ruleId, finding };
    return;
  }
  const evidence = packetData.evidence.find(item => item.ruleId === finding.ruleId);
  if (!evidence) {
    pendingFocus = { ruleId: finding.ruleId, finding };
    highlightEvidenceFrames(finding.ruleId);
    return;
  }
  highlightEvidenceFrames(finding.ruleId);
  openEvidence(evidence, packetData.wiresharkFilter, finding);
}

function applyPendingFocus() {
  if (!pendingFocus || !packetData) return;

  if (pendingFocus.ruleId) {
    const finding = pendingFocus.finding || currentSession?.findings?.find(item => item.ruleId === pendingFocus.ruleId);
    const evidence = packetData.evidence.find(item => item.ruleId === pendingFocus.ruleId);
    highlightEvidenceFrames(pendingFocus.ruleId);
    if (evidence) openEvidence(evidence, packetData.wiresharkFilter, finding || null);
    pendingFocus = null;
    return;
  }

  if (pendingFocus.frame != null) {
    const row = document.querySelector(`.ladder-frame[data-frame="${pendingFocus.frame}"]`);
    if (row) {
      row.classList.add('establishing-frame');
      row.tabIndex = 0;
      row.focus({ preventScroll: true });
      row.scrollIntoView({ block: 'center' });
    }
    pendingFocus = null;
  }
}

export function openEvidence(ev, wiresharkFilter = '', finding = null) {
  const overlay = document.getElementById('evidence-overlay');
  const body = document.getElementById('evidence-body');
  const title = document.getElementById('evidence-title');

  if (!overlay || !body) return;

  if (title) title.textContent = `Evidence: ${ev.ruleId} (Frame #${ev.frame})`;

  let contentHtml = finding ? `
    <div class="evidence-finding-summary">
      <div><span>What</span><p>${escapeHtml(finding.what)}</p></div>
      <div><span>Why</span><p>${escapeHtml(finding.why)}</p></div>
      <div><span>Severity</span><p><span class="severity-chip ${escapeHtml(finding.severity.toLowerCase())}">${escapeHtml(finding.severity)}</span></p></div>
      <div><span>Fix</span><p>${escapeHtml(finding.fix)}</p></div>
      <div><span>Remediation effort</span><p>${escapeHtml(effortLabel(finding.remediationEffort))}</p></div>
    </div>
  ` : '';

  contentHtml += `
    <div class="evidence-info">
      <div><span class="ei-label">Frame:</span> <span class="ei-value">${ev.frame}</span></div>
      <div><span class="ei-label">Field:</span> <span class="ei-value">${escapeHtml(ev.field)}</span></div>
      <div><span class="ei-label">Offset:</span> <span class="ei-value">${ev.byteOffset}</span></div>
      <div><span class="ei-label">Length:</span> <span class="ei-value">${ev.byteLength} bytes</span></div>
    </div>
  `;

  if (ev.redacted || ev.withheldBytes > 0) {
    const withheld = ev.withheldBytes == null ? '' : ` (${ev.withheldBytes} bytes)`;
    const notice = ev.field === 'cleartext-auth'
      ? `Credential bytes withheld${withheld}`
      : `Evidence bytes withheld${withheld}`;
    contentHtml += `
      <div class="evidence-redacted">
        ${LOCK_SVG}
        <span>[REDACTED] — ${escapeHtml(notice)}${ev.reason ? `: ${escapeHtml(ev.reason)}` : ''}</span>
      </div>
    `;
  }
  if (ev.hexWindow) {
    contentHtml += renderHexViewer(ev.hexWindow, ev.asciiWindow, ev.byteOffset, ev.highlight);
  }

  const wsFilter = wiresharkFilterForFrame(wiresharkFilter, ev.frame);
  contentHtml += `
    <div style="margin-top:16px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">
      <span style="font-family:var(--mono);font-size:0.78rem;color:var(--text-muted)">Wireshark Filter: ${escapeHtml(wsFilter)}</span>
      <button class="btn btn-secondary wireshark-btn" id="copy-ws-filter">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        Copy Wireshark filter
      </button>
    </div>
  `;

  body.innerHTML = contentHtml;
  overlay.hidden = false;

  const copyWs = body.querySelector('#copy-ws-filter');
  if (copyWs) {
    copyWs.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(wsFilter); }
      catch (_) { copyWs.textContent = 'Clipboard unavailable'; return; }
      copyWs.innerHTML = `<span>Copied to clipboard</span>`;
      setTimeout(() => {
        copyWs.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy Wireshark filter`;
      }, 1500);
    });
  }
}

function renderHexViewer(hexWindow, asciiWindow, byteOffset, highlight) {
  const bytes = hexWindow.trim().split(/\s+/);
  const [hlStart, hlEnd] = Array.isArray(highlight) && highlight.length === 2 ? highlight : [-1, -1];

  let rowsHtml = '';
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const rowOffset = (byteOffset - Math.max(0, hlStart) + i).toString(16).padStart(4, '0').toUpperCase();

    let hexCols = '';
    let asciiCols = '';

    for (let j = 0; j < chunk.length; j++) {
      const byteIdx = i + j;
      const b = chunk[j];
      const isHl = byteIdx >= hlStart && byteIdx < hlEnd;
      const char = escapeHtml(asciiWindow[byteIdx] || '.');

      if (isHl) {
        hexCols += `<span class="hex-highlight">${b}</span> `;
        asciiCols += `<span class="hex-highlight">${char}</span>`;
      } else {
        hexCols += `${b} `;
        asciiCols += char;
      }
    }

    rowsHtml += `
      <div class="hex-row">
        <span class="hex-offset">0x${rowOffset}</span>
        <span class="hex-bytes">${hexCols}</span>
        <span class="hex-ascii">${asciiCols}</span>
      </div>
    `;
  }

  return `<div class="hex-grid">${rowsHtml}</div>`;
}

export function closeEvidence() {
  const overlay = document.getElementById('evidence-overlay');
  if (overlay) overlay.hidden = true;
}

function renderDowngradeEvidence(tls) {
  const signals = [];
  if (tls.hasFallbackScsv) signals.push('<li>Fallback SCSV (0x5600) is present in the ClientHello cipher list.</li>');
  if (tls.downgradeSentinel) signals.push(`<li>${escapeHtml(sentinelLabel(tls))}.</li>`);
  return `
    <div class="drawer-panel downgrade-panel">
      <h3>Negotiation signals</h3>
      <div class="downgrade-delta">Delta <strong>${tls.downgradeDelta ?? '—'}</strong></div>
      ${signals.length ? `<ul>${signals.join('')}</ul>` : '<p>No corroborating Fallback SCSV or downgrade sentinel is present in the report.</p>'}
      ${tls.downgradeAnomaly ? '<div class="composite-signal">Engine-reported downgrade anomaly</div>' : ''}
    </div>
  `;
}

function renderTier(entry) {
  if (!entry || !entry.tier || entry.tier === '—') return '';
  const css = entry.tier.toLowerCase().replace(/_/g, '-');
  const tooltip = entry.tier === 'NOT_OBSERVABLE'
    ? (entry.reasonCode || 'Absent: fact_reason_codes entry')
    : entry.tier;
  return `<span class="tier-badge tier-${css}" title="${escapeHtml(tooltip)}">${entry.tier}</span>${entry.tier === 'NOT_OBSERVABLE' ? `<small class="fact-reason">${escapeHtml(tooltip)}</small>` : ''}`;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}

function wiresharkFilterForFrame(filter, frame) {
  const fallback = `frame.number == ${frame}`;
  if (!filter || filter === '—') return fallback;
  if (/frame\.number\s*==\s*\d+/.test(filter)) {
    return filter.replace(/frame\.number\s*==\s*\d+/, `frame.number == ${frame}`);
  }
  return `${filter} && ${fallback}`;
}
