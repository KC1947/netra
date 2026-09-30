/** Routing and lifecycle for the NETRA UI. */
import * as api from './api.js';
import { mapReport } from './model.js';
import * as library from './views/library.js';
import * as analysis from './views/analysis.js';
import * as overview from './views/overview.js';
import * as sessions from './views/sessions.js';
import * as drawer from './views/drawer.js';
import * as findings from './views/fixfirst.js';

const state = { capture: null, analysisId: null, report: null, ai: true, busy: false };

document.addEventListener('DOMContentLoaded', async () => {
  window.addEventListener('hashchange', () => navigateTo(location.hash.slice(1) || 'library'));
  document.querySelectorAll('.nav-item').forEach(link => link.addEventListener('click', event => {
    event.preventDefault(); navigateTo(link.dataset.section);
  }));
  drawer.setupListeners();
  analysis.init();
  library.onSelect(startAnalysisFlow);
  document.getElementById('analyse-btn').addEventListener('click', () => {
    const capture = library.getSelectedCapture();
    if (capture) startAnalysisFlow(capture);
  });
  document.getElementById('ai-checkbox').addEventListener('change', async event => {
    state.ai = event.target.checked;
    api.setAiEnabled(state.ai);
    if (state.capture) await startAnalysisFlow(state.capture);
  });
  sessions.onRowClick(session => drawer.open(session, state.analysisId));
  overview.onSupportEvidenceClick(focus => openSession(focus.sessionId, focus));
  findings.onFindingClick((sessionId, ruleId) => openSession(sessionId, { ruleId }));
  findings.onAISessionClick(sessionId => openSession(sessionId));
  setupExports();
  clearReport();
  updateHealth(await api.init());
  await library.init();
  navigateTo(location.hash.slice(1) || 'library');
});

function openSession(id, focus) {
  const session = state.report?.sessions.find(item => item.id === id);
  if (session) drawer.open(session, state.analysisId, focus);
}

export function navigateTo(sectionId) {
  const target = document.querySelector(`.section[id="${CSS.escape(sectionId)}"]`) ? sectionId : 'library';
  document.querySelectorAll('.section').forEach(section => {
    section.classList.toggle('section-active', section.id === target);
    section.style.display = section.id === target ? 'block' : 'none';
  });
  document.querySelectorAll('.nav-item').forEach(link => link.classList.toggle('active', link.dataset.section === target));
  if (location.hash !== `#${target}`) history.replaceState(null, '', `#${target}`);
  document.getElementById('main-content').scrollTop = 0;
  window.scrollTo(0, 0);
}

function notice(message) {
  const element = document.getElementById('app-status');
  element.textContent = message;
  element.hidden = !message;
}
function updateHealth(health) {
  const online = health.status === 'ok';
  document.getElementById('engine-label').textContent = online ? 'Engine online' : 'Service unavailable';
  document.getElementById('engine-pill').classList.toggle('offline', !online);
  document.getElementById('engine-pill').title = online ? 'Connected to the passive analysis service' : api.CONNECTION_HELP;
  if (!online) notice(`Unable to connect to the analysis service. ${api.CONNECTION_HELP}`);
}

function clearReport() {
  state.report = null;
  state.analysisId = null;
  document.getElementById('overview-content').hidden = true;
  document.getElementById('overview-empty').hidden = false;
  document.getElementById('overview-export-actions').hidden = true;
  sessions.render(null);
  findings.renderFixFirst(null);
  findings.renderAIQueue(null);
  findings.renderExport(null);
  document.querySelectorAll('a[id*="export-"][id$="-btn"]').forEach(link => {
    link.removeAttribute('href');
    link.classList.add('disabled');
    link.setAttribute('aria-disabled', 'true');
    link.title = 'Export unavailable until an analysis report is loaded.';
    link.tabIndex = -1;
  });
}

async function startAnalysisFlow(capture) {
  if (state.busy) { notice('Analysis in progress. Capture selection is unavailable until completion.'); return; }
  state.capture = capture;
  state.busy = true;
  drawer.close();
  clearReport();
  document.getElementById('ai-checkbox').disabled = true;
  document.getElementById('analyse-btn').disabled = true;
  document.getElementById('pipeline-retry-btn').disabled = true;
  notice(`Analysis in progress: ${capture.file}. No verdict is available yet.`);
  navigateTo('analysis');
  try {
    const id = await analysis.run(capture.id, state.ai);
    const report = mapReport(await api.getReport(id));
    state.analysisId = id;
    state.report = report;
    overview.render(report, id);
    sessions.render(report);
    findings.renderFixFirst(report);
    findings.renderAIQueue(report);
    findings.renderExport(id);
    library.updateReportCapture(report.capture);
    document.querySelectorAll('a[id*="export-"][id$="-btn"]').forEach(link => {
      const format = exportFormat(link);
      link.href = api.exportUrl(id, format);
      link.classList.remove('disabled');
      link.setAttribute('aria-disabled', 'false');
      link.title = `Download engine-generated ${format.toUpperCase()}`;
      link.tabIndex = 0;
    });
    updateHealth({ status: 'ok' });
    notice(report.summary.findingsAssessed ? '' : `NOT ANALYSED — ${report.captureHealth.analysisStatus}. Findings were not assessed. An empty result is not a clean verdict.`);
    navigateTo('overview');
  } catch (error) {
    analysis.showError(error.message);
    notice(`Analysis failed. No report is loaded. ${error.message}`);
    updateHealth(await api.health());
    navigateTo('analysis');
  } finally {
    state.busy = false;
    document.getElementById('ai-checkbox').disabled = false;
    document.getElementById('analyse-btn').disabled = false;
    document.getElementById('pipeline-retry-btn').disabled = false;
  }
}

function exportFormat(link) { return link.id.match(/export-(json|html|cbom|pdf)-btn/)[1]; }
function setupExports() {
  document.querySelectorAll('a[id*="export-"][id$="-btn"]').forEach(link => {
    link.addEventListener('click', async event => {
      event.preventDefault();
      if (!state.report || link.getAttribute('aria-disabled') === 'true') return;
      link.setAttribute('aria-busy', 'true');
      try { await api.download(state.analysisId, exportFormat(link), state.report.capture.filename); }
      catch (error) { notice(`Export failed: ${error.message}`); }
      finally { link.removeAttribute('aria-busy'); }
    });
  });
}
