/**
 * analysis.js — Live analysis pipeline stepper view (M1…M9)
 */

import * as api from '../api.js';

const STAGES = [
  { id: 'M1', label: 'Ingest & TCP reassembly' },
  { id: 'M2', label: 'Protocol identification' },
  { id: 'M3', label: 'STARTTLS state machine' },
  { id: 'M4', label: 'TLS handshake analysis' },
  { id: 'M5', label: 'X.509 certificate checks' },
  { id: 'P3', label: 'Cross-session correlation' },
  { id: 'M6', label: 'Rule engine' },
  { id: 'M7', label: 'AI anomaly layer' },
  { id: 'M8', label: 'Scoring & HNDL' },
  { id: 'M9', label: 'Report' }
];

const CHECKMARK_SVG = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>`;

let currentStream = null;

export function init() {
  const stepper = document.getElementById('stepper');
  if (!stepper) return;

  stepper.innerHTML = '';

  STAGES.forEach(stage => {
    const step = document.createElement('div');
    step.className = 'step pending';
    step.dataset.stage = stage.id;

    step.innerHTML = `
      <div class="step-circle">${stage.id}</div>
      <div class="step-label">${stage.label}</div>
      <div class="step-detail"></div>
      <div class="step-time"></div>
      <div class="step-line"></div>
    `;
    stepper.appendChild(step);
  });

  const retryBtn = document.getElementById('pipeline-retry-btn');
  if (retryBtn) {
    retryBtn.addEventListener('click', () => {
      const btn = document.getElementById('analyse-btn');
      if (btn) btn.click();
    });
  }
}

export function reset() {
  if (currentStream && currentStream.stop) {
    currentStream.stop();
    currentStream = null;
  }

  const steps = document.querySelectorAll('.step');
  steps.forEach(step => {
    step.className = 'step pending';
    const detail = step.querySelector('.step-detail');
    const time = step.querySelector('.step-time');
    const circle = step.querySelector('.step-circle');
    if (detail) detail.textContent = '';
    if (time) time.textContent = '';
    if (circle) circle.innerHTML = step.dataset.stage;
  });

  const log = document.getElementById('pipeline-log');
  if (log) log.innerHTML = '';

  const errorContainer = document.getElementById('pipeline-error');
  if (errorContainer) errorContainer.hidden = true;
}

export async function run(captureId, ml = true) {
  const container = document.getElementById('pipeline-container');
  const empty = document.getElementById('pipeline-empty');
  const errorContainer = document.getElementById('pipeline-error');
  const subtitle = document.getElementById('analysis-subtitle');

  if (container) container.hidden = false;
  if (empty) empty.hidden = true;
  if (errorContainer) errorContainer.hidden = true;
  if (subtitle) subtitle.textContent = `Analysing capture: ${captureId}`;

  reset();

  const { analysis_id: analysisId } = await api.startAnalysis(captureId, ml);
  if (!analysisId) throw new Error('Engine did not return an analysis ID.');
  return new Promise((resolve, reject) => {
    currentStream = api.streamEvents(analysisId, event => {
      handleEvent(event, analysisId);
      if (event.stage === 'DONE') resolve(analysisId);
      if (event.stage === 'ERROR') reject(new Error(event.message || 'Analysis failed.'));
    });
  });
}

function handleEvent(event, analysisId) {
  const log = document.getElementById('pipeline-log');
  const errorContainer = document.getElementById('pipeline-error');

  if (event.stage && event.stage !== 'DONE' && event.stage !== 'ERROR') {
    const step = document.querySelector(`.step[data-stage="${event.stage}"]`);
    if (step) {
      const circle = step.querySelector('.step-circle');
      const detail = step.querySelector('.step-detail');
      const time = step.querySelector('.step-time');

      if (event.status === 'start') {
        step.className = 'step running';
      } else if (event.status === 'done') {
        step.className = 'step done';
        if (circle) circle.innerHTML = CHECKMARK_SVG;
        if (detail) detail.textContent = event.detail || '';
        if (time && event.t_ms != null) time.textContent = `+${event.t_ms}ms`;
      } else if (event.status === 'skipped') {
        step.className = 'step skipped';
        if (detail) detail.textContent = event.detail || 'Skipped';
      } else if (event.status === 'error') {
        step.className = 'step error';
        if (detail) detail.textContent = event.detail || 'Error';
      }
    }
  }

  if (log) {
    const line = document.createElement('div');
    line.className = 'log-line';

    if (event.status === 'done' || event.stage === 'DONE') line.classList.add('log-done');
    else if (event.status === 'error' || event.stage === 'ERROR') line.classList.add('log-error');
    else if (event.status === 'start') line.classList.add('log-start');

    const t_ms = event.t_ms != null ? event.t_ms : 0;
    const stageStr = event.stage || '';
    const labelStr = event.label || '';
    const statusStr = event.status || '';
    const detailStr = event.detail || event.message || '';

    if (event.stage === 'DONE') {
      line.textContent = `[ +${t_ms} ms ] Pipeline complete — analysis_id: ${event.analysis_id || analysisId}`;
    } else if (event.stage === 'ERROR') {
      line.textContent = `[ +${t_ms} ms ] ERROR: ${event.message || 'Pipeline failed'}`;
    } else {
      line.textContent = `[ +${t_ms} ms ] ${stageStr} ${labelStr} — ${statusStr} — ${detailStr}`;
    }

    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
  }

  if (event.stage === 'DONE' || (event.status === 'done' && event.stage === 'DONE')) {
    document.getElementById('analysis-subtitle').textContent = 'Analysis complete. Report available in Overview.';
  } else if (event.stage === 'ERROR' || event.status === 'error') {
    if (errorContainer) {
      errorContainer.hidden = false;
      const msg = document.getElementById('pipeline-error-msg');
      if (msg) msg.textContent = event.message || event.detail || 'Analysis pipeline encountered an error';
    }
  }
}

export function showError(message) {
  document.getElementById('pipeline-error').hidden = false;
  document.getElementById('pipeline-error-msg').textContent = message;
  document.getElementById('analysis-subtitle').textContent = 'Analysis failed — no result is available.';
}
