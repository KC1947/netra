/** Local engine client. Failures stay failures; no synthetic report fallback. */
export const BASE_URL = '';
export const CONNECTION_HELP = 'Please retry. If this keeps happening, the service may be restarting.';
let _aiEnabled = true;
export function setAiEnabled(value) { _aiEnabled = !!value; }
export function getAiEnabled() { return _aiEnabled; }

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${BASE_URL}/api${path}`, { cache: 'no-store', ...options });
  } catch (_) {
    throw new Error(`Unable to connect to the analysis service. ${CONNECTION_HELP}`);
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || body.detail || `Engine request failed (${response.status}).`);
  }
  return response;
}
export async function health() {
  try { return await (await request('/health')).json(); }
  catch (error) { return { status: 'offline', message: error.message }; }
}
export const init = health;
export async function listCaptures() { return (await request('/captures')).json(); }
export async function upload(file) {
  const body = new FormData();
  body.append('file', file);
  return (await request('/captures/upload', { method: 'POST', body })).json();
}
export async function startAnalysis(captureId, ml = true) {
  return (await request('/analyses', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ capture_id: captureId, ml })
  })).json();
}
export function streamEvents(analysisId, onEvent) {
  const stream = new EventSource(`/api/analyses/${encodeURIComponent(analysisId)}/events`);
  stream.onmessage = event => {
    let data;
    try { data = JSON.parse(event.data); }
    catch (_) {
      stream.close();
      onEvent({ stage: 'ERROR', message: 'Engine sent an invalid progress event.' });
      return;
    }
    if (data.stage === 'DONE' || data.stage === 'ERROR') stream.close();
    onEvent(data);
  };
  stream.onerror = () => {
    stream.close();
    onEvent({ stage: 'ERROR', message: `Analysis connection interrupted. ${CONNECTION_HELP}` });
  };
  return { stop: () => stream.close() };
}
export async function getReport(analysisId) {
  return (await request(`/analyses/${encodeURIComponent(analysisId)}/report`)).json();
}
export async function getPackets(analysisId, sessionId) {
  const view = await (await request(`/analyses/${encodeURIComponent(analysisId)}/sessions/${encodeURIComponent(sessionId)}/packets`)).json();
  if (!Array.isArray(view.frames) || !Array.isArray(view.evidence)) throw new Error('Invalid packet view response.');
  return view;
}
export function exportUrl(analysisId, format) {
  return `/api/analyses/${encodeURIComponent(analysisId)}/export?format=${encodeURIComponent(format)}`;
}
// Download the engine's artifact unchanged; never save an error as a PDF.
export async function download(analysisId, format, filename) {
  const response = await request(`/analyses/${encodeURIComponent(analysisId)}/export?format=${format}`);
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement('a');
  link.href = url;
  link.download = `${filename.replace(/\.(pcap|pcapng)$/i, '')}.${format === 'cbom' ? 'cdx.json' : format}`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
