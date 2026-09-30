/** API-driven capture library. Registry copy and measurements stay authoritative. */
import * as api from '../api.js';
let selectedCapture = null;
let selectCallback = null;
let uploadedId = null;

export async function init() {
  const grid = document.getElementById('capture-grid');
  const uploadContainer = document.getElementById('upload-zone-container');
  if (!uploadContainer.children.length) uploadContainer.append(createUploadDropzone());
  try {
    const captures = await api.listCaptures();
    grid.replaceChildren();
    const groups = new Map();
    for (const capture of captures) {
      const category = capture.category || 'Uncategorised';
      if (!groups.has(category)) groups.set(category, []);
      groups.get(category).push(capture);
    }
    for (const [category, entries] of groups) {
      const section = document.createElement('section');
      section.className = 'capture-library-section';
      const heading = document.createElement('h3');
      heading.textContent = category.charAt(0).toUpperCase() + category.slice(1);
      const cards = document.createElement('div');
      cards.className = 'capture-grid';
      for (const capture of entries) cards.append(createCaptureCard(capture));
      section.append(heading, cards);
      grid.append(section);
    }
    document.getElementById('library-actions').hidden = false;
  } catch (error) {
    const message = document.createElement('p');
    message.className = 'library-error';
    message.textContent = `Capture library unavailable. ${error.message}`;
    grid.replaceChildren(message);
  }
}

function createCaptureCard(capture) {
  const card = document.createElement('article');
  card.className = 'capture-card scenario-card';
  card.dataset.id = capture.id;
  card.tabIndex = 0;
  card.setAttribute('role', 'button');
  card.setAttribute('aria-label', `Analyse ${capture.file}`);
  const label = document.createElement('p');
  label.className = 'scenario-label';
  label.textContent = capture.file;
  const description = document.createElement('p');
  description.className = 'scenario-detail';
  description.textContent = capture.description || 'Registry description absent.';
  const counts = document.createElement('p');
  counts.className = 'capture-measurements';
  counts.textContent = `${capture.frames ?? 'Unreported'} frames · ${capture.sessions ?? 'Unreported'} sessions`;
  card.append(label, description, counts);
  card.addEventListener('click', () => selectCard(card, capture));
  card.addEventListener('keydown', event => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      selectCard(card, capture);
    }
  });
  return card;
}

function createUploadDropzone() {
  const zone = document.createElement('div');
  zone.className = 'upload-card';
  zone.id = 'upload-dropzone';
  zone.tabIndex = 0;
  zone.setAttribute('role', 'button');
  zone.setAttribute('aria-label', 'Choose a packet capture');
  zone.innerHTML = `
    <div id="upload-expanded" class="upload-expanded">
      <div class="upload-primary">Drop a .pcap or .pcapng capture here</div>
      <div class="upload-secondary">or choose a file from this computer</div>
    </div>
    <div id="upload-collapsed" class="upload-collapsed" hidden>
      <span id="upload-filename" class="upload-filename"></span>
      <span id="upload-sha" class="upload-sha"></span>
      <button id="upload-choose-another" class="upload-choose-another" type="button">choose another</button>
    </div>
    <input id="file-upload-input" type="file" accept=".pcap,.pcapng">
    <div id="upload-status" class="upload-status" role="status"></div>`;
  const input = zone.querySelector('input');
  zone.addEventListener('click', event => { if (event.target !== input) input.click(); });
  zone.addEventListener('keydown', event => {
    if ((event.key === 'Enter' || event.key === ' ') && event.target === zone) {
      event.preventDefault(); input.click();
    }
  });
  zone.addEventListener('dragover', event => { event.preventDefault(); zone.classList.add('dragover'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
  zone.addEventListener('drop', event => {
    event.preventDefault(); zone.classList.remove('dragover');
    if (event.dataTransfer.files[0]) handleUpload(event.dataTransfer.files[0], zone);
  });
  input.addEventListener('change', () => {
    if (input.files[0]) handleUpload(input.files[0], zone);
    input.value = '';
  });
  return zone;
}

async function handleUpload(file, zone) {
  const status = zone.querySelector('#upload-status');
  status.className = 'upload-status';
  status.textContent = `Uploading ${file.name}…`;
  try {
    if (!/\.(pcap|pcapng)$/i.test(file.name)) throw new Error('Only .pcap and .pcapng files are supported.');
    const capture = await api.upload(file);
    uploadedId = capture.id;
    zone.querySelector('#upload-expanded').hidden = true;
    zone.querySelector('#upload-collapsed').hidden = false;
    zone.querySelector('#upload-filename').textContent = capture.file;
    zone.querySelector('#upload-sha').textContent = `SHA-256 ${capture.sha256.slice(0, 16)}`;
    zone.classList.add('collapsed');
    status.textContent = '';
    selectCard(zone, capture);
  } catch (error) {
    status.textContent = error.message;
    status.className = 'upload-status upload-error';
  }
}

function selectCard(card, capture) {
  document.querySelectorAll('.capture-card, .upload-card').forEach(item => item.classList.remove('selected'));
  card.classList.add('selected');
  selectedCapture = capture;
  document.getElementById('analyse-btn').disabled = false;
  document.getElementById('analyse-btn-text').textContent = `Analyse ${capture.file}`;
  selectCallback?.(capture);
}
export function updateReportCapture(capture) {
  if (selectedCapture?.id === uploadedId) document.getElementById('upload-sha').textContent = `SHA-256 ${capture.sha256.slice(0, 16)}`;
}
export function getSelectedCapture() { return selectedCapture; }
export function onSelect(callback) { selectCallback = callback; }
