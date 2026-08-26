const $ = (selector) => document.querySelector(selector);
let state = {repositories: [], findings: [], summary: {total: 0, counts: {}, categories: {}}};

const colors = {critical: '#ff4d6d', high: '#ff8359', medium: '#f8c15c', low: '#73b7ff', info: '#929aa5'};
const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));

function render() {
  const counts = state.summary.counts || {};
  ['critical','high','medium','low'].forEach(level => $(`#${level}`).textContent = counts[level] || 0);
  $('#total').textContent = state.summary.total || 0;
  $('#nav-count').textContent = state.summary.total || 0;
  $('#repo-count').textContent = `${state.repositories.length} scanned`;
  $('#risk-label').textContent = counts.critical ? 'Critical exposure' : counts.high ? 'High risk detected' : state.summary.total ? 'Review recommended' : 'No active risk';
  $('#updated').textContent = state.repositories.length ? `Updated ${new Date(state.generated_at).toLocaleString()}` : 'Scan a repository to begin';
  renderChart(counts);
  renderRepositories();
  renderFindings();
}

function renderChart(counts) {
  const max = Math.max(1, ...Object.values(counts));
  $('#severity-chart').innerHTML = ['critical','high','medium','low','info'].map(level => `<div class="bar-row"><span>${level}</span><div class="bar-track"><div class="bar-fill" style="width:${(counts[level] || 0) / max * 100}%;background:${colors[level]}"></div></div><strong>${counts[level] || 0}</strong></div>`).join('');
}

function renderRepositories() {
  const target = $('#repo-list');
  if (!state.repositories.length) { target.className = 'repo-list empty-state'; target.textContent = 'No repositories scanned yet.'; return; }
  target.className = 'repo-list';
  target.innerHTML = state.repositories.map(repo => {
    const severe = repo.findings.filter(f => ['critical','high'].includes(f.severity)).length;
    return `<div class="repo-item"><span class="repo-name">${escapeHtml(repo.name)}</span><span class="repo-risk">${repo.findings.length} findings</span><span class="repo-meta">${repo.duration_ms} ms · ${severe} high priority</span></div>`;
  }).join('');
}

function filteredFindings() {
  const query = $('#search').value.toLowerCase();
  const severity = $('#severity-filter').value;
  return state.findings.filter(f => (severity === 'all' || f.severity === severity) && `${f.title} ${f.rule_id} ${f.path} ${f.repository}`.toLowerCase().includes(query));
}

function renderFindings() {
  const findings = filteredFindings();
  $('#findings-empty').classList.toggle('hidden', findings.length > 0);
  $('#finding-rows').innerHTML = findings.map(f => `<tr data-fingerprint="${escapeHtml(f.fingerprint)}"><td><span class="severity ${f.severity}">${f.severity}</span></td><td><strong>${escapeHtml(f.title)}</strong><div class="muted">${escapeHtml(f.rule_id)}</div></td><td>${escapeHtml(f.repository)}</td><td class="location">${escapeHtml(f.path)}:${f.line}</td><td>${escapeHtml(f.category)}</td></tr>`).join('');
  document.querySelectorAll('#finding-rows tr').forEach(row => row.addEventListener('click', () => openFinding(row.dataset.fingerprint)));
}

function openFinding(fingerprint) {
  const f = state.findings.find(item => item.fingerprint === fingerprint);
  if (!f) return;
  $('#dialog-rule').textContent = f.rule_id;
  $('#dialog-title').textContent = f.title;
  $('#dialog-severity').className = `severity ${f.severity}`;
  $('#dialog-severity').textContent = f.severity;
  $('#dialog-location').textContent = `${f.repository} · ${f.path}:${f.line}`;
  $('#dialog-description').textContent = f.description;
  $('#dialog-remediation').textContent = f.remediation || 'Review the affected code and remove the unsafe pattern.';
  $('#dialog-fingerprint').textContent = f.fingerprint;
  $('#finding-dialog').showModal();
}

async function refresh() {
  const response = await fetch('/api/state');
  state = await response.json();
  render();
}

$('#scan-toggle').addEventListener('click', () => $('#scan-form').classList.toggle('hidden'));
$('#scan-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button');
  button.disabled = true; button.textContent = 'Scanning…'; $('#scan-message').textContent = '';
  try {
    const response = await fetch('/api/scan', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({repository:$('#repository').value})});
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || 'Scan failed');
    state = payload.state; render(); $('#scan-message').textContent = `Scanned ${payload.scan.name} in ${payload.scan.duration_ms} ms.`;
  } catch (error) { $('#scan-message').textContent = error.message; }
  finally { button.disabled = false; button.textContent = 'Run scan'; }
});
$('#search').addEventListener('input', renderFindings);
$('#severity-filter').addEventListener('change', renderFindings);
$('#dialog-close').addEventListener('click', () => $('#finding-dialog').close());
refresh().catch(error => { $('#updated').textContent = `Dashboard error: ${error.message}`; });
