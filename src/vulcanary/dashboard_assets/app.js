const $ = (selector) => document.querySelector(selector);
let state = {repositories: [], findings: [], summary: {total: 0, counts: {}, categories: {}}};
const selectedFixes = new Set();
let appliedBatch = null;

const colors = {critical: '#ff4d6d', high: '#ff8359', medium: '#f8c15c', low: '#73b7ff', info: '#929aa5'};
const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));

function render() {
  const counts = state.summary.counts || {};
  ['critical','high','medium','low'].forEach(level => $(`#${level}`).textContent = counts[level] || 0);
  $('#total').textContent = state.summary.total || 0;
  $('#nav-count').textContent = state.summary.total || 0;
  $('#repo-count').textContent = `${state.repositories.length} watched`;
  $('#risk-label').textContent = counts.critical ? 'Forge at critical heat' : counts.high ? 'High heat detected' : state.summary.total ? 'Work the remediation queue' : 'Forge clear';
  $('#updated').textContent = state.repositories.length ? `Updated ${new Date(state.generated_at).toLocaleString()}` : 'Scan a repository to begin';
  renderChart(counts);
  renderRepositories();
  renderGovernance();
  renderFindings();
}

function renderGovernance() {
  const records = state.repositories.flatMap(repo => (repo.suppressions || []).map(item => ({...item, repository:repo.name})));
  const expiring = records.filter(item => item.status === 'expiring').length;
  const expired = records.filter(item => item.status === 'expired').length;
  const legacy = records.filter(item => item.status === 'legacy').length;
  $('#governance-count').textContent = records.length;
  $('#governance-summary').textContent = `${records.length} exceptions · ${expiring} expiring · ${expired} expired`;
  $('#governance-register').innerHTML = records.map(item => {
    const blocked = ['expired','legacy'].includes(item.status) ? 'blocked' : '';
    const expiry = item.expires ? `expires ${item.expires}` : 'no expiration';
    return `<div class="fix-item ${blocked}"><strong>${escapeHtml(item.repository)} · ${escapeHtml(item.reason.replaceAll('_', ' '))}</strong><span>${escapeHtml(item.status.toUpperCase())} · ${escapeHtml(item.owner)} · ${escapeHtml(expiry)}</span><span>${escapeHtml(item.justification)}</span><span class="mono">${escapeHtml(item.fingerprint)}</span></div>`;
  }).join('') || '<p class="muted">No security exceptions are active. Findings follow normal remediation policy.</p>';
  const audit = state.suppression_audit || [];
  $('#governance-audit').innerHTML = audit.slice(0, 12).map(item => `<div class="fix-item"><strong>${escapeHtml(item.repository)} · ${escapeHtml(item.action)} exception</strong><span>${escapeHtml(item.owner)} · ${escapeHtml(item.reason)} · ${escapeHtml(item.expires || 'no expiration')}</span><span class="mono">${escapeHtml(item.fingerprint)} · ${escapeHtml(new Date(item.scanned_at).toLocaleString())}</span></div>`).join('') || '<p class="muted">No exception changes have been recorded yet.</p>';
}

function renderChart(counts) {
  const max = Math.max(1, ...Object.values(counts));
  $('#severity-chart').innerHTML = ['critical','high','medium','low','info'].map(level => `<div class="bar-row"><span>${level}</span><div class="bar-track"><div class="bar-fill" style="width:${(counts[level] || 0) / max * 100}%;background:${colors[level]}"></div></div><strong>${counts[level] || 0}</strong></div>`).join('');
}

function renderRepositories() {
  const target = $('#repo-list');
  if (!state.repositories.length) { target.className = 'repo-list empty-state'; target.textContent = 'No repositories under watch.'; return; }
  target.className = 'repo-list';
  target.innerHTML = state.repositories.map(repo => {
    const severe = repo.findings.filter(f => ['critical','high'].includes(f.severity)).length;
    const reachable = repo.findings.filter(f => ['direct_import_observed','parent_import_observed'].includes(f.metadata?.reachability?.status)).length;
    const parentCount = repo.findings.filter(f => f.metadata?.parent_packages?.length).length;
    const evaluate = parentCount ? `<button class="parent-evaluate secondary" data-repository="${escapeHtml(repo.repository)}" type="button">Evaluate ${parentCount} upgrade path${parentCount === 1 ? '' : 's'}</button>` : '';
    const platform = repo.findings.some(f => f.metadata?.parent_packages?.includes('expo')) ? `<button class="platform-evaluate secondary" data-repository="${escapeHtml(repo.repository)}" type="button">Evaluate Expo platform set</button><button class="platform-evaluate secondary" data-repository="${escapeHtml(repo.repository)}" data-migration="true" type="button">Evaluate next Expo SDK migration</button>` : '';
    const sbom = `<a class="secondary" href="/api/repositories/sbom?repository=${encodeURIComponent(repo.repository)}" download>Download SBOM</a>`;
    const changes = repo.inventory_change || {added:[],removed:[]};
    const inventoryLabel = changes.baseline ? `${changes.current_count || 0} components · baseline` : `${changes.current_count || 0} components · +${changes.added.length} / −${changes.removed.length}`;
    const inventoryButton = `<button class="inventory-change secondary" data-repository="${escapeHtml(repo.repository)}" type="button">Inventory changes</button>`;
    return `<div class="repo-item"><span class="repo-name">${escapeHtml(repo.name)}</span><span class="repo-risk">${repo.findings.length} findings</span><span class="repo-meta">${repo.duration_ms} ms · ${severe} high priority · ${reachable} import-observed · ${inventoryLabel}</span><div class="repo-actions">${sbom}${inventoryButton}${evaluate}${platform}</div></div>`;
  }).join('');
  document.querySelectorAll('.parent-evaluate').forEach(button => button.addEventListener('click', () => evaluateParents(button)));
  document.querySelectorAll('.platform-evaluate').forEach(button => button.addEventListener('click', () => evaluatePlatform(button)));
  document.querySelectorAll('.inventory-change').forEach(button => button.addEventListener('click', () => showInventoryChange(button.dataset.repository)));
}

function showInventoryChange(repository) {
  const repo = state.repositories.find(item => item.repository === repository);
  if (!repo) return;
  const change = repo.inventory_change || {baseline:true,current_count:0,added:[],removed:[]};
  $('#inventory-title').textContent = `${repo.name} dependency inventory`;
  $('#inventory-summary').textContent = change.baseline ? `Baseline established with ${change.current_count} components. Future scans will be compared with this snapshot.` : `${change.previous_count} → ${change.current_count} components · ${change.added.length} added · ${change.removed.length} removed`;
  const renderItems = (items, label, className) => items.map(item => `<div class="fix-item ${className}"><strong>${escapeHtml(item.name)} ${escapeHtml(item.version)}</strong><span>${label} · ${escapeHtml(item.ecosystem)} · ${item.direct ? 'direct' : 'transitive'}</span><span class="mono">${escapeHtml(item.ref)}</span></div>`).join('');
  $('#inventory-results').innerHTML = renderItems(change.added, 'ADDED', '') + renderItems(change.removed, 'REMOVED', 'blocked') || '<p class="muted">No dependency inventory changes since the previous scan.</p>';
  $('#inventory-dialog').showModal();
}

async function evaluatePlatform(button) {
  button.disabled = true;
  const original = button.textContent;
  button.textContent = 'Testing platform…';
  try {
    const body = await postJson('/api/platform/evaluate', {repository:button.dataset.repository, migration:button.dataset.migration === 'true'});
    const item = body.evaluation;
    const labels = {safe_candidate:'Safe platform candidate',verification_skipped:'Security pass · checks not configured',partial_improvement:'Partial improvement',still_vulnerable:'Still vulnerable',install_failed:'Dependency conflict',alignment_failed:'Expo alignment failed',worktree_failed:'Worktree failed',no_candidate:'No compatible candidate'};
    const checks = item.verification?.skipped ? ' Project checks not configured.' : item.verification?.passed ? ' Project checks passed.' : ' Project checks failed.';
    const outcome = item.resolved?.length ? `Clears ${item.resolved.length} of ${item.advisories.length} targeted advisories.${checks}` : checks;
    const migration = !item.is_migration && item.migration_candidate ? ` Expo ${item.migration_candidate} is available only as an explicit SDK migration.` : '';
    const mode = item.is_migration ? 'Explicit SDK migration' : 'Current SDK line';
    $('#parent-results').innerHTML = `<div class="fix-item ${item.status === 'safe_candidate' ? '' : 'blocked'}"><strong>Expo SDK set → ${escapeHtml(item.candidate_version || '—')}</strong><span>${escapeHtml(mode)} · ${escapeHtml(labels[item.status] || item.status)}</span><span class="mono">${escapeHtml(outcome + migration)} · ${escapeHtml((item.changed_files || []).join(' · '))}</span></div>`;
    $('#platform-downloads').classList.remove('hidden');
    $('#create-migration-branch').classList.toggle('hidden', !item.is_migration);
    $('#platform-message').textContent = '';
    $('#parent-dialog').showModal();
  } catch(error) { $('#scan-message').textContent = error.message; }
  finally { button.disabled = false; button.textContent = original; }
}

async function evaluateParents(button) {
  button.disabled = true;
  const original = button.textContent;
  button.textContent = 'Evaluating…';
  try {
    const body = await postJson('/api/parents/evaluate', {repository:button.dataset.repository});
    const labels = {safe_candidate:'Safe candidate',verification_skipped:'Security pass · checks not configured',verification_failed:'Project checks failed',partial_improvement:'Partial improvement',still_vulnerable:'Still vulnerable',install_failed:'Dependency conflict or migration required',worktree_failed:'Worktree failed',no_candidate:'No compatible candidate'};
    $('#parent-results').innerHTML = body.evaluation.results.map(item => { const outcome = item.resolved?.length ? ` · clears ${item.resolved.length} of ${item.advisories.length}` : ''; return `<div class="fix-item ${item.status === 'safe_candidate' ? '' : 'blocked'}"><strong>${escapeHtml(item.package)} ${escapeHtml(item.specification)} → ${escapeHtml(item.candidate_version || '—')}</strong><span>${escapeHtml(labels[item.status] || item.status)}${escapeHtml(outcome)}</span><span class="mono">Affects ${escapeHtml(item.vulnerable_packages.join(', '))} · ${escapeHtml(item.advisories.join(', '))}</span></div>`; }).join('') || '<p class="muted">No direct parent candidates were found.</p>';
    $('#platform-downloads').classList.add('hidden');
    $('#create-migration-branch').classList.add('hidden');
    $('#parent-dialog').showModal();
  } catch(error) { $('#scan-message').textContent = error.message; }
  finally { button.disabled = false; button.textContent = original; }
}

function filteredFindings() {
  const query = $('#search').value.toLowerCase();
  const severity = $('#severity-filter').value;
  return state.findings.filter(f => (severity === 'all' || f.severity === severity) && `${f.title} ${f.rule_id} ${f.path} ${f.repository}`.toLowerCase().includes(query));
}

function automaticFixStatus(finding) {
  const metadata = finding.metadata || {};
  if (metadata.fix_eligible) {
    return {label: 'Safe automatic fix', detail: `Upgrade ${metadata.package} to ${metadata.fixed_version}`};
  }
  if (finding.category !== 'dependency') {
    return {label: 'Manual code fix', detail: 'This finding requires a contextual source-code change'};
  }
  if (metadata.fix_block_reason) {
    const parents = metadata.parent_packages?.length ? ` Suggested parent${metadata.parent_packages.length === 1 ? '' : 's'}: ${metadata.parent_packages.join(', ')}.` : '';
    return {label: metadata.direct ? 'Manual dependency fix' : 'Parent upgrade required', detail: `${metadata.fix_block_reason}.${parents}`.replace('..', '.')};
  }
  if (metadata.ecosystem && metadata.ecosystem !== 'npm') {
    return {label: 'Manual dependency fix', detail: `Automatic upgrades do not yet support ${metadata.ecosystem}`};
  }
  if (!metadata.fixed_version) {
    return {label: 'No safe version available', detail: 'The advisory does not identify a patched release yet'};
  }
  return {label: 'Major upgrade review', detail: `The fix requires upgrading to ${metadata.fixed_version} and may contain breaking changes`};
}

function reachabilityStatus(finding) {
  const reachability = finding.metadata?.reachability;
  if (!reachability) return '';
  const observed = ['direct_import_observed','parent_import_observed'].includes(reachability.status);
  const label = observed ? 'IMPORT OBSERVED' : 'IMPORT NOT OBSERVED';
  const paths = reachability.evidence_paths?.length ? ` ${reachability.evidence_paths.join(', ')}` : '';
  return `<div class="fix-unavailable" title="${escapeHtml(reachability.reason)}"><span>${label}</span>${escapeHtml(paths)}</div>`;
}

function renderFindings() {
  const findings = filteredFindings();
  $('#findings-empty').classList.toggle('hidden', findings.length > 0);
  $('#finding-rows').innerHTML = findings.map(f => {
    const eligible = Boolean(f.metadata?.fix_eligible);
    const checked = selectedFixes.has(f.fingerprint) ? 'checked' : '';
    const fixStatus = automaticFixStatus(f);
    const reason = eligible ? `Select ${fixStatus.detail}` : `${fixStatus.label}: ${fixStatus.detail}`;
    const manualStatus = eligible ? '' : `<div class="fix-unavailable" title="${escapeHtml(fixStatus.detail)}"><span>${escapeHtml(fixStatus.label)}</span> · ${escapeHtml(fixStatus.detail)}</div>`;
    return `<tr data-fingerprint="${escapeHtml(f.fingerprint)}"><td class="check-cell"><input class="fix-check" type="checkbox" aria-label="${escapeHtml(reason)}" title="${escapeHtml(reason)}" ${eligible ? '' : 'disabled'} ${checked}></td><td><span class="severity ${f.severity}">${f.severity}</span></td><td><strong>${escapeHtml(f.title)}</strong><div class="muted">${escapeHtml(f.rule_id)}</div>${reachabilityStatus(f)}${manualStatus}</td><td>${escapeHtml(f.repository)}</td><td class="location">${escapeHtml(f.path)}:${f.line}</td><td>${escapeHtml(f.category)}</td></tr>`;
  }).join('');
  document.querySelectorAll('#finding-rows tr').forEach(row => {
    row.addEventListener('click', event => { if (!event.target.classList.contains('fix-check')) openFinding(row.dataset.fingerprint); });
    const checkbox = row.querySelector('.fix-check');
    checkbox.addEventListener('change', () => { checkbox.checked ? selectedFixes.add(row.dataset.fingerprint) : selectedFixes.delete(row.dataset.fingerprint); updateFixBar(); });
  });
}

function updateFixBar() {
  $('#fix-bar').classList.toggle('hidden', selectedFixes.size === 0);
  $('#selected-count').textContent = `${selectedFixes.size} selected`;
}

async function postJson(url, payload = {}) {
  const response = await fetch(url, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || 'Request failed');
  return body;
}

function renderFixPlan(plan) {
  $('#fix-summary').textContent = `${plan.changes.length} safe upgrade${plan.changes.length === 1 ? '' : 's'} · ${plan.blocked.length} manual review`;
  $('#fix-plan').innerHTML = [...plan.changes.map(item => `<div class="fix-item"><strong>${escapeHtml(item.package)} ${escapeHtml(item.from)} → ${escapeHtml(item.to)}</strong><span>${escapeHtml(item.strategy === 'override' ? 'TRANSITIVE OVERRIDE' : 'DIRECT UPGRADE')}</span><span class="mono">${escapeHtml(item.advisories.join(', '))} · ${escapeHtml(item.files.join(' · '))}</span></div>`), ...plan.blocked.map(item => `<div class="fix-item blocked"><strong>${escapeHtml(item.title)}</strong><span>Manual</span><span class="mono">${escapeHtml(item.reason)}</span></div>`)].join('');
  $('#apply-fixes').disabled = plan.changes.length === 0;
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
  const reachability = f.metadata?.reachability;
  $('#dialog-reachability').textContent = reachability ? `${reachability.status.replaceAll('_', ' ')}. ${reachability.reason}${reachability.evidence_paths?.length ? ` Evidence: ${reachability.evidence_paths.join(', ')}` : ''}` : 'Not applicable to this finding.';
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
$('#clear-fixes').addEventListener('click', () => { selectedFixes.clear(); updateFixBar(); renderFindings(); });
$('#select-safe').addEventListener('click', () => { state.findings.filter(f => f.metadata?.fix_eligible).forEach(f => selectedFixes.add(f.fingerprint)); updateFixBar(); renderFindings(); });
$('#preview-fixes').addEventListener('click', async () => {
  $('#fix-message').textContent = '';
  try { const body = await postJson('/api/fixes/preview', {fingerprints:[...selectedFixes]}); renderFixPlan(body.plan); $('#fix-dialog').showModal(); }
  catch(error) { $('#fix-message').textContent = error.message; }
});
$('#fix-close').addEventListener('click', () => $('#fix-dialog').close());
$('#parent-close').addEventListener('click', () => $('#parent-dialog').close());
$('#inventory-close').addEventListener('click', () => $('#inventory-dialog').close());
$('#create-migration-branch').addEventListener('click', async () => {
  const button = $('#create-migration-branch');
  button.disabled = true; button.textContent = 'Creating draft branch…'; $('#platform-message').textContent = '';
  try {
    const body = await postJson('/api/platform/create-branch', {});
    const created = body.created;
    const files = created.changed_files?.length ? created.changed_files.join(' · ') : 'No tracked files changed';
    $('#parent-results').innerHTML = `<div class="fix-item"><strong>${escapeHtml(created.branch)}</strong><span>Draft created from ${escapeHtml(created.original_branch)} · Expo ${escapeHtml(created.candidate_version)}</span><span class="mono">Review with git diff · ${escapeHtml(files)}</span></div>`;
    $('#platform-message').textContent = 'Changes are uncommitted and have not been pushed. Review and repair project checks before committing.';
    button.classList.add('hidden');
  } catch(error) { $('#platform-message').textContent = error.message; button.disabled = false; button.textContent = 'Create draft migration branch'; }
});
$('#apply-fixes').addEventListener('click', async () => {
  const button = $('#apply-fixes'); button.disabled = true; button.textContent = 'Applying and rescanning…'; $('#fix-message').textContent = '';
  try {
    const body = await postJson('/api/fixes/apply', {fingerprints:[...selectedFixes]}); appliedBatch = body.applied;
    if (!appliedBatch.validation.passed) throw new Error(appliedBatch.diagnostic || `Validation failed and the fix was rolled back.`);
    $('#fix-message').textContent = `Applied on ${appliedBatch.branch}. Rescan passed with ${appliedBatch.validation.finding_count} remaining findings.`;
    $('#commit-fixes').classList.remove('hidden'); await refresh();
  } catch(error) { $('#fix-message').textContent = error.message; }
  finally { button.disabled = false; button.textContent = 'Apply to working tree'; }
});
$('#commit-fixes').addEventListener('click', async () => {
  const button = $('#commit-fixes'); button.disabled = true; button.textContent = 'Committing…';
  try { const body = await postJson('/api/fixes/commit'); $('#fix-message').textContent = `Committed ${body.committed.commit.slice(0, 8)} on ${body.committed.branch}.`; button.classList.add('hidden'); selectedFixes.clear(); updateFixBar(); }
  catch(error) { $('#fix-message').textContent = error.message; button.disabled = false; button.textContent = 'Commit verified fixes'; }
});
refresh().catch(error => { $('#updated').textContent = `Dashboard error: ${error.message}`; });
