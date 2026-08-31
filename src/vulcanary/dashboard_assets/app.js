const $ = (selector) => document.querySelector(selector);
let state = {repositories: [], findings: [], summary: {total: 0, counts: {}, categories: {}}};
const selectedFixes = new Set();
let appliedBatch = null;
let sourceProposalFingerprint = null;

const colors = {critical: '#ff4d6d', high: '#ff8359', medium: '#f8c15c', low: '#73b7ff', info: '#929aa5'};
const MIN_THREAT_SCALE = 10;
const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));

function render() {
  const counts = state.summary.counts || {};
  ['critical','high','medium','low'].forEach(level => $(`#${level}`).textContent = counts[level] || 0);
  $('#total').textContent = state.summary.total || 0;
  $('#nav-count').textContent = state.summary.total || 0;
  $('#repo-count').textContent = `${state.repositories.length} watched`;
  $('#risk-label').textContent = counts.critical ? 'Forge at critical heat' : counts.high ? 'High heat detected' : state.summary.total ? 'Work the remediation queue' : 'Forge clear';
  $('#updated').textContent = state.repositories.length ? `Updated ${new Date(state.generated_at).toLocaleString()}` : 'Scan a repository to begin';
  const ruleset = state.summary.ruleset;
  $('#ruleset-info').textContent = ruleset ? `${ruleset.rule_count} rules · ${ruleset.digest.slice(0, 10)}` : 'Ruleset unavailable';
  renderChart(counts);
  renderRepositories();
  renderLedger();
  renderGovernance();
  renderRemediationHistory();
  renderFilterOptions();
  renderFindings();
}

function renderLedger() {
  const history = state.history || [];
  $('#ledger-summary').textContent = `${history.length} scan${history.length === 1 ? '' : 's'} retained`;
  const previousByRepository = new Map();
  const entries = [...history].reverse().map(item => {
    const previous = previousByRepository.get(item.repository);
    previousByRepository.set(item.repository, item);
    return {...item, delta: previous ? item.finding_count - previous.finding_count : null};
  }).reverse().slice(0, 20);
  // vulcanary:ignore CODE-JS-INNERHTML owner=vulcanary-maintainers expires=2027-08-28 -- External ledger strings are escaped; remaining values are numeric or fixed labels.
  $('#ledger-list').innerHTML = entries.map(item => {
    const delta = item.delta === null ? 'BASELINE' : item.delta === 0 ? 'NO CHANGE' : item.delta > 0 ? `+${item.delta} OPEN` : `${Math.abs(item.delta)} CLEARED`;
    const deltaClass = item.delta === null || item.delta === 0 ? 'steady' : item.delta > 0 ? 'worse' : 'better';
    return `<div class="ledger-entry"><span class="ledger-mark ${deltaClass}" aria-hidden="true"></span><div><strong>${escapeHtml(item.name)}</strong><span>${escapeHtml(new Date(item.scanned_at).toLocaleString())}</span></div><div class="ledger-result"><strong>${item.finding_count} findings</strong><span>${item.duration_ms} ms · ${item.suppression_count || 0} exceptions</span></div><span class="ledger-delta ${deltaClass}">${escapeHtml(delta)}</span></div>`;
  }).join('') || '<p class="muted">The ledger begins after the first successful scan.</p>';
}

function renderFilterOptions() {
  const update = (selector, values, label) => {
    const target = $(selector); const selected = target.value;
    // vulcanary:ignore CODE-JS-INNERHTML owner=vulcanary-maintainers expires=2027-08-28 -- Option values are escaped and label is a fixed caller-owned noun.
    target.innerHTML = `<option value="all">All ${label}</option>` + values.map(value => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join('');
    target.value = values.includes(selected) ? selected : 'all';
  };
  update('#scanner-filter', Object.keys(state.summary.scanners || {}).sort(), 'scanners');
  update('#category-filter', Object.keys(state.summary.categories || {}).sort(), 'categories');
}

function renderGovernance() {
  const records = state.repositories.flatMap(repo => (repo.suppressions || []).map(item => ({...item, repository:repo.name})));
  const expiring = records.filter(item => item.status === 'expiring').length;
  const expired = records.filter(item => item.status === 'expired').length;
  const invalid = records.filter(item => ['invalid','legacy'].includes(item.status)).length;
  $('#governance-count').textContent = records.length;
  $('#governance-summary').textContent = `${records.length} exceptions · ${expiring} expiring · ${expired} expired · ${invalid} invalid`;
  // vulcanary:ignore CODE-JS-INNERHTML owner=vulcanary-maintainers expires=2027-08-28 -- Every exception field is escaped; CSS state is selected from a fixed allowlist.
  $('#governance-register').innerHTML = records.map(item => {
    const blocked = ['expired','legacy','invalid'].includes(item.status) ? 'blocked' : '';
    const expiry = item.expires ? `expires ${item.expires}` : 'no expiration';
    const source = item.path ? `${item.path}:${item.line} · ${item.rule_id}` : item.fingerprint;
    return `<div class="fix-item ${blocked}"><strong>${escapeHtml(item.repository)} · ${escapeHtml(item.reason.replaceAll('_', ' '))}</strong><span>${escapeHtml(item.status.toUpperCase())} · ${escapeHtml(item.owner)} · ${escapeHtml(expiry)}</span><span>${escapeHtml(item.justification)}</span><span class="mono">${escapeHtml(source)} · ${escapeHtml(item.fingerprint)}</span></div>`;
  }).join('') || '<p class="muted">No security exceptions are active. Findings follow normal remediation policy.</p>';
  const audit = state.suppression_audit || [];
  // vulcanary:ignore CODE-JS-INNERHTML owner=vulcanary-maintainers expires=2027-08-28 -- Every audit field is escaped and fallback markup is static.
  $('#governance-audit').innerHTML = audit.slice(0, 12).map(item => `<div class="fix-item"><strong>${escapeHtml(item.repository)} · ${escapeHtml(item.action)} exception</strong><span>${escapeHtml(item.owner)} · ${escapeHtml(item.reason)} · ${escapeHtml(item.expires || 'no expiration')}</span><span class="mono">${escapeHtml(item.fingerprint)} · ${escapeHtml(new Date(item.scanned_at).toLocaleString())}</span></div>`).join('') || '<p class="muted">No exception changes have been recorded yet.</p>';
}

function renderRemediationHistory() {
  const records = state.remediation_audit || [];
  const invalid = records.filter(item => !item.receipt_valid).length;
  const rolledBack = records.filter(item => item.action === 'rolled_back').length;
  $('#receipt-count').textContent = records.length;
  $('#receipt-summary').textContent = `${records.length} receipt${records.length === 1 ? '' : 's'} · ${rolledBack} rolled back · ${invalid} invalid`;
  // vulcanary:ignore CODE-JS-INNERHTML owner=vulcanary-maintainers expires=2027-08-28 -- Receipt fields are escaped, numeric counts are normalized, and download URLs contain validated proof hashes only.
  $('#receipt-list').innerHTML = records.slice(0, 20).map(item => {
    const status = item.receipt_valid ? (item.action === 'committed' ? 'COMMITTED' : item.action === 'rolled_back' ? 'ROLLED BACK' : 'VERIFIED') : 'INVALID PROOF';
    const blocked = item.receipt_valid && item.action !== 'rolled_back' ? '' : 'blocked';
    const checks = item.checks_skipped ? 'checks skipped' : item.checks_passed ? `${Number(item.checks?.length) || 0} checks passed` : 'project checks failed';
    const download = item.receipt_valid ? `<a class="secondary" href="/api/remediation/receipt.json?proof=${encodeURIComponent(item.proof)}" download>Download receipt</a>` : '';
    return `<div class="fix-item ${blocked}"><strong>${escapeHtml(item.repository)} · ${escapeHtml(status)}</strong><span>${escapeHtml(new Date(item.created_at).toLocaleString())} · ${escapeHtml(checks)} · ${Number(item.finding_count) || 0} findings remain</span><span>${escapeHtml((item.changed_files || []).join(' · ') || 'No tracked files')}</span><span class="mono">SHA-256 ${escapeHtml(item.proof || 'missing')}</span><div class="fix-actions">${download}</div></div>`;
  }).join('') || '<p class="muted">No remediation receipts yet. A receipt appears after a dashboard fix passes its rescan and project checks.</p>';
}

function renderChart(counts) {
  const normalized = Object.fromEntries(['critical','high','medium','low','info'].map(level => [level, Math.max(0, Number(counts[level]) || 0)]));
  const max = Math.max(MIN_THREAT_SCALE, ...Object.values(normalized));
  // vulcanary:ignore CODE-JS-INNERHTML owner=vulcanary-maintainers expires=2027-08-28 -- Severity names are fixed and all count values are normalized finite numbers.
  $('#severity-chart').innerHTML = ['critical','high','medium','low','info'].map(level => `<div class="bar-row"><span>${level}</span><progress class="threat-progress ${level}" max="${max}" value="${normalized[level]}" aria-label="${level}: ${normalized[level]}"></progress><strong>${normalized[level]}</strong></div>`).join('');
}

function renderRepositories() {
  const target = $('#repo-list');
  if (!state.repositories.length) { target.className = 'repo-list empty-state'; target.textContent = 'No repositories under watch.'; return; }
  target.className = 'repo-list';
  // vulcanary:ignore CODE-JS-INNERHTML owner=vulcanary-maintainers expires=2027-08-28 -- Repository strings are escaped or URL-encoded; counts and timing are backend numbers.
  target.innerHTML = state.repositories.map(repo => {
    const severe = repo.findings.filter(f => ['critical','high'].includes(f.severity)).length;
    const reachable = repo.findings.filter(f => ['direct_import_observed','parent_import_observed'].includes(f.metadata?.reachability?.status)).length;
    const parentCount = repo.findings.filter(f => f.metadata?.parent_packages?.length).length;
    const evaluate = parentCount ? `<button class="parent-evaluate secondary" data-repository="${escapeHtml(repo.repository)}" type="button">Evaluate ${parentCount} upgrade path${parentCount === 1 ? '' : 's'}</button>` : '';
    const platform = repo.findings.some(f => f.metadata?.parent_packages?.includes('expo')) ? `<button class="platform-evaluate secondary" data-repository="${escapeHtml(repo.repository)}" type="button">Evaluate Expo platform set</button><button class="platform-evaluate secondary" data-repository="${escapeHtml(repo.repository)}" data-migration="true" type="button">Evaluate next Expo SDK migration</button>` : '';
    const sbom = `<a class="secondary" href="/api/repositories/sbom?repository=${encodeURIComponent(repo.repository)}" download>Download SBOM</a>`;
    const spdx = `<a class="secondary" href="/api/repositories/spdx?repository=${encodeURIComponent(repo.repository)}" download>Download SPDX</a>`;
    const changes = repo.inventory_change || {added:[],removed:[]};
    const inventoryLabel = changes.baseline ? `${changes.current_count || 0} components · baseline` : `${changes.current_count || 0} components · +${changes.added.length} / −${changes.removed.length}`;
    const inventoryButton = `<button class="inventory-change secondary" data-repository="${escapeHtml(repo.repository)}" type="button">Inventory changes</button>`;
    const scanners = [...new Set(repo.findings.map(f => f.scanner))].sort().join(' · ');
    const owner = repo.policy?.owner || 'unassigned';
    const overdue = Number(repo.policy?.overdue_count) || 0;
    return `<div class="repo-item"><span class="repo-name">${escapeHtml(repo.name)}</span><span class="repo-risk">${repo.findings.length} findings</span><span class="repo-meta">Owner ${escapeHtml(owner)} · ${overdue} overdue · ${repo.duration_ms} ms · ${severe} high priority · ${reachable} import-observed · ${inventoryLabel} · ${escapeHtml(scanners || 'builtin')}</span><div class="repo-actions">${sbom}${spdx}${inventoryButton}${evaluate}${platform}</div></div>`;
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
  // vulcanary:ignore CODE-JS-INNERHTML owner=vulcanary-maintainers expires=2027-08-28 -- Inventory fields are escaped and labels/classes are fixed call-site constants.
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
    // vulcanary:ignore CODE-JS-INNERHTML owner=vulcanary-maintainers expires=2027-08-28 -- All evaluation response strings are escaped; class selection is boolean.
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
    // vulcanary:ignore CODE-JS-INNERHTML owner=vulcanary-maintainers expires=2027-08-28 -- All parent evaluation strings are escaped; class selection is boolean.
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
  const scanner = $('#scanner-filter').value;
  const category = $('#category-filter').value;
  const sort = $('#sort-findings').value;
  const severityRank = {critical:5,high:4,medium:3,low:2,info:1};
  const findings = state.findings.filter(f => (severity === 'all' || f.severity === severity) && (scanner === 'all' || f.scanner === scanner) && (category === 'all' || f.category === category) && `${f.title} ${f.rule_id} ${f.path} ${f.repository} ${f.scanner} ${f.category} ${f.metadata?.policy?.owner || ''}`.toLowerCase().includes(query));
  return findings.sort((left, right) => {
    if (sort === 'severity') return (severityRank[right.severity] || 0) - (severityRank[left.severity] || 0);
    if (sort === 'deadline') return String(left.metadata?.policy?.deadline || '9999').localeCompare(String(right.metadata?.policy?.deadline || '9999'));
    if (sort === 'fixability') return Number(Boolean(right.metadata?.fix_eligible)) - Number(Boolean(left.metadata?.fix_eligible));
    if (sort === 'repository') return left.repository.localeCompare(right.repository) || left.path.localeCompare(right.path);
    return (Number(right.metadata?.priority?.score) || 0) - (Number(left.metadata?.priority?.score) || 0);
  });
}

function automaticFixStatus(finding) {
  const metadata = finding.metadata || {};
  const recommendation = metadata.recommendation?.reason;
  if (metadata.fix_eligible) {
    return {label: 'Safe automatic fix', detail: recommendation || `Upgrade ${metadata.package} to ${metadata.fixed_version}`};
  }
  if (finding.category !== 'dependency') {
    return {label: 'Manual code fix', detail: 'This finding requires a contextual source-code change'};
  }
  if (metadata.fix_block_reason) {
    const parents = metadata.parent_packages?.length ? ` Suggested parent${metadata.parent_packages.length === 1 ? '' : 's'}: ${metadata.parent_packages.join(', ')}.` : '';
    return {label: metadata.direct ? 'Manual dependency fix' : 'Parent upgrade required', detail: recommendation || `${metadata.fix_block_reason}.${parents}`.replace('..', '.')};
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

function dependencyPathStatus(finding) {
  const paths = finding.metadata?.dependency_paths || [];
  if (!paths.length) return '';
  const first = paths[0].join(' → ');
  const additional = paths.length > 1 ? ` · +${paths.length - 1} path${paths.length === 2 ? '' : 's'}` : '';
  return `<div class="fix-unavailable" title="${escapeHtml(paths.map(path => path.join(' → ')).join('\n'))}"><span>DEPENDENCY PATH</span> ${escapeHtml(first + additional)}</div>`;
}

function priorityBadge(finding) {
  const priority = finding.metadata?.priority;
  if (!priority) return '<span class="priority unknown">Unscored</span>';
  return `<span class="priority ${escapeHtml(priority.level)}" title="${escapeHtml(priority.reason)}">${escapeHtml(priority.label)}</span><span class="priority-score">${priority.score}</span>`;
}

function deadlineBadge(finding) {
  const policy = finding.metadata?.policy;
  if (!policy) return '';
  const label = policy.status === 'overdue' ? 'OVERDUE' : policy.status === 'due_soon' ? 'DUE SOON' : `DUE ${new Date(policy.deadline).toLocaleDateString()}`;
  return `<span class="priority ${escapeHtml(policy.status)}" title="Owner ${escapeHtml(policy.owner)} · ${escapeHtml(policy.sla_days)} day SLA">${escapeHtml(label)}</span>`;
}

function renderFindings() {
  const findings = filteredFindings();
  $('#findings-empty').classList.toggle('hidden', findings.length > 0);
  // vulcanary:ignore CODE-JS-INNERHTML owner=vulcanary-maintainers expires=2027-08-28 -- Finding/API strings pass through escapeHtml; severity and control modes are fixed scanner enums.
  $('#finding-rows').innerHTML = findings.map(f => {
    const eligible = Boolean(f.metadata?.fix_eligible);
    const checked = selectedFixes.has(f.fingerprint) ? 'checked' : '';
    const fixStatus = automaticFixStatus(f);
    const reason = eligible ? `Select ${fixStatus.detail}` : `${fixStatus.label}: ${fixStatus.detail}`;
    const manualStatus = eligible ? '' : `<div class="fix-unavailable" title="${escapeHtml(fixStatus.detail)}"><span>${escapeHtml(fixStatus.label)}</span> · ${escapeHtml(fixStatus.detail)}</div>`;
    const hasParents = Boolean(f.metadata?.parent_packages?.length);
    const noPatchedRelease = f.category === 'dependency' && !f.metadata?.fixed_version;
    const control = eligible
      ? `<input class="fix-check" type="checkbox" aria-label="${escapeHtml(reason)}" title="${escapeHtml(reason)}" ${checked}>`
      : noPatchedRelease
        ? `<button class="fix-path secondary" type="button" disabled title="No patched release is available">No patch</button>`
        : `<button class="fix-path secondary" type="button" data-mode="${hasParents ? (f.metadata.parent_packages.includes('expo') ? 'platform' : 'parent') : 'code'}">${hasParents ? 'Evaluate' : 'Draft fix'}</button>`;
    return `<tr data-fingerprint="${escapeHtml(f.fingerprint)}"><td class="check-cell">${control}</td><td><span class="severity ${f.severity}">${f.severity}</span></td><td>${priorityBadge(f)}${deadlineBadge(f)}</td><td><strong>${escapeHtml(f.title)}</strong><div class="muted">${escapeHtml(f.rule_id)}</div>${dependencyPathStatus(f)}${reachabilityStatus(f)}${manualStatus}</td><td>${escapeHtml(f.repository)}</td><td class="location">${escapeHtml(f.path)}:${f.line}</td><td><span class="pill">${escapeHtml(f.scanner)}</span></td><td>${escapeHtml(f.category)}</td></tr>`;
  }).join('');
  document.querySelectorAll('#finding-rows tr').forEach(row => {
    row.addEventListener('click', event => { if (!event.target.classList.contains('fix-check') && !event.target.classList.contains('fix-path')) openFinding(row.dataset.fingerprint); });
    const checkbox = row.querySelector('.fix-check');
    if (checkbox) checkbox.addEventListener('change', () => { checkbox.checked ? selectedFixes.add(row.dataset.fingerprint) : selectedFixes.delete(row.dataset.fingerprint); updateFixBar(); });
    const fixPath = row.querySelector('.fix-path:not([disabled])');
    if (fixPath) fixPath.addEventListener('click', () => evaluateFindingFix(fixPath, row.dataset.fingerprint));
  });
}

async function evaluateFindingFix(button, fingerprint) {
  const finding = state.findings.find(item => item.fingerprint === fingerprint);
  if (!finding) return;
  if (button.dataset.mode === 'code') {
    button.disabled = true;
    button.textContent = 'Drafting…';
    try {
      const body = await postJson('/api/source/preview', {fingerprint});
      const proposal = body.proposal;
      sourceProposalFingerprint = fingerprint;
      $('#fix-summary').textContent = `${proposal.recipe.replaceAll('-', ' ')} · ${proposal.file}:${proposal.line}`;
      // vulcanary:ignore CODE-JS-INNERHTML owner=vulcanary-maintainers expires=2027-08-28 -- Proposal rule and diff are escaped before rendering.
      $('#fix-plan').innerHTML = `<div class="fix-item"><strong>Verified source recipe</strong><span>${escapeHtml(proposal.rule_id)}</span><pre class="source-diff">${escapeHtml(proposal.diff)}</pre></div>`;
      $('#fix-message').textContent = 'Review the exact diff. Application occurs on an isolated source-fix branch and must pass project checks plus a rescan.';
      $('#apply-fixes').disabled = false;
      $('#apply-fixes').textContent = 'Apply source draft';
      $('#commit-fixes').classList.add('hidden');
      $('#fix-dialog').showModal();
    } catch(error) { $('#scan-message').textContent = error.message; }
    finally { button.disabled = false; button.textContent = 'Draft fix'; }
    return;
  }
  const proxy = {disabled:false, textContent:'Evaluate', dataset:{repository:finding.repository_path}};
  if (button.dataset.mode === 'platform') await evaluatePlatform(proxy);
  else await evaluateParents(proxy);
}

async function evaluateAllBlocked() {
  const button = $('#evaluate-all');
  const blocked = state.findings.filter(finding => !finding.metadata?.fix_eligible);
  const repositories = [...new Set(blocked.map(finding => finding.repository_path))];
  const results = [];
  button.disabled = true;
  button.textContent = 'Evaluating…';
  $('#scan-message').textContent = `Evaluating ${blocked.length} blocked findings across ${repositories.length} repositories…`;
  try {
    for (const repository of repositories) {
      const repoFindings = blocked.filter(finding => finding.repository_path === repository);
      const expoFindings = repoFindings.filter(finding => finding.metadata?.parent_packages?.includes('expo'));
      const otherParents = [...new Set(repoFindings.flatMap(finding => finding.metadata?.parent_packages || []).filter(parent => parent !== 'expo'))];
      if (expoFindings.length) {
        const body = await postJson('/api/platform/evaluate', {repository, migration:false});
        const item = body.evaluation;
        results.push({title:`${repoFindings[0].repository} · Expo ${item.candidate_version || '—'}`, status:item.status, detail:item.resolved?.length ? `Resolves ${item.resolved.length} of ${item.advisories.length} targeted advisories` : 'No compatible resolving candidate'});
      }
      if (otherParents.length) {
        const body = await postJson('/api/parents/evaluate', {repository, packages:otherParents});
        body.evaluation.results.forEach(item => results.push({title:`${repoFindings[0].repository} · ${item.package} ${item.candidate_version || '—'}`, status:item.status, detail:item.resolved?.length ? `Resolves ${item.resolved.length} of ${item.advisories.length} advisories` : `Affects ${item.vulnerable_packages.join(', ')}`}));
      }
      const toolingCandidates = repoFindings.filter(finding => finding.metadata?.usage?.classification === 'tooling_path_via_runtime_parent' && finding.metadata?.fixed_version);
      if (toolingCandidates.length) {
        const body = await postJson('/api/overrides/evaluate', {repository});
        state = body.state;
        body.evaluation.results.forEach(item => results.push({
          title:`${repoFindings[0].repository} · ${item.parent} → ${item.package} ${item.candidate_version}`,
          status:item.status,
          detail:item.resolved?.length ? `Verified parent-scoped override resolves ${item.resolved.length} advisory` : 'Scoped override was not proven safe',
        }));
      }
      const noPatch = repoFindings.filter(finding => finding.category === 'dependency' && !finding.metadata?.fixed_version);
      if (noPatch.length) results.push({title:`${repoFindings[0].repository} · upstream patches`, status:'no_patch', detail:`${noPatch.length} finding${noPatch.length === 1 ? '' : 's'} have no patched release`});
      const source = repoFindings.filter(finding => finding.category !== 'dependency');
      if (source.length) results.push({title:`${repoFindings[0].repository} · source drafts`, status:'draft_required', detail:`${source.length} contextual code fix${source.length === 1 ? '' : 'es'} require a verified patch`});
    }
    const safeStatuses = new Set(['safe_candidate']);
    // vulcanary:ignore CODE-JS-INNERHTML owner=vulcanary-maintainers expires=2027-08-28 -- All aggregate evaluation strings are escaped; class selection uses a fixed status set.
    $('#parent-results').innerHTML = results.map(item => `<div class="fix-item ${safeStatuses.has(item.status) ? '' : 'blocked'}"><strong>${escapeHtml(item.title)}</strong><span>${escapeHtml(item.status.replaceAll('_', ' ').toUpperCase())}</span><span class="mono">${escapeHtml(item.detail)}</span></div>`).join('') || '<p class="muted">No blocked findings need evaluation.</p>';
    $('#platform-downloads').classList.add('hidden');
    $('#create-migration-branch').classList.add('hidden');
    $('#platform-message').textContent = 'Evaluation is isolated. Only candidates that pass project checks and rescanning are considered verified.';
    $('#parent-dialog').showModal();
    $('#scan-message').textContent = `Evaluated ${blocked.length} blocked findings.`;
  } catch(error) {
    $('#scan-message').textContent = `Evaluation stopped: ${error.message}`;
  } finally {
    button.disabled = false;
    button.textContent = 'Evaluate all blocked fixes';
  }
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
  // vulcanary:ignore CODE-JS-INNERHTML owner=vulcanary-maintainers expires=2027-08-28 -- Every fix-plan field is escaped and structural labels are static.
  $('#fix-plan').innerHTML = [...plan.changes.map(item => `<div class="fix-item"><strong>${escapeHtml(item.package)} ${escapeHtml(item.from)} → ${escapeHtml(item.to)}</strong><span>${escapeHtml(item.strategy === 'override' ? 'TRANSITIVE OVERRIDE' : 'DIRECT UPGRADE')}</span><span class="mono">${escapeHtml(item.advisories.join(', '))} · ${escapeHtml(item.files.join(' · '))}</span></div>`), ...plan.blocked.map(item => `<div class="fix-item blocked"><strong>${escapeHtml(item.title)}</strong><span>Manual</span><span class="mono">${escapeHtml(item.reason)}</span></div>`)].join('');
  $('#apply-fixes').disabled = plan.changes.length === 0;
  $('#fix-receipt').classList.add('hidden');
}

function renderRemediationReceipt(receipt) {
  const checks = receipt.checks_skipped ? 'No project checks configured' : `${receipt.checks.length} project check${receipt.checks.length === 1 ? '' : 's'} passed`;
  // vulcanary:ignore CODE-JS-INNERHTML owner=vulcanary-maintainers expires=2027-08-28 -- Receipt fields are escaped and boolean status labels are fixed locally.
  $('#fix-receipt').innerHTML = `<strong>Verification receipt</strong><span>Rescan passed · ${escapeHtml(checks)} · ${receipt.finding_count} findings remain</span><span>${escapeHtml(receipt.changed_files.join(' · ') || 'No tracked files')}</span><span class="mono">SHA-256 ${escapeHtml(receipt.proof)}</span>`;
  $('#fix-receipt').classList.remove('hidden');
}

function openFinding(fingerprint) {
  const f = state.findings.find(item => item.fingerprint === fingerprint);
  if (!f) return;
  $('#dialog-rule').textContent = f.rule_id;
  $('#dialog-title').textContent = f.title;
  $('#dialog-severity').className = `severity ${f.severity}`;
  $('#dialog-severity').textContent = f.severity;
  const priority = f.metadata?.priority;
  const policy = f.metadata?.policy;
  const deadline = policy ? ` Owner: ${policy.owner}. Deadline: ${new Date(policy.deadline).toLocaleDateString()} (${policy.status.replaceAll('_', ' ')}).` : '';
  $('#dialog-priority').textContent = (priority ? `${priority.label} (${priority.score}/100). ${priority.reason}` : 'Not scored.') + deadline;
  $('#dialog-scanner').textContent = `${f.scanner} · ${f.category}`;
  const confidence = f.metadata?.confidence || (f.scanner === 'builtin' ? 'high — deterministic local pattern' : 'scanner-reported');
  $('#dialog-confidence').textContent = confidence;
  $('#dialog-location').textContent = `${f.repository} · ${f.path}:${f.line}`;
  $('#dialog-description').textContent = f.description;
  $('#dialog-evidence').textContent = f.evidence || 'Evidence is unavailable or intentionally excluded.';
  $('#dialog-remediation').textContent = f.remediation || 'Review the affected code and remove the unsafe pattern.';
  const dependencyPaths = f.metadata?.dependency_paths || [];
  $('#dialog-dependency-path').textContent = dependencyPaths.length ? dependencyPaths.map(path => path.join(' → ')).join('\n') : f.category === 'dependency' ? 'Direct dependency or path unavailable.' : 'Not applicable.';
  const usage = f.metadata?.usage;
  $('#dialog-usage').textContent = usage ? `${usage.classification.replaceAll('_', ' ')}. ${usage.reason}` : 'Not classified.';
  const reachability = f.metadata?.reachability;
  $('#dialog-reachability').textContent = reachability ? `${reachability.status.replaceAll('_', ' ')}. ${reachability.reason}${reachability.evidence_paths?.length ? ` Evidence: ${reachability.evidence_paths.join(', ')}` : ''}` : 'Not applicable to this finding.';
  const exposure = f.metadata?.exposure;
  $('#dialog-exposure').textContent = exposure ? `${exposure.classification.replaceAll('_', ' ')}. ${exposure.reason}${exposure.route_paths?.length ? ` Route candidates: ${exposure.route_paths.join(', ')}.` : ''}${exposure.deployment_assets?.length ? ` Deploy assets: ${exposure.deployment_assets.join(', ')}.` : ''}` : 'Exposure remains unknown.';
  const recommendation = f.metadata?.recommendation;
  $('#dialog-recommendation').textContent = recommendation ? `${recommendation.action.replaceAll('_', ' ')}. ${recommendation.reason}` : 'Review the finding and choose the least disruptive verified remediation.';
  $('#dialog-fingerprint').textContent = f.fingerprint;
  $('#ticket-markdown').href = `/api/ticket.md?fingerprint=${encodeURIComponent(f.fingerprint)}`;
  $('#ticket-json').href = `/api/ticket.json?fingerprint=${encodeURIComponent(f.fingerprint)}`;
  $('#finding-dialog').showModal();
}

async function refresh({rescan = false} = {}) {
  const response = await fetch(rescan ? '/api/rescan' : '/api/state', rescan ? {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'
  } : undefined);
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || 'Refresh failed');
  state = rescan ? payload.state : payload;
  render();
}

$('#scan-toggle').addEventListener('click', () => $('#scan-form').classList.toggle('hidden'));
$('#scan-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button');
  button.disabled = true; button.textContent = 'Scanning…'; $('#scan-message').textContent = '';
  try {
    const reports = Object.fromEntries([
      ['semgrep', $('#semgrep-report').value.trim()], ['gitleaks', $('#gitleaks-report').value.trim()],
      ['trivy', $('#trivy-report').value.trim()], ['trivy-image', $('#trivy-image-report').value.trim()],
      ['checkov', $('#checkov-report').value.trim()],
    ].filter(([, path]) => path));
    const response = await fetch('/api/scan', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({repository:$('#repository').value,reports})});
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || 'Scan failed');
    state = payload.state; render(); $('#scan-message').textContent = `Scanned ${payload.scan.name} in ${payload.scan.duration_ms} ms.`;
  } catch (error) { $('#scan-message').textContent = error.message; }
  finally { button.disabled = false; button.textContent = 'Run scan'; }
});
$('#search').addEventListener('input', renderFindings);
$('#severity-filter').addEventListener('change', renderFindings);
$('#scanner-filter').addEventListener('change', renderFindings);
$('#category-filter').addEventListener('change', renderFindings);
$('#sort-findings').addEventListener('change', renderFindings);
$('#dialog-close').addEventListener('click', () => $('#finding-dialog').close());
$('#clear-fixes').addEventListener('click', () => { selectedFixes.clear(); updateFixBar(); renderFindings(); });
$('#select-safe').addEventListener('click', () => { state.findings.filter(f => f.metadata?.fix_eligible).forEach(f => selectedFixes.add(f.fingerprint)); updateFixBar(); renderFindings(); });
$('#evaluate-all').addEventListener('click', evaluateAllBlocked);
$('#preview-fixes').addEventListener('click', async () => {
  $('#fix-message').textContent = '';
  sourceProposalFingerprint = null;
  $('#apply-fixes').textContent = 'Apply to working tree';
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
    // vulcanary:ignore CODE-JS-INNERHTML owner=vulcanary-maintainers expires=2027-08-28 -- Every branch-creation response string is escaped.
    $('#parent-results').innerHTML = `<div class="fix-item"><strong>${escapeHtml(created.branch)}</strong><span>Draft created from ${escapeHtml(created.original_branch)} · Expo ${escapeHtml(created.candidate_version)}</span><span class="mono">Review with git diff · ${escapeHtml(files)}</span></div>`;
    $('#platform-message').textContent = 'Changes are uncommitted and have not been pushed. Review and repair project checks before committing.';
    button.classList.add('hidden');
  } catch(error) { $('#platform-message').textContent = error.message; button.disabled = false; button.textContent = 'Create draft migration branch'; }
});
$('#apply-fixes').addEventListener('click', async () => {
  const button = $('#apply-fixes'); button.disabled = true; button.textContent = 'Applying and rescanning…'; $('#fix-message').textContent = '';
  try {
    const body = sourceProposalFingerprint
      ? await postJson('/api/source/apply', {fingerprint:sourceProposalFingerprint})
      : await postJson('/api/fixes/apply', {fingerprints:[...selectedFixes]});
    appliedBatch = body.applied;
    if (!appliedBatch.validation.passed) throw new Error(appliedBatch.diagnostic || `Validation failed and the fix was rolled back.`);
    renderRemediationReceipt(appliedBatch.receipt);
    $('#fix-message').textContent = `Applied on ${appliedBatch.branch}. Rescan passed with ${appliedBatch.validation.finding_count} remaining findings.`;
    $('#commit-fixes').classList.remove('hidden'); await refresh();
  } catch(error) { $('#fix-message').textContent = error.message; }
  finally { button.disabled = false; button.textContent = sourceProposalFingerprint ? 'Apply source draft' : 'Apply to working tree'; }
});
$('#commit-fixes').addEventListener('click', async () => {
  const button = $('#commit-fixes'); button.disabled = true; button.textContent = 'Committing…';
  try { const body = await postJson('/api/fixes/commit'); $('#fix-message').textContent = `Committed ${body.committed.commit.slice(0, 8)} on ${body.committed.branch}. Proof ${body.committed.receipt.proof.slice(0, 12)} recorded.`; button.classList.add('hidden'); selectedFixes.clear(); updateFixBar(); }
  catch(error) { $('#fix-message').textContent = error.message; button.disabled = false; button.textContent = 'Commit verified fixes'; }
});
refresh({rescan: true}).catch(error => { $('#updated').textContent = `Dashboard error: ${error.message}`; });
