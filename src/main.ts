import './style.css';
import { ensureSignedIn, firebaseConfigured, loadSettings, type AppSettings } from './firebase';
import { createRedactor, probeNano, type NanoAvailability } from './ai/models';
import { runPipeline, type PipelineResult, type RunMode, type StageEvent } from './pipeline';
import { TokenVault } from './redact/vault';
import { deleteAudit, getAudit, listAudits, saveAudit, type SavedAudit } from './storage';
import { remediationScript } from './core';
import type { AuditFinding, Severity } from './ai/schemas';
import iosSample from '../samples/cisco-iosxe-branch.cfg?raw';
import panSample from '../samples/panos-edge-set.txt?raw';
import asaSample from '../samples/cisco-asa-edge.cfg?raw';
import junosSample from '../samples/junos-srx-set.txt?raw';
import fortiSample from '../samples/fortigate.conf?raw';

const SAMPLES: Record<string, string> = { ios: iosSample, pan: panSample, asa: asaSample, junos: junosSample, forti: fortiSample };
const MAX_INPUT_BYTES = 2 * 1024 * 1024;

const $ = <T extends HTMLElement>(id: string) => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`#${id} missing from index.html`);
  return el as T;
};
const raw = $<HTMLTextAreaElement>('raw');
const rawMeta = $<HTMLParagraphElement>('raw-meta');
const stagesEl = $<HTMLOListElement>('stages');
const summaryEl = $<HTMLDivElement>('summary');
const filtersEl = $<HTMLDivElement>('filters');
const findingsEl = $<HTMLDivElement>('findings');
const sanitizedEl = $<HTMLPreElement>('sanitized');
const vaultEl = $<HTMLDivElement>('vault-table');
const viewingEl = $<HTMLDivElement>('viewing');
const historyEl = $<HTMLUListElement>('history');
const receiptEl = $<HTMLParagraphElement>('receipt');
const reveal = $<HTMLInputElement>('reveal');
const saveBtn = $<HTMLButtonElement>('save');
const exportBtn = $<HTMLButtonElement>('export');
const scriptBtn = $<HTMLButtonElement>('script');
const runBtn = $<HTMLButtonElement>('run');
const cancelBtn = $<HTMLButtonElement>('cancel');
const prepBtn = $<HTMLButtonElement>('prep');
const dl = $<HTMLProgressElement>('dl');
const toastEl = $<HTMLDivElement>('toast');

const vault = new TokenVault();
let last: PipelineResult | null = null;
/** A saved report being viewed from history (its tokens do NOT belong to the current vault). */
let viewing: SavedAudit | null = null;
let running: AbortController | null = null;
let sevFilter: Severity | 'all' = 'all';

const STAGE_NAMES = ['Deterministic rules', 'On-device contextual redaction', 'Leak gate', 'Deep audit', 'Cross-check & local re-hydration'];
const SOURCE_LABEL: Record<string, string> = {
  on_device: 'ON-DEVICE · Gemini Nano',
  in_cloud: 'CLOUD · Gemini',
  local_rules: 'LOCAL · rules',
  skipped: 'SKIPPED',
};
const ORIGIN_LABEL: Record<string, string> = { cloud: 'Cloud Gemini', on_device: 'Gemini Nano', rule: 'Local rule' };
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

// ------------------------------------------------------------------ helpers
function esc(s: unknown): string {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

/** Whether placeholders may be re-hydrated right now (never for a saved report). */
const canReveal = () => reveal.checked && !viewing && !!last;

/** Escape, then highlight placeholders so users see exactly what was masked. */
function showText(s: string): string {
  const text = canReveal() ? vault.rehydrate(s) : s;
  return esc(text).replace(/&lt;([A-Z_]+)_(\d+)&gt;/g, '<mark class="tok" title="masked $1">&lt;$1_$2&gt;</mark>');
}

let toastTimer = 0;
function toast(msg: string, kind: 'ok' | 'warn' | 'bad' = 'ok') {
  toastEl.textContent = msg;
  toastEl.className = `toast ${kind}`;
  toastEl.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => (toastEl.hidden = true), 3200);
}

async function copyText(text: string, what: string) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    if (!ok) return toast(`Could not copy ${what}`, 'bad');
  }
  toast(`${what} copied${canReveal() ? ' — contains REAL values' : ''}`, canReveal() ? 'warn' : 'ok');
}

function download(name: string, content: string, type: string) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], { type }));
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

function updateRawMeta() {
  const v = raw.value;
  const lines = v ? v.split('\n').length : 0;
  rawMeta.textContent = `${lines.toLocaleString()} lines · ${v.length.toLocaleString()} chars · nothing is sent until you press Redact & audit`;
}

function setInput(text: string) {
  raw.value = text;
  updateRawMeta();
}

// ------------------------------------------------------------------ stages + boundary
function renderStage(e: StageEvent) {
  let li = stagesEl.querySelector<HTMLLIElement>(`li[data-stage="${e.stage}"]`);
  if (!li) {
    li = document.createElement('li');
    li.dataset.stage = String(e.stage);
    stagesEl.appendChild(li);
  }
  li.className = `stage ${e.status}`;
  li.innerHTML = `<div><strong>${e.stage} · ${STAGE_NAMES[e.stage]}</strong><span class="src src-${e.source}">${SOURCE_LABEL[e.source] ?? esc(e.source)}</span></div><p>${esc(e.message)}</p>`;
  setFlow(e);
}

/** Light up the privacy-boundary diagram as stages run. */
function setFlow(e: StageEvent) {
  const map: Record<number, number> = { 0: 1, 1: 2, 2: 3, 3: e.source === 'in_cloud' ? 4 : -1, 4: 5 };
  const idx = map[e.stage];
  document.querySelectorAll<HTMLLIElement>('.flow li').forEach((li) => {
    if (Number(li.dataset.flow) === idx) li.className = e.status === 'running' ? 'active' : e.status;
  });
  if (e.stage === 0 && e.status === 'running') {
    document.querySelectorAll<HTMLLIElement>('.flow li').forEach((li) => (li.className = li.dataset.flow === '0' ? 'done' : ''));
  }
  if (e.stage === 1 && e.source === 'skipped') document.querySelector<HTMLLIElement>('.flow li[data-flow="2"]')!.className = 'skipped';
}

function renderReceipt(r: PipelineResult | null) {
  const cloud = document.querySelector('.zone.cloud')!;
  if (!r) {
    receiptEl.textContent = 'Sanitized text only. Never secrets, IPs or names.';
    cloud.classList.remove('used', 'unused');
    return;
  }
  const masked = r.stats.deterministicTokens + r.stats.onDeviceTokens + r.stats.freeTextMasked;
  if (r.stats.cloudChars > 0 && r.stats.cloudFailed) {
    receiptEl.innerHTML = `Sent <strong>${r.stats.cloudChars.toLocaleString()}</strong> chars of sanitized text (<strong>${masked}</strong> values masked first), but the cloud request <strong>failed</strong>. The audit finished ${r.stats.auditSource === 'on_device' ? 'on Gemini Nano' : 'with local rules'}.`;
    cloud.classList.add('used');
    cloud.classList.remove('unused');
  } else if (r.stats.cloudChars > 0) {
    receiptEl.innerHTML = `Received <strong>${r.stats.cloudChars.toLocaleString()}</strong> chars of sanitized text · <strong>${masked}</strong> values masked before upload · leak gate <strong>passed</strong>`;
    cloud.classList.add('used');
    cloud.classList.remove('unused');
  } else {
    receiptEl.innerHTML = `<strong>Nothing left this device.</strong> ${r.leak.ok ? '' : 'Leak gate blocked the upload. '}${masked} values masked locally.`;
    cloud.classList.add('unused');
    cloud.classList.remove('used');
    document.querySelector<HTMLLIElement>('.flow li[data-flow="4"]')!.className = 'skipped';
  }
}

// ------------------------------------------------------------------ report rendering
function scoreRing(score: number): string {
  const c = 2 * Math.PI * 38;
  const cls = score >= 80 ? 'good' : score >= 50 ? 'mid' : 'bad';
  return `<div class="score ${cls}" role="img" aria-label="Security score ${score} out of 100">
    <svg viewBox="0 0 88 88" aria-hidden="true"><circle cx="44" cy="44" r="38" class="track"/><circle cx="44" cy="44" r="38" class="bar" stroke-dasharray="${((score / 100) * c).toFixed(1)} ${c.toFixed(1)}"/></svg>
    <span>${score}</span><small>/100</small></div>`;
}

function badges(f: AuditFinding): string {
  const out: string[] = [];
  if (f.origin) out.push(`<span class="badge origin-${f.origin}" title="Where this finding came from">${ORIGIN_LABEL[f.origin]}</span>`);
  if (f.confirmedBy) out.push(`<span class="badge ok" title="Independently confirmed by deterministic check ${esc(f.confirmedBy)}">✓ rule-confirmed</span>`);
  if (f.evidenceCheck === 'verified') out.push('<span class="badge ok" title="Every cited line exists in the sanitized config">✓ evidence verified</span>');
  if (f.evidenceCheck === 'partial') out.push('<span class="badge warn" title="Some cited lines were not found verbatim in the config">◐ evidence partial</span>');
  if (f.evidenceCheck === 'unverified') out.push('<span class="badge bad" title="The cited evidence was not found in the config — treat with caution">⚠ evidence not found</span>');
  return out.join('');
}

function findingHtml(f: AuditFinding): string {
  return `
    <article class="finding ${f.severity}" data-sev="${f.severity}">
      <header>
        <span class="sev ${f.severity}">${f.severity}</span>
        <h3>${esc(f.id)} · ${showText(f.title)}</h3>
        <span class="cat">${esc(f.category)}</span>
      </header>
      <div class="badges">${badges(f)}</div>
      <p class="why">${showText(f.why)}</p>
      <div class="cols">
        <div><h4>Evidence</h4><pre>${showText(f.evidence)}</pre></div>
        <div><h4>Fix <button class="ghost tiny" type="button" data-copy-fix="${esc(f.id)}">Copy</button></h4><pre>${showText(f.fix)}</pre></div>
      </div>
      ${f.reference ? `<p class="ref">${esc(f.reference)}</p>` : ''}
    </article>`;
}

function currentFindings(): AuditFinding[] {
  return viewing ? viewing.findings : last?.audit.findings ?? [];
}

function renderFilters(findings: AuditFinding[]) {
  if (!findings.length) {
    filtersEl.hidden = true;
    return;
  }
  const count = (s: Severity) => findings.filter((f) => f.severity === s).length;
  const btn = (key: Severity | 'all', label: string, n: number) =>
    `<button type="button" class="filter ${key}${sevFilter === key ? ' on' : ''}" data-filter="${key}" aria-pressed="${sevFilter === key}" ${n === 0 && key !== 'all' ? 'disabled' : ''}>${label} <b>${n}</b></button>`;
  filtersEl.innerHTML = btn('all', 'All', findings.length) + SEVERITIES.map((s) => btn(s, s, count(s))).join('');
  filtersEl.hidden = false;
}

function renderFindings() {
  const all = currentFindings();
  renderFilters(all);
  const shown = sevFilter === 'all' ? all : all.filter((f) => f.severity === sevFilter);
  findingsEl.innerHTML = all.length
    ? shown.map(findingHtml).join('') || '<p class="muted">No findings at this severity.</p>'
    : last || viewing
      ? '<p class="muted">No findings — this configuration passed every check.</p>'
      : '';
}

function render() {
  const hasReport = !!(last || viewing);
  saveBtn.disabled = !last || !!viewing || !firebaseConfigured;
  exportBtn.disabled = scriptBtn.disabled = !hasReport;
  reveal.disabled = !!viewing;
  if (viewing) {
    const v = viewing;
    viewingEl.hidden = false;
    viewingEl.innerHTML = `Viewing a saved report from <strong>${esc(v.createdAt?.toLocaleString() ?? 'unknown date')}</strong>. It holds placeholders only, so real values cannot be revealed. <button class="ghost small" type="button" id="back-live">${last ? 'Back to current audit' : 'Close'}</button>`;
    summaryEl.className = 'summary';
    summaryEl.innerHTML = `${scoreRing(v.score)}
      <div class="meta">
        <p><strong>${esc(v.vendor)}</strong> · ${v.findings.length} findings · audit ${esc(v.auditSource.replace('_', ' '))}</p>
        <p class="muted">${v.tokensMasked} values were masked · ${v.cloudChars ? `${v.cloudChars.toLocaleString()} sanitized chars sent to the cloud` : 'nothing was sent to the cloud'}</p>
        <p>${showText(v.summary)}</p>
      </div>`;
    sanitizedEl.textContent = 'Sanitized configs are never stored, so they are not available for saved reports.';
    vaultEl.innerHTML = '<p class="muted">The vault exists only in memory during an audit and is never saved.</p>';
    renderFindings();
    return;
  }
  viewingEl.hidden = true;
  if (!last) return;
  const r = last;
  const s = r.stats;
  const where = s.auditSource === 'in_cloud' ? 'in the cloud' : s.auditSource === 'on_device' ? 'on-device' : 'with local rules only';
  summaryEl.className = 'summary';
  summaryEl.innerHTML = `${scoreRing(r.score)}
    <div class="meta">
      <p><strong>${esc(r.vendor)}</strong> · ${r.audit.findings.length} findings · audit ran <strong>${where}</strong> · ${(s.elapsedMs / 1000).toFixed(1)}s</p>
      <ul class="stats">
        <li><b>${s.deterministicTokens}</b> masked by rules</li>
        <li><b>${s.onDeviceTokens}</b> by Gemini Nano</li>
        ${s.freeTextMasked ? `<li><b>${s.freeTextMasked}</b> descriptions scrubbed</li>` : ''}
        <li><b>${s.aiFindings}</b> AI findings</li>
        <li><b>${s.confirmed}</b> rule-confirmed</li>
        <li><b>${s.ruleFindings}</b> added by ${s.baselineChecks} local checks</li>
        ${s.unverified ? `<li class="warn"><b>${s.unverified}</b> unverified evidence</li>` : ''}
      </ul>
      <p>${showText(r.audit.summary)}</p>
    </div>`;
  renderFindings();
  sanitizedEl.innerHTML = showText(r.sanitized);
  renderVault();
}

function renderVault() {
  const entries = vault.entries();
  if (!entries.length) {
    vaultEl.innerHTML = '<p class="muted">Nothing was masked.</p>';
    return;
  }
  const show = canReveal();
  const rows = entries
    .map((e) => {
      const orig = e.original.length > 80 ? `${e.original.slice(0, 77)}…` : e.original;
      return `<tr><td><mark class="tok">${esc(e.token)}</mark></td><td>${esc(e.kind)}</td><td>${e.source === 'on_device' ? '<span class="src src-on_device">Gemini Nano</span>' : '<span class="src src-local_rules">rules</span>'}</td><td class="orig">${show ? esc(orig) : '•'.repeat(Math.min(12, Math.max(4, e.original.length)))}</td></tr>`;
    })
    .join('');
  vaultEl.innerHTML = `<p class="muted">${entries.length} placeholder(s). ${show ? 'Showing real values — this table exists only in this tab.' : 'Tick "Reveal real values" to see originals (local only).'}</p>
    <table><thead><tr><th>Placeholder</th><th>Kind</th><th>Found by</th><th>Original</th></tr></thead><tbody>${rows}</tbody></table>`;
}

// ------------------------------------------------------------------ export
function toMarkdown(rehydrate: boolean): string {
  const t = (s: string) => (rehydrate && !viewing ? vault.rehydrate(s) : s);
  const findings = currentFindings();
  const vendor = viewing?.vendor ?? last?.vendor ?? 'Unknown vendor';
  const score = viewing?.score ?? last?.score ?? 0;
  const summary = viewing?.summary ?? last?.audit.summary ?? '';
  const lines = [`# ConfigShield audit — ${vendor}`, ''];
  if (last && !viewing) {
    const s = last.stats;
    lines.push(
      `Score: **${score}/100** · Findings: ${findings.length} · Audit: ${s.auditSource} · Redaction: rules + ${s.redactionSource}`,
      `Privacy receipt: ${s.cloudChars ? `${s.cloudChars} sanitized chars sent to the cloud${s.cloudFailed ? ' (request failed)' : ''}` : 'nothing sent to the cloud'} · ${s.deterministicTokens + s.onDeviceTokens + s.freeTextMasked} values masked · leak gate ${last.leak.ok ? 'passed' : 'blocked upload'}`,
    );
  } else {
    lines.push(`Score: **${score}/100** · Findings: ${findings.length} · Saved report ${viewing?.createdAt?.toISOString() ?? ''}`);
  }
  lines.push(rehydrate && !viewing ? '> ⚠️ Contains REAL values — handle as confidential.' : '> Sanitized report — placeholders only.', '', t(summary), '');
  for (const f of findings) {
    const tags = [f.origin ? ORIGIN_LABEL[f.origin] : '', f.confirmedBy ? `confirmed by ${f.confirmedBy}` : '', f.evidenceCheck ? `evidence ${f.evidenceCheck}` : '']
      .filter(Boolean)
      .join(' · ');
    lines.push(`## ${f.id} [${f.severity.toUpperCase()}] ${t(f.title)}`, '', `*${f.category}*${tags ? ` · ${tags}` : ''}`, '', t(f.why), '', '**Evidence**', '```', t(f.evidence), '```', '**Fix**', '```', t(f.fix), '```');
    if (f.reference) lines.push(`Reference: ${f.reference}`);
    lines.push('');
  }
  return lines.join('\n');
}

// ------------------------------------------------------------------ history
async function refreshHistory() {
  if (!firebaseConfigured) {
    historyEl.innerHTML = '<li class="muted">Local-only mode: add a Firebase project to save reports (see README).</li>';
    return;
  }
  try {
    const items = await listAudits();
    historyEl.innerHTML = items.length
      ? items
          .map(
            (a) => `<li>
              <button class="link" type="button" data-view="${esc(a.id)}"><strong>${esc(a.score)}/100</strong> ${esc(a.vendor)} · ${esc(a.findingCount)} findings · ${esc(a.auditSource.replace('_', ' '))}</button>
              <span class="muted">${esc(a.createdAt?.toLocaleString() ?? '')}</span>
              <button class="ghost tiny danger" type="button" data-del="${esc(a.id)}" aria-label="Delete saved report">Delete</button>
            </li>`,
          )
          .join('')
      : '<li class="muted">No saved reports yet.</li>';
  } catch (e) {
    historyEl.innerHTML = `<li class="muted">History unavailable: ${esc((e as Error).message)}</li>`;
  }
}

historyEl.addEventListener('click', async (ev) => {
  const target = ev.target as HTMLElement;
  const viewBtn = target.closest<HTMLButtonElement>('[data-view]');
  const delBtn = target.closest<HTMLButtonElement>('[data-del]');
  if (viewBtn) {
    try {
      const doc = await getAudit(viewBtn.dataset.view!);
      if (!doc) return toast('That report no longer exists', 'warn');
      viewing = doc;
      sevFilter = 'all';
      render();
      summaryEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (e) {
      toast(`Could not open report: ${(e as Error).message}`, 'bad');
    }
  } else if (delBtn) {
    // Two-step confirm without a blocking dialog.
    if (delBtn.dataset.armed !== '1') {
      delBtn.dataset.armed = '1';
      delBtn.textContent = 'Confirm delete';
      setTimeout(() => {
        if (delBtn.isConnected) {
          delBtn.dataset.armed = '';
          delBtn.textContent = 'Delete';
        }
      }, 3000);
      return;
    }
    delBtn.disabled = true;
    try {
      await deleteAudit(delBtn.dataset.del!);
      if (viewing?.id === delBtn.dataset.del) {
        viewing = null;
        render();
      }
      toast('Saved report deleted');
      void refreshHistory();
    } catch (e) {
      delBtn.disabled = false;
      toast(`Delete failed: ${(e as Error).message}`, 'bad');
    }
  }
});

viewingEl.addEventListener('click', (ev) => {
  if ((ev.target as HTMLElement).id !== 'back-live') return;
  viewing = null;
  sevFilter = 'all';
  if (!last) {
    summaryEl.className = 'summary empty';
    summaryEl.innerHTML = '<p>Run an audit to see findings.</p>';
    findingsEl.innerHTML = '';
    filtersEl.hidden = true;
    sanitizedEl.textContent = '';
  }
  render();
});

// ------------------------------------------------------------------ Gemini Nano
const NANO_TEXT: Record<NanoAvailability, string> = {
  available: 'ready',
  downloadable: 'download needed',
  downloading: 'downloading…',
  unavailable: 'not available',
  unsupported: 'not supported',
};

async function updateNanoChip(): Promise<NanoAvailability> {
  const a = await probeNano();
  const chip = $('nano-chip');
  chip.textContent = `Gemini Nano: ${NANO_TEXT[a] ?? a}`;
  chip.className = `chip ${a === 'available' ? 'ok' : a === 'unsupported' || a === 'unavailable' ? 'bad' : 'warn'}`;
  prepBtn.textContent = a === 'available' ? 'On-device model ready ✓' : 'Prepare on-device model';
  prepBtn.disabled = a === 'available' || a === 'unsupported' || a === 'unavailable';
  if (a === 'unsupported' || a === 'unavailable')
    prepBtn.title = 'Gemini Nano needs Chrome Desktop 139+ with the Prompt API enabled. The app still works: rules + strict scrub + cloud or rules-only audit.';
  return a;
}

let preparing: Promise<void> | null = null;

/** Must start from a user gesture (click) — Chrome requires it for the model download. */
function prepareDevice(): Promise<void> {
  return (preparing ??= (async () => {
    const before = await probeNano();
    if (before === 'available' || before === 'unsupported' || before === 'unavailable') return;
    dl.hidden = false;
    dl.removeAttribute('value'); // indeterminate until the first progress event
    try {
      await createRedactor().initializeDeviceModel((p) => (dl.value = p));
    } catch (e) {
      console.warn('initializeDeviceModel failed', e);
      toast('Gemini Nano could not be prepared — continuing without it', 'warn');
    } finally {
      dl.hidden = true;
    }
  })().finally(() => {
    preparing = null;
    void updateNanoChip();
  }));
}

prepBtn.addEventListener('click', () => void prepareDevice());

// ------------------------------------------------------------------ run
async function run() {
  if (running) return;
  if (!raw.value.trim()) {
    raw.focus();
    return toast('Paste a configuration or load a sample first', 'warn');
  }
  const mode = (document.querySelector<HTMLInputElement>('input[name=mode]:checked')?.value ?? 'hybrid') as RunMode;
  // Start the on-device model preparation FIRST, while the click's user activation is fresh.
  const prep = mode !== 'cloud' ? prepareDevice() : Promise.resolve();
  const ctrl = new AbortController();
  running = ctrl;
  runBtn.disabled = true;
  runBtn.textContent = 'Auditing…';
  cancelBtn.hidden = false;
  saveBtn.disabled = exportBtn.disabled = scriptBtn.disabled = true;
  viewing = null;
  sevFilter = 'all';
  stagesEl.innerHTML = '';
  findingsEl.innerHTML = '';
  filtersEl.hidden = true;
  renderReceipt(null);
  try {
    const [s] = await Promise.all([loadSettings(), prep]);
    if (mode === 'cloud' && !s.enableCloudAudit) toast(`Cloud audit unavailable (${s.cloudDisabledReason ?? 'disabled'}) — using local rules`, 'warn');
    last = await runPipeline(raw.value, mode, s, vault, renderStage, ctrl.signal);
    render();
    renderReceipt(last);
    if (!firebaseConfigured) saveBtn.title = 'Saving needs a Firebase project';
  } catch (e) {
    const aborted = ctrl.signal.aborted || (e as Error).name === 'AbortError';
    last = null;
    vault.clear();
    summaryEl.className = `summary ${aborted ? 'empty' : 'error'}`;
    summaryEl.textContent = aborted ? 'Audit cancelled. Nothing further was sent.' : (e as Error).message;
    sanitizedEl.textContent = '';
    renderVault();
  } finally {
    running = null;
    runBtn.disabled = false;
    runBtn.textContent = 'Redact & audit';
    cancelBtn.hidden = true;
  }
}

runBtn.addEventListener('click', () => void run());
cancelBtn.addEventListener('click', () => running?.abort());
raw.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    void run();
  }
});
raw.addEventListener('input', updateRawMeta);

reveal.addEventListener('change', () => {
  render();
  if (reveal.checked) toast('Real values shown locally only', 'warn');
});

filtersEl.addEventListener('click', (ev) => {
  const b = (ev.target as HTMLElement).closest<HTMLButtonElement>('[data-filter]');
  if (!b) return;
  sevFilter = b.dataset.filter as Severity | 'all';
  renderFindings();
});

findingsEl.addEventListener('click', (ev) => {
  const b = (ev.target as HTMLElement).closest<HTMLButtonElement>('[data-copy-fix]');
  if (!b) return;
  const f = currentFindings().find((x) => x.id === b.dataset.copyFix);
  if (f) void copyText(canReveal() ? vault.rehydrate(f.fix) : f.fix, 'Fix');
});

saveBtn.addEventListener('click', async () => {
  if (!last || viewing) return;
  saveBtn.disabled = true;
  try {
    await saveAudit(last);
    saveBtn.textContent = 'Saved ✓';
    toast('Sanitized report saved to Firestore (no real values)');
    void refreshHistory();
  } catch (e) {
    saveBtn.textContent = 'Save failed';
    toast(`Save failed: ${(e as Error).message}`, 'bad');
    console.error(e);
  } finally {
    setTimeout(() => {
      saveBtn.textContent = 'Save sanitized report';
      saveBtn.disabled = !last || !!viewing;
    }, 2000);
  }
});

exportBtn.addEventListener('click', () => {
  if (!last && !viewing) return;
  const conf = canReveal();
  download(`configshield-${conf ? 'CONFIDENTIAL' : 'sanitized'}-${new Date().toISOString().replace(/[:.]/g, '-')}.md`, toMarkdown(conf), 'text/markdown');
});

scriptBtn.addEventListener('click', () => {
  const vendor = viewing?.vendor ?? last?.vendor ?? 'Unknown vendor';
  const script = remediationScript(currentFindings(), vendor);
  void copyText(canReveal() ? vault.rehydrate(script) : script, 'Fix script');
});

$('copy-sanitized').addEventListener('click', () => {
  if (last && !viewing) void copyText(canReveal() ? vault.rehydrate(last.sanitized) : last.sanitized, 'Sanitized config');
});

$<HTMLSelectElement>('sample').addEventListener('change', (ev) => {
  const sel = ev.target as HTMLSelectElement;
  const text = SAMPLES[sel.value];
  if (text) {
    setInput(text);
    toast('Fictitious sample loaded — every name, IP and secret is made up');
  }
  sel.value = '';
});

async function loadFile(f: File | undefined | null) {
  if (!f) return;
  if (f.size > MAX_INPUT_BYTES) return toast(`File is too large (${(f.size / 1048576).toFixed(1)} MB, max 2 MB)`, 'bad');
  setInput(await f.text());
  toast(`Loaded ${f.name} locally — nothing was uploaded`);
}

$<HTMLInputElement>('file').addEventListener('change', async (ev) => {
  const input = ev.target as HTMLInputElement;
  await loadFile(input.files?.[0]);
  input.value = '';
});

const drop = $('drop');
drop.addEventListener('dragover', (e) => {
  e.preventDefault();
  drop.classList.add('over');
});
drop.addEventListener('dragleave', () => drop.classList.remove('over'));
drop.addEventListener('drop', (e) => {
  e.preventDefault();
  drop.classList.remove('over');
  void loadFile(e.dataTransfer?.files?.[0]);
});

$('clear').addEventListener('click', () => {
  running?.abort();
  setInput('');
  vault.clear();
  last = null;
  viewing = null;
  reveal.checked = false;
  stagesEl.innerHTML = '';
  findingsEl.innerHTML = '';
  filtersEl.hidden = true;
  sanitizedEl.textContent = '';
  summaryEl.className = 'summary empty';
  summaryEl.innerHTML = '<p>Cleared. The in-memory vault has been wiped.</p>';
  document.querySelectorAll<HTMLLIElement>('.flow li').forEach((li) => (li.className = ''));
  renderReceipt(null);
  render();
  renderVault();
});

// ------------------------------------------------------------------ boot
function updateNet() {
  const chip = $('net-chip');
  chip.textContent = navigator.onLine ? 'Network: online' : 'Network: offline';
  chip.className = `chip ${navigator.onLine ? 'ok' : 'warn'}`;
}
window.addEventListener('online', updateNet);
window.addEventListener('offline', updateNet);
updateNet();
updateRawMeta();
void updateNanoChip();

const rcChip = $('rc-chip');
const authChip = $('auth-chip');
if (!firebaseConfigured) {
  authChip.textContent = 'Firebase: not configured (local-only)';
  authChip.className = 'chip warn';
  authChip.title = 'Rules, the baseline auditor and Gemini Nano work. Cloud audit and saved reports need a Firebase project.';
  rcChip.textContent = 'Config: defaults';
  saveBtn.title = 'Saving needs a Firebase project';
  void refreshHistory();
} else {
  ensureSignedIn()
    .then((u) => {
      authChip.textContent = `Auth: anonymous ${u.uid.slice(0, 6)}…`;
      authChip.className = 'chip ok';
      void refreshHistory();
    })
    .catch((e) => {
      authChip.textContent = 'Auth: offline';
      authChip.className = 'chip warn';
      historyEl.innerHTML = '<li class="muted">Sign-in failed, so saved reports are unavailable right now.</li>';
      console.warn(e);
    });
}
loadSettings().then((s: AppSettings) => {
  rcChip.textContent = `Config: ${s.source === 'remote' ? 'Remote Config' : 'defaults'}${s.enableCloudAudit ? '' : ' · cloud OFF'}`;
  rcChip.className = `chip ${s.enableCloudAudit ? 'ok' : 'warn'}`;
  rcChip.title = `Cloud model: ${s.cloudModel} · policy pack: ${s.policyPack} · Nano chunk: ${s.chunkChars} chars · max findings: ${s.maxFindings}`;
});
