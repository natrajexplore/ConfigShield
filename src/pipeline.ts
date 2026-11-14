/**
 * ConfigShield pipeline
 *
 *   raw config ──► [0] deterministic redaction (local rules)
 *              ──► [1] contextual redaction   (Gemini Nano, ONLY_ON_DEVICE;
 *                                              strict free-text scrub if Nano can't run)
 *              ──► [2] leak gate              (local; blocks cloud on any residual secret)
 *              ──► [3] deep audit             (PREFER_IN_CLOUD → on-device → rules-only)
 *              ──► [4] cross-check + local re-hydration (baseline rules, evidence check;
 *                                              the vault never leaves memory)
 *
 * The pipeline always produces a report: if every AI path fails, the deterministic
 * baseline audit still runs and the stage list says exactly why.
 */
import type { GenerativeModel } from 'firebase/ai';
import { TokenVault, type TokenKind } from './redact/vault';
import { deterministicRedact, leakGate, detectVendor, replaceIdentifier, scrubFreeText, type LeakReport } from './redact/deterministic';
import { createAuditor, createLocalAuditor, createRedactor } from './ai/models';
import type { AuditFinding, AuditResult, PiiKind } from './ai/schemas';
import { acceptCandidate, chunkLines, normaliseAudit, renumber, safeJson, scoreFindings, severityRank, verifyEvidence } from './core';
import { BASELINE_CHECK_COUNT, mergeWithBaseline, runBaseline } from './audit/baseline';
import type { AppSettings } from './firebase';

export { acceptCandidate, chunkLines, scoreFindings };

export type RunMode = 'hybrid' | 'local' | 'cloud';
export type Source = 'on_device' | 'in_cloud' | 'local_rules' | 'skipped';

export interface StageEvent {
  stage: 0 | 1 | 2 | 3 | 4;
  status: 'running' | 'done' | 'warn' | 'error';
  source: Source;
  message: string;
}

export interface PipelineResult {
  vendor: string;
  mode: RunMode;
  sanitized: string;
  audit: AuditResult;
  score: number;
  leak: LeakReport;
  stats: {
    deterministicTokens: number;
    onDeviceTokens: number;
    freeTextMasked: number;
    rulesHit: Record<string, number>;
    redactionSource: Source;
    auditSource: Source;
    chunks: number;
    elapsedMs: number;
    /** Characters of (sanitized) text sent to the cloud model. 0 = nothing left the device. */
    cloudChars: number;
    /** A cloud request was sent but failed (the audit then ran on-device or on rules). */
    cloudFailed: boolean;
    aiFindings: number;
    ruleFindings: number;
    confirmed: number;
    unverified: number;
    baselineChecks: number;
  };
}

/** Hard cap shared with firestore.rules (findings.size() <= 50). */
export const MAX_REPORT_FINDINGS = 50;

const KIND_MAP: Record<PiiKind, TokenKind> = {
  ORG: 'ORG', PERSON: 'PERSON', LOCATION: 'LOCATION', SITE: 'SITE', HOST: 'HOST',
  USER: 'USER', CIRCUIT: 'CIRCUIT', PHONE: 'PHONE', SECRET: 'SECRET', OTHER: 'OTHER',
};

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e)).replace(/\s+/g, ' ').slice(0, 220);

function isAbort(e: unknown): boolean {
  return e instanceof DOMException ? e.name === 'AbortError' : e instanceof Error && e.name === 'AbortError';
}

/**
 * The SDK honours AbortSignal for cloud requests but not for on-device prompts, so
 * race every model call against the signal: Cancel then returns immediately.
 */
function withAbort<T>(p: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return p;
  signal.throwIfAborted();
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason ?? new DOMException('Aborted', 'AbortError'));
    signal.addEventListener('abort', onAbort, { once: true });
    p.then(
      (v) => {
        signal.removeEventListener('abort', onAbort);
        resolve(v);
      },
      (e) => {
        signal.removeEventListener('abort', onAbort);
        reject(e);
      },
    );
  });
}

/** Number of <...> groups that are NOT well-formed placeholder tokens. */
function brokenTokens(s: string): number {
  const groups = s.match(/<[^<>\n]*>/g) ?? [];
  return groups.filter((t) => !/^<[A-Z_]+_\d+>$/.test(t)).length + (s.match(/<</g) ?? []).length;
}

async function onDeviceRedact(
  text: string,
  vault: TokenVault,
  chunkChars: number,
  emit: (e: StageEvent) => void,
  signal?: AbortSignal,
): Promise<{ text: string; chunks: number }> {
  const redactor = createRedactor();
  const chunks = chunkLines(text, chunkChars);
  let out = text;
  for (let i = 0; i < chunks.length; i++) {
    signal?.throwIfAborted();
    emit({ stage: 1, status: 'running', source: 'on_device', message: `Gemini Nano scanning chunk ${i + 1}/${chunks.length}…` });
    const res = await withAbort(
      redactor.generateContent(`Configuration excerpt:\n"""\n${chunks[i]}\n"""\nList remaining sensitive values as JSON.`, { signal }),
      signal,
    );
    if (res.response.inferenceSource && res.response.inferenceSource !== 'on_device') {
      // Defence in depth — ONLY_ON_DEVICE should make this impossible.
      throw new Error('Privacy violation: redaction did not run on-device. Aborting.');
    }
    const parsed = safeJson<{ items?: Array<{ value?: unknown; kind?: unknown }> }>(res.response.text());
    const items = (Array.isArray(parsed?.items) ? parsed.items : [])
      .filter((it): it is { value: string; kind?: unknown } => !!it && typeof it.value === 'string' && acceptCandidate(it.value, chunks[i]))
      .map((it) => ({ value: it.value.trim(), kind: KIND_MAP[it.kind as PiiKind] ?? 'OTHER' }));
    items.sort((a, b) => b.value.length - a.value.length);
    for (const it of items) {
      // Never apply a replacement that would damage an existing placeholder.
      const probe = replaceIdentifier(out, it.value, '<PROBE_0>');
      if (probe === out || brokenTokens(probe) > brokenTokens(out)) continue;
      out = replaceIdentifier(out, it.value, vault.tokenFor(it.value, it.kind, 'on_device'));
    }
  }
  return { text: out, chunks: chunks.length };
}

async function auditPrompt(model: GenerativeModel, vendor: string, policy: string, text: string, signal?: AbortSignal) {
  const res = await withAbort(
    model.generateContent(
      `Vendor/platform: ${vendor}\nPolicy pack: ${policy}\nSanitized configuration:\n"""\n${text}\n"""\nReturn the audit as JSON.`,
      { signal },
    ),
    signal,
  );
  return { text: res.response.text(), source: (res.response.inferenceSource ?? 'in_cloud') as Source };
}

async function localAudit(
  sanitized: string,
  vendor: string,
  settings: AppSettings,
  emit: (e: StageEvent) => void,
  signal?: AbortSignal,
): Promise<AuditResult> {
  const local = createLocalAuditor();
  const findings: unknown[] = [];
  const summaries: string[] = [];
  const parts = chunkLines(sanitized, Math.min(settings.chunkChars, 9000));
  for (let i = 0; i < parts.length; i++) {
    signal?.throwIfAborted();
    emit({ stage: 3, status: 'running', source: 'on_device', message: `Gemini Nano auditing chunk ${i + 1}/${parts.length}…` });
    const r = await auditPrompt(local, vendor, settings.policyPack, parts[i], signal);
    if (r.source !== 'on_device') throw new Error('Air-gapped audit did not run on-device. Aborting.');
    const p = safeJson<{ summary?: unknown; findings?: unknown }>(r.text);
    if (Array.isArray(p?.findings)) findings.push(...p.findings);
    if (typeof p?.summary === 'string' && p.summary.trim()) summaries.push(p.summary.trim());
  }
  return normaliseAudit({ summary: summaries.join(' '), findings }, settings.maxFindings);
}

export async function runPipeline(
  raw: string,
  mode: RunMode,
  settings: AppSettings,
  vault: TokenVault,
  emit: (e: StageEvent) => void,
  signal?: AbortSignal,
): Promise<PipelineResult> {
  const t0 = performance.now();
  vault.clear();
  const vendor = detectVendor(raw);

  // ---- Stage 0 · deterministic rules
  emit({ stage: 0, status: 'running', source: 'local_rules', message: 'Applying deterministic secret rules…' });
  const det = deterministicRedact(raw, vault);
  const deterministicTokens = vault.entries().length;
  emit({ stage: 0, status: 'done', source: 'local_rules', message: `${deterministicTokens} values tokenised by rules (${vendor}).` });

  // ---- Stage 1 · contextual redaction on-device
  let sanitized = det.sanitized;
  let redactionSource: Source = 'on_device';
  let nanoUsable = mode !== 'cloud';
  let chunks = 0;
  let freeTextMasked = 0;
  const strictScrub = (why: string) => {
    const s = scrubFreeText(sanitized, vault);
    sanitized = s.text;
    freeTextMasked = s.masked;
    emit({ stage: 1, status: 'warn', source: 'skipped', message: `${why} Strict rule-based scrub applied instead: ${s.masked} free-text description(s) masked.` });
  };
  if (mode === 'cloud') {
    redactionSource = 'skipped';
    strictScrub('Cloud mode: Gemini Nano contextual redaction skipped.');
  } else {
    try {
      const r = await onDeviceRedact(sanitized, vault, settings.chunkChars, emit, signal);
      sanitized = r.text;
      chunks = r.chunks;
      emit({ stage: 1, status: 'done', source: 'on_device', message: `Gemini Nano masked ${vault.countBySource('on_device')} contextual identifiers on-device (${chunks} chunk${chunks === 1 ? '' : 's'}).` });
    } catch (e) {
      if (isAbort(e)) throw e;
      if (/Privacy violation/.test(errMsg(e))) throw e;
      redactionSource = 'skipped';
      nanoUsable = false;
      strictScrub(`Gemini Nano unavailable (${errMsg(e)}).`);
    }
  }
  signal?.throwIfAborted();

  // ---- Stage 2 · leak gate
  const leak = leakGate(sanitized, vault);
  if (!leak.ok) {
    emit({ stage: 2, status: 'error', source: 'local_rules', message: `Leak gate BLOCKED cloud upload: ${leak.leaks.length} residual sensitive value(s) (${[...new Set(leak.leaks.map((l) => l.kind))].join(', ')}).` });
  } else {
    emit({ stage: 2, status: 'done', source: 'local_rules', message: 'Leak gate passed — no residual secrets detected.' });
  }

  // ---- Stage 3 · deep audit
  let aiAudit: AuditResult | null = null;
  let auditSource: Source = 'local_rules';
  let cloudChars = 0;
  let cloudFailed = false;
  const cloudAllowed = leak.ok && settings.enableCloudAudit && mode !== 'local';
  const notes: string[] = [];

  if (cloudAllowed) {
    try {
      emit({ stage: 3, status: 'running', source: 'in_cloud', message: `Deep audit with ${settings.cloudModel} (${mode === 'cloud' ? 'cloud only' : 'hybrid, cloud-preferred — Gemini Nano takes over automatically if the cloud fails, which can take a few minutes'})…` });
      cloudChars = sanitized.length;
      const r = await auditPrompt(createAuditor(settings.cloudModel, mode === 'cloud' ? 'cloud' : 'hybrid'), vendor, settings.policyPack, sanitized, signal);
      const parsed = normaliseAudit(safeJson(r.text), settings.maxFindings);
      if (r.source === 'on_device') {
        // PREFER_IN_CLOUD: the request was sent but failed, and the SDK fell back to Gemini Nano.
        cloudFailed = true;
        notes.push('cloud request failed, so the SDK fell back to Gemini Nano');
      }
      aiAudit = parsed;
      auditSource = r.source;
    } catch (e) {
      if (isAbort(e)) throw e;
      cloudFailed = true;
      notes.push(`cloud audit failed: ${errMsg(e)}`);
    }
  } else if (mode !== 'local') {
    notes.push(!leak.ok ? 'leak gate blocked the cloud' : !settings.enableCloudAudit ? settings.cloudDisabledReason ?? 'cloud audit disabled' : 'cloud unavailable');
  }

  if (!aiAudit && mode !== 'cloud' && nanoUsable) {
    emit({ stage: 3, status: 'running', source: 'on_device', message: `Running audit on-device${notes.length ? ` (${notes.join('; ')})` : ''}…` });
    try {
      aiAudit = await localAudit(sanitized, vendor, settings, emit, signal);
      auditSource = 'on_device';
    } catch (e) {
      if (isAbort(e)) throw e;
      if (/did not run on-device/.test(errMsg(e))) throw e;
      notes.push(`on-device audit failed: ${errMsg(e)}`);
    }
  } else if (!aiAudit && mode !== 'cloud' && !nanoUsable) {
    notes.push('Gemini Nano unavailable');
  }

  if (aiAudit) {
    emit({ stage: 3, status: notes.length ? 'warn' : 'done', source: auditSource, message: `${aiAudit.findings.length} AI findings (${auditSource === 'in_cloud' ? 'cloud' : 'on-device'})${notes.length ? ` — ${notes.join('; ')}` : ''}.` });
  } else {
    emit({ stage: 3, status: 'warn', source: 'local_rules', message: `No AI audit (${notes.join('; ') || 'not available'}). Falling back to the deterministic baseline audit.` });
  }

  // ---- Stage 4 · cross-check + re-hydration
  const fromAi: AuditFinding[] = (aiAudit?.findings ?? []).map((f) => ({
    ...f,
    origin: auditSource === 'in_cloud' ? 'cloud' : 'on_device',
    evidenceCheck: verifyEvidence(f.evidence, sanitized),
  }));
  const hits = runBaseline(sanitized, vendor);
  const merged = mergeWithBaseline(fromAi, hits)
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
    .slice(0, MAX_REPORT_FINDINGS);
  const findings = renumber(merged);
  const ruleFindings = findings.filter((f) => f.origin === 'rule').length;
  const confirmed = findings.filter((f) => f.confirmedBy).length;
  const unverified = findings.filter((f) => f.evidenceCheck === 'unverified').length;
  const summary =
    aiAudit?.summary ||
    (findings.length
      ? `Deterministic baseline audit of ${vendor}: ${findings.length} issue(s) found by ${BASELINE_CHECK_COUNT} local rule checks. Run with Gemini available for a deeper review.`
      : `No issues found by the ${BASELINE_CHECK_COUNT} local baseline checks for ${vendor}.`);

  emit({
    stage: 4,
    status: unverified ? 'warn' : 'done',
    source: 'local_rules',
    message:
      `Cross-check: ${confirmed} AI finding(s) confirmed by rules, ${ruleFindings} added by rules` +
      (unverified ? `, ${unverified} AI finding(s) cite evidence not found in the config` : '') +
      '. Real values can be revealed locally — they never left this browser.',
  });

  return {
    vendor,
    mode,
    sanitized,
    audit: { summary, findings },
    score: scoreFindings(findings),
    leak,
    stats: {
      deterministicTokens,
      onDeviceTokens: vault.countBySource('on_device'),
      freeTextMasked,
      rulesHit: det.rulesHit,
      redactionSource,
      auditSource,
      chunks,
      elapsedMs: Math.round(performance.now() - t0),
      cloudChars,
      cloudFailed,
      aiFindings: fromAi.length,
      ruleFindings,
      confirmed,
      unverified,
      baselineChecks: BASELINE_CHECK_COUNT,
    },
  };
}
