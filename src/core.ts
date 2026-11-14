/** Pure helpers (no Firebase imports) — unit-testable in Node. */
import { CATEGORIES, SEVERITIES, type AuditFinding, type AuditResult, type Category, type Severity } from './ai/schemas';

const KEYWORD_STOPLIST = new Set([
  'interface', 'description', 'shutdown', 'vlan', 'router', 'access-list', 'permit', 'deny', 'any', 'host',
  'uplink', 'downlink', 'trunk', 'access', 'management', 'mgmt', 'core', 'distribution', 'edge', 'wan', 'lan',
  'internet', 'isp', 'firewall', 'switch', 'server', 'printer', 'guest', 'voice', 'data', 'native', 'unused',
]);

/** Split on line boundaries so each chunk fits Gemini Nano's context (≈9216 tokens). */
export function chunkLines(text: string, maxChars: number): string[] {
  const limit = Math.max(16, Number.isFinite(maxChars) ? Math.floor(maxChars) : 12000);
  const lines = text.split('\n');
  const chunks: string[] = [];
  let cur: string[] = [];
  let len = 0;
  for (const raw of lines) {
    // A single pathological line longer than the limit is hard-split so no chunk overflows.
    const pieces = raw.length > limit ? raw.match(new RegExp(`[\\s\\S]{1,${limit - 1}}`, 'g')) ?? [raw] : [raw];
    for (const line of pieces) {
      if (len + line.length + 1 > limit && cur.length) {
        chunks.push(cur.join('\n'));
        cur = [];
        len = 0;
      }
      cur.push(line);
      len += line.length + 1;
    }
  }
  if (cur.length) chunks.push(cur.join('\n'));
  return chunks;
}

export function safeJson<T>(text: string): T | null {
  try {
    return JSON.parse(text) as T;
  } catch {
    const m = text.match(/\{[\s\S]*\}/);
    if (!m) return null;
    try {
      return JSON.parse(m[0]) as T;
    } catch {
      return null;
    }
  }
}

const TOKEN_RE = /<[A-Z_]+_\d+>/;

/** Accept a model-suggested value only if it really is a verbatim, non-trivial substring. */
export function acceptCandidate(value: string, chunk: string): boolean {
  if (typeof value !== 'string') return false;
  const v = value.trim();
  if (v.length < 3 || v.length > 120) return false;
  if (TOKEN_RE.test(v)) return false; // never re-mask an existing placeholder (or text around one)
  if (KEYWORD_STOPLIST.has(v.toLowerCase())) return false;
  if (/^(?:Gi|Te|Fa|Eth|Po|Vl|Lo|Tu|Hu|Fo)[a-zA-Z]*\d/.test(v)) return false; // interface names
  if (/^\d+$/.test(v)) return false;
  return chunk.includes(v);
}

/** 100 = clean. Deductions are capped per severity so one noisy class can't zero the score. */
export function scoreFindings(findings: Array<Pick<AuditFinding, 'severity'>>): number {
  const w: Record<string, [number, number]> = { critical: [20, 60], high: [10, 40], medium: [4, 20], low: [1, 8], info: [0, 0] };
  const tally: Record<string, number> = {};
  for (const f of findings) tally[f.severity] = (tally[f.severity] ?? 0) + 1;
  let ded = 0;
  for (const [sev, n] of Object.entries(tally)) {
    const [each, cap] = w[sev] ?? [0, 0];
    ded += Math.min(each * n, cap);
  }
  return Math.max(0, 100 - ded);
}

const str = (v: unknown, max = 2000): string => (typeof v === 'string' ? v : v == null ? '' : String(v)).slice(0, max);

export function coerceSeverity(v: unknown): Severity {
  const s = str(v).toLowerCase().trim();
  return (SEVERITIES as readonly string[]).includes(s) ? (s as Severity) : 'info';
}

export function coerceCategory(v: unknown): Category {
  const s = str(v).toLowerCase().trim();
  return (CATEGORIES as readonly string[]).includes(s) ? (s as Category) : 'hygiene';
}

export const severityRank = (s: string): number => {
  const i = SEVERITIES.indexOf(s as Severity);
  return i < 0 ? 99 : i;
};

/**
 * Turn untrusted model output into a well-formed audit: enums are enforced (the
 * values end up in CSS classes and Firestore), strings are bounded, duplicates are
 * dropped and findings are ordered by severity.
 */
export function normaliseAudit(a: unknown, max: number): AuditResult {
  const obj = (a && typeof a === 'object' ? a : {}) as { summary?: unknown; findings?: unknown };
  if (!Array.isArray(obj.findings)) return { summary: str(obj.summary) || 'The model returned no parseable findings.', findings: [] };
  const seen = new Set<string>();
  const findings: AuditFinding[] = [];
  for (const raw of obj.findings as unknown[]) {
    if (!raw || typeof raw !== 'object') continue;
    const f = raw as Record<string, unknown>;
    const title = str(f.title, 200).trim();
    if (!title) continue;
    const key = title.toLowerCase().replace(/\W+/g, ' ').trim();
    if (seen.has(key)) continue;
    seen.add(key);
    const finding: AuditFinding = {
      id: '',
      title,
      severity: coerceSeverity(f.severity),
      category: coerceCategory(f.category),
      evidence: str(f.evidence).trim(),
      why: str(f.why).trim(),
      fix: str(f.fix).trim(),
    };
    const ref = str(f.reference, 300).trim();
    if (ref) finding.reference = ref;
    findings.push(finding);
  }
  findings.sort((x, y) => severityRank(x.severity) - severityRank(y.severity));
  const limit = Math.max(1, Math.floor(Number.isFinite(max) ? max : 25));
  return { summary: str(obj.summary, 3000).trim(), findings: findings.slice(0, limit) };
}

const norm = (s: string) => s.replace(/\s+/g, ' ').trim();

/**
 * Hallucination check for AI findings: does the cited evidence actually exist in the
 * sanitized config the model was given?
 */
export function verifyEvidence(evidence: string, sanitized: string): 'verified' | 'partial' | 'unverified' {
  const hay = norm(sanitized);
  const configLines = new Set(
    sanitized
      .split('\n')
      .map(norm)
      .filter((l) => l.length >= 3 && !/^[!#]/.test(l)),
  );
  const lines = evidence
    .split(/\n|\s\|\s|;\s+(?=\S)/)
    .map((l) => norm(l.replace(/^\s*(?:[-*•]|\d+[:.)])\s+/, '').replace(/^["'`]+|["'`,;]+$/g, '').replace(/\s*(?:\.{3}|…)\s*$/, '')))
    .filter((l) => l.length >= 4 && !/^(?:\.{3}|!|…)$/.test(l));
  if (!lines.length) return 'unverified';

  /**
   * Small models often flatten several config lines into one ("line vty 0 4 login
   * exec-timeout 0 0"). Segment such a line greedily into real config lines and
   * report how much of it is covered: 1 = fully real, 0 = nothing real.
   */
  const coverage = (line: string): number => {
    if (hay.includes(line)) return 1;
    const words = line.split(' ');
    let covered = 0;
    for (let i = 0; i < words.length; ) {
      let j = words.length;
      while (j > i && !configLines.has(words.slice(i, j).join(' '))) j--;
      if (j > i) {
        covered += j - i;
        i = j;
      } else i++;
    }
    return covered / words.length;
  };
  const scores = lines.map(coverage);
  if (scores.every((s) => s === 1)) return 'verified';
  return scores.some((s) => s > 0) ? 'partial' : 'unverified';
}

/** Renumber findings CS-001… after the final ordering. */
export function renumber(findings: AuditFinding[]): AuditFinding[] {
  return findings.map((f, i) => ({ ...f, id: `CS-${String(i + 1).padStart(3, '0')}` }));
}

/** Concatenate every fix into one change script, grouped by severity. */
export function remediationScript(findings: AuditFinding[], vendor: string): string {
  const comment = /Junos|PAN-OS|FortiOS/.test(vendor) ? '#' : '!';
  const out = [`${comment} ConfigShield remediation plan — ${vendor}`, `${comment} Review every line before applying. Replace <PLACEHOLDERS> with real values.`, ''];
  for (const f of findings) {
    if (!f.fix.trim()) continue;
    out.push(`${comment} ${f.id} [${f.severity.toUpperCase()}] ${f.title}`, f.fix.trim(), '');
  }
  return out.join('\n');
}
