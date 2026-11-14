/**
 * Firestore persistence — stores ONLY the sanitized report (placeholders kept).
 * The TokenVault (real values) and the raw / sanitized config are never written.
 * Every field is copied explicitly from an allow-list, mirroring firestore.rules.
 */
import { addDoc, collection, deleteDoc, doc, getDoc, getDocs, limit, orderBy, query, serverTimestamp } from 'firebase/firestore';
import { ensureSignedIn, getDb } from './firebase';
import type { AuditFinding } from './ai/schemas';
import { coerceCategory, coerceSeverity } from './core';
import { MAX_REPORT_FINDINGS, type PipelineResult } from './pipeline';

export interface SavedAudit {
  id: string;
  vendor: string;
  score: number;
  summary: string;
  findings: AuditFinding[];
  findingCount: number;
  auditSource: string;
  redactionSource: string;
  tokensMasked: number;
  mode?: string;
  cloudChars?: number;
  createdAt?: Date;
}


/** Copy only the known, string-typed finding fields (Firestore rejects `undefined`). */
function storableFinding(f: AuditFinding): Record<string, string> {
  const out: Record<string, string> = {
    id: f.id.slice(0, 20),
    title: f.title.slice(0, 200),
    severity: f.severity,
    category: f.category,
    evidence: f.evidence.slice(0, 1500),
    why: f.why.slice(0, 1500),
    fix: f.fix.slice(0, 1500),
  };
  if (f.reference) out.reference = f.reference.slice(0, 300);
  if (f.origin) out.origin = f.origin;
  if (f.evidenceCheck) out.evidenceCheck = f.evidenceCheck;
  if (f.confirmedBy) out.confirmedBy = f.confirmedBy.slice(0, 40);
  return out;
}

export async function saveAudit(r: PipelineResult): Promise<string> {
  const user = await ensureSignedIn();
  const ref = await addDoc(collection(getDb(), 'users', user.uid, 'audits'), {
    vendor: r.vendor.slice(0, 80),
    score: Math.round(r.score),
    summary: r.audit.summary.slice(0, 3900),
    findings: r.audit.findings.slice(0, MAX_REPORT_FINDINGS).map(storableFinding), // sanitized — placeholders only
    findingCount: r.audit.findings.length,
    auditSource: r.stats.auditSource,
    redactionSource: r.stats.redactionSource,
    tokensMasked: r.stats.deterministicTokens + r.stats.onDeviceTokens + r.stats.freeTextMasked,
    mode: r.mode,
    cloudChars: r.stats.cloudChars,
    createdAt: serverTimestamp(),
    schema: 2,
  });
  return ref.id;
}

function fromDoc(id: string, d: Record<string, unknown>): SavedAudit {
  const ts = d.createdAt as { toDate?: () => Date } | undefined;
  const findings = Array.isArray(d.findings) ? (d.findings as Array<Record<string, unknown>>) : [];
  return {
    id,
    vendor: String(d.vendor ?? 'Unknown vendor'),
    score: Number(d.score ?? 0),
    summary: String(d.summary ?? ''),
    findings: findings.map((f) => ({
      id: String(f.id ?? ''),
      title: String(f.title ?? ''),
      severity: coerceSeverity(f.severity),
      category: coerceCategory(f.category),
      evidence: String(f.evidence ?? ''),
      why: String(f.why ?? ''),
      fix: String(f.fix ?? ''),
      ...(f.reference ? { reference: String(f.reference) } : {}),
      ...(f.origin === 'cloud' || f.origin === 'on_device' || f.origin === 'rule' ? { origin: f.origin } : {}),
      ...(f.evidenceCheck === 'verified' || f.evidenceCheck === 'partial' || f.evidenceCheck === 'unverified' ? { evidenceCheck: f.evidenceCheck } : {}),
      ...(f.confirmedBy ? { confirmedBy: String(f.confirmedBy) } : {}),
    })),
    findingCount: Number(d.findingCount ?? findings.length),
    auditSource: String(d.auditSource ?? ''),
    redactionSource: String(d.redactionSource ?? ''),
    tokensMasked: Number(d.tokensMasked ?? 0),
    mode: d.mode ? String(d.mode) : undefined,
    cloudChars: typeof d.cloudChars === 'number' ? d.cloudChars : undefined,
    createdAt: typeof ts?.toDate === 'function' ? ts.toDate() : undefined,
  };
}

export async function listAudits(n = 10): Promise<SavedAudit[]> {
  const user = await ensureSignedIn();
  const q = query(collection(getDb(), 'users', user.uid, 'audits'), orderBy('createdAt', 'desc'), limit(n));
  const snap = await getDocs(q);
  return snap.docs.map((d) => fromDoc(d.id, d.data()));
}

export async function getAudit(id: string): Promise<SavedAudit | null> {
  const user = await ensureSignedIn();
  const snap = await getDoc(doc(getDb(), 'users', user.uid, 'audits', id));
  return snap.exists() ? fromDoc(snap.id, snap.data()) : null;
}

export async function deleteAudit(id: string): Promise<void> {
  const user = await ensureSignedIn();
  await deleteDoc(doc(getDb(), 'users', user.uid, 'audits', id));
}
