/**
 * Pipeline integration tests with the Firebase AI Logic models mocked out.
 * The key assertions are about the privacy boundary: exactly what text reaches
 * a model whose inference ran in the cloud.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';

type Reply = { text: string; source: 'on_device' | 'in_cloud' } | Error;
const calls: Array<{ model: string; prompt: string }> = [];
const replies: Record<'redactor' | 'auditor' | 'local', (prompt: string) => Reply> = {
  redactor: () => new Error('LanguageModel API not available'),
  auditor: () => new Error('cloud down'),
  local: () => new Error('LanguageModel API not available'),
};

function fakeModel(name: keyof typeof replies) {
  return {
    generateContent: vi.fn(async (prompt: string) => {
      calls.push({ model: name, prompt });
      const r = await replies[name](prompt);
      if (r instanceof Error) throw r;
      return { response: { text: () => r.text, inferenceSource: r.source } };
    }),
    initializeDeviceModel: vi.fn(async () => {}),
  };
}

vi.mock('../src/ai/models', () => ({
  createRedactor: () => fakeModel('redactor'),
  createAuditor: () => fakeModel('auditor'),
  createLocalAuditor: () => fakeModel('local'),
  probeNano: async () => 'unavailable',
}));

const { runPipeline } = await import('../src/pipeline');
const { TokenVault } = await import('../src/redact/vault');

const ios = readFileSync(new URL('../samples/cisco-iosxe-branch.cfg', import.meta.url), 'utf8');
const SETTINGS = { cloudModel: 'test-model', enableCloudAudit: true, chunkChars: 12000, policyPack: 'baseline-v1', maxFindings: 25, source: 'defaults' as const };
const RAW_SECRETS = ['0822455D0A16', 'Sup3rS3cret!', 'C0ntos0RW', 'Branch@VPN2026', 'cisco123', 'BLR-BR-SW01', 'netadmin', '203.0.113.45', '10.20.99.2', 'Priya Raman', '091BANG623410', 'Ravi Kumar', 'noc@contoso'];

const cloudAudit = JSON.stringify({
  summary: 'Branch switch has weak management-plane security.',
  findings: [
    { id: '1', title: 'Telnet enabled on VTY lines', severity: 'medium', category: 'management-plane', evidence: 'transport input telnet ssh', why: 'cleartext', fix: 'transport input ssh' },
    { id: '2', title: 'Made-up finding', severity: 'low', category: 'hygiene', evidence: 'feature fabricated-thing', why: 'n/a', fix: 'n/a' },
  ],
});

const events: string[] = [];
const emit = (e: { stage: number; status: string; source: string }) => events.push(`${e.stage}:${e.status}:${e.source}`);

beforeEach(() => {
  calls.length = 0;
  events.length = 0;
  replies.redactor = () => new Error('LanguageModel API not available');
  replies.auditor = () => ({ text: cloudAudit, source: 'in_cloud' });
  replies.local = () => new Error('LanguageModel API not available');
});

describe('hybrid pipeline', () => {
  it('without Gemini Nano: strict scrub, then a cloud audit that never sees a raw secret or name', async () => {
    const r = await runPipeline(ios, 'hybrid', SETTINGS, new TokenVault(), emit);
    const cloudPrompts = calls.filter((c) => c.model === 'auditor').map((c) => c.prompt);
    expect(cloudPrompts).toHaveLength(1);
    for (const s of RAW_SECRETS) expect(cloudPrompts[0], s).not.toContain(s);
    expect(r.stats.redactionSource).toBe('skipped');
    expect(r.stats.freeTextMasked).toBeGreaterThan(0);
    expect(r.stats.auditSource).toBe('in_cloud');
    expect(r.stats.cloudChars).toBe(r.sanitized.length);
    expect(r.stats.cloudFailed).toBe(false);
    expect(events).toContain('1:warn:skipped');
    expect(events).toContain('2:done:local_rules');
  });

  it('cross-checks AI findings: confirms real ones, flags invented evidence, adds what the AI missed', async () => {
    const r = await runPipeline(ios, 'hybrid', SETTINGS, new TokenVault(), emit);
    const telnet = r.audit.findings.find((f) => /telnet/i.test(f.title))!;
    expect(telnet.origin).toBe('cloud');
    expect(telnet.confirmedBy).toBe('BL-IOS-TELNET');
    expect(telnet.evidenceCheck).toBe('verified');
    expect(r.audit.findings.find((f) => f.title === 'Made-up finding')!.evidenceCheck).toBe('unverified');
    expect(r.stats.ruleFindings).toBeGreaterThan(5);
    expect(r.audit.findings.map((f) => f.id)).toEqual(r.audit.findings.map((_, i) => `CS-${String(i + 1).padStart(3, '0')}`));
    expect(r.score).toBeLessThan(50);
  });

  it('uses Gemini Nano redaction when available and masks its verbatim, non-hallucinated suggestions', async () => {
    replies.redactor = () => ({ text: JSON.stringify({ items: [{ value: 'Priya Raman', kind: 'PERSON' }, { value: 'Not In Config', kind: 'PERSON' }] }), source: 'on_device' });
    const vault = new TokenVault();
    const r = await runPipeline(ios, 'hybrid', SETTINGS, vault, emit);
    expect(r.stats.redactionSource).toBe('on_device');
    expect(r.stats.onDeviceTokens).toBe(1);
    expect(r.sanitized).toContain('<PERSON_');
    expect(vault.entries().some((e) => e.original === 'Not In Config')).toBe(false);
    // The redactor saw the rules-sanitized text, never the raw secrets.
    const redactorPrompt = calls.find((c) => c.model === 'redactor')!.prompt;
    expect(redactorPrompt).not.toContain('Sup3rS3cret!');
  });

  it('ignores Gemini Nano suggestions that are fragments of existing placeholders (real-run regression)', async () => {
    // Observed live: Nano echoed token internals, which corrupted <SECRET_1> into <<OTHER_1>>
    // and made the leak gate (correctly, but needlessly) block the cloud audit.
    replies.redactor = () => ({
      text: JSON.stringify({
        items: [
          { value: 'SECRET_1', kind: 'SECRET' }, { value: 'WEAKSECRET_2', kind: 'SECRET' }, { value: 'IP_PUB_1', kind: 'OTHER' },
          { value: 'HOST', kind: 'HOST' }, { value: 'LOCATION_1', kind: 'LOCATION' }, { value: 'Priya Raman', kind: 'PERSON' },
        ],
      }),
      source: 'on_device',
    });
    const r = await runPipeline(ios, 'hybrid', SETTINGS, new TokenVault(), emit);
    expect(r.leak.ok).toBe(true);
    expect(r.sanitized).not.toMatch(/<</);
    expect(r.sanitized).toContain('enable password 7 <SECRET_1>');
    expect(r.stats.onDeviceTokens).toBe(1); // only "Priya Raman"
    expect(r.stats.auditSource).toBe('in_cloud');
  });

  it('cancels immediately even while an on-device prompt is still running', async () => {
    replies.redactor = () => ({ text: '{"items":[]}', source: 'on_device' });
    replies.auditor = () => new Error('cloud down');
    const ctrl = new AbortController();
    const hang = new Promise<never>(() => {});
    replies.local = () => {
      setTimeout(() => ctrl.abort(), 10);
      return hang as unknown as Reply; // never resolves, like a stuck Nano session
    };
    await expect(runPipeline(ios, 'hybrid', SETTINGS, new TokenVault(), emit, ctrl.signal)).rejects.toThrow(/abort/i);
  });

  it('aborts if the redactor ever reports cloud inference', async () => {
    replies.redactor = () => ({ text: '{"items":[]}', source: 'in_cloud' });
    await expect(runPipeline(ios, 'hybrid', SETTINGS, new TokenVault(), emit)).rejects.toThrow(/Privacy violation/);
    expect(calls.some((c) => c.model === 'auditor')).toBe(false);
  });

  it('falls back to the on-device auditor when the cloud fails', async () => {
    replies.redactor = () => ({ text: '{"items":[]}', source: 'on_device' });
    replies.auditor = () => new Error('fetch failed');
    replies.local = () => ({ text: cloudAudit, source: 'on_device' });
    const r = await runPipeline(ios, 'hybrid', SETTINGS, new TokenVault(), emit);
    expect(r.stats.auditSource).toBe('on_device');
    expect(r.audit.findings.some((f) => f.origin === 'on_device')).toBe(true);
    expect(r.stats.cloudFailed).toBe(true);
    expect(r.stats.cloudChars).toBeGreaterThan(0); // the sanitized text WAS sent before the failure
  });

  it('reports an SDK-level PREFER_IN_CLOUD fallback honestly (request sent, then ran on-device)', async () => {
    replies.auditor = () => ({ text: cloudAudit, source: 'on_device' });
    const r = await runPipeline(ios, 'hybrid', SETTINGS, new TokenVault(), emit);
    expect(r.stats.auditSource).toBe('on_device');
    expect(r.stats.cloudFailed).toBe(true);
    expect(r.stats.cloudChars).toBe(r.sanitized.length);
    expect(events).toContain('3:warn:on_device');
  });

  it('still produces a rules-only report when every AI path fails', async () => {
    replies.auditor = () => new Error('cloud down');
    const r = await runPipeline(ios, 'hybrid', SETTINGS, new TokenVault(), emit);
    expect(r.stats.auditSource).toBe('local_rules');
    expect(r.audit.findings.length).toBeGreaterThan(5);
    expect(r.audit.findings.every((f) => f.origin === 'rule')).toBe(true);
    expect(r.audit.summary).toMatch(/baseline/i);
  });

  it('honours the Remote Config kill switch', async () => {
    const r = await runPipeline(ios, 'hybrid', { ...SETTINGS, enableCloudAudit: false }, new TokenVault(), emit);
    expect(calls.some((c) => c.model === 'auditor')).toBe(false);
    expect(r.stats.cloudChars).toBe(0);
  });

  it('honours cancellation', async () => {
    const ctrl = new AbortController();
    ctrl.abort();
    await expect(runPipeline(ios, 'hybrid', SETTINGS, new TokenVault(), emit, ctrl.signal)).rejects.toThrow();
    expect(calls.some((c) => c.model === 'auditor')).toBe(false);
  });
});

describe('air-gapped and cloud modes', () => {
  it('air-gapped never calls the cloud auditor, even without Nano', async () => {
    const r = await runPipeline(ios, 'local', SETTINGS, new TokenVault(), emit);
    expect(calls.some((c) => c.model === 'auditor')).toBe(false);
    expect(r.stats.cloudChars).toBe(0);
    expect(r.audit.findings.length).toBeGreaterThan(0);
  });

  it('air-gapped audit runs on Gemini Nano when available', async () => {
    replies.redactor = () => ({ text: '{"items":[]}', source: 'on_device' });
    replies.local = () => ({ text: cloudAudit, source: 'on_device' });
    const r = await runPipeline(ios, 'local', SETTINGS, new TokenVault(), emit);
    expect(r.stats.auditSource).toBe('on_device');
    expect(calls.some((c) => c.model === 'auditor')).toBe(false);
  });

  it('cloud mode skips Nano, scrubs free text, and reports rules-only if the cloud fails', async () => {
    replies.auditor = () => new Error('quota');
    const r = await runPipeline(ios, 'cloud', SETTINGS, new TokenVault(), emit);
    expect(calls.some((c) => c.model === 'redactor' || c.model === 'local')).toBe(false);
    expect(r.stats.freeTextMasked).toBeGreaterThan(0);
    expect(r.stats.auditSource).toBe('local_rules');
  });
});
