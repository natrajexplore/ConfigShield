import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { TokenVault } from '../src/redact/vault';
import { deterministicRedact, detectVendor } from '../src/redact/deterministic';
import { mergeWithBaseline, runBaseline, vendorFamily } from '../src/audit/baseline';
import { normaliseAudit, remediationScript, verifyEvidence } from '../src/core';
import type { AuditFinding } from '../src/ai/schemas';

const sanitize = (f: string) => {
  const raw = readFileSync(new URL(`../samples/${f}`, import.meta.url), 'utf8');
  const v = new TokenVault();
  return { text: deterministicRedact(raw, v).sanitized, vendor: detectVendor(raw) };
};
const ids = (f: string) => {
  const { text, vendor } = sanitize(f);
  return runBaseline(text, vendor).map((h) => h.finding.id);
};

describe('deterministic baseline audit', () => {
  it('maps vendor strings to families', () => {
    expect(vendorFamily('Cisco IOS / IOS-XE')).toBe('ios');
    expect(vendorFamily('Cisco NX-OS')).toBe('ios');
    expect(vendorFamily('Cisco ASA')).toBe('asa');
    expect(vendorFamily('Palo Alto PAN-OS')).toBe('panos');
    expect(vendorFamily('Juniper Junos')).toBe('junos');
    expect(vendorFamily('Fortinet FortiOS')).toBe('fortios');
    expect(vendorFamily('Unknown vendor')).toBe('unknown');
  });

  it('finds the planted IOS-XE issues', () => {
    expect(ids('cisco-iosxe-branch.cfg')).toEqual(
      expect.arrayContaining(['BL-WEAK-SECRET', 'BL-IOS-TELNET', 'BL-IOS-HTTP', 'BL-IOS-ENABLE-PASSWORD', 'BL-IOS-NO-AAA', 'BL-IOS-EXEC-TIMEOUT', 'BL-IOS-SNMP-RW', 'BL-WEAK-IKE', 'BL-IOS-VTY-NO-ACL']),
    );
    // logging host and ntp server ARE configured in this sample
    expect(ids('cisco-iosxe-branch.cfg')).not.toContain('BL-IOS-NO-REMOTE-LOG');
    expect(ids('cisco-iosxe-branch.cfg')).not.toContain('BL-IOS-NO-NTP');
  });
  it('finds the planted ASA issues', () => {
    expect(ids('cisco-asa-edge.cfg')).toEqual(expect.arrayContaining(['BL-ASA-TELNET', 'BL-ASA-SSH-V1', 'BL-ASA-MGMT-ANY', 'BL-ASA-ANY-ANY', 'BL-WEAK-IKE', 'BL-SNMP-V2C']));
  });
  it('finds the planted PAN-OS issues', () => {
    expect(ids('panos-edge-set.txt')).toEqual(expect.arrayContaining(['BL-PAN-TELNET-HTTP', 'BL-PAN-ANY-ANY', 'BL-PAN-NO-LOG', 'BL-PAN-WEAK-IKE', 'BL-PAN-RDP-UNTRUST', 'BL-SNMP-V2C']));
  });
  it('finds the planted Junos issues', () => {
    expect(ids('junos-srx-set.txt')).toEqual(expect.arrayContaining(['BL-JUNOS-TELNET-HTTP', 'BL-JUNOS-ROOT-SSH', 'BL-JUNOS-WEAK-IKE', 'BL-JUNOS-ANY-ANY', 'BL-WEAK-SECRET']));
  });
  it('finds the planted FortiOS issues', () => {
    expect(ids('fortigate.conf')).toEqual(expect.arrayContaining(['BL-FORTI-ALLOWACCESS', 'BL-FORTI-WEAK-IKE', 'BL-FORTI-ANY-ANY', 'BL-SNMP-V2C']));
  });

  it('stays quiet on a hardened config', () => {
    const hardened = [
      'hostname <HOST_1>', 'service timestamps log datetime msec', 'service password-encryption', 'aaa new-model',
      'enable algorithm-type scrypt secret 9 <HASH_1>', 'ip ssh version 2', 'no ip http server', 'logging host <IP_PRIV_1>',
      'ntp server <IP_PRIV_2>', 'line vty 0 15', ' access-class MGMT-ONLY in', ' transport input ssh', ' exec-timeout 10 0',
    ].join('\n');
    expect(runBaseline(hardened, 'Cisco IOS / IOS-XE')).toEqual([]);
  });

  it('only runs checks for the detected vendor', () => {
    const { text } = sanitize('panos-edge-set.txt');
    expect(runBaseline(text, 'Palo Alto PAN-OS').every((h) => !h.finding.id.startsWith('BL-IOS'))).toBe(true);
  });

  it('every baseline finding carries evidence, a fix and a compliance reference', () => {
    for (const f of ['cisco-iosxe-branch.cfg', 'cisco-asa-edge.cfg', 'panos-edge-set.txt', 'junos-srx-set.txt', 'fortigate.conf']) {
      const { text, vendor } = sanitize(f);
      for (const { finding } of runBaseline(text, vendor)) {
        expect(finding.evidence.length, finding.id).toBeGreaterThan(3);
        expect(finding.fix.length, finding.id).toBeGreaterThan(3);
        expect(finding.reference, finding.id).toMatch(/NIST|PCI/);
        expect(finding.origin).toBe('rule');
      }
    }
  });
});

const ai = (over: Partial<AuditFinding>): AuditFinding => ({
  id: 'x', title: 'Telnet enabled on VTY', severity: 'medium', category: 'management-plane',
  evidence: 'line vty 0 4\ntransport input telnet ssh', why: 'cleartext', fix: 'transport input ssh', origin: 'cloud', ...over,
});

describe('AI + baseline merge', () => {
  const { text, vendor } = sanitize('cisco-iosxe-branch.cfg');
  const hits = runBaseline(text, vendor);

  it('marks a matching AI finding as rule-confirmed instead of duplicating it, and raises an under-rated severity', () => {
    const merged = mergeWithBaseline([ai({})], hits);
    const telnet = merged.filter((f) => /telnet/i.test(f.title));
    expect(telnet).toHaveLength(1);
    expect(telnet[0].confirmedBy).toBe('BL-IOS-TELNET');
    expect(telnet[0].severity).toBe('high');
    expect(telnet[0].origin).toBe('cloud');
  });

  it('adds baseline hits the AI missed', () => {
    const merged = mergeWithBaseline([ai({})], hits);
    expect(merged.filter((f) => f.origin === 'rule').length).toBe(hits.length - 1);
  });

  it('does not let a weak-password-TYPE finding be swallowed by the weak-SECRET check', () => {
    const merged = mergeWithBaseline(
      [ai({ title: 'Weak password types (type 7 / cleartext)', category: 'aaa', evidence: 'enable password 7 <SECRET_1>', severity: 'high' })],
      hits,
    );
    const f = merged.find((x) => x.origin === 'cloud')!;
    expect(f.confirmedBy).not.toBe('BL-WEAK-SECRET');
    expect(f.severity).toBe('high');
  });
});

describe('model-output hardening', () => {
  it('coerces enums so untrusted output can never inject markup via severity/category', () => {
    const a = normaliseAudit(
      {
        summary: 'ok',
        findings: [
          { title: 'A', severity: '"><img src=x onerror=alert(1)>', category: 'evil', evidence: 'x', why: 'y', fix: 'z' },
          { title: 'B', severity: 'HIGH', category: 'crypto', evidence: 1, why: null, fix: undefined, reference: '' },
          { title: 'a', severity: 'low' }, // duplicate title
          null,
          'nonsense',
          { severity: 'critical' }, // no title
        ],
      },
      25,
    );
    expect(a.findings.map((f) => [f.title, f.severity, f.category])).toEqual([
      ['B', 'high', 'crypto'],
      ['A', 'info', 'hygiene'],
    ]);
    expect(a.findings[0]).not.toHaveProperty('reference');
    expect(a.findings[0].evidence).toBe('1');
    expect(a.findings[0].why).toBe('');
  });

  it('handles non-object and missing output', () => {
    expect(normaliseAudit(null, 5).findings).toEqual([]);
    expect(normaliseAudit('text', 5).findings).toEqual([]);
    expect(normaliseAudit({ findings: 'x' }, 5).findings).toEqual([]);
  });

  it('caps the number of findings', () => {
    const many = { summary: '', findings: Array.from({ length: 60 }, (_, i) => ({ title: `F${i}`, severity: 'low' })) };
    expect(normaliseAudit(many, 10).findings).toHaveLength(10);
    expect(normaliseAudit(many, Number.NaN).findings).toHaveLength(25);
  });
});

describe('evidence verification', () => {
  const cfg = 'line vty 0 4\n password <WEAKSECRET_2>\n login\n transport input telnet ssh\n exec-timeout 0 0';
  it('verifies, partially verifies or rejects cited evidence', () => {
    expect(verifyEvidence('transport input telnet ssh', cfg)).toBe('verified');
    expect(verifyEvidence('line vty 0 4\n  transport   input telnet ssh', cfg)).toBe('verified');
    expect(verifyEvidence('- exec-timeout 0 0\n...', cfg)).toBe('verified');
    expect(verifyEvidence('transport input telnet ssh\nip http server', cfg)).toBe('partial');
    expect(verifyEvidence('snmp-server community public RO', cfg)).toBe('unverified');
    expect(verifyEvidence('', cfg)).toBe('unverified');
  });

  // Real Gemini Nano outputs observed on the IOS-XE sample.
  const ios = [
    'line vty 0 4',
    ' password <WEAKSECRET_2>',
    ' login',
    ' transport input telnet ssh',
    ' exec-timeout 0 0',
    'username <USER_1> privilege 15 password 0 <SECRET_2>',
    'snmp-server community <WEAKSECRET_1> RO',
    'snmp-server community <SECRET_4> RW',
  ].join('\n');
  it('accepts several real config lines flattened onto one line', () => {
    expect(verifyEvidence('line vty 0 4 password <WEAKSECRET_2> login exec-timeout 0 0', ios)).toBe('verified');
  });
  it('ignores stray trailing punctuation from the model', () => {
    expect(verifyEvidence('username <USER_1> privilege 15 password 0 <SECRET_2>`,', ios)).toBe('verified');
  });
  it('grades invented lines mixed with real ones as partial, and pure inventions as unverified', () => {
    expect(verifyEvidence('interface Vty 0 4 password <WEAKSECRET_2> login transport input telnet ssh', ios)).toBe('partial');
    expect(verifyEvidence('snmp-server community <WEAKSECRET_1> RO snmp-server community <WEAKSECRET_1> RW', ios)).toBe('partial');
    expect(verifyEvidence('ip ssh version 1', ios)).toBe('unverified');
  });
});

describe('remediation script', () => {
  it('concatenates fixes with vendor-appropriate comments', () => {
    const s = remediationScript([ai({ id: 'CS-001', severity: 'high' }), ai({ id: 'CS-002', fix: '' })], 'Cisco IOS / IOS-XE');
    expect(s).toContain('! CS-001 [HIGH]');
    expect(s).toContain('transport input ssh');
    expect(s).not.toContain('CS-002');
    expect(remediationScript([ai({ id: 'CS-001' })], 'Juniper Junos')).toMatch(/^# /);
  });
});
