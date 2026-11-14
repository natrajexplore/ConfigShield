import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { TokenVault } from '../src/redact/vault';
import { deterministicRedact, leakGate, isMaskLike, detectVendor, scrubFreeText, sweepVault } from '../src/redact/deterministic';
import { acceptCandidate, chunkLines, scoreFindings } from '../src/core';

const sample = (f: string) => readFileSync(new URL(`../samples/${f}`, import.meta.url), 'utf8');
const ios = sample('cisco-iosxe-branch.cfg');
const pan = sample('panos-edge-set.txt');
const asa = sample('cisco-asa-edge.cfg');
const junos = sample('junos-srx-set.txt');
const forti = sample('fortigate.conf');

const MUST_NOT_SURVIVE_IOS = [
  '0822455D0A16', 'Sup3rS3cret!', '$1$mERr$hx5rVt7rPNoS4wqbXKX7m0', 'C0ntos0RW', 'public RO',
  '045802150C2E', 'Branch@VPN2026', '094F471A1A0A', 'cisco123', 'BLR-BR-SW01',
  'branch.contoso-finserv.example', 'noc@contoso-finserv.example', '+91 80 4000 1234',
  '203.0.113.45', '198.51.100.7', '10.20.99.2', 'netadmin',
];
const MUST_NOT_SURVIVE_PAN = [
  'CHN-DC-PA01', 'dc.northwind-health.example', '203.0.113.20', '$1$abcdefgh$Hk3s9dP0aQwL2mVx7yZ1t.',
  'Nw@Ike!2026', 'Nw-public', '198.51.100.10', '10.50.0.25', 'Northwind Health Chennai DC',
];
const MUST_NOT_SURVIVE_ASA = [
  'MUM-EDGE-FW01', 'edge.fabrikam-retail.example', '8Ry2YjIyt7RRXU24', '2KFQnbNIdI.2KYOU', 'Fabr1k@m#Edge2026',
  'fwadmin', 'T@cacsK3y!2026', 'community fabrikam', 'Fabr1kamL2L!', 'Meera Iyer', 'Andheri East',
  '203.0.113.66', '198.51.100.200', '10.30.1.20',
];
const MUST_NOT_SURVIVE_JUNOS = [
  'HYD-SRX-01', 'hyd.woodgrove-bank.example', '$6$k1Lm2Nop$', '$1$aB3dE6gH$', 'ops-admin', '$9$hZ0cyKoJGjqP5Qn9tO1EhrlKvL',
  '$9$Wt8XNbs2aZDkPfQ3n6CuOBIhcl', 'Kiran Reddy', 'Hitech City', 'community public', '203.0.113.130', '198.51.100.77', '10.60.0.15',
];
const MUST_NOT_SURVIVE_FORTI = [
  'PUN-FGT-01', 'SH2nBq7Lq0wPmXv3RkTz9yUe1cFhJdA4sG6iO8pK5lM2nB7vC9xZ0', 'Qm9yZ2VkUFNLRm9yRGVtb09ubHkyMDI2IQ==',
  'tailspin-ro', '203.0.113.180', '198.51.100.150', '10.70.0.40',
];

describe('deterministic redaction — every bundled sample', () => {
  const cases: Array<[string, string, string[], string]> = [
    ['Cisco IOS-XE', ios, MUST_NOT_SURVIVE_IOS, 'Cisco IOS / IOS-XE'],
    ['PAN-OS', pan, MUST_NOT_SURVIVE_PAN, 'Palo Alto PAN-OS'],
    ['Cisco ASA', asa, MUST_NOT_SURVIVE_ASA, 'Cisco ASA'],
    ['Junos', junos, MUST_NOT_SURVIVE_JUNOS, 'Juniper Junos'],
    ['FortiOS', forti, MUST_NOT_SURVIVE_FORTI, 'Fortinet FortiOS'],
  ];
  for (const [name, cfg, secrets, vendor] of cases) {
    it(`removes every known secret / identifier from the ${name} sample and passes the leak gate`, () => {
      const v = new TokenVault();
      const { sanitized } = deterministicRedact(cfg, v);
      for (const s of secrets) expect(sanitized, s).not.toContain(s.replace(' RO', ''));
      expect(leakGate(sanitized, v)).toEqual({ ok: true, leaks: [] });
      expect(detectVendor(cfg)).toBe(vendor);
    });
  }

  it('keeps audit-relevant structure (masks, syntax, weak settings)', () => {
    const v = new TokenVault();
    const { sanitized } = deterministicRedact(ios, v);
    for (const keep of ['255.255.255.0', '0.0.0.0 0.0.0.0', 'transport input telnet ssh', 'encr des', 'group 1',
      'no service password-encryption', 'snmp-server community <WEAKSECRET_', 'snmp-server community <SECRET_', ' password <WEAKSECRET_', 'enable password 7 <SECRET_', 'exec-timeout 0 0'])
      expect(sanitized, keep).toContain(keep);
  });

  it('uses consistent tokens and re-hydrates locally', () => {
    const v = new TokenVault();
    const { sanitized } = deterministicRedact(ios, v);
    expect(v.rehydrate(sanitized)).toContain('Branch@VPN2026');
    const t1 = v.tokenFor('BLR-BR-SW01', 'HOST');
    expect(v.tokenFor('BLR-BR-SW01', 'HOST')).toBe(t1);
    expect(v.lookup(t1)?.original).toBe('BLR-BR-SW01');
  });

  it('does not treat key ids / syntax words as secrets', () => {
    const v = new TokenVault();
    const cfg = 'key chain EIGRP\n key 1\n  key-string 7 06070E2B4D\ncrypto key generate rsa modulus 2048\n';
    const { sanitized } = deterministicRedact(cfg, v);
    expect(sanitized).toContain('key chain EIGRP');
    expect(sanitized).toContain(' key 1');
    expect(sanitized).toContain('crypto key generate rsa');
    expect(sanitized).not.toContain('06070E2B4D');
  });

  it('flags weak / default secrets without revealing them', () => {
    const v = new TokenVault();
    const { sanitized } = deterministicRedact('snmp-server community public RO\nusername a secret 0 Xy9!long-pass\n', v);
    expect(sanitized).toContain('community <WEAKSECRET_1> RO');
    expect(sanitized).toContain('secret 0 <SECRET_1>');
    expect(sanitized).not.toContain('public');
  });

  it('masks the community in version-less and ASA-style snmp-server host lines', () => {
    const v = new TokenVault();
    const { sanitized } = deterministicRedact(
      'snmp-server host 10.1.1.1 S3cr3tComm\nsnmp-server host 10.1.1.2 traps version 2c Tr@pComm\nsnmp-server host 10.1.1.3 version 3 priv v3user\nsnmp-server host mgmt 10.1.1.4 community AsaComm99 version 2c\n',
      v,
    );
    for (const s of ['S3cr3tComm', 'Tr@pComm', 'AsaComm99']) expect(sanitized).not.toContain(s);
    expect(sanitized).toContain('version 3 priv v3user'); // SNMPv3 user names are not communities
  });

  it('sweeps a reused secret everywhere, not only at the keyword position', () => {
    const v = new TokenVault();
    const { sanitized, rulesHit } = deterministicRedact('enable secret 0 Re-Used!Pass77\ninterface Gi1\n description temp pw Re-Used!Pass77\n', v);
    expect(sanitized).not.toContain('Re-Used!Pass77');
    expect(rulesHit.reuse).toBeGreaterThan(0);
    expect(leakGate(sanitized, v).ok).toBe(true);
  });

  it('leak gate blocks a residual secret', () => {
    const v = new TokenVault();
    v.tokenFor('hunter2pass', 'SECRET');
    const r = leakGate('username x secret 0 hunter2pass\nlogging host 8.8.8.8', v);
    expect(r.ok).toBe(false);
    expect(r.leaks.length).toBeGreaterThanOrEqual(2);
    expect(JSON.stringify(r)).not.toContain('hunter2pass'); // the report itself never echoes the value
  });

  it('leak gate matches identifiers on word boundaries (no false positives)', () => {
    const v = new TokenVault();
    v.tokenFor('admin', 'USER');
    v.tokenFor('ops', 'HOST');
    expect(leakGate('username <USER_1>\nrole netadmin\nsuperadmin-group\n', v).ok).toBe(true);
    expect(leakGate('logging userinfo admin\n', v).ok).toBe(false);
  });

  it('leak gate catches IPv6 addresses and FortiOS SNMP community names', () => {
    const v = new TokenVault();
    expect(leakGate('ipv6 address 2001:db8:10::1/64', v).ok).toBe(false);
    expect(leakGate('config system snmp community\n    edit 1\n        set name "leaky"\n    next\nend', v).ok).toBe(false);
  });

  it('sweepVault leaves common config words alone', () => {
    const v = new TokenVault();
    v.tokenFor('public', 'WEAKSECRET');
    v.tokenFor('default', 'WEAKSECRET');
    expect(sweepVault('ip nat inside source list 1 interface Gi0 overload\nip route 0.0.0.0 0.0.0.0 default\npublic-key', v)).toContain('default');
  });
});

describe('strict free-text scrub (used when Gemini Nano is unavailable)', () => {
  it('masks identifying descriptions/comments and keeps generic ones', () => {
    const v = new TokenVault();
    const { text, masked } = scrubFreeText(
      'interface Gi1/0/1\n description Uplink to core\ninterface Gi1/0/2\n description Desk of Priya Raman - Treasury\nset network interface ethernet ethernet1/1 comment "ISP: Tata Comm circuit 045CHEN88812"\ninterface Vlan99\n description MGMT\n',
      v,
    );
    expect(masked).toBe(2);
    expect(text).toContain('description Uplink to core');
    expect(text).toContain('description MGMT');
    expect(text).not.toContain('Priya Raman');
    expect(text).not.toContain('045CHEN88812');
    expect(v.rehydrate(text)).toContain('Desk of Priya Raman - Treasury');
  });

  it('removes every person, site and circuit name from the IOS sample with rules alone', () => {
    const v = new TokenVault();
    const det = deterministicRedact(ios, v);
    const { text } = scrubFreeText(det.sanitized, v);
    for (const s of ['Priya Raman', 'Treasury', '091BANG623410', 'Airtel', 'Koramangala', 'Ravi Kumar', 'Contoso']) expect(text, s).not.toContain(s);
    expect(leakGate(text, v).ok).toBe(true);
  });
});

describe('helpers', () => {
  it('mask detection', () => {
    expect(isMaskLike('255.255.255.0')).toBe(true);
    expect(isMaskLike('0.0.0.255')).toBe(true);
    expect(isMaskLike('10.0.0.1')).toBe(false);
    expect(isMaskLike('192.168.1.0')).toBe(false);
  });
  it('rejects hallucinated or trivial on-device candidates', () => {
    const chunk = ' description Desk of Priya Raman - Treasury <HOST_1> lab';
    expect(acceptCandidate('Priya Raman', chunk)).toBe(true);
    expect(acceptCandidate('John Doe', chunk)).toBe(false);
    expect(acceptCandidate('GigabitEthernet1/0/1', 'interface GigabitEthernet1/0/1')).toBe(false);
    expect(acceptCandidate('<HOST_1>', '<HOST_1>')).toBe(false);
    expect(acceptCandidate('<HOST_1> lab', chunk)).toBe(false); // would swallow an existing token
    expect(acceptCandidate(42 as unknown as string, chunk)).toBe(false);
    // placeholder fragments seen from real Gemini Nano output
    const tokenised = 'enable password 7 <SECRET_1>\nsnmp-server community <WEAKSECRET_2> RO\nntp server <IP_PUB_1>';
    for (const frag of ['SECRET_1', 'WEAKSECRET_2', 'IP_PUB_1', 'WEAKSECRET', 'SECRET', 'IP_PUB', '<SECRET_1']) expect(acceptCandidate(frag, tokenised), frag).toBe(false);
    expect(acceptCandidate('Treasury', 'description Treasury <HOST_1>')).toBe(true);
  });
  it('chunks on line boundaries and hard-splits pathological lines', () => {
    const c = chunkLines(Array.from({ length: 100 }, (_, i) => `line ${i}`).join('\n'), 100);
    expect(c.length).toBeGreaterThan(5);
    expect(c.every((x) => x.length <= 100)).toBe(true);
    const long = chunkLines('x'.repeat(1000), 100);
    expect(long.every((x) => x.length <= 100)).toBe(true);
    expect(long.join('').replace(/\n/g, '')).toHaveLength(1000);
  });
  it('scores with per-severity caps', () => {
    const f = (severity: 'critical' | 'low') => ({ severity });
    expect(scoreFindings([])).toBe(100);
    expect(scoreFindings(Array(10).fill(f('critical')))).toBe(40);
    expect(scoreFindings([f('low')])).toBe(99);
  });
});
