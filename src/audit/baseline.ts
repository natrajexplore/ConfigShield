/**
 * Deterministic baseline audit — runs locally on the SANITIZED config, no AI.
 *
 * Two jobs:
 *  1. Guarantee a useful report even when neither Gemini Nano nor the cloud is
 *     available (no browser support, offline, quota exhausted, kill switch).
 *  2. Cross-check the AI: a rule hit that the model also reported marks the AI
 *     finding "rule-confirmed"; a rule hit the model missed is added to the report.
 *
 * Every check is anchored on exact config syntax, so these findings never
 * hallucinate. They are intentionally conservative — the AI audit goes deeper.
 */
import type { AuditFinding, Category, Severity } from '../ai/schemas';

export type VendorFamily = 'ios' | 'asa' | 'panos' | 'junos' | 'fortios' | 'unknown';

export function vendorFamily(vendor: string): VendorFamily {
  if (/PAN-OS/i.test(vendor)) return 'panos';
  if (/Junos/i.test(vendor)) return 'junos';
  if (/FortiOS/i.test(vendor)) return 'fortios';
  if (/ASA/i.test(vendor)) return 'asa';
  if (/Cisco/i.test(vendor)) return 'ios';
  return 'unknown';
}

interface Check {
  id: string;
  vendors: VendorFamily[] | 'all';
  severity: Severity;
  category: Category;
  title: string;
  why: string;
  fix: string;
  reference: string;
  /** Lines that prove the problem. Return [] when the check passes. */
  detect: (text: string, lines: string[]) => string[];
  /** Matches an AI finding (title + evidence) that describes the same problem. */
  covers: RegExp;
}

const MAX_EVIDENCE = 6;

/** Lines matching any of the patterns (trimmed, de-duplicated, capped). */
function grep(lines: string[], ...patterns: RegExp[]): string[] {
  const out: string[] = [];
  for (const l of lines) {
    if (patterns.some((p) => p.test(l))) {
      const t = l.trim();
      if (!out.includes(t)) out.push(t);
      if (out.length >= MAX_EVIDENCE) break;
    }
  }
  return out;
}

/** "Not configured" evidence, emitted only when the config clearly is a device config of that family. */
const absent = (what: string, comment = '!') => [`${comment} not configured: ${what}`];

const CHECKS: Check[] = [
  // ---------------------------------------------------------------- universal
  {
    id: 'BL-WEAK-SECRET',
    vendors: 'all',
    severity: 'critical',
    category: 'aaa',
    title: 'Weak or vendor-default secret in use',
    why: 'A local check found a password, community or key that is a vendor default, a dictionary word or shorter than 8 characters. These are the first values an attacker tries.',
    fix: 'Replace every <WEAKSECRET_n> value with a unique random secret of at least 16 characters, stored in a password vault or delivered by AAA. Rotate it on all devices that share it.',
    reference: 'NIST SP 800-53 IA-5(1) · PCI DSS v4.0 2.2.2, 8.3.6',
    detect: (_t, lines) => grep(lines, /<WEAKSECRET_\d+>/),
    covers: /WEAKSECRET|default (?:snmp )?(?:community|password|credential|secret)|dictionary|guessable|weak (?:or default )?(?:secret|community|credential)|short (?:password|secret|community)/i,
  },

  // ---------------------------------------------------------------- Cisco IOS / IOS-XE / NX-OS
  {
    id: 'BL-IOS-TELNET',
    vendors: ['ios'],
    severity: 'high',
    category: 'management-plane',
    title: 'Telnet allowed on VTY lines',
    why: 'Telnet sends credentials and session data in cleartext, so anyone on the path can capture the admin password.',
    fix: 'line vty 0 15\n transport input ssh\nip ssh version 2',
    reference: 'NIST SP 800-53 AC-17(2), SC-8 · PCI DSS v4.0 2.2.7',
    detect: (_t, lines) => grep(lines, /^\s*transport\s+input\s+(?:.*\btelnet\b|all\b)/i),
    covers: /telnet/i,
  },
  {
    id: 'BL-IOS-HTTP',
    vendors: ['ios'],
    severity: 'medium',
    category: 'management-plane',
    title: 'Cleartext HTTP management server enabled',
    why: 'The HTTP server exposes a web management interface without encryption and has a history of remotely exploitable vulnerabilities.',
    fix: 'no ip http server\n! keep only if web management is required:\nip http secure-server\nip http access-class ipv4 MGMT-ONLY',
    reference: 'NIST SP 800-53 CM-7, SC-8 · PCI DSS v4.0 2.2.4, 2.2.7',
    detect: (_t, lines) => grep(lines, /^\s*ip\s+http\s+server\s*$/i),
    covers: /\bhttp\b(?!s)|web (?:server|management|ui)/i,
  },
  {
    id: 'BL-IOS-ENABLE-PASSWORD',
    vendors: ['ios'],
    severity: 'high',
    category: 'aaa',
    title: '"enable password" used instead of "enable secret"',
    why: '"enable password" is stored in cleartext or reversible type 7 encoding, which can be decoded instantly by anyone who sees the config.',
    fix: 'no enable password\nenable algorithm-type scrypt secret <NEW_SECRET>',
    reference: 'NIST SP 800-53 IA-5(1) · PCI DSS v4.0 8.3.2',
    detect: (_t, lines) => grep(lines, /^\s*enable\s+password\b/i),
    covers: /enable password|enable secret/i,
  },
  {
    id: 'BL-IOS-REVERSIBLE-PASSWORD',
    vendors: ['ios'],
    severity: 'high',
    category: 'aaa',
    title: 'Cleartext or type 7 (reversible) passwords',
    why: 'Type 0 is plain text and type 7 is a reversible obfuscation, so these credentials are effectively stored in the clear.',
    fix: 'username <USER> privilege 15 algorithm-type scrypt secret <NEW_SECRET>\nline con 0\n login local\nline vty 0 15\n login local\n! then remove the "password" lines',
    reference: 'NIST SP 800-53 IA-5(1) · PCI DSS v4.0 8.3.2',
    detect: (_t, lines) =>
      grep(
        lines.filter((l) => !/^\s*enable\s+password\b/i.test(l)),
        /^\s*username\s+\S+.*\bpassword\s+[07]?\s*\S/i,
        /^\s*password\s+(?:[07]\s+)?\S+\s*$/i,
      ),
    covers: /type ?7|type ?0|cleartext|clear-text|plain ?text|reversibl|password-encryption|weak password (?:type|encryption|hash)/i,
  },
  {
    id: 'BL-IOS-MD5-SECRET',
    vendors: ['ios'],
    severity: 'medium',
    category: 'aaa',
    title: 'MD5 (type 5) password hashes',
    why: 'Type 5 hashes are salted MD5 and can be brute-forced quickly on modern GPUs. Type 8 (PBKDF2) or type 9 (scrypt) is the current recommendation.',
    fix: 'username <USER> privilege 15 algorithm-type scrypt secret <NEW_SECRET>',
    reference: 'NIST SP 800-53 IA-5(1) · PCI DSS v4.0 8.3.2',
    detect: (_t, lines) => grep(lines, /\bsecret\s+5\s+/i),
    covers: /type ?5|md5 (?:hash|password|secret)/i,
  },
  {
    id: 'BL-IOS-NO-PWD-ENCRYPTION',
    vendors: ['ios'],
    severity: 'low',
    category: 'hygiene',
    title: 'service password-encryption disabled',
    why: 'Without it, any remaining line or username passwords are shown in plain text to anyone who views the configuration.',
    fix: 'service password-encryption\n! and migrate remaining passwords to "secret" with scrypt',
    reference: 'NIST SP 800-53 IA-5(1)',
    detect: (_t, lines) => grep(lines, /^\s*no\s+service\s+password-encryption\b/i),
    covers: /password-encryption/i,
  },
  {
    id: 'BL-IOS-NO-AAA',
    vendors: ['ios'],
    severity: 'high',
    category: 'aaa',
    title: 'AAA not enabled (no centralised authentication or accounting)',
    why: 'Without "aaa new-model" there is no TACACS+/RADIUS authentication, per-user authorisation or command accounting, so admin actions cannot be attributed.',
    fix: 'aaa new-model\naaa authentication login default group tacacs+ local\naaa authorization exec default group tacacs+ local\naaa accounting commands 15 default start-stop group tacacs+',
    reference: 'NIST SP 800-53 AC-2, AU-12, IA-2 · PCI DSS v4.0 7.2, 8.2.1, 10.2.1',
    detect: (text, lines) => {
      const hit = grep(lines, /^\s*no\s+aaa\s+new-model\b/i);
      if (hit.length) return hit;
      return /^\s*hostname\s/im.test(text) && !/^\s*aaa\s+new-model\b/im.test(text) && /^\s*line\s+vty\b/im.test(text) ? absent('aaa new-model') : [];
    },
    covers: /\baaa\b|tacacs|radius|centrali[sz]ed auth/i,
  },
  {
    id: 'BL-IOS-EXEC-TIMEOUT',
    vendors: ['ios', 'asa'],
    severity: 'medium',
    category: 'management-plane',
    title: 'Idle session timeout disabled',
    why: '"exec-timeout 0 0" keeps an unattended admin session open forever, so anyone who reaches the terminal inherits the privileges.',
    fix: 'line con 0\n exec-timeout 10 0\nline vty 0 15\n exec-timeout 10 0',
    reference: 'NIST SP 800-53 AC-12 · PCI DSS v4.0 8.2.8',
    detect: (_t, lines) => grep(lines, /^\s*exec-timeout\s+0(?:\s+0)?\s*$/i),
    covers: /timeout/i,
  },
  {
    id: 'BL-IOS-VTY-NO-ACL',
    vendors: ['ios'],
    severity: 'medium',
    category: 'management-plane',
    title: 'Remote management not restricted by an access-class',
    why: 'Without an access-class on the VTY lines, any host that can reach the device can attempt to log in.',
    fix: 'ip access-list standard MGMT-ONLY\n permit <MGMT_SUBNET> <WILDCARD>\nline vty 0 15\n access-class MGMT-ONLY in',
    reference: 'NIST SP 800-53 AC-17, SC-7 · PCI DSS v4.0 1.3.1',
    detect: (text, lines) => (/^\s*line\s+vty\b/im.test(text) && !/^\s*access-class\s/im.test(text) ? grep(lines, /^\s*line\s+vty\b/i) : []),
    covers: /access-class|vty (?:acl|access)|management access (?:is )?(?:not )?restrict|unrestricted (?:management|vty)/i,
  },
  {
    id: 'BL-IOS-SNMP-RW',
    vendors: ['ios'],
    severity: 'high',
    category: 'management-plane',
    title: 'SNMP read-write community configured',
    why: 'An SNMP RW community lets anyone who learns it change the configuration, often over cleartext SNMPv2c.',
    fix: 'no snmp-server community <COMMUNITY> RW\n! use SNMPv3 with authPriv for any write access',
    reference: 'NIST SP 800-53 AC-3, SC-8 · PCI DSS v4.0 2.2.7',
    detect: (_t, lines) => grep(lines, /^\s*snmp-server\s+community\s+\S+\s+RW\b/i),
    covers: /\bRW\b|read[- ]write/i,
  },
  {
    id: 'BL-SNMP-V2C',
    vendors: ['ios', 'asa', 'panos', 'junos', 'fortios'],
    severity: 'medium',
    category: 'management-plane',
    title: 'SNMPv1/v2c community strings in use',
    why: 'SNMPv1/v2c sends the community string in cleartext and has no per-user authentication. SNMPv3 with authPriv provides both.',
    fix: 'Replace v1/v2c communities with SNMPv3 users using SHA-256 authentication and AES-256 privacy, restricted to the NMS by ACL.',
    reference: 'NIST SP 800-53 IA-3, SC-8 · PCI DSS v4.0 2.2.7, 8.3.2',
    detect: (_t, lines) =>
      grep(lines, /^\s*snmp-server\s+community\s+/i, /^\s*snmp-server\s+host\s+.*\bcommunity\b/i, /\bsnmp-community-string\b|\bversion\s+v2c\b/i, /^\s*set\s+snmp\s+community\s/i,
        /^\s*config\s+system\s+snmp\s+community\b/i,
      ),
    covers: /snmp ?v1|snmp ?v2c|\bv2c\b|community string|snmp community|snmpv3/i,
  },
  {
    id: 'BL-WEAK-IKE',
    vendors: ['ios', 'asa'],
    severity: 'high',
    category: 'crypto',
    title: 'Weak IKE/IPsec cryptography (DES/3DES, MD5, DH group 1/2/5)',
    why: 'DES and 3DES are broken or deprecated, MD5 is collision-prone and Diffie-Hellman groups 1, 2 and 5 are too small to resist a well-resourced attacker.',
    fix: 'crypto ikev2 proposal STRONG\n encryption aes-gcm-256\n prf sha384\n group 19 20 21\n! or, for IKEv1 policies:\ncrypto isakmp policy 10\n encr aes 256\n hash sha256\n group 14',
    reference: 'NIST SP 800-53 SC-13 · NIST SP 800-77r1 · PCI DSS v4.0 4.2.1',
    detect: (_t, lines) => grep(lines, /^\s*(?:encr|encryption)\s+(?:des|3des)\s*$/i, /^\s*hash\s+md5\s*$/i, /^\s*group\s+(?:1|2|5)\s*$/i),
    covers: /\bdes\b|3des|\bmd5\b|dh group|diffie|group ?[125]\b|ike|isakmp|weak (?:crypto|cipher|encryption)/i,
  },
  {
    id: 'BL-IOS-NO-LOG-TIMESTAMPS',
    vendors: ['ios'],
    severity: 'low',
    category: 'logging',
    title: 'Log messages lack timestamps',
    why: 'Without "service timestamps log datetime" syslog entries cannot be correlated across devices during an incident investigation.',
    fix: 'service timestamps log datetime msec localtime show-timezone',
    reference: 'NIST SP 800-53 AU-8 · PCI DSS v4.0 10.6.1',
    detect: (text) => (/^\s*hostname\s/im.test(text) && !/^\s*service\s+timestamps\s+log\b/im.test(text) ? absent('service timestamps log datetime') : []),
    covers: /timestamp/i,
  },
  {
    id: 'BL-IOS-NO-REMOTE-LOG',
    vendors: ['ios'],
    severity: 'medium',
    category: 'logging',
    title: 'No remote syslog server configured',
    why: 'Logs kept only on the device are lost on reboot and can be erased by an attacker who gains access.',
    fix: 'logging host <SYSLOG_IP>\nlogging trap informational\nlogging source-interface <MGMT_INTERFACE>',
    reference: 'NIST SP 800-53 AU-4(1), AU-9 · PCI DSS v4.0 10.3.3',
    detect: (text) => (/^\s*hostname\s/im.test(text) && !/^\s*logging\s+(?:host\s+)?<(?:IP_|HOST_|IPV6_)|^\s*logging\s+server\s/im.test(text) ? absent('logging host') : []),
    covers: /syslog|remote log|logging host/i,
  },
  {
    id: 'BL-IOS-NO-NTP',
    vendors: ['ios'],
    severity: 'low',
    category: 'logging',
    title: 'No NTP server configured',
    why: 'Without a trusted time source, timestamps drift and log correlation, certificate validation and forensics all suffer.',
    fix: 'ntp server <NTP_IP>\nntp authenticate\nntp authentication-key 1 hmac-sha2-256 <KEY>\nntp trusted-key 1',
    reference: 'NIST SP 800-53 AU-8(1) · PCI DSS v4.0 10.6.2',
    detect: (text) => (/^\s*hostname\s/im.test(text) && !/^\s*ntp\s+server\s/im.test(text) ? absent('ntp server') : []),
    covers: /\bntp\b|time source|time sync/i,
  },

  // ---------------------------------------------------------------- Cisco ASA
  {
    id: 'BL-ASA-TELNET',
    vendors: ['asa'],
    severity: 'high',
    category: 'management-plane',
    title: 'Telnet management enabled on the ASA',
    why: 'Telnet sends credentials in cleartext. ASA management should use SSH version 2 or ASDM over HTTPS only.',
    fix: 'no telnet <NETWORK> <MASK> <INTERFACE>\nssh <MGMT_SUBNET> <MASK> management\nssh version 2',
    reference: 'NIST SP 800-53 AC-17(2), SC-8 · PCI DSS v4.0 2.2.7',
    detect: (_t, lines) => grep(lines, /^\s*telnet\s+(?!timeout\b)\S+\s+\S+\s+\S+/i),
    covers: /telnet/i,
  },
  {
    id: 'BL-ASA-SSH-V1',
    vendors: ['asa'],
    severity: 'high',
    category: 'crypto',
    title: 'SSH version 1 permitted',
    why: 'SSHv1 has known cryptographic weaknesses that allow session hijacking and credential recovery.',
    fix: 'ssh version 2\nssh key-exchange group dh-group14-sha256',
    reference: 'NIST SP 800-53 SC-13 · PCI DSS v4.0 2.2.7, 4.2.1',
    detect: (_t, lines) => grep(lines, /^\s*ssh\s+version\s+1\s*$/i),
    covers: /ssh ?v(?:ersion)? ?1|sshv1/i,
  },
  {
    id: 'BL-ASA-MGMT-ANY',
    vendors: ['asa'],
    severity: 'high',
    category: 'management-plane',
    title: 'Management access (SSH/ASDM) open to any address',
    why: '"0.0.0.0 0.0.0.0" lets every host on that interface attempt to log in, which invites brute-force attacks.',
    fix: 'no ssh 0.0.0.0 0.0.0.0 <INTERFACE>\nno http 0.0.0.0 0.0.0.0 <INTERFACE>\nssh <MGMT_SUBNET> <MASK> management\nhttp <MGMT_SUBNET> <MASK> management',
    reference: 'NIST SP 800-53 AC-17, SC-7 · PCI DSS v4.0 1.3.1',
    detect: (_t, lines) => grep(lines, /^\s*(?:ssh|http|telnet)\s+0\.0\.0\.0\s+0\.0\.0\.0\s+\S+/i),
    covers: /0\.0\.0\.0 0\.0\.0\.0|any (?:address|host|source)|unrestricted management/i,
  },
  {
    id: 'BL-ASA-ANY-ANY',
    vendors: ['asa'],
    severity: 'critical',
    category: 'segmentation',
    title: 'Permit ip any any access rule',
    why: 'An any-to-any permit turns the firewall into a router for that interface and defeats segmentation.',
    fix: 'no access-list <ACL> extended permit ip any any\n! replace with explicit permits for required source, destination and service',
    reference: 'NIST SP 800-53 AC-4, SC-7 · PCI DSS v4.0 1.2.1, 1.3.1',
    detect: (_t, lines) => grep(lines, /^\s*access-list\s+\S+\s+extended\s+permit\s+ip\s+any[46]?\s+any[46]?\b/i),
    covers: /any[ /-]?any|permit ip any|overly permissive|allow[- ]all/i,
  },

  // ---------------------------------------------------------------- Palo Alto PAN-OS
  {
    id: 'BL-PAN-TELNET-HTTP',
    vendors: ['panos'],
    severity: 'high',
    category: 'management-plane',
    title: 'Telnet or HTTP management enabled',
    why: 'Telnet and HTTP send administrator credentials and session cookies in cleartext.',
    fix: 'set deviceconfig system service disable-telnet yes\nset deviceconfig system service disable-http yes\nset deviceconfig system service disable-ssh no\nset deviceconfig system service disable-https no',
    reference: 'NIST SP 800-53 AC-17(2), SC-8 · PCI DSS v4.0 2.2.7',
    detect: (_t, lines) => grep(lines, /\bdisable-(?:telnet|http)\s+no\b/i),
    covers: /telnet|\bhttp\b(?!s)/i,
  },
  {
    id: 'BL-PAN-ANY-ANY',
    vendors: ['panos'],
    severity: 'critical',
    category: 'segmentation',
    title: 'Security rule allows any source, destination, application and service',
    why: 'An allow-all rule removes App-ID and zone enforcement, so any traffic between those zones is permitted.',
    fix: 'delete rulebase security rules <RULE>\n! or narrow it:\nset rulebase security rules <RULE> application [ <APPS> ]\nset rulebase security rules <RULE> service application-default\nset rulebase security rules <RULE> source [ <SRC> ] destination [ <DST> ]',
    reference: 'NIST SP 800-53 AC-4, SC-7 · PCI DSS v4.0 1.2.1, 1.3.1',
    detect: (_t, lines) =>
      grep(lines, /\brulebase\s+security\s+rules\s+\S+.*\bsource\s+any\b.*\bdestination\s+any\b.*\bapplication\s+any\b.*\bservice\s+any\b.*\baction\s+allow\b/i),
    covers: /any[ /-]?any|allow[- ]all|overly permissive|any application|any service/i,
  },
  {
    id: 'BL-PAN-NO-LOG',
    vendors: ['panos'],
    severity: 'medium',
    category: 'logging',
    title: 'Security rule logging disabled',
    why: 'With log-end disabled, sessions matching the rule leave no traffic log, which blinds detection and forensics.',
    fix: 'set rulebase security rules <RULE> log-end yes\nset rulebase security rules <RULE> log-setting <LOG_FORWARDING_PROFILE>',
    reference: 'NIST SP 800-53 AU-2, AU-12 · PCI DSS v4.0 10.2.1',
    detect: (_t, lines) => grep(lines, /\blog-end\s+no\b/i),
    covers: /log-end|logging (?:is )?disabled|no log/i,
  },
  {
    id: 'BL-PAN-WEAK-IKE',
    vendors: ['panos'],
    severity: 'high',
    category: 'crypto',
    title: 'Weak IKE/IPsec crypto profile (3DES/DES, MD5/SHA1, DH group 1/2/5)',
    why: 'These algorithms are deprecated: DES and 3DES are breakable, MD5 and SHA-1 are collision-prone and small DH groups enable precomputation attacks.',
    fix: 'set network ike crypto-profiles ike-crypto-profiles <PROFILE> encryption aes-256-gcm\nset network ike crypto-profiles ike-crypto-profiles <PROFILE> hash sha384\nset network ike crypto-profiles ike-crypto-profiles <PROFILE> dh-group group20',
    reference: 'NIST SP 800-53 SC-13 · PCI DSS v4.0 4.2.1',
    detect: (_t, lines) => grep(lines, /crypto-profiles\s.*\b(?:encryption\s+(?:3des|des)\b|hash\s+(?:md5|sha1)\b|dh-group\s+group(?:1|2|5)\b)/i),
    covers: /\bdes\b|3des|\bmd5\b|sha-?1\b|dh[- ]group|group ?[125]\b|weak (?:ike|crypto|cipher)/i,
  },
  {
    id: 'BL-PAN-RDP-UNTRUST',
    vendors: ['panos'],
    severity: 'high',
    category: 'segmentation',
    title: 'RDP allowed from the untrusted zone',
    why: 'Exposing RDP to the internet is one of the most common ransomware entry points.',
    fix: 'set rulebase security rules <RULE> action deny\n! publish RDP only through GlobalProtect or a bastion with MFA',
    reference: 'NIST SP 800-53 AC-17, SC-7 · PCI DSS v4.0 1.3.1',
    detect: (_t, lines) => grep(lines, /\brules\s+\S+\s+from\s+untrust\b.*\b(?:ms-rdp|service-rdp|3389)\b.*\baction\s+allow\b/i),
    covers: /\brdp\b|remote desktop|3389/i,
  },

  // ---------------------------------------------------------------- Juniper Junos
  {
    id: 'BL-JUNOS-TELNET-HTTP',
    vendors: ['junos'],
    severity: 'high',
    category: 'management-plane',
    title: 'Telnet or cleartext J-Web (HTTP) enabled',
    why: 'Telnet and HTTP send credentials in cleartext.',
    fix: 'delete system services telnet\ndelete system services web-management http\nset system services ssh protocol-version v2',
    reference: 'NIST SP 800-53 AC-17(2), SC-8 · PCI DSS v4.0 2.2.7',
    detect: (_t, lines) => grep(lines, /^\s*set\s+system\s+services\s+(?:telnet|web-management\s+http)\b(?!s)/i),
    covers: /telnet|\bhttp\b(?!s)|j-web/i,
  },
  {
    id: 'BL-JUNOS-ROOT-SSH',
    vendors: ['junos'],
    severity: 'high',
    category: 'aaa',
    title: 'Root login over SSH allowed',
    why: 'Direct root login bypasses per-user accountability and gives an attacker a single high-value account to brute-force.',
    fix: 'set system services ssh root-login deny',
    reference: 'NIST SP 800-53 AC-6(2), IA-2 · PCI DSS v4.0 8.2.2',
    detect: (_t, lines) => grep(lines, /^\s*set\s+system\s+services\s+ssh\s+root-login\s+allow\b/i),
    covers: /root[- ]login|root (?:access|account)/i,
  },
  {
    id: 'BL-JUNOS-WEAK-IKE',
    vendors: ['junos'],
    severity: 'high',
    category: 'crypto',
    title: 'Weak IKE/IPsec proposal (DES/3DES, MD5/SHA1, DH group 1/2/5)',
    why: 'These algorithms are deprecated and do not provide adequate protection for VPN traffic.',
    fix: 'set security ike proposal <PROPOSAL> encryption-algorithm aes-256-gcm\nset security ike proposal <PROPOSAL> dh-group group20\nset security ipsec proposal <PROPOSAL> encryption-algorithm aes-256-gcm',
    reference: 'NIST SP 800-53 SC-13 · PCI DSS v4.0 4.2.1',
    detect: (_t, lines) => grep(lines, /\b(?:encryption-algorithm\s+(?:des|3des)-cbc|authentication-algorithm\s+(?:md5|sha1)\b|dh-group\s+group(?:1|2|5)\b)/i),
    covers: /\bdes\b|3des|\bmd5\b|sha-?1\b|dh[- ]group|group ?[125]\b|weak (?:ike|crypto|cipher)/i,
  },
  {
    id: 'BL-JUNOS-ANY-ANY',
    vendors: ['junos'],
    severity: 'critical',
    category: 'segmentation',
    title: 'Security policy permits any source, destination and application',
    why: 'An any/any/any permit policy removes segmentation between the zones it connects.',
    fix: 'deactivate security policies from-zone <FROM> to-zone <TO> policy <POLICY>\n! replace with explicit address-book entries and applications',
    reference: 'NIST SP 800-53 AC-4, SC-7 · PCI DSS v4.0 1.2.1, 1.3.1',
    detect: (text) => {
      const out: string[] = [];
      for (const m of text.matchAll(/^\s*(set\s+security\s+policies\s+from-zone\s+\S+\s+to-zone\s+\S+\s+policy\s+\S+)\s+match\s+source-address\s+any\s*$/gim)) {
        const p = m[1];
        const has = (s: string) => text.includes(`${p} ${s}`);
        if (has('match destination-address any') && has('match application any') && has('then permit')) out.push(`${p} match source-address any`, `${p} then permit`);
      }
      return out.slice(0, MAX_EVIDENCE);
    },
    covers: /any[ /-]?any|permit[- ]all|allow[- ]all|overly permissive/i,
  },

  // ---------------------------------------------------------------- Fortinet FortiOS
  {
    id: 'BL-FORTI-ALLOWACCESS',
    vendors: ['fortios'],
    severity: 'high',
    category: 'management-plane',
    title: 'Telnet or HTTP administrative access enabled on an interface',
    why: 'Telnet and HTTP expose administrator credentials in cleartext on that interface.',
    fix: 'config system interface\n    edit <PORT>\n        set allowaccess ping https ssh\n    next\nend',
    reference: 'NIST SP 800-53 AC-17(2), SC-8 · PCI DSS v4.0 2.2.7',
    detect: (_t, lines) => grep(lines, /^\s*set\s+allowaccess\s+.*\b(?:telnet|http)\b/i),
    covers: /telnet|\bhttp\b(?!s)|allowaccess/i,
  },
  {
    id: 'BL-FORTI-WEAK-IKE',
    vendors: ['fortios'],
    severity: 'high',
    category: 'crypto',
    title: 'Weak IPsec phase-1/phase-2 proposal (DES/3DES, MD5, DH group 1/2/5)',
    why: 'These algorithms are deprecated and do not provide adequate protection for VPN traffic.',
    fix: 'config vpn ipsec phase1-interface\n    edit <TUNNEL>\n        set proposal aes256gcm-prfsha384\n        set dhgrp 20 21\n    next\nend',
    reference: 'NIST SP 800-53 SC-13 · PCI DSS v4.0 4.2.1',
    detect: (_t, lines) => grep(lines, /^\s*set\s+proposal\s+.*\b(?:des|3des)-|^\s*set\s+proposal\s+.*-md5\b/i, /^\s*set\s+dhgrp\s+(?:.*\s)?(?:1|2|5)(?:\s|$)/i),
    covers: /\bdes\b|3des|\bmd5\b|dh ?gr(?:ou)?p|group ?[125]\b|weak (?:ike|crypto|cipher|proposal)/i,
  },
  {
    id: 'BL-FORTI-ANY-ANY',
    vendors: ['fortios'],
    severity: 'critical',
    category: 'segmentation',
    title: 'Firewall policy accepts all addresses and all services',
    why: 'A policy with srcaddr/dstaddr "all" and service "ALL" set to accept defeats segmentation between those interfaces.',
    fix: 'config firewall policy\n    edit <ID>\n        set srcaddr <SRC_GROUP>\n        set dstaddr <DST_GROUP>\n        set service <REQUIRED_SERVICES>\n    next\nend',
    reference: 'NIST SP 800-53 AC-4, SC-7 · PCI DSS v4.0 1.2.1, 1.3.1',
    detect: (text) => {
      const sect = text.match(/^\s*config\s+firewall\s+policy\b([\s\S]*?)^\s*end\b/im)?.[1] ?? '';
      const out: string[] = [];
      for (const b of sect.matchAll(/^\s*edit\s+(\S+)([\s\S]*?)^\s*next\b/gim)) {
        const body = b[2];
        if (/set\s+srcaddr\s+"?all"?\s*$/im.test(body) && /set\s+dstaddr\s+"?all"?\s*$/im.test(body) && /set\s+service\s+"?ALL"?\s*$/im.test(body) && /set\s+action\s+accept\b/i.test(body))
          out.push(`edit ${b[1]}`, 'set srcaddr "all"', 'set dstaddr "all"', 'set service "ALL"', 'set action accept');
      }
      return out.slice(0, MAX_EVIDENCE);
    },
    covers: /any[ /-]?any|all[ /-]all|allow[- ]all|accept[- ]all|overly permissive/i,
  },
];

export const BASELINE_CHECK_COUNT = CHECKS.length;

/** Internal: a baseline hit plus the pattern used to recognise the same issue in an AI finding. */
export interface BaselineHit {
  finding: AuditFinding;
  covers: RegExp;
}

export function runBaseline(sanitized: string, vendor: string): BaselineHit[] {
  const fam = vendorFamily(vendor);
  const lines = sanitized.split('\n').filter((l) => !/^\s*[!#]/.test(l));
  const text = lines.join('\n');
  const hits: BaselineHit[] = [];
  for (const c of CHECKS) {
    if (c.vendors !== 'all' && !c.vendors.includes(fam)) continue;
    const evidence = c.detect(text, lines);
    if (!evidence.length) continue;
    const comment = fam === 'ios' || fam === 'asa' ? '!' : '#';
    hits.push({
      finding: {
        id: c.id,
        title: c.title,
        severity: c.severity,
        category: c.category,
        evidence: evidence.map((e) => e.replace(/^! not configured/, `${comment} not configured`)).join('\n'),
        why: c.why,
        fix: c.fix,
        reference: c.reference,
        origin: 'rule',
      },
      covers: c.covers,
    });
  }
  return hits;
}

/**
 * Merge AI findings with the deterministic baseline.
 *  - AI findings keep their place; one that matches a baseline hit is marked `confirmedBy`.
 *  - Baseline hits no AI finding covers are appended, so nothing obvious is ever missed.
 *  - Severity of a confirmed AI finding is raised to the baseline severity if the model under-rated it.
 */
export function mergeWithBaseline(ai: AuditFinding[], hits: BaselineHit[]): AuditFinding[] {
  const merged = ai.map((f) => ({ ...f }));
  const sevRank = ['critical', 'high', 'medium', 'low', 'info'];
  for (const h of hits) {
    const bEvidence = h.finding.evidence.split('\n').map((l) => l.trim().toLowerCase()).filter((l) => l && !/not configured/.test(l));
    const open = merged.filter((f) => !f.confirmedBy && f.origin !== 'rule');
    // Prefer an AI finding that describes the same problem AND cites the same line,
    // then the same line alone, then the same problem in the same category.
    const describes = (f: AuditFinding) => h.covers.test(`${f.title}\n${f.evidence}`);
    const shares = (f: AuditFinding) => bEvidence.some((l) => f.evidence.toLowerCase().includes(l));
    const match =
      open.find((f) => describes(f) && shares(f)) ??
      open.find((f) => shares(f) && f.category === h.finding.category) ??
      open.find((f) => describes(f) && f.category === h.finding.category);
    if (match) {
      match.confirmedBy = h.finding.id;
      if (sevRank.indexOf(h.finding.severity) < sevRank.indexOf(match.severity)) match.severity = h.finding.severity;
    } else {
      merged.push({ ...h.finding });
    }
  }
  return merged;
}
