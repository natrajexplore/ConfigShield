/**
 * TokenVault — keeps the mapping between real values and placeholder tokens.
 *
 * The vault lives ONLY in browser memory. It is never persisted, never sent to
 * the cloud model and never written to Firestore. It exists so the user can
 * "re-hydrate" the sanitized audit report locally and see real values again.
 */
export type TokenKind =
  | 'SECRET'
  | 'WEAKSECRET'
  | 'HASH'
  | 'KEYBLOCK'
  | 'IP_PRIV'
  | 'IP_PUB'
  | 'IPV6'
  | 'EMAIL'
  | 'HOST'
  | 'DOMAIN'
  | 'USER'
  | 'BANNER'
  | 'ORG'
  | 'PERSON'
  | 'LOCATION'
  | 'SITE'
  | 'CIRCUIT'
  | 'PHONE'
  | 'DESC'
  | 'OTHER';

export interface VaultEntry {
  token: string;
  original: string;
  kind: TokenKind;
  source: 'deterministic' | 'on_device';
}

export class TokenVault {
  private byOriginal = new Map<string, VaultEntry>();
  private byToken = new Map<string, VaultEntry>();
  private counters = new Map<TokenKind, number>();

  tokenFor(original: string, kind: TokenKind, source: VaultEntry['source'] = 'deterministic'): string {
    const existing = this.byOriginal.get(original);
    if (existing) return existing.token;
    const n = (this.counters.get(kind) ?? 0) + 1;
    this.counters.set(kind, n);
    const token = `<${kind}_${n}>`;
    const entry: VaultEntry = { token, original, kind, source };
    this.byOriginal.set(original, entry);
    this.byToken.set(token, entry);
    return token;
  }

  /** Look up the vault entry behind a placeholder token (local display only). */
  lookup(token: string): VaultEntry | undefined {
    return this.byToken.get(token);
  }

  get size(): number {
    return this.byOriginal.size;
  }

  has(original: string): boolean {
    return this.byOriginal.has(original);
  }

  entries(): VaultEntry[] {
    return [...this.byOriginal.values()];
  }

  countBySource(source: VaultEntry['source']): number {
    return this.entries().filter((e) => e.source === source).length;
  }

  /** Replace tokens with real values — for local display only. */
  rehydrate(text: string): string {
    return text.replace(/<[A-Z_]+_\d+>/g, (t) => this.byToken.get(t)?.original ?? t);
  }

  clear(): void {
    this.byOriginal.clear();
    this.byToken.clear();
    this.counters.clear();
  }
}

/** Escape a literal string for use inside a RegExp. */
export function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Replace every literal occurrence of `value` in `text` with `token`. */
export function replaceAllLiteral(text: string, value: string, token: string): string {
  if (!value) return text;
  return text.replace(new RegExp(escapeRegExp(value), 'g'), token);
}
