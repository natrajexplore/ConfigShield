/**
 * Firebase bootstrap: App, App Check (required by Firebase AI Logic),
 * Authentication, Firestore, Remote Config and the AI Logic instance.
 *
 * If the web-app config is missing (e.g. someone runs the repo without a
 * .env.local), the app still boots in "local-only" mode: deterministic rules,
 * the baseline auditor and Gemini Nano all work, and every cloud feature is
 * disabled with a clear message instead of crashing at import time.
 */
import { initializeApp } from 'firebase/app';
import { initializeAppCheck, ReCaptchaEnterpriseProvider } from 'firebase/app-check';
import { getAuth, signInAnonymously, type Auth, type User } from 'firebase/auth';
import { getFirestore, type Firestore } from 'firebase/firestore';
import { getRemoteConfig, fetchAndActivate, getValue, type RemoteConfig } from 'firebase/remote-config';
import { getAI, GoogleAIBackend } from 'firebase/ai';

const env = import.meta.env;

/** Values copied verbatim from .env.example (or CI placeholders) are not a real config. */
const isPlaceholder = (v: string | undefined) =>
  !v || /^(?:your-|ci-placeholder$)|^1:0+:web:0+$/.test(v.trim());

/** True when a real Firebase web-app config was provided at build time. */
export const firebaseConfigured =
  !isPlaceholder(env.VITE_FIREBASE_API_KEY) && !isPlaceholder(env.VITE_FIREBASE_PROJECT_ID) && !isPlaceholder(env.VITE_FIREBASE_APP_ID);
if (!firebaseConfigured && (env.VITE_FIREBASE_API_KEY || env.VITE_FIREBASE_PROJECT_ID)) {
  console.warn('[ConfigShield] .env.local still contains placeholder values from .env.example — running in local-only mode.');
}

const firebaseConfig = firebaseConfigured
  ? {
      apiKey: env.VITE_FIREBASE_API_KEY,
      authDomain: env.VITE_FIREBASE_AUTH_DOMAIN,
      projectId: env.VITE_FIREBASE_PROJECT_ID,
      storageBucket: env.VITE_FIREBASE_STORAGE_BUCKET,
      messagingSenderId: env.VITE_FIREBASE_MESSAGING_SENDER_ID,
      appId: env.VITE_FIREBASE_APP_ID,
    }
  : // Placeholder so the on-device (Gemini Nano) path of AI Logic can still be constructed.
    // No request is ever made with it: cloud features are disabled below.
    { apiKey: 'local-only', projectId: 'local-only', appId: 'local-only' };

export const app = initializeApp(firebaseConfig);

// ---- App Check -------------------------------------------------------------
// Firebase AI Logic requires App Check. For local dev / judges' testing we use
// the debug provider (debug tokens are accepted by the contest rules).
// NOTE: do NOT add "localhost" to the reCAPTCHA allowed domains — use the
// debug token instead (per Firebase docs).
if (firebaseConfigured) {
  if (env.DEV || env.VITE_APPCHECK_DEBUG === 'true') {
    const debugToken = env.VITE_APPCHECK_DEBUG_TOKEN;
    (self as unknown as { FIREBASE_APPCHECK_DEBUG_TOKEN: string | boolean }).FIREBASE_APPCHECK_DEBUG_TOKEN =
      debugToken && debugToken.length > 0 ? debugToken : true;
  }
  try {
    initializeAppCheck(app, {
      provider: new ReCaptchaEnterpriseProvider(env.VITE_RECAPTCHA_ENTERPRISE_SITE_KEY ?? 'unset'),
      isTokenAutoRefreshEnabled: true,
    });
  } catch (e) {
    console.warn('[ConfigShield] App Check initialisation failed', e);
  }
}

// ---- Auth / Firestore --------------------------------------------------------
let authInstance: Auth | null = null;
let dbInstance: Firestore | null = null;

export class NotConfiguredError extends Error {
  constructor(feature: string) {
    super(`${feature} needs a Firebase project. Add your web-app config to .env.local (see README).`);
    this.name = 'NotConfiguredError';
  }
}

export function getAuthInstance(): Auth {
  if (!firebaseConfigured) throw new NotConfiguredError('Sign-in');
  return (authInstance ??= getAuth(app));
}

export function getDb(): Firestore {
  if (!firebaseConfigured) throw new NotConfiguredError('Saved reports');
  return (dbInstance ??= getFirestore(app));
}

let signInPromise: Promise<User> | null = null;

/**
 * Resolve the current user, signing in anonymously only if no session was restored.
 * Waiting for `authStateReady()` matters: `currentUser` is null until persistence
 * loads, and signing in before that would create a new anonymous user (and an empty
 * report history) on every page load. The promise is shared so concurrent callers
 * never trigger two sign-ins.
 */
export function ensureSignedIn(): Promise<User> {
  if (!signInPromise) {
    signInPromise = (async () => {
      const auth = getAuthInstance();
      await auth.authStateReady();
      return auth.currentUser ?? (await signInAnonymously(auth)).user;
    })();
    signInPromise.catch(() => (signInPromise = null)); // allow a retry after a failure
  }
  return signInPromise;
}

// ---- Remote Config -----------------------------------------------------------
export interface AppSettings {
  cloudModel: string;
  enableCloudAudit: boolean;
  chunkChars: number;
  policyPack: string;
  maxFindings: number;
  /** Where the values came from — shown in the UI so the kill switch is visible. */
  source: 'remote' | 'defaults';
  /** Human-readable reason when enableCloudAudit is false. */
  cloudDisabledReason?: string;
}

export const DEFAULT_SETTINGS: AppSettings = {
  cloudModel: 'gemini-3.5-flash-lite',
  enableCloudAudit: true,
  chunkChars: 12000,
  policyPack: 'baseline-v1',
  maxFindings: 25,
  source: 'defaults',
};

let remoteConfig: RemoteConfig | null = null;
if (firebaseConfigured) {
  try {
    remoteConfig = getRemoteConfig(app);
    remoteConfig.settings.minimumFetchIntervalMillis = env.DEV ? 60_000 : 3_600_000;
    // Keep this short: in air-gapped / offline use, an audit must not wait on the network.
    remoteConfig.settings.fetchTimeoutMillis = 5_000;
    remoteConfig.defaultConfig = {
      cloud_model: DEFAULT_SETTINGS.cloudModel,
      enable_cloud_audit: DEFAULT_SETTINGS.enableCloudAudit,
      on_device_chunk_chars: DEFAULT_SETTINGS.chunkChars,
      audit_policy_pack: DEFAULT_SETTINGS.policyPack,
      max_findings: DEFAULT_SETTINGS.maxFindings,
    };
  } catch (e) {
    console.warn('[ConfigShield] Remote Config unavailable, using defaults', e);
    remoteConfig = null;
  }
}

const clamp = (n: number, lo: number, hi: number, fallback: number) => (Number.isFinite(n) && n > 0 ? Math.min(hi, Math.max(lo, n)) : fallback);

let settingsPromise: Promise<AppSettings> | null = null;

/** Fetch Remote Config once per page load (shared promise), falling back to compiled-in defaults. */
export function loadSettings(): Promise<AppSettings> {
  return (settingsPromise ??= (async (): Promise<AppSettings> => {
    if (!remoteConfig) {
      return firebaseConfigured
        ? DEFAULT_SETTINGS
        : { ...DEFAULT_SETTINGS, enableCloudAudit: false, cloudDisabledReason: 'no Firebase project configured — local-only mode' };
    }
    const rc = remoteConfig;
    let fetched = false;
    try {
      await Promise.race([
        fetchAndActivate(rc).then(() => (fetched = true)),
        new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 6_000)),
      ]);
    } catch (e) {
      console.warn('[ConfigShield] Remote Config fetch failed, using cached/default values', e);
    }
    const model = getValue(rc, 'cloud_model').asString().trim();
    const enableCloudAudit = getValue(rc, 'enable_cloud_audit').asBoolean();
    return {
      cloudModel: /^[\w.\-/]{3,80}$/.test(model) ? model : DEFAULT_SETTINGS.cloudModel,
      enableCloudAudit,
      ...(enableCloudAudit ? {} : { cloudDisabledReason: 'cloud audit switched off by the Remote Config kill switch' }),
      chunkChars: clamp(getValue(rc, 'on_device_chunk_chars').asNumber(), 2_000, 24_000, DEFAULT_SETTINGS.chunkChars),
      policyPack: getValue(rc, 'audit_policy_pack').asString().slice(0, 60) || DEFAULT_SETTINGS.policyPack,
      maxFindings: Math.round(clamp(getValue(rc, 'max_findings').asNumber(), 1, 40, DEFAULT_SETTINGS.maxFindings)),
      source: fetched || getValue(rc, 'cloud_model').getSource() === 'remote' ? 'remote' : 'defaults',
    };
  })());
}

// ---- Firebase AI Logic ---------------------------------------------------------
export const ai = getAI(app, { backend: new GoogleAIBackend() });
