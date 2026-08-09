import {
  requestYubicoApiCredentials,
  type YubicoApiCredentials,
} from '../utils/yubico-otp';
import type { Env } from '../types';
import { decryptServerSecret, encryptServerSecret, isEncryptedServerSecret } from '../utils/server-secret';

export const YUBICO_CLIENT_ID_CONFIG_KEY = 'globalSettings__yubico__clientId';
export const YUBICO_SECRET_KEY_CONFIG_KEY = 'globalSettings__yubico__key';
export const YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY = 'yubico.bootstrap.claim.v1';

const YUBICO_BOOTSTRAP_CLAIM_TTL_MS = 2 * 60 * 1000;
const YUBICO_SECRET_CONTEXT_PREFIX = 'nodewarden.yubico.validation-secret.v1';

export interface YubicoCredentialInitializationResult {
  credentials: YubicoApiCredentials;
  created: boolean;
}

function yubicoSecretContext(clientId: string): string {
  return `${YUBICO_SECRET_CONTEXT_PREFIX}:${String(clientId || '').trim()}`;
}

export function isYubicoCredentialConfigKey(key: unknown): boolean {
  const normalized = String(key || '').trim();
  return normalized === YUBICO_CLIENT_ID_CONFIG_KEY || normalized === YUBICO_SECRET_KEY_CONFIG_KEY;
}

export async function getYubicoCredentials(env: Pick<Env, 'DB' | 'JWT_SECRET'>): Promise<YubicoApiCredentials | null> {
  const result = await env.DB
    .prepare('SELECT key, value FROM config WHERE key IN (?, ?)')
    .bind(YUBICO_CLIENT_ID_CONFIG_KEY, YUBICO_SECRET_KEY_CONFIG_KEY)
    .all<{ key: string; value: string }>();
  const values = new Map((result.results || []).map((row) => [row.key, String(row.value || '').trim()]));
  const clientId = values.get(YUBICO_CLIENT_ID_CONFIG_KEY) || '';
  const storedSecret = values.get(YUBICO_SECRET_KEY_CONFIG_KEY) || '';
  if (!clientId || !storedSecret) return null;
  const secretKey = await decryptServerSecret(storedSecret, env.JWT_SECRET, yubicoSecretContext(clientId));
  if (!isEncryptedServerSecret(storedSecret)) {
    const encrypted = await encryptServerSecret(secretKey, env.JWT_SECRET, yubicoSecretContext(clientId));
    await env.DB.prepare(
      'INSERT INTO config(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
    ).bind(YUBICO_SECRET_KEY_CONFIG_KEY, encrypted).run();
  }
  return { clientId, secretKey };
}

export async function replaceYubicoCredentials(
  env: Pick<Env, 'DB' | 'JWT_SECRET'>,
  credentials: YubicoApiCredentials
): Promise<void> {
  const clientId = String(credentials.clientId || '').trim();
  const secretKey = String(credentials.secretKey || '').trim();
  if (!clientId || !secretKey) throw new Error('Yubico credentials are incomplete');
  const encryptedSecret = await encryptServerSecret(secretKey, env.JWT_SECRET, yubicoSecretContext(clientId));
  await env.DB.batch([
    env.DB.prepare(
      'INSERT INTO config(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
    ).bind(YUBICO_CLIENT_ID_CONFIG_KEY, clientId),
    env.DB.prepare(
      'INSERT INTO config(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
    ).bind(YUBICO_SECRET_KEY_CONFIG_KEY, encryptedSecret),
  ]);
}

async function acquireBootstrapClaim(db: D1Database): Promise<string | null> {
  const now = Date.now();
  await db
    .prepare('DELETE FROM config WHERE key = ? AND CAST(value AS INTEGER) < ?')
    .bind(YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY, now)
    .run();
  const claim = `${now + YUBICO_BOOTSTRAP_CLAIM_TTL_MS}:${crypto.randomUUID()}`;
  const result = await db
    .prepare('INSERT OR IGNORE INTO config(key, value) VALUES(?, ?)')
    .bind(YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY, claim)
    .run();
  return (result.meta.changes ?? 0) > 0 ? claim : null;
}

async function releaseBootstrapClaim(db: D1Database, claim: string): Promise<void> {
  await db
    .prepare('DELETE FROM config WHERE key = ? AND value = ?')
    .bind(YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY, claim)
    .run();
}

export async function initializeYubicoCredentialsOnce(
  env: Pick<Env, 'DB' | 'JWT_SECRET'>,
  email: string,
  otp: string
): Promise<YubicoCredentialInitializationResult | null> {
  const existing = await getYubicoCredentials(env);
  if (existing) return { credentials: existing, created: false };

  const claim = await acquireBootstrapClaim(env.DB);
  if (!claim) {
    const concurrentlyCreated = await getYubicoCredentials(env);
    return concurrentlyCreated ? { credentials: concurrentlyCreated, created: false } : null;
  }

  try {
    const rechecked = await getYubicoCredentials(env);
    if (rechecked) return { credentials: rechecked, created: false };

    const issued = await requestYubicoApiCredentials(email, otp);
    if (!issued?.clientId || !issued.secretKey) return null;

    const configuredDuringRequest = await getYubicoCredentials(env);
    if (configuredDuringRequest) {
      return { credentials: configuredDuringRequest, created: false };
    }

    await replaceYubicoCredentials(env, issued);
    return { credentials: issued, created: true };
  } finally {
    await releaseBootstrapClaim(env.DB, claim).catch(() => undefined);
  }
}
