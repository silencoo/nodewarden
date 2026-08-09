import type { Env } from '../types';
import {
  setConfigValue as saveConfigValue,
} from './storage-config-repo';
import { decryptServerSecret, encryptServerSecret, isEncryptedServerSecret } from '../utils/server-secret';
import { readBoundedResponseJson } from '../utils/bounded-response';
import { rejectRedirectResponse } from '../utils/redirect-response';

const PUSH_RELAY_URI = 'https://push.bitwarden.com';
const PUSH_IDENTITY_URI = 'https://identity.bitwarden.com';
const INSTALLATIONS_URI = 'https://api.bitwarden.com/installations';
export const PUSH_INSTALLATION_ID_KEY = 'push.installation.id';
export const PUSH_INSTALLATION_KEY_KEY = 'push.installation.key';
const PUSH_REQUEST_TIMEOUT_MS = 5000;
const PUSH_RESPONSE_MAX_BYTES = 64 * 1024;
const PUSH_INSTALLATION_SECRET_CONTEXT_PREFIX = 'nodewarden.push.installation-secret.v1';

interface CachedPushAccessToken {
  token: string;
  expiresAt: number;
}

let cachedPushAccessToken: CachedPushAccessToken | null = null;

async function fetchPushEndpoint(url: string, init: RequestInit, errorMessage: string): Promise<Response | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), PUSH_REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(url, { ...init, redirect: 'manual', signal: controller.signal });
    return await rejectRedirectResponse(response, 'Bitwarden push endpoint');
  } catch (error) {
    console.error(errorMessage, error);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function randomInstallationEmail(): string {
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  const localPart = Array.from(bytes, (byte) => (byte % 36).toString(36)).join('');
  return `${localPart}@nodewarden.app`;
}

async function getConfigKeyPresence(db: D1Database, key: string): Promise<string | null> {
  const row = await db.prepare('SELECT value FROM config WHERE key = ? LIMIT 1').bind(key).first<{ value: string }>();
  return typeof row?.value === 'string' ? row.value : null;
}

function pushInstallationSecretContext(id: string): string {
  return `${PUSH_INSTALLATION_SECRET_CONTEXT_PREFIX}:${String(id || '').trim()}`;
}

export function isPushCredentialConfigKey(key: unknown): boolean {
  const normalized = String(key || '').trim();
  return normalized === PUSH_INSTALLATION_ID_KEY || normalized === PUSH_INSTALLATION_KEY_KEY;
}

async function getPushInstallationCredentials(
  env: Pick<Env, 'DB' | 'JWT_SECRET'>
): Promise<{ id: string; key: string } | null> {
  const [id, key] = await Promise.all([
    getConfigKeyPresence(env.DB, PUSH_INSTALLATION_ID_KEY),
    getConfigKeyPresence(env.DB, PUSH_INSTALLATION_KEY_KEY),
  ]);
  const normalizedId = String(id || '').trim();
  const storedKey = String(key || '').trim();
  if (!normalizedId || normalizedId.length > 256 || !storedKey || storedKey.length > 16_384) return null;
  const plaintextKey = await decryptServerSecret(
    storedKey,
    env.JWT_SECRET,
    pushInstallationSecretContext(normalizedId)
  );
  if (!isEncryptedServerSecret(storedKey)) {
    const encryptedKey = await encryptServerSecret(
      plaintextKey,
      env.JWT_SECRET,
      pushInstallationSecretContext(normalizedId)
    );
    await saveConfigValue(env.DB, PUSH_INSTALLATION_KEY_KEY, encryptedKey);
  }
  return { id: normalizedId, key: plaintextKey };
}

export async function ensurePushInstallationCredentials(
  env: Pick<Env, 'DB' | 'JWT_SECRET'>
): Promise<{ id: string; key: string } | null> {
  const existing = await getPushInstallationCredentials(env);
  if (existing) return existing;

  const response = await fetchPushEndpoint(
    INSTALLATIONS_URI,
    {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        email: randomInstallationEmail(),
      }),
    },
    'Failed to request Bitwarden push installation:'
  );
  if (!response) return null;

  if (!response.ok) {
    console.error('Failed to request Bitwarden push installation:', response.status);
    return null;
  }

  const body = await readBoundedResponseJson<{
    id?: string;
    Id?: string;
    key?: string;
    Key?: string;
    enabled?: boolean;
    Enabled?: boolean;
  }>(response, PUSH_RESPONSE_MAX_BYTES, 'Push installation response').catch(() => null);
  const id = String(body?.id || body?.Id || '').trim();
  const key = String(body?.key || body?.Key || '').trim();
  if (!id || id.length > 256 || !key || key.length > 4096) {
    console.error('Bitwarden push installation response did not include id/key');
    return null;
  }

  const encryptedKey = await encryptServerSecret(
    key,
    env.JWT_SECRET,
    pushInstallationSecretContext(id)
  );
  await env.DB.batch([
    env.DB.prepare(
      'INSERT INTO config(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
    ).bind(PUSH_INSTALLATION_ID_KEY, id),
    env.DB.prepare(
      'INSERT INTO config(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
    ).bind(PUSH_INSTALLATION_KEY_KEY, encryptedKey),
  ]);
  return { id, key };
}

async function getPushAccessToken(env: Env): Promise<string | null> {
  const credentials = await ensurePushInstallationCredentials(env).catch((error) => {
    console.error('Failed to load Bitwarden push installation:', error instanceof Error ? error.message : 'unknown error');
    return null;
  });
  if (!credentials) return null;

  const now = Date.now();
  if (cachedPushAccessToken && cachedPushAccessToken.expiresAt > now + 30_000) {
    return cachedPushAccessToken.token;
  }

  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    scope: 'api.push',
    client_id: `installation.${credentials.id}`,
    client_secret: credentials.key,
  });

  const response = await fetchPushEndpoint(
    `${PUSH_IDENTITY_URI}/connect/token`,
    {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    },
    'Failed to get Bitwarden push relay token:'
  );
  if (!response) return null;

  if (!response.ok) {
    console.error('Failed to get Bitwarden push relay token:', response.status);
    return null;
  }

  const body = await readBoundedResponseJson<{ access_token?: string; expires_in?: number }>(
    response,
    PUSH_RESPONSE_MAX_BYTES,
    'Push relay token response'
  ).catch(() => null);
  const token = String(body?.access_token || '').trim();
  if (!token || token.length > 16_384) {
    console.error('Bitwarden push relay token response did not include an access_token');
    return null;
  }

  const rawExpiresInSeconds = Number(body?.expires_in || 3600);
  const expiresInSeconds = Number.isFinite(rawExpiresInSeconds)
    ? Math.max(60, Math.min(24 * 60 * 60, rawExpiresInSeconds))
    : 3600;
  cachedPushAccessToken = {
    token,
    expiresAt: now + Math.floor(expiresInSeconds * 500),
  };
  return token;
}

async function postToPushRelay(env: Env, path: string, body?: unknown): Promise<boolean> {
  const token = await getPushAccessToken(env);
  if (!token) return false;

  const response = await fetchPushEndpoint(
    `${PUSH_RELAY_URI}${path}`,
    {
      method: 'POST',
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    },
    `Bitwarden push relay request failed: ${path}`
  );
  if (!response) return false;

  if (!response.ok) {
    console.error('Bitwarden push relay request failed:', path, response.status);
    return false;
  }

  return true;
}

function mobilePayloadFromSignalR(updateType: number, userId: string, revisionDate: string, payload: Record<string, unknown> | null | undefined): Record<string, unknown> {
  const source = payload || {};
  const id = source.Id ?? source.id;
  const organizationId = source.OrganizationId ?? source.organizationId ?? null;
  const collectionIds = source.CollectionIds ?? source.collectionIds ?? null;

  if (id != null) {
    return {
      id,
      userId: source.UserId ?? source.userId ?? userId,
      organizationId,
      collectionIds,
      revisionDate: source.RevisionDate ?? source.revisionDate ?? revisionDate,
    };
  }

  return {
    userId: source.UserId ?? source.userId ?? userId,
    date: source.Date ?? source.date ?? revisionDate,
  };
}

export async function registerMobilePushDevice(
  env: Env,
  input: {
    userId: string;
    deviceIdentifier: string;
    type: number;
    pushUuid: string;
    pushToken: string;
  }
): Promise<boolean> {
  const credentials = await ensurePushInstallationCredentials(env).catch(() => null);
  if (!credentials) return false;

  return postToPushRelay(env, '/push/register', {
    deviceId: input.pushUuid,
    pushToken: input.pushToken,
    userId: input.userId,
    type: input.type,
    identifier: input.deviceIdentifier,
    installationId: credentials.id,
  });
}

export async function unregisterMobilePushDevice(env: Env, pushUuid: string | null | undefined): Promise<boolean> {
  const normalized = String(pushUuid || '').trim();
  if (!normalized) return false;
  return postToPushRelay(env, '/push/delete', { id: normalized });
}

export async function notifyMobilePush(
  env: Env,
  input: {
    userId: string;
    updateType: number;
    revisionDate: string;
    contextId: string | null;
    payload: Record<string, unknown> | null | undefined;
  }
): Promise<void> {
  const hasPushDevice = await env.DB
    .prepare('SELECT 1 FROM devices WHERE user_id = ? AND push_token IS NOT NULL AND push_token <> ? LIMIT 1')
    .bind(input.userId, '')
    .first<{ '1': number }>();
  if (!hasPushDevice) return;

  let actingPushUuid: string | null = null;
  if (input.contextId) {
    const row = await env.DB
      .prepare('SELECT push_uuid FROM devices WHERE user_id = ? AND device_identifier = ? LIMIT 1')
      .bind(input.userId, input.contextId)
      .first<{ push_uuid: string | null }>();
    actingPushUuid = row?.push_uuid ?? null;
  }

  await postToPushRelay(env, '/push/send', {
    userId: input.userId,
    organizationId: null,
    deviceId: actingPushUuid,
    identifier: input.contextId,
    type: input.updateType,
    payload: mobilePayloadFromSignalR(input.updateType, input.userId, input.revisionDate, input.payload),
    clientType: null,
    installationId: null,
  });
}
