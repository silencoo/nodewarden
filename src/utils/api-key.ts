import { decryptServerSecret, encryptServerSecret, isEncryptedServerSecret } from './server-secret';

const API_KEY_HASH_PREFIX = 'sha256:';
const API_KEY_ENCRYPTION_CONTEXT_PREFIX = 'nodewarden.api-key.v1';

function apiKeyEncryptionContext(userId: string): string {
  const normalized = String(userId || '').trim();
  if (!normalized) throw new Error('API key owner is required');
  return `${API_KEY_ENCRYPTION_CONTEXT_PREFIX}:${normalized}`;
}

export function constantTimeEquals(a: string, b: string): boolean {
  const encA = new TextEncoder().encode(a);
  const encB = new TextEncoder().encode(b);
  if (encA.length !== encB.length) return false;

  let diff = 0;
  for (let i = 0; i < encA.length; i++) {
    diff |= encA[i] ^ encB[i];
  }
  return diff === 0;
}

function toHex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

export function isStoredApiKeyHash(value: string | null | undefined): boolean {
  return String(value || '').startsWith(API_KEY_HASH_PREFIX);
}

export function isStoredApiKeyEncrypted(value: string | null | undefined): boolean {
  return isEncryptedServerSecret(value);
}

export async function hashApiKey(apiKey: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(apiKey));
  return `${API_KEY_HASH_PREFIX}${toHex(digest)}`;
}

export async function encryptApiKey(apiKey: string, jwtSecret: string, userId: string): Promise<string> {
  return encryptServerSecret(apiKey, jwtSecret, apiKeyEncryptionContext(userId));
}

export async function decryptApiKey(
  storedApiKey: string | null | undefined,
  jwtSecret: string,
  userId: string
): Promise<string | null> {
  const stored = String(storedApiKey || '').trim();
  if (!stored || isStoredApiKeyHash(stored)) return null;
  return decryptServerSecret(stored, jwtSecret, apiKeyEncryptionContext(userId));
}

export async function verifyApiKey(
  apiKey: string,
  storedApiKey: string | null | undefined,
  jwtSecret?: string,
  userId?: string
): Promise<boolean> {
  const stored = String(storedApiKey || '').trim();
  if (!stored) return false;

  if (isStoredApiKeyEncrypted(stored)) {
    if (!jwtSecret || !userId) return false;
    try {
      const decrypted = await decryptApiKey(stored, jwtSecret, userId);
      return !!decrypted && constantTimeEquals(apiKey, decrypted);
    } catch {
      return false;
    }
  }

  // Readable keys from earlier releases are accepted and migrated the next
  // time the user opens the API-key settings page.
  if (!isStoredApiKeyHash(stored)) {
    return constantTimeEquals(apiKey, stored);
  }

  const hashed = await hashApiKey(apiKey);
  return constantTimeEquals(hashed, stored);
}
