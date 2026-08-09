const SERVER_SECRET_PREFIX = 'nwsecret:v1:';
const SERVER_SECRET_SALT = 'nodewarden.server-secret.v1';
const AES_GCM_IV_BYTES = 12;

const keyCache = new Map<string, Promise<CryptoKey>>();

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(value: string): Uint8Array {
  if (!value || value.length > 16_384 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('Server secret envelope is invalid');
  }
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function contextBytes(context: string): Uint8Array {
  const normalized = String(context || '').trim();
  if (!normalized || normalized.length > 512) throw new Error('Server secret context is invalid');
  return new TextEncoder().encode(normalized);
}

function deriveServerSecretKey(jwtSecret: string, context: string): Promise<CryptoKey> {
  const normalizedSecret = String(jwtSecret || '').trim();
  if (normalizedSecret.length < 32) throw new Error('Server secret key is unavailable');
  const normalizedContext = String(context || '').trim();
  contextBytes(normalizedContext);
  const cacheKey = `${normalizedSecret}\0${normalizedContext}`;
  let cached = keyCache.get(cacheKey);
  if (cached) return cached;
  cached = (async () => {
    const encoder = new TextEncoder();
    const material = await crypto.subtle.importKey(
      'raw',
      encoder.encode(normalizedSecret),
      'HKDF',
      false,
      ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits({
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode(SERVER_SECRET_SALT),
      info: encoder.encode(normalizedContext),
    }, material, 256);
    return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  })();
  keyCache.set(cacheKey, cached);
  return cached;
}

export function isEncryptedServerSecret(value: unknown): boolean {
  return String(value || '').startsWith(SERVER_SECRET_PREFIX);
}

export async function encryptServerSecret(
  plaintextRaw: string,
  jwtSecret: string,
  context: string
): Promise<string> {
  const plaintext = String(plaintextRaw ?? '');
  if (!plaintext) throw new Error('Server secret value is required');
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const key = await deriveServerSecretKey(jwtSecret, context);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({
    name: 'AES-GCM',
    iv,
    additionalData: contextBytes(context),
  }, key, new TextEncoder().encode(plaintext)));
  return `${SERVER_SECRET_PREFIX}${bytesToBase64Url(iv)}:${bytesToBase64Url(ciphertext)}`;
}

export async function decryptServerSecret(
  envelopeOrPlaintext: string,
  jwtSecret: string,
  context: string
): Promise<string> {
  const value = String(envelopeOrPlaintext || '');
  if (!isEncryptedServerSecret(value)) return value;
  const parts = value.slice(SERVER_SECRET_PREFIX.length).split(':');
  if (parts.length !== 2) throw new Error('Server secret envelope is invalid');
  const iv = base64UrlToBytes(parts[0]);
  const ciphertext = base64UrlToBytes(parts[1]);
  if (iv.byteLength !== AES_GCM_IV_BYTES || ciphertext.byteLength < 17) {
    throw new Error('Server secret envelope is invalid');
  }
  try {
    const key = await deriveServerSecretKey(jwtSecret, context);
    const plaintext = await crypto.subtle.decrypt({
      name: 'AES-GCM',
      iv,
      additionalData: contextBytes(context),
    }, key, ciphertext);
    return new TextDecoder().decode(plaintext);
  } catch {
    throw new Error('Server secret cannot be decrypted with the current key');
  }
}
