import { JWTPayload } from '../types';
import { LIMITS } from '../config/limits';

const hmacKeyCache = new Map<string, Promise<CryptoKey>>();

// Base64 URL encode
function base64UrlEncode(data: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...data));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Base64 URL decode
function base64UrlDecode(str: string): Uint8Array {
  if (!str || str.length > 16_384 || !/^[A-Za-z0-9_-]+$/.test(str)) {
    throw new Error('Invalid base64url value');
  }
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function hasValidJwtHeader(headerB64: string): boolean {
  try {
    const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(headerB64))) as {
      alg?: unknown;
      typ?: unknown;
    };
    return header.alg === 'HS256' && header.typ === 'JWT';
  } catch {
    return false;
  }
}

function hasValidTemporalClaims(
  payload: { iat?: unknown; exp?: unknown },
  maxLifetimeSeconds: number
): payload is { iat: number; exp: number } {
  const now = Math.floor(Date.now() / 1000);
  return (
    Number.isSafeInteger(payload.iat)
    && Number.isSafeInteger(payload.exp)
    && (payload.iat as number) <= now + 60
    && (payload.exp as number) >= now
    && (payload.exp as number) >= (payload.iat as number)
    && (payload.exp as number) - (payload.iat as number) <= maxLifetimeSeconds
  );
}

function getHmacKey(secret: string): Promise<CryptoKey> {
  const cacheKey = secret;
  let cached = hmacKeyCache.get(cacheKey);
  if (cached) return cached;

  const encoder = new TextEncoder();
  cached = crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
  hmacKeyCache.set(cacheKey, cached);
  return cached;
}

// Create JWT
export async function createJWT(payload: Omit<JWTPayload, 'iat' | 'exp' | 'iss' | 'premium' | 'email_verified' | 'amr'>, secret: string, expiresIn: number = LIMITS.auth.accessTokenTtlSeconds): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  
  const fullPayload: JWTPayload = {
    ...payload,
    email_verified: true,  // required by mobile client
    amr: ['Application'],  // authentication methods reference - required by mobile client
    iat: now,
    exp: now + expiresIn,
    iss: 'nodewarden',
    premium: true,
  };

  const encoder = new TextEncoder();
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(fullPayload)));
  
  const data = `${headerB64}.${payloadB64}`;
  
  const key = await getHmacKey(secret);
  
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureB64 = base64UrlEncode(new Uint8Array(signature));
  
  return `${data}.${signatureB64}`;
}

// Verify JWT
export async function verifyJWT(token: string, secret: string): Promise<JWTPayload | null> {
  try {
    if (!token || token.length > 16_384) return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    if (!hasValidJwtHeader(headerB64)) return null;
    const encoder = new TextEncoder();
    
    const key = await getHmacKey(secret);
    
    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload: JWTPayload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
    
    if (
      payload.iss !== 'nodewarden'
      || typeof payload.sub !== 'string' || !payload.sub
      || typeof payload.sstamp !== 'string' || !payload.sstamp
      || !hasValidTemporalClaims(payload, LIMITS.auth.accessTokenTtlSeconds)
    ) return null;

    return payload;
  } catch {
    return null;
  }
}

// Create refresh token (simple random string)
export function createRefreshToken(): string {
  const bytes = new Uint8Array(LIMITS.auth.refreshTokenRandomBytes);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

export interface NotificationConnectionClaims {
  sub: string;
  did: string | null;
  typ: 'notification_connect';
  jti: string;
  iat: number;
  exp: number;
}

export async function createNotificationConnectionToken(
  userId: string,
  deviceIdentifier: string | null,
  secret: string
): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload: NotificationConnectionClaims = {
    sub: userId,
    did: String(deviceIdentifier || '').trim() || null,
    typ: 'notification_connect',
    jti: createRefreshToken(),
    iat: now,
    exp: now + LIMITS.auth.notificationConnectionTokenTtlSeconds,
  };
  const encoder = new TextEncoder();
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const data = `${headerB64}.${payloadB64}`;
  const key = await getHmacKey(secret);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return `${data}.${base64UrlEncode(new Uint8Array(signature))}`;
}

export async function verifyNotificationConnectionToken(
  token: string,
  secret: string
): Promise<NotificationConnectionClaims | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [headerB64, payloadB64, signatureB64] = parts;
    const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(headerB64))) as {
      alg?: unknown;
      typ?: unknown;
    };
    if (header.alg !== 'HS256' || header.typ !== 'JWT') return null;

    const encoder = new TextEncoder();
    const key = await getHmacKey(secret);
    const data = `${headerB64}.${payloadB64}`;
    const valid = await crypto.subtle.verify('HMAC', key, base64UrlDecode(signatureB64), encoder.encode(data));
    if (!valid) return null;

    const payload = JSON.parse(
      new TextDecoder().decode(base64UrlDecode(payloadB64))
    ) as Partial<NotificationConnectionClaims>;
    const now = Math.floor(Date.now() / 1000);
    if (
      payload.typ !== 'notification_connect' ||
      typeof payload.sub !== 'string' || !payload.sub ||
      typeof payload.jti !== 'string' || !payload.jti ||
      typeof payload.iat !== 'number' ||
      typeof payload.exp !== 'number' || payload.exp < now ||
      payload.exp - payload.iat > LIMITS.auth.notificationConnectionTokenTtlSeconds
    ) {
      return null;
    }
    return {
      sub: payload.sub,
      did: typeof payload.did === 'string' && payload.did.trim() ? payload.did.trim() : null,
      typ: 'notification_connect',
      jti: payload.jti,
      iat: payload.iat,
      exp: payload.exp,
    };
  } catch {
    return null;
  }
}

// File download token payload
export interface FileDownloadClaims {
  typ: 'attachment_download';
  cipherId: string;
  attachmentId: string;
  jti: string;
  iat: number;
  exp: number;
}

export interface AttachmentUploadClaims {
  typ: 'attachment_upload';
  userId: string;
  cipherId: string;
  attachmentId: string;
  iat: number;
  exp: number;
}

// Create file download token (short-lived, 5 minutes)
export async function createFileDownloadToken(
  cipherId: string,
  attachmentId: string,
  secret: string
): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  
  const payload: FileDownloadClaims = {
    typ: 'attachment_download',
    cipherId,
    attachmentId,
    jti: createRefreshToken(),
    iat: now,
    exp: now + LIMITS.auth.fileDownloadTokenTtlSeconds, // 5 minutes
  };

  const encoder = new TextEncoder();
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  
  const data = `${headerB64}.${payloadB64}`;
  
  const key = await getHmacKey(secret);
  
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureB64 = base64UrlEncode(new Uint8Array(signature));
  
  return `${data}.${signatureB64}`;
}

// Verify file download token
export async function verifyFileDownloadToken(
  token: string,
  secret: string
): Promise<FileDownloadClaims | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    if (!hasValidJwtHeader(headerB64)) return null;
    const encoder = new TextEncoder();
    
    const key = await getHmacKey(secret);
    
    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload: FileDownloadClaims = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
    
    if (
      payload.typ !== 'attachment_download'
      || typeof payload.cipherId !== 'string' || !payload.cipherId
      || typeof payload.attachmentId !== 'string' || !payload.attachmentId
      || typeof payload.jti !== 'string' || !payload.jti
      || !hasValidTemporalClaims(payload, LIMITS.auth.fileDownloadTokenTtlSeconds)
    ) return null;

    return payload;
  } catch {
    return null;
  }
}

export async function createAttachmentUploadToken(
  userId: string,
  cipherId: string,
  attachmentId: string,
  secret: string
): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload: AttachmentUploadClaims = {
    typ: 'attachment_upload',
    userId,
    cipherId,
    attachmentId,
    iat: now,
    exp: now + LIMITS.auth.fileDownloadTokenTtlSeconds,
  };

  const encoder = new TextEncoder();
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const data = `${headerB64}.${payloadB64}`;

  const key = await getHmacKey(secret);

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureB64 = base64UrlEncode(new Uint8Array(signature));
  return `${data}.${signatureB64}`;
}

export async function verifyAttachmentUploadToken(
  token: string,
  secret: string
): Promise<AttachmentUploadClaims | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    if (!hasValidJwtHeader(headerB64)) return null;
    const encoder = new TextEncoder();

    const key = await getHmacKey(secret);

    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload: AttachmentUploadClaims = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
    if (
      payload.typ !== 'attachment_upload'
      || typeof payload.userId !== 'string' || !payload.userId
      || typeof payload.cipherId !== 'string' || !payload.cipherId
      || typeof payload.attachmentId !== 'string' || !payload.attachmentId
      || !hasValidTemporalClaims(payload, LIMITS.auth.fileDownloadTokenTtlSeconds)
    ) return null;
    return payload;
  } catch {
    return null;
  }
}

export interface SendFileDownloadClaims {
  typ: 'send_file_download';
  sendId: string;
  fileId: string;
  jti: string;
  iat: number;
  exp: number;
}

export interface SendFileUploadClaims {
  typ: 'send_file_upload';
  userId: string;
  sendId: string;
  fileId: string;
  iat: number;
  exp: number;
}

export async function createSendFileDownloadToken(
  sendId: string,
  fileId: string,
  secret: string
): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload: SendFileDownloadClaims = {
    typ: 'send_file_download',
    sendId,
    fileId,
    jti: createRefreshToken(),
    iat: now,
    exp: now + LIMITS.auth.fileDownloadTokenTtlSeconds,
  };

  const encoder = new TextEncoder();
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const data = `${headerB64}.${payloadB64}`;

  const key = await getHmacKey(secret);

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureB64 = base64UrlEncode(new Uint8Array(signature));
  return `${data}.${signatureB64}`;
}

export async function verifySendFileDownloadToken(
  token: string,
  secret: string
): Promise<SendFileDownloadClaims | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    if (!hasValidJwtHeader(headerB64)) return null;
    const encoder = new TextEncoder();

    const key = await getHmacKey(secret);

    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload: SendFileDownloadClaims = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
    if (
      payload.typ !== 'send_file_download' ||
      typeof payload.sendId !== 'string' || !payload.sendId ||
      typeof payload.fileId !== 'string' ||
      !payload.fileId ||
      typeof payload.jti !== 'string' ||
      !payload.jti ||
      !hasValidTemporalClaims(payload, LIMITS.auth.fileDownloadTokenTtlSeconds)
    ) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

export async function createSendFileUploadToken(
  userId: string,
  sendId: string,
  fileId: string,
  secret: string
): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload: SendFileUploadClaims = {
    typ: 'send_file_upload',
    userId,
    sendId,
    fileId,
    iat: now,
    exp: now + LIMITS.auth.fileDownloadTokenTtlSeconds,
  };

  const encoder = new TextEncoder();
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const data = `${headerB64}.${payloadB64}`;

  const key = await getHmacKey(secret);

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureB64 = base64UrlEncode(new Uint8Array(signature));
  return `${data}.${signatureB64}`;
}

export async function verifySendFileUploadToken(
  token: string,
  secret: string
): Promise<SendFileUploadClaims | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    if (!hasValidJwtHeader(headerB64)) return null;
    const encoder = new TextEncoder();

    const key = await getHmacKey(secret);

    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload: SendFileUploadClaims = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
    if (
      payload.typ !== 'send_file_upload'
      || typeof payload.userId !== 'string' || !payload.userId
      || typeof payload.sendId !== 'string' || !payload.sendId
      || typeof payload.fileId !== 'string' || !payload.fileId
      || !hasValidTemporalClaims(payload, LIMITS.auth.fileDownloadTokenTtlSeconds)
    ) return null;
    return payload;
  } catch {
    return null;
  }
}

export interface SendAccessTokenClaims {
  sub: string; // send id
  typ: 'send_access';
  iat: number;
  exp: number;
}

export async function createSendAccessToken(sendId: string, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload: SendAccessTokenClaims = {
    sub: sendId,
    typ: 'send_access',
    iat: now,
    exp: now + LIMITS.auth.sendAccessTokenTtlSeconds,
  };

  const encoder = new TextEncoder();
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const data = `${headerB64}.${payloadB64}`;

  const key = await getHmacKey(secret);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureB64 = base64UrlEncode(new Uint8Array(signature));
  return `${data}.${signatureB64}`;
}

export async function verifySendAccessToken(token: string, secret: string): Promise<SendAccessTokenClaims | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    if (!hasValidJwtHeader(headerB64)) return null;
    const encoder = new TextEncoder();

    const key = await getHmacKey(secret);

    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload: SendAccessTokenClaims = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
    if (payload.typ !== 'send_access') return null;
    if (!payload.sub) return null;
    if (!hasValidTemporalClaims(payload, LIMITS.auth.sendAccessTokenTtlSeconds)) return null;
    return payload;
  } catch {
    return null;
  }
}
