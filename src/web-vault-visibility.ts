import type { Env } from './types';

const BACKEND_PATH_PREFIXES = [
  '/api',
  '/identity',
  '/icons',
  '/fill-assist',
  '/notifications',
  '/.well-known',
  // Compatibility aliases retained for older Bitwarden clients.
  '/devices',
  '/auth-requests',
  '/webauthn',
] as const;

const BACKEND_EXACT_PATHS = new Set([
  '/v1/assetlinks:check',
  '/web-bootstrap',
  '/config',
  '/accounts/kdf',
  '/settings/domains',
]);

// These static protocol helpers are loaded by official clients. They remain
// available even when the interactive Web Vault is gated or fully hidden.
const CLIENT_PROTOCOL_ASSET_PATHS = new Set([
  // Keep this public so previously installed workers can update, discard an
  // old cached root shell, and start enforcing network-first navigation.
  '/sw.js',
  '/webauthn-connector.html',
  '/webauthn-connector.js',
  '/webauthn-fallback-connector.html',
  '/webauthn-mobile-connector.html',
  '/webauthn-mobile-connector.js',
]);

const WEB_VAULT_ACCESS_TTL_SECONDS = 7 * 24 * 60 * 60;
const WEB_VAULT_ENTRY_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

function getWebVaultEntrySegment(env: Env): string | null {
  const raw = String(env.WEB_VAULT_ENTRY_PATH || '').trim().replace(/^\/+|\/+$/g, '');
  if (!raw) return null;
  return WEB_VAULT_ENTRY_PATTERN.test(raw) ? raw : '';
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecode(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

async function importWebVaultGateKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

function getCookieValue(request: Request, name: string): string | null {
  const cookie = String(request.headers.get('Cookie') || '');
  if (!cookie || cookie.length > 16_384) return null;
  for (const part of cookie.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) {
      return part.slice(separator + 1).trim() || null;
    }
  }
  return null;
}

function getWebVaultGateCookieName(request: Request): string {
  return new URL(request.url).protocol === 'https:' ? '__Host-vault_gate' : 'vault_gate';
}

function webVaultGateMessage(entrySegment: string, expiresAt: number): Uint8Array {
  return new TextEncoder().encode(`web-vault-gate:v1:${entrySegment}:${expiresAt}`);
}

async function createWebVaultGateCookie(request: Request, env: Env, entrySegment: string): Promise<string> {
  const expiresAt = Math.floor(Date.now() / 1000) + WEB_VAULT_ACCESS_TTL_SECONDS;
  const key = await importWebVaultGateKey(String(env.JWT_SECRET || ''));
  const signature = await crypto.subtle.sign('HMAC', key, webVaultGateMessage(entrySegment, expiresAt));
  const value = `v1.${expiresAt}.${base64UrlEncode(new Uint8Array(signature))}`;
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  return `${getWebVaultGateCookieName(request)}=${value}; Path=/; Max-Age=${WEB_VAULT_ACCESS_TTL_SECONDS}; HttpOnly; SameSite=Strict${secure}`;
}

async function hasValidWebVaultGateCookie(request: Request, env: Env, entrySegment: string): Promise<boolean> {
  const raw = getCookieValue(request, getWebVaultGateCookieName(request));
  if (!raw || raw.length > 256) return false;
  const match = raw.match(/^v1\.(\d{10})\.([A-Za-z0-9_-]+)$/);
  if (!match) return false;
  const expiresAt = Number(match[1]);
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(expiresAt) || expiresAt < now || expiresAt > now + WEB_VAULT_ACCESS_TTL_SECONDS + 60) {
    return false;
  }
  const signature = base64UrlDecode(match[2]);
  if (!signature) return false;
  const key = await importWebVaultGateKey(String(env.JWT_SECRET || ''));
  return crypto.subtle.verify('HMAC', key, signature, webVaultGateMessage(entrySegment, expiresAt));
}

export function isBackendRequestPath(pathname: string): boolean {
  const path = pathname.toLowerCase();
  if (BACKEND_EXACT_PATHS.has(path)) return true;

  return BACKEND_PATH_PREFIXES.some((prefix) => (
    path === prefix || path.startsWith(`${prefix}/`)
  ));
}

export function isWebVaultHidden(env: Env): boolean {
  return String(env.HIDE_WEB_VAULT || '').trim() === '1';
}

export function webVaultNotFoundResponse(request: Request): Response {
  const body = request.method === 'HEAD' ? null : 'Not Found';
  return new Response(body, {
    status: 404,
    headers: {
      'Cache-Control': 'no-store, max-age=0',
      'Content-Type': 'text/plain; charset=utf-8',
      'X-Robots-Tag': 'noindex, nofollow, noarchive, nosnippet',
      'Referrer-Policy': 'no-referrer',
    },
  });
}

export async function enforceWebVaultVisibility(request: Request, env: Env): Promise<Response | null> {
  const pathname = new URL(request.url).pathname;
  if (isBackendRequestPath(pathname) || CLIENT_PROTOCOL_ASSET_PATHS.has(pathname.toLowerCase())) return null;
  if (isWebVaultHidden(env)) return webVaultNotFoundResponse(request);

  const entrySegment = getWebVaultEntrySegment(env);
  // The private entry is mandatory. Missing or malformed configuration must
  // never fall back to a public Web Vault.
  if (!entrySegment || String(env.JWT_SECRET || '').trim().length < 32) {
    return webVaultNotFoundResponse(request);
  }

  // Even an authorized browser never receives the application shell at the
  // conventional root paths. The private entry redirects to /login instead.
  if (pathname === '/' || pathname.toLowerCase() === '/index.html') {
    return webVaultNotFoundResponse(request);
  }

  if (pathname === `/${entrySegment}`) {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return webVaultNotFoundResponse(request);
    }
    if (await hasValidWebVaultGateCookie(request, env, entrySegment)) {
      return null;
    }
    return new Response(null, {
      status: 303,
      headers: {
        // Redirect once to the same private URL so the browser stores the
        // HttpOnly gate cookie while the login panel remains on that URL.
        'Location': `/${entrySegment}`,
        'Set-Cookie': await createWebVaultGateCookie(request, env, entrySegment),
        'Cache-Control': 'no-store, max-age=0',
        'Referrer-Policy': 'no-referrer',
        'X-Robots-Tag': 'noindex, nofollow, noarchive, nosnippet',
      },
    });
  }

  if (!await hasValidWebVaultGateCookie(request, env, entrySegment)) {
    return webVaultNotFoundResponse(request);
  }
  return null;
}
