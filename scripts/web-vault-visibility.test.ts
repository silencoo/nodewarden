import assert from 'node:assert/strict';
import test from 'node:test';
import type { Env } from '../src/types';
import { enforceWebVaultVisibility } from '../src/web-vault-visibility';

const strongSecret = 'test-secret-that-is-longer-than-thirty-two-characters';

function env(overrides: Partial<Env> = {}): Env {
  return {
    JWT_SECRET: strongSecret,
    ...overrides,
  } as Env;
}

test('fails closed when the mandatory entry path is not configured', async () => {
  const response = await enforceWebVaultVisibility(new Request('https://vault.example/'), env());
  assert.equal(response?.status, 404);
});

test('keeps backend compatibility routes available behind the Web Vault gate', async () => {
  const response = await enforceWebVaultVisibility(
    new Request('https://vault.example/api/sync'),
    env({ WEB_VAULT_ENTRY_PATH: 'a-high-entropy-entry-path' })
  );
  assert.equal(response, null);

  // This one public static route lets older installed PWAs update and discard
  // a previously cached root login shell after the mandatory gate is enabled.
  const serviceWorker = await enforceWebVaultVisibility(
    new Request('https://vault.example/sw.js'),
    env()
  );
  assert.equal(serviceWorker, null);

  for (const pathname of ['/webauthn-connector.html', '/webauthn-connector.js']) {
    const assetResponse = await enforceWebVaultVisibility(
      new Request(`https://vault.example${pathname}`),
      env({ HIDE_WEB_VAULT: '1', WEB_VAULT_ENTRY_PATH: 'a-high-entropy-entry-path' })
    );
    assert.equal(assetResponse, null);
  }
});

test('requires a signed cookie after visiting the configured entry path', async () => {
  const gatedEnv = env({ WEB_VAULT_ENTRY_PATH: '/a-high-entropy-entry-path/' });
  const blocked = await enforceWebVaultVisibility(new Request('https://vault.example/'), gatedEnv);
  assert.equal(blocked?.status, 404);

  const entry = await enforceWebVaultVisibility(
    new Request('https://vault.example/a-high-entropy-entry-path'),
    gatedEnv
  );
  assert.equal(entry?.status, 303);
  assert.equal(entry?.headers.get('location'), '/a-high-entropy-entry-path');
  const setCookie = entry?.headers.get('set-cookie') || '';
  assert.match(setCookie, /^__Host-vault_gate=/);
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Strict/);
  assert.match(setCookie, /Secure/);

  const cookie = setCookie.split(';', 1)[0];
  const allowed = await enforceWebVaultVisibility(
    new Request('https://vault.example/assets/app.js', { headers: { Cookie: cookie } }),
    gatedEnv
  );
  assert.equal(allowed, null);

  const loginAllowed = await enforceWebVaultVisibility(
    new Request('https://vault.example/login', { headers: { Cookie: cookie } }),
    gatedEnv
  );
  assert.equal(loginAllowed, null);

  const rootStillHidden = await enforceWebVaultVisibility(
    new Request('https://vault.example/', { headers: { Cookie: cookie } }),
    gatedEnv
  );
  assert.equal(rootStillHidden?.status, 404);

  const entryAllowed = await enforceWebVaultVisibility(
    new Request('https://vault.example/a-high-entropy-entry-path', { headers: { Cookie: cookie } }),
    gatedEnv
  );
  assert.equal(entryAllowed, null);

  const tampered = await enforceWebVaultVisibility(
    new Request('https://vault.example/', { headers: { Cookie: `${cookie}x` } }),
    gatedEnv
  );
  assert.equal(tampered?.status, 404);
});

test('fails closed for malformed entry paths or weak signing secrets', async () => {
  const malformed = await enforceWebVaultVisibility(
    new Request('https://vault.example/'),
    env({ WEB_VAULT_ENTRY_PATH: 'short' })
  );
  assert.equal(malformed?.status, 404);

  const weak = await enforceWebVaultVisibility(
    new Request('https://vault.example/a-high-entropy-entry-path'),
    env({ WEB_VAULT_ENTRY_PATH: 'a-high-entropy-entry-path', JWT_SECRET: 'weak' })
  );
  assert.equal(weak?.status, 404);
});

test('hard hide mode overrides the entry path', async () => {
  const response = await enforceWebVaultVisibility(
    new Request('https://vault.example/a-high-entropy-entry-path'),
    env({ HIDE_WEB_VAULT: '1', WEB_VAULT_ENTRY_PATH: 'a-high-entropy-entry-path' })
  );
  assert.equal(response?.status, 404);
});
