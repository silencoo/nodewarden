import assert from 'node:assert/strict';
import test from 'node:test';
import {
  WEB_VAULT_ENTRY_SECRET,
  extractWranglerTargetArgs,
  generateWebVaultEntryPath,
  hasWranglerOption,
  normalizeWebVaultEntryPath,
  parseSecretList,
} from './web-vault-entry-utils.mjs';

test('normalizes and validates an explicit private Web Vault entry', () => {
  assert.equal(
    normalizeWebVaultEntryPath('/a-private-entry-segment-123/'),
    'a-private-entry-segment-123'
  );
  assert.throws(() => normalizeWebVaultEntryPath('short'), /16-128/);
  assert.throws(() => normalizeWebVaultEntryPath('not/a/single/path/segment'), /16-128/);
});

test('generates a high-entropy URL-safe private entry path', () => {
  const entry = generateWebVaultEntryPath((size) => {
    assert.equal(size, 24);
    return Uint8Array.from({ length: size }, (_, index) => index);
  });
  assert.match(entry, /^vault_[A-Za-z0-9_-]{32}$/);
  assert.equal(entry.includes('/'), false);
});

test('parses Wrangler secret names without exposing values', () => {
  const names = parseSecretList(JSON.stringify([
    { name: 'JWT_SECRET', type: 'secret_text' },
    { name: WEB_VAULT_ENTRY_SECRET, type: 'secret_text' },
  ]));
  assert.deepEqual([...names], ['JWT_SECRET', WEB_VAULT_ENTRY_SECRET]);
});

test('reuses deployment targeting flags for the secret lookup', () => {
  const args = ['--config=wrangler.kv.toml', '--env', 'production', '--name', 'custom', '--keep-vars'];
  assert.deepEqual(
    extractWranglerTargetArgs(args),
    ['--config=wrangler.kv.toml', '--env', 'production', '--name', 'custom']
  );
  assert.equal(hasWranglerOption(args, '--keep-vars'), true);
  assert.equal(hasWranglerOption(args, '--dry-run'), false);
});
