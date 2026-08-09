import assert from 'node:assert/strict';
import test from 'node:test';
import {
  decryptApiKey,
  encryptApiKey,
  isStoredApiKeyEncrypted,
  verifyApiKey,
} from '../src/utils/api-key';
import {
  decryptServerSecret,
  encryptServerSecret,
  isEncryptedServerSecret,
} from '../src/utils/server-secret';

const secret = 'server-secret-test-key-that-is-longer-than-thirty-two-characters';

test('server-managed secrets use authenticated, randomized envelopes', async () => {
  const first = await encryptServerSecret('provider-password', secret, 'provider:test');
  const second = await encryptServerSecret('provider-password', secret, 'provider:test');
  assert.ok(isEncryptedServerSecret(first));
  assert.notEqual(first, second);
  assert.doesNotMatch(first, /provider-password/);
  assert.equal(await decryptServerSecret(first, secret, 'provider:test'), 'provider-password');
});

test('server-managed secret envelopes are bound to their key and context', async () => {
  const envelope = await encryptServerSecret('provider-password', secret, 'provider:test');
  await assert.rejects(
    () => decryptServerSecret(envelope, `${secret}-wrong`, 'provider:test'),
    /cannot be decrypted/
  );
  await assert.rejects(
    () => decryptServerSecret(envelope, secret, 'provider:other'),
    /cannot be decrypted/
  );
});

test('personal API keys remain retrievable while encrypted at rest', async () => {
  const envelope = await encryptApiKey('personal-api-key', secret, 'user-1');
  assert.ok(isStoredApiKeyEncrypted(envelope));
  assert.equal(await decryptApiKey(envelope, secret, 'user-1'), 'personal-api-key');
  assert.equal(await verifyApiKey('personal-api-key', envelope, secret, 'user-1'), true);
  assert.equal(await verifyApiKey('personal-api-key', envelope, secret, 'user-2'), false);
});
