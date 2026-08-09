import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createNotificationConnectionToken,
  verifyNotificationConnectionToken,
} from '../src/utils/jwt';

const secret = 'notification-test-secret-that-is-longer-than-thirty-two-characters';

test('creates a short-lived notification token scoped to one user and device', async () => {
  const token = await createNotificationConnectionToken('user-1', 'device-1', secret);
  const claims = await verifyNotificationConnectionToken(token, secret);
  assert.equal(claims?.sub, 'user-1');
  assert.equal(claims?.did, 'device-1');
  assert.equal(claims?.typ, 'notification_connect');
  assert.ok(claims?.jti);
  assert.ok((claims?.exp || 0) - (claims?.iat || 0) <= 60);
});

test('rejects tampered notification connection tokens', async () => {
  const token = await createNotificationConnectionToken('user-1', null, secret);
  const parts = token.split('.');
  parts[1] = `${parts[1].startsWith('a') ? 'b' : 'a'}${parts[1].slice(1)}`;
  assert.equal(await verifyNotificationConnectionToken(parts.join('.'), secret), null);
  assert.equal(await verifyNotificationConnectionToken(token, `${secret}-wrong`), null);
});
