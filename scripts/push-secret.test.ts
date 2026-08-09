import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ensurePushInstallationCredentials,
  PUSH_INSTALLATION_ID_KEY,
  PUSH_INSTALLATION_KEY_KEY,
} from '../src/services/push-relay';
import { isEncryptedServerSecret } from '../src/utils/server-secret';

function createConfigDb(initial: Record<string, string>): {
  db: D1Database;
  values: Map<string, string>;
} {
  const values = new Map(Object.entries(initial));
  const db = {
    prepare(sql: string) {
      let bindings: unknown[] = [];
      return {
        bind(...next: unknown[]) {
          bindings = next;
          return this;
        },
        async first() {
          const value = values.get(String(bindings[0] || ''));
          return value === undefined ? null : { value };
        },
        async run() {
          if (/INSERT INTO config/i.test(sql)) {
            values.set(String(bindings[0] || ''), String(bindings[1] || ''));
          }
          return { success: true, meta: { changes: 1 } };
        },
      };
    },
  } as unknown as D1Database;
  return { db, values };
}

test('legacy push installation secrets migrate to encrypted storage', async () => {
  const { db, values } = createConfigDb({
    [PUSH_INSTALLATION_ID_KEY]: 'installation-id',
    [PUSH_INSTALLATION_KEY_KEY]: 'legacy-plaintext-key',
  });
  const env = {
    DB: db,
    JWT_SECRET: 'a-stable-jwt-secret-with-at-least-thirty-two-characters',
  };

  const credentials = await ensurePushInstallationCredentials(env);
  assert.deepEqual(credentials, {
    id: 'installation-id',
    key: 'legacy-plaintext-key',
  });
  const stored = values.get(PUSH_INSTALLATION_KEY_KEY) || '';
  assert.equal(isEncryptedServerSecret(stored), true);
  assert.doesNotMatch(stored, /legacy-plaintext-key/);

  assert.deepEqual(await ensurePushInstallationCredentials(env), credentials);
});
