import assert from 'node:assert/strict';
import test from 'node:test';
import { unzipSync } from 'fflate';
import { buildBackupArchive } from '../src/services/backup-archive';
import type { Env } from '../src/types';
import {
  YUBICO_CLIENT_ID_CONFIG_KEY,
  YUBICO_SECRET_KEY_CONFIG_KEY,
} from '../src/services/yubico-config';
import {
  PUSH_INSTALLATION_ID_KEY,
  PUSH_INSTALLATION_KEY_KEY,
} from '../src/services/push-relay';

test('instance backups exclude external validation credentials', async () => {
  const db = {
    prepare(sql: string) {
      return {
        bind() {
          return this;
        },
        async all() {
          return {
            results: /SELECT key, value FROM config/i.test(sql)
              ? [
                  { key: 'safe.preference', value: 'kept' },
                  { key: YUBICO_CLIENT_ID_CONFIG_KEY, value: 'client-id' },
                  { key: YUBICO_SECRET_KEY_CONFIG_KEY, value: 'provider-secret' },
                  { key: PUSH_INSTALLATION_ID_KEY, value: 'push-installation-id' },
                  { key: PUSH_INSTALLATION_KEY_KEY, value: 'push-provider-secret' },
                ]
              : [],
          };
        },
      };
    },
  } as unknown as D1Database;

  const archive = await buildBackupArchive({ DB: db } as Env, new Date(0), {
    includeAttachments: false,
  });
  const files = unzipSync(archive.bytes);
  const payload = JSON.parse(new TextDecoder().decode(files['db.json'])) as {
    config: Array<{ key: string; value: string }>;
  };
  assert.deepEqual(payload.config, [{ key: 'safe.preference', value: 'kept' }]);
  assert.doesNotMatch(
    new TextDecoder().decode(files['db.json']),
    /provider-secret|client-id|push-installation-id/
  );
});
