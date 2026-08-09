import assert from 'node:assert/strict';
import test from 'node:test';
import { normalizeBackupEndpointUrl } from '../src/services/backup-config';

test('accepts public HTTPS backup endpoints and normalizes trailing slashes', () => {
  assert.equal(
    normalizeBackupEndpointUrl('https://backup.example.test/dav///', 'WebDAV server URL'),
    'https://backup.example.test/dav'
  );
});

test('rejects insecure, credential-bearing, and ambiguous backup endpoints', () => {
  for (const endpoint of [
    'http://backup.example.test/dav',
    'https://user:password@backup.example.test/dav',
    'https://backup.example.test/dav?redirect=https://example.test',
    'https://backup.example.test/dav#fragment',
  ]) {
    assert.throws(() => normalizeBackupEndpointUrl(endpoint, 'WebDAV server URL'));
  }
});

test('rejects local and reserved backup endpoint hosts', () => {
  for (const endpoint of [
    'https://localhost/dav',
    'https://127.0.0.1/dav',
    'https://10.0.0.1/dav',
    'https://169.254.169.254/latest/meta-data',
    'https://[::1]/dav',
    'https://metadata.google.internal/dav',
  ]) {
    assert.throws(() => normalizeBackupEndpointUrl(endpoint, 'WebDAV server URL'), /not allowed/);
  }
});
