import assert from 'node:assert/strict';
import test from 'node:test';
import {
  TextReader,
  TextWriter,
  Uint8ArrayReader,
  Uint8ArrayWriter,
  ZipReader,
  ZipWriter,
} from '@zip.js/zip.js';
import {
  decryptBackupZipBytes,
  encryptBackupZipBytes,
  getBackupZipEncryptionState,
  validateBackupEncryptionPassword,
} from '../shared/backup-encryption';

const password = 'correct horse battery staple';

async function createPlainArchive(): Promise<Uint8Array> {
  const writer = new ZipWriter(new Uint8ArrayWriter(), { useWebWorkers: false });
  await writer.add('manifest.json', new TextReader('{"formatVersion":1}'), { level: 0 });
  await writer.add('db.json', new TextReader('{"users":[]}'), { level: 0 });
  return Uint8Array.from(await writer.close());
}

async function readArchiveText(bytes: Uint8Array, fileName: string): Promise<string> {
  const reader = new ZipReader(new Uint8ArrayReader(bytes), { useWebWorkers: false });
  try {
    const entry = (await reader.getEntries()).find((candidate) => candidate.filename === fileName);
    assert.ok(entry && !entry.directory);
    return await entry.getData(new TextWriter());
  } finally {
    await reader.close();
  }
}

test('encrypts every backup entry with AES-256 ZIP encryption and restores it', async () => {
  const plain = await createPlainArchive();
  assert.equal(await getBackupZipEncryptionState(plain), 'plain');

  const encrypted = await encryptBackupZipBytes(plain, password);
  assert.equal(await getBackupZipEncryptionState(encrypted), 'encrypted');
  assert.notDeepEqual(encrypted, plain);

  const restored = await decryptBackupZipBytes(encrypted, password);
  assert.equal(await getBackupZipEncryptionState(restored), 'plain');
  assert.equal(await readArchiveText(restored, 'manifest.json'), '{"formatVersion":1}');
  assert.equal(await readArchiveText(restored, 'db.json'), '{"users":[]}');
});

test('rejects an incorrect backup password without exposing archive details', async () => {
  const encrypted = await encryptBackupZipBytes(await createPlainArchive(), password);
  await assert.rejects(
    () => decryptBackupZipBytes(encrypted, 'this password is incorrect'),
    /password is invalid or the archive is damaged/
  );
});

test('rejects partially encrypted archives', async () => {
  const writer = new ZipWriter(new Uint8ArrayWriter(), { useWebWorkers: false });
  await writer.add('manifest.json', new TextReader('{}'), { level: 0 });
  await writer.add('db.json', new TextReader('{}'), {
    password,
    encryptionStrength: 3,
    level: 0,
  });
  const mixed = Uint8Array.from(await writer.close());
  assert.equal(await getBackupZipEncryptionState(mixed), 'mixed');
  await assert.rejects(() => decryptBackupZipBytes(mixed, password), /encrypt every file entry/);
});

test('enforces an independent minimum-strength backup password', () => {
  assert.throws(() => validateBackupEncryptionPassword('too-short'), /between 12 and 1024 characters/);
  assert.equal(validateBackupEncryptionPassword(password), password);
});
