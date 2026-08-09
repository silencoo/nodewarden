import {
  Uint8ArrayReader,
  Uint8ArrayWriter,
  ZipReader,
  ZipWriter,
} from '@zip.js/zip.js';

export const BACKUP_ENCRYPTION_MIN_PASSWORD_LENGTH = 12;
export const BACKUP_ENCRYPTION_MAX_PASSWORD_LENGTH = 1024;
export const MAX_ENCRYPTED_BACKUP_ARCHIVE_BYTES = 72 * 1024 * 1024;
const MAX_BACKUP_ENCRYPTION_ENTRY_COUNT = 10_000;
const MAX_BACKUP_ENCRYPTION_EXTRACTED_BYTES = 64 * 1024 * 1024;

export type BackupZipEncryptionState = 'plain' | 'encrypted' | 'mixed';

class LimitedUint8ArrayWriter extends Uint8ArrayWriter {
  private writtenBytes = 0;

  constructor(
    private readonly maxBytes: number,
    private readonly limitMessage: string
  ) {
    super(Math.min(256 * 1024, Math.max(1, maxBytes)));
  }

  override async init(size: number = 0): Promise<void> {
    if (!Number.isFinite(size) || size < 0 || size > this.maxBytes) {
      throw new Error(this.limitMessage);
    }
    await super.init?.(size);
  }

  override async writeUint8Array(array: Uint8Array): Promise<void> {
    const nextSize = this.writtenBytes + array.byteLength;
    if (!Number.isSafeInteger(nextSize) || nextSize > this.maxBytes) {
      throw new Error(this.limitMessage);
    }
    this.writtenBytes = nextSize;
    await super.writeUint8Array(array);
  }
}

function normalizedBytes(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(bytes);
}

function validateEntryName(name: string): void {
  const normalized = String(name || '').trim();
  if (
    !normalized
    || normalized !== name
    || normalized.includes('\\')
    || normalized.includes('\0')
    || normalized.startsWith('/')
    || normalized.includes('//')
    || normalized.split('/').some((part) => part === '.' || part === '..')
  ) {
    throw new Error('Backup archive contains an unsafe file name');
  }
}

export function validateBackupEncryptionPassword(passwordRaw: string, required: boolean = true): string {
  const password = String(passwordRaw ?? '');
  if (!password.trim()) {
    if (required) throw new Error('Backup encryption password is required');
    return '';
  }
  const length = Array.from(password).length;
  if (length < BACKUP_ENCRYPTION_MIN_PASSWORD_LENGTH || length > BACKUP_ENCRYPTION_MAX_PASSWORD_LENGTH) {
    throw new Error(
      `Backup encryption password must be between ${BACKUP_ENCRYPTION_MIN_PASSWORD_LENGTH} and ${BACKUP_ENCRYPTION_MAX_PASSWORD_LENGTH} characters`
    );
  }
  return password;
}

async function readBackupEntries(bytes: Uint8Array, password?: string) {
  if (bytes.byteLength > MAX_ENCRYPTED_BACKUP_ARCHIVE_BYTES) {
    throw new Error('Backup archive is too large');
  }
  const reader = new ZipReader(new Uint8ArrayReader(bytes), {
    password,
    useWebWorkers: false,
    checkOverlappingEntry: true,
    checkOverlappingEntryOnly: false,
  });
  try {
    const entries = await reader.getEntries();
    if (!entries.length || entries.length > MAX_BACKUP_ENCRYPTION_ENTRY_COUNT) {
      throw new Error('Backup archive contains an invalid number of files');
    }
    let extractedBytes = 0;
    for (const entry of entries) {
      validateEntryName(entry.filename);
      const size = Number(entry.uncompressedSize || 0);
      if (!Number.isFinite(size) || size < 0) {
        throw new Error('Backup archive contains an invalid file size');
      }
      if (!entry.directory) extractedBytes += size;
      if (extractedBytes > MAX_BACKUP_ENCRYPTION_EXTRACTED_BYTES) {
        throw new Error('Backup archive expands beyond the current restore limit');
      }
    }
    return { reader, entries };
  } catch (error) {
    await reader.close().catch(() => undefined);
    throw error;
  }
}

export async function getBackupZipEncryptionState(bytes: Uint8Array): Promise<BackupZipEncryptionState> {
  let opened: Awaited<ReturnType<typeof readBackupEntries>>;
  try {
    opened = await readBackupEntries(bytes);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('Backup archive ')) throw error;
    throw new Error('Invalid backup archive');
  }
  try {
    const files = opened.entries.filter((entry) => !entry.directory);
    const encryptedFiles = files.filter((entry) => entry.encrypted).length;
    if (encryptedFiles === 0) return 'plain';
    if (encryptedFiles === files.length) return 'encrypted';
    return 'mixed';
  } finally {
    await opened.reader.close();
  }
}

export async function encryptBackupZipBytes(bytes: Uint8Array, passwordRaw: string): Promise<Uint8Array> {
  const password = validateBackupEncryptionPassword(passwordRaw);
  const opened = await readBackupEntries(bytes);
  const writer = new ZipWriter(new LimitedUint8ArrayWriter(
    MAX_ENCRYPTED_BACKUP_ARCHIVE_BYTES,
    'Encrypted backup archive is too large'
  ), { useWebWorkers: false });
  let remainingExtractedBytes = MAX_BACKUP_ENCRYPTION_EXTRACTED_BYTES;
  try {
    for (const entry of opened.entries) {
      if (entry.directory) {
        await writer.add(entry.filename, undefined, {
          directory: true,
          lastModDate: entry.lastModDate,
        });
        continue;
      }
      const data = await entry.getData(new LimitedUint8ArrayWriter(
        remainingExtractedBytes,
        'Backup archive expands beyond the current restore limit'
      ));
      remainingExtractedBytes -= data.byteLength;
      await writer.add(entry.filename, new Uint8ArrayReader(data), {
        password,
        encryptionStrength: 3,
        level: 0,
        lastModDate: entry.lastModDate,
      });
    }
    const encrypted = normalizedBytes(await writer.close());
    if (encrypted.byteLength > MAX_ENCRYPTED_BACKUP_ARCHIVE_BYTES) {
      throw new Error('Encrypted backup archive is too large');
    }
    return encrypted;
  } finally {
    await opened.reader.close();
  }
}

export async function decryptBackupZipBytes(bytes: Uint8Array, passwordRaw: string): Promise<Uint8Array> {
  const state = await getBackupZipEncryptionState(bytes);
  if (state === 'plain') return normalizedBytes(bytes);
  if (state === 'mixed') {
    throw new Error('Backup archive must encrypt every file entry');
  }

  const password = validateBackupEncryptionPassword(passwordRaw);
  const opened = await readBackupEntries(bytes, password);
  const writer = new ZipWriter(new LimitedUint8ArrayWriter(
    MAX_ENCRYPTED_BACKUP_ARCHIVE_BYTES,
    'Backup archive is too large'
  ), { useWebWorkers: false });
  let remainingExtractedBytes = MAX_BACKUP_ENCRYPTION_EXTRACTED_BYTES;
  try {
    for (const entry of opened.entries) {
      if (entry.directory) {
        await writer.add(entry.filename, undefined, {
          directory: true,
          lastModDate: entry.lastModDate,
        });
        continue;
      }
      const data = await entry.getData(new LimitedUint8ArrayWriter(
        remainingExtractedBytes,
        'Backup archive expands beyond the current restore limit'
      ), { password });
      remainingExtractedBytes -= data.byteLength;
      await writer.add(entry.filename, new Uint8ArrayReader(data), {
        level: 0,
        lastModDate: entry.lastModDate,
      });
    }
    return normalizedBytes(await writer.close());
  } catch {
    throw new Error('Backup encryption password is invalid or the archive is damaged');
  } finally {
    await opened.reader.close();
  }
}
