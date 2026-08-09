import { randomBytes } from 'node:crypto';

export const WEB_VAULT_ENTRY_SECRET = 'WEB_VAULT_ENTRY_PATH';
export const WEB_VAULT_ENTRY_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

export function normalizeWebVaultEntryPath(value) {
  const normalized = String(value || '').trim().replace(/^\/+|\/+$/g, '');
  if (!WEB_VAULT_ENTRY_PATTERN.test(normalized)) {
    throw new Error(
      `${WEB_VAULT_ENTRY_SECRET} must be a single 16-128 character path segment containing only letters, numbers, "_", or "-".`
    );
  }
  return normalized;
}

export function generateWebVaultEntryPath(randomSource = randomBytes) {
  const bytes = randomSource(24);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 24) {
    throw new Error('The Web Vault entry random source must return exactly 24 bytes.');
  }
  return normalizeWebVaultEntryPath(`vault_${Buffer.from(bytes).toString('base64url')}`);
}

export function parseSecretList(output) {
  const text = String(output || '').trim();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    const start = text.indexOf('[');
    const end = text.lastIndexOf(']');
    if (start < 0 || end <= start) throw new Error('Wrangler returned an unreadable secret list.');
    parsed = JSON.parse(text.slice(start, end + 1));
  }
  if (!Array.isArray(parsed)) throw new Error('Wrangler returned an invalid secret list.');
  return new Set(parsed.map((item) => String(item?.name || '')).filter(Boolean));
}

const TARGET_VALUE_OPTIONS = new Set([
  '-c',
  '--config',
  '-e',
  '--env',
  '--name',
  '--cwd',
  '--profile',
]);

const TARGET_BOOLEAN_OPTIONS = new Set(['--legacy-env']);

export function extractWranglerTargetArgs(args) {
  const result = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = String(args[index]);
    if (TARGET_BOOLEAN_OPTIONS.has(arg)) {
      result.push(arg);
      continue;
    }
    if (TARGET_VALUE_OPTIONS.has(arg)) {
      const value = args[index + 1];
      if (value === undefined) throw new Error(`Missing value for Wrangler option ${arg}.`);
      result.push(arg, String(value));
      index += 1;
      continue;
    }
    const option = Array.from(TARGET_VALUE_OPTIONS).find((candidate) => arg.startsWith(`${candidate}=`));
    if (option) result.push(arg);
  }
  return result;
}

export function hasWranglerOption(args, option) {
  return args.some((arg) => arg === option || String(arg).startsWith(`${option}=`));
}
