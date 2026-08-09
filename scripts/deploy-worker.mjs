#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  WEB_VAULT_ENTRY_SECRET,
  extractWranglerTargetArgs,
  generateWebVaultEntryPath,
  hasWranglerOption,
  normalizeWebVaultEntryPath,
  parseSecretList,
} from './web-vault-entry-utils.mjs';

const repositoryRoot = fileURLToPath(new URL('..', import.meta.url));
const wranglerBin = path.join(repositoryRoot, 'node_modules', 'wrangler', 'bin', 'wrangler.js');

function runWrangler(args, stdio = 'inherit') {
  return spawnSync(process.execPath, [wranglerBin, ...args], {
    cwd: repositoryRoot,
    env: process.env,
    encoding: stdio === 'pipe' ? 'utf8' : undefined,
    stdio,
  });
}

function commandFailure(result, action) {
  if (result.error) return new Error(`${action}: ${result.error.message}`);
  const detail = [result.stderr, result.stdout].map((value) => String(value || '').trim()).filter(Boolean).join('\n');
  return new Error(`${action} (exit ${result.status ?? 'unknown'})${detail ? `:\n${detail}` : '.'}`);
}

function isMissingWorkerError(result) {
  const detail = `${result.stderr || ''}\n${result.stdout || ''}`;
  return /(?:code\s*[=:]?\s*10007|workers\.api\.error\.code\s*[=:]?\s*10007|object does not exist|worker[^\n]*does not exist|worker[^\n]*not found)/i.test(detail);
}

function listRemoteSecretNames(targetArgs) {
  const result = runWrangler(['secret', 'list', '--format', 'json', ...targetArgs], 'pipe');
  if (result.status === 0) return parseSecretList(result.stdout);
  if (isMissingWorkerError(result)) return new Set();
  throw commandFailure(result, 'Unable to inspect the Worker secrets');
}

function addSafeDeploymentDefaults(args) {
  const result = [...args];
  if (!hasWranglerOption(result, '--keep-vars')) result.push('--keep-vars');
  return result;
}

function createTemporarySecretsFile(entryPath) {
  const directory = mkdtempSync(path.join(tmpdir(), 'nodewarden-deploy-'));
  const file = path.join(directory, 'generated-secrets.json');
  writeFileSync(file, `${JSON.stringify({ [WEB_VAULT_ENTRY_SECRET]: entryPath })}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  });
  return { directory, file };
}

function removeTemporarySecretsFile(temporary) {
  if (!temporary) return;
  if (existsSync(temporary.file)) unlinkSync(temporary.file);
  if (existsSync(temporary.directory)) rmdirSync(temporary.directory);
}

function main() {
  if (!existsSync(wranglerBin)) {
    throw new Error('Wrangler is not installed. Run npm install before deploying.');
  }

  const originalArgs = process.argv.slice(2);
  const deployArgs = addSafeDeploymentDefaults(originalArgs);

  // Dry runs are local verification only. They must not depend on remote
  // credentials and must never create or rotate the private entry secret.
  if (hasWranglerOption(deployArgs, '--dry-run')) {
    const result = runWrangler(['deploy', ...deployArgs]);
    if (result.status !== 0) throw commandFailure(result, 'Wrangler dry run failed');
    return;
  }

  const targetArgs = extractWranglerTargetArgs(deployArgs);
  const secretNames = listRemoteSecretNames(targetArgs);
  let temporary = null;
  let generatedEntryPath = null;

  if (!secretNames.has(WEB_VAULT_ENTRY_SECRET)) {
    if (hasWranglerOption(deployArgs, '--secrets-file')) {
      throw new Error(
        `${WEB_VAULT_ENTRY_SECRET} is missing, but a custom --secrets-file was supplied. Add the mandatory entry to that file or deploy without the custom file.`
      );
    }

    const configuredEntry = String(process.env[WEB_VAULT_ENTRY_SECRET] || '').trim();
    const entryPath = configuredEntry
      ? normalizeWebVaultEntryPath(configuredEntry)
      : generateWebVaultEntryPath();
    temporary = createTemporarySecretsFile(entryPath);
    deployArgs.push('--secrets-file', temporary.file);
    if (!configuredEntry) generatedEntryPath = entryPath;
  }

  try {
    const result = runWrangler(['deploy', ...deployArgs]);
    if (result.status !== 0) throw commandFailure(result, 'Wrangler deployment failed');
  } finally {
    removeTemporarySecretsFile(temporary);
  }

  if (generatedEntryPath) {
    console.log('\n[web-vault] Generated mandatory private entry path (shown once):');
    console.log(`/${generatedEntryPath}`);
    console.log('[web-vault] Save this path now. Future deployments preserve the Secret and cannot read it back.');
  }
}

try {
  main();
} catch (error) {
  console.error(`[deploy] ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
