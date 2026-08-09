import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createBackupDestinationRecord,
  type BackupDestinationRecord,
  type S3BackupDestination,
  type WebDavBackupDestination,
} from '../shared/backup-schema';
import {
  downloadRemoteBackupFile,
  listRemoteBackupEntries,
} from '../src/services/backup-uploader';

function webDavDestination(): BackupDestinationRecord {
  const destination = createBackupDestinationRecord('webdav', 1, { id: 'webdav-test' });
  destination.destination = {
    baseUrl: 'https://backup.example.test/dav',
    username: 'backup-user',
    password: 'backup-password',
    remotePath: 'nodewarden',
  } satisfies WebDavBackupDestination;
  return destination;
}

function s3Destination(): BackupDestinationRecord {
  const destination = createBackupDestinationRecord('s3', 1, { id: 's3-test' });
  destination.destination = {
    endpoint: 'https://s3.example.test',
    bucket: 'vault-backups',
    addressingStyle: 'path-style',
    region: 'auto',
    accessKeyId: 'access-key',
    secretAccessKey: 'secret-key',
    rootPath: '',
  } satisfies S3BackupDestination;
  return destination;
}

test('WebDAV listings are parsed from bounded, non-redirected responses', async () => {
  const originalFetch = globalThis.fetch;
  let redirect: RequestRedirect | undefined;
  globalThis.fetch = async (_input, init) => {
    redirect = init?.redirect;
    const xml = `<?xml version="1.0"?>
      <d:multistatus xmlns:d="DAV:">
        <d:response><d:href>/dav/nodewarden/</d:href></d:response>
        <d:response>
          <d:href>/dav/nodewarden/backup.zip</d:href>
          <d:resourcetype></d:resourcetype>
          <d:getcontentlength>123</d:getcontentlength>
          <d:getlastmodified>Sun, 09 Aug 2026 12:00:00 GMT</d:getlastmodified>
        </d:response>
      </d:multistatus>`;
    return new Response(xml, {
      status: 207,
      headers: { 'Content-Length': String(new TextEncoder().encode(xml).byteLength) },
    });
  };
  try {
    const listing = await listRemoteBackupEntries(webDavDestination(), '');
    assert.equal(redirect, 'manual');
    assert.equal(listing.items.length, 1);
    assert.deepEqual(listing.items[0], {
      path: 'backup.zip',
      name: 'backup.zip',
      isDirectory: false,
      size: 123,
      modifiedAt: '2026-08-09T12:00:00.000Z',
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('S3 listings use fixed XML fields with manual redirect handling', async () => {
  const originalFetch = globalThis.fetch;
  let redirect: RequestRedirect | undefined;
  globalThis.fetch = async (_input, init) => {
    redirect = init?.redirect;
    const xml = `<ListBucketResult>
      <CommonPrefixes><Prefix>attachments/</Prefix></CommonPrefixes>
      <Contents><Key>backup.zip</Key><Size>456</Size><LastModified>2026-08-09T12:00:00.000Z</LastModified></Contents>
    </ListBucketResult>`;
    return new Response(xml, {
      status: 200,
      headers: { 'Content-Length': String(new TextEncoder().encode(xml).byteLength) },
    });
  };
  try {
    const listing = await listRemoteBackupEntries(s3Destination(), '');
    assert.equal(redirect, 'manual');
    assert.deepEqual(listing.items.map((item) => [item.path, item.isDirectory, item.size]), [
      ['attachments', true, null],
      ['backup.zip', false, 456],
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('remote downloads stop before buffering a declared oversized body', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('small', {
    status: 200,
    headers: {
      'Content-Type': 'application/zip',
      'Content-Length': '4096',
    },
  });
  try {
    await assert.rejects(
      () => downloadRemoteBackupFile(webDavDestination(), 'backup.zip', { maxBytes: 32 }),
      /too large/
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('same-origin WebDAV redirects preserve the method and credentials', async () => {
  const originalFetch = globalThis.fetch;
  const requests: Array<{ url: string; method: string | undefined; authorization: string | null; redirect: RequestRedirect | undefined }> = [];
  globalThis.fetch = async (input, init) => {
    const url = input.toString();
    requests.push({
      url,
      method: init?.method,
      authorization: new Headers(init?.headers).get('Authorization'),
      redirect: init?.redirect,
    });
    if (requests.length === 1) {
      return new Response(null, {
        status: 301,
        headers: { Location: '/dav/nodewarden/' },
      });
    }
    const xml = `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"></d:multistatus>`;
    return new Response(xml, {
      status: 207,
      headers: { 'Content-Length': String(new TextEncoder().encode(xml).byteLength) },
    });
  };
  try {
    const listing = await listRemoteBackupEntries(webDavDestination(), '');
    assert.equal(listing.items.length, 0);
    assert.equal(requests.length, 2);
    assert.deepEqual(requests.map((request) => [request.url, request.method, request.redirect]), [
      ['https://backup.example.test/dav/nodewarden', 'PROPFIND', 'manual'],
      ['https://backup.example.test/dav/nodewarden/', 'PROPFIND', 'manual'],
    ]);
    assert.match(requests[0].authorization || '', /^Basic /);
    assert.equal(requests[1].authorization, requests[0].authorization);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('cross-origin redirect responses are rejected before credentials can be forwarded', async () => {
  const originalFetch = globalThis.fetch;
  let redirect: RequestRedirect | undefined;
  let requestCount = 0;
  globalThis.fetch = async (_input, init) => {
    requestCount += 1;
    redirect = init?.redirect;
    return new Response(null, {
      status: 302,
      headers: { Location: 'https://attacker.example.test/capture' },
    });
  };
  try {
    await assert.rejects(
      () => listRemoteBackupEntries(webDavDestination(), ''),
      /different origin/
    );
    assert.equal(redirect, 'manual');
    assert.equal(requestCount, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('redirect loops are rejected with a bounded number of requests', async () => {
  const originalFetch = globalThis.fetch;
  let requestCount = 0;
  globalThis.fetch = async () => {
    requestCount += 1;
    return new Response(null, {
      status: 301,
      headers: { Location: requestCount % 2 === 1 ? '/dav/nodewarden/' : '/dav/nodewarden' },
    });
  };
  try {
    await assert.rejects(
      () => listRemoteBackupEntries(webDavDestination(), ''),
      /redirect loop/
    );
    assert.equal(requestCount, 2);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('same-origin S3 redirects are re-signed for the redirected path', async () => {
  const originalFetch = globalThis.fetch;
  const requests: Array<{ url: string; authorization: string | null }> = [];
  globalThis.fetch = async (input, init) => {
    requests.push({
      url: input.toString(),
      authorization: new Headers(init?.headers).get('Authorization'),
    });
    if (requests.length === 1) {
      return new Response(null, {
        status: 307,
        headers: { Location: '/vault-backups/?list-type=2&delimiter=%2F' },
      });
    }
    const xml = '<ListBucketResult></ListBucketResult>';
    return new Response(xml, {
      status: 200,
      headers: { 'Content-Length': String(new TextEncoder().encode(xml).byteLength) },
    });
  };
  try {
    const listing = await listRemoteBackupEntries(s3Destination(), '');
    assert.equal(listing.items.length, 0);
    assert.equal(requests.length, 2);
    assert.notEqual(requests[0].authorization, requests[1].authorization);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
