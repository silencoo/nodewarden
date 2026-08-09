import assert from 'node:assert/strict';
import test from 'node:test';
import {
  directUploadValidationMessage,
  parseDirectUploadPayload,
} from '../src/utils/direct-upload';

const options = {
  expectedSize: 3,
  maxFileSize: 4,
  tooLargeMessage: 'File is too large',
  sizeMismatchMessage: 'File size does not match',
};

function rawUpload(body: Uint8Array, contentLength?: number): Request {
  const headers = new Headers({ 'Content-Type': 'application/octet-stream' });
  if (contentLength !== undefined) headers.set('Content-Length', String(contentLength));
  return new Request('https://vault.example/api/upload', {
    method: 'PUT',
    headers,
    body,
  });
}

test('rejects raw direct uploads without a declared length', async () => {
  const result = await parseDirectUploadPayload(rawUpload(new Uint8Array([1, 2, 3])), options);
  assert.ok(result instanceof Response);
  assert.equal(result.status, 400);
});

test('rejects a declared upload size that differs from the pending record', async () => {
  const result = await parseDirectUploadPayload(rawUpload(new Uint8Array([1, 2]), 2), options);
  assert.ok(result instanceof Response);
  assert.equal(result.status, 400);
});

test('stream guard rejects bytes beyond the declared size', async () => {
  const result = await parseDirectUploadPayload(rawUpload(new Uint8Array([1, 2, 3, 4]), 3), options);
  assert.ok(!(result instanceof Response));
  await assert.rejects(async () => {
    await new Response(result.body).arrayBuffer();
  }, (error: unknown) => directUploadValidationMessage(error) === 'File size does not match');
});

test('stream guard rejects a truncated body after parsing succeeds', async () => {
  const result = await parseDirectUploadPayload(rawUpload(new Uint8Array([1, 2]), 3), options);
  assert.ok(!(result instanceof Response));
  await assert.rejects(async () => {
    await new Response(result.body).arrayBuffer();
  }, (error: unknown) => directUploadValidationMessage(error) === 'File size does not match');
});
