import assert from 'node:assert/strict';
import test from 'node:test';
import {
  readBoundedResponseBytes,
  readBoundedResponseJson,
} from '../src/utils/bounded-response';

test('bounded response reader accepts a response within its limit', async () => {
  const response = new Response(JSON.stringify({ ok: true }), {
    headers: { 'Content-Type': 'application/json' },
  });
  assert.deepEqual(await readBoundedResponseJson(response, 1024), { ok: true });
});

test('bounded response reader rejects an oversized declared length before buffering', async () => {
  const response = new Response('small', {
    headers: { 'Content-Length': '4096' },
  });
  await assert.rejects(() => readBoundedResponseBytes(response, 32), /too large/);
});

test('bounded response reader enforces its limit when content length is absent', async () => {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(20));
      controller.enqueue(new Uint8Array(20));
      controller.close();
    },
  });
  await assert.rejects(
    () => readBoundedResponseBytes(new Response(stream), 32, 'Provider response'),
    /Provider response is too large/
  );
});
