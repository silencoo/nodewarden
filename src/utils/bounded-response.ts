function normalizeResponseLimit(maxBytes: number): number {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new Error('Response byte limit is invalid');
  }
  return maxBytes;
}

function declaredResponseLength(response: Response): number | null {
  const raw = response.headers.get('Content-Length');
  if (raw === null || raw.trim() === '') return null;
  const parsed = Number(raw);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

export async function readBoundedResponseBytes(
  response: Response,
  maxBytes: number,
  label: string = 'Response'
): Promise<Uint8Array> {
  const limit = normalizeResponseLimit(maxBytes);
  const declaredLength = declaredResponseLength(response);
  if (declaredLength !== null && declaredLength > limit) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error(`${label} is too large`);
  }
  if (!response.body) return new Uint8Array();

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value?.byteLength) continue;
      totalBytes += value.byteLength;
      if (totalBytes > limit) {
        await reader.cancel().catch(() => undefined);
        throw new Error(`${label} is too large`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  if (chunks.length === 0) return new Uint8Array();
  if (chunks.length === 1) return chunks[0];
  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

export async function readBoundedResponseText(
  response: Response,
  maxBytes: number,
  label?: string
): Promise<string> {
  return new TextDecoder().decode(await readBoundedResponseBytes(response, maxBytes, label));
}

export async function readBoundedResponseJson<T>(
  response: Response,
  maxBytes: number,
  label?: string
): Promise<T> {
  return JSON.parse(await readBoundedResponseText(response, maxBytes, label)) as T;
}
