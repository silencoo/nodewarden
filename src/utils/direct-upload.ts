import { LIMITS } from '../config/limits';
import { Env } from '../types';
import { errorResponse } from './response';

export interface DirectUploadPayload {
  body: ReadableStream;
  contentType: string;
  size: number;
}

interface ParseDirectUploadOptions {
  expectedSize?: number | null;
  expectedFileName?: string | null;
  maxFileSize: number;
  tooLargeMessage: string;
  missingBodyMessage?: string;
  contentLengthRequiredMessage?: string;
  sizeMismatchMessage?: string;
  fileNameMismatchMessage?: string;
}

const MULTIPART_FORMDATA_OVERHEAD_BYTES = 256 * 1024;
const DIRECT_UPLOAD_STREAM_ERROR_PREFIX = 'Direct upload rejected:';

export function buildDirectUploadUrl(request: Request, path: string, token: string): string {
  const version = '2023-11-03';
  const expiresAt = '2099-12-31T23:59:59Z';
  const origin = new URL(request.url).origin;
  return `${origin}${path}?sv=${encodeURIComponent(version)}&se=${encodeURIComponent(expiresAt)}&token=${encodeURIComponent(token)}`;
}

export function getSafeJwtSecret(env: Env): string | null {
  const secret = (env.JWT_SECRET || '').trim();
  if (!secret || secret.length < LIMITS.auth.jwtSecretMinLength) {
    return null;
  }
  return secret;
}

export function getMultipartRequestMaxBytes(maxFileSize: number): number {
  return maxFileSize + MULTIPART_FORMDATA_OVERHEAD_BYTES;
}

function parseContentLength(request: Request): number | null {
  const raw = request.headers.get('content-length');
  if (!raw) return null;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) return null;
  return Math.floor(value);
}

function guardedUploadStream(
  body: ReadableStream<Uint8Array>,
  options: {
    expectedSize: number;
    maxFileSize: number;
    tooLargeMessage: string;
    sizeMismatchMessage: string;
  }
): ReadableStream<Uint8Array> {
  const reader = body.getReader();
  let received = 0;
  let finished = false;

  const reject = async (controller: ReadableStreamDefaultController<Uint8Array>, message: string) => {
    finished = true;
    try {
      await reader.cancel(message);
    } catch {
      // The source may already be closed after an HTTP framing error.
    }
    controller.error(new Error(`${DIRECT_UPLOAD_STREAM_ERROR_PREFIX} ${message}`));
  };

  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (finished) return;
      try {
        const { done, value } = await reader.read();
        if (done) {
          finished = true;
          if (received !== options.expectedSize) {
            controller.error(new Error(`${DIRECT_UPLOAD_STREAM_ERROR_PREFIX} ${options.sizeMismatchMessage}`));
            return;
          }
          controller.close();
          return;
        }

        const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
        received += chunk.byteLength;
        if (received > options.maxFileSize) {
          await reject(controller, options.tooLargeMessage);
          return;
        }
        if (received > options.expectedSize) {
          await reject(controller, options.sizeMismatchMessage);
          return;
        }
        controller.enqueue(chunk);
      } catch (error) {
        finished = true;
        controller.error(error);
      }
    },
    async cancel(reason) {
      finished = true;
      await reader.cancel(reason).catch(() => undefined);
    },
  });
}

export function directUploadValidationMessage(error: unknown): string | null {
  const message = error instanceof Error ? error.message : String(error || '');
  const index = message.indexOf(DIRECT_UPLOAD_STREAM_ERROR_PREFIX);
  if (index < 0) return null;
  return message.slice(index + DIRECT_UPLOAD_STREAM_ERROR_PREFIX.length).trim() || null;
}

export async function parseDirectUploadPayload(
  request: Request,
  options: ParseDirectUploadOptions
): Promise<DirectUploadPayload | Response> {
  const {
    expectedSize = null,
    expectedFileName = null,
    maxFileSize,
    tooLargeMessage,
    missingBodyMessage = 'No file uploaded',
    contentLengthRequiredMessage = 'Content-Length is required for direct uploads',
    sizeMismatchMessage,
    fileNameMismatchMessage,
  } = options;
  const contentType = request.headers.get('content-type') || '';

  if (contentType.includes('multipart/form-data')) {
    const declaredSize = parseContentLength(request);
    if (declaredSize === null) {
      return errorResponse(contentLengthRequiredMessage, 411);
    }
    if (declaredSize !== null && declaredSize > getMultipartRequestMaxBytes(maxFileSize)) {
      return errorResponse(tooLargeMessage, 413);
    }
    const formData = await request.formData();
    const file = formData.get('data') as File | null;
    if (!file) {
      return errorResponse(missingBodyMessage, 400);
    }
    if (file.size > maxFileSize) {
      return errorResponse(tooLargeMessage, 413);
    }
    if (expectedFileName && file.name !== expectedFileName) {
      return errorResponse(fileNameMismatchMessage || 'File name does not match.', 400);
    }
    if (expectedSize !== null && expectedSize !== undefined && file.size !== expectedSize) {
      return errorResponse(sizeMismatchMessage || 'File size does not match.', 400);
    }
    return {
      body: file.stream(),
      contentType: file.type || 'application/octet-stream',
      size: file.size,
    };
  }

  if (!request.body) {
    return errorResponse(missingBodyMessage, 400);
  }

  const declaredSize = parseContentLength(request);
  if (declaredSize === null) {
    return errorResponse(contentLengthRequiredMessage, 400);
  }
  const uploadSize = declaredSize;
  if (uploadSize > maxFileSize) {
    return errorResponse(tooLargeMessage, 413);
  }
  if (expectedSize !== null && expectedSize !== undefined && uploadSize !== expectedSize) {
    return errorResponse(sizeMismatchMessage || 'File size does not match.', 400);
  }

  return {
    body: guardedUploadStream(request.body, {
      expectedSize: uploadSize,
      maxFileSize,
      tooLargeMessage,
      sizeMismatchMessage: sizeMismatchMessage || 'File size does not match.',
    }),
    contentType: contentType || 'application/octet-stream',
    size: uploadSize,
  };
}
