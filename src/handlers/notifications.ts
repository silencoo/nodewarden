import { AuthService } from '../services/auth';
import { StorageService } from '../services/storage';
import { isAuthRequestExpired } from '../services/storage-auth-request-repo';
import type { Env, JWTPayload } from '../types';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import {
  createNotificationConnectionToken,
  verifyNotificationConnectionToken,
} from '../utils/jwt';
import { getSafeJwtSecret } from '../utils/direct-upload';

function extractAccessToken(request: Request): string | null {
  const url = new URL(request.url);
  const queryToken = String(url.searchParams.get('access_token') || '').trim();
  if (queryToken) return queryToken;

  const authHeader = String(request.headers.get('Authorization') || '').trim();
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() || null;
}

async function authenticateNotificationsRequest(request: Request, env: Env): Promise<JWTPayload | null> {
  const accessToken = extractAccessToken(request);
  if (!accessToken) return null;

  const auth = new AuthService(env);
  return auth.verifyAccessToken(`Bearer ${accessToken}`);
}

export async function handleNotificationsNegotiate(request: Request, env: Env): Promise<Response> {
  const payload = await authenticateNotificationsRequest(request, env);
  if (!payload?.sub) return errorResponse('Unauthorized', 401);

  const jwtSecret = getSafeJwtSecret(env);
  if (!jwtSecret) return errorResponse('Server configuration error', 500);

  const connectionId = generateUUID();
  const connectionToken = await createNotificationConnectionToken(
    payload.sub,
    String(payload.did || '').trim() || null,
    jwtSecret
  );
  return jsonResponse({
    connectionId,
    connectionToken,
    negotiateVersion: 1,
    availableTransports: [
      {
        transport: 'WebSockets',
        transferFormats: ['Text', 'Binary'],
      },
    ],
  });
}

export async function handleNotificationsHub(request: Request, env: Env): Promise<Response> {
  const requestUrl = new URL(request.url);
  const shortToken = String(requestUrl.searchParams.get('connection_token') || '').trim();
  const jwtSecret = getSafeJwtSecret(env);
  const connectionClaims = shortToken && jwtSecret
    ? await verifyNotificationConnectionToken(shortToken, jwtSecret)
    : null;
  const payload = connectionClaims || await authenticateNotificationsRequest(request, env);
  if (!payload?.sub) return errorResponse('Unauthorized', 401);
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
    return errorResponse('Expected websocket', 426);
  }

  const userId = payload.sub;
  const id = env.NOTIFICATIONS_HUB.idFromName(userId);
  const stub = env.NOTIFICATIONS_HUB.get(id);
  const forwardedUrl = new URL(request.url);
  forwardedUrl.searchParams.delete('access_token');
  forwardedUrl.searchParams.delete('connection_token');
  forwardedUrl.searchParams.set('nw_uid', userId);
  if (payload.did) {
    forwardedUrl.searchParams.set('nw_did', payload.did);
  }
  if (connectionClaims) {
    forwardedUrl.searchParams.set('nw_connect_jti', connectionClaims.jti);
    forwardedUrl.searchParams.set('nw_connect_exp', String(connectionClaims.exp));
  }
  return stub.fetch(new Request(forwardedUrl.toString(), request));
}

export async function handleAnonymousNotificationsHub(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const authRequestId = String(url.searchParams.get('Token') || url.searchParams.get('token') || '').trim();
  if (!authRequestId) return errorResponse('Token is required', 400);
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
    return errorResponse('Expected websocket', 426);
  }

  const storage = new StorageService(env.DB);
  const authRequest = await storage.getAuthRequestById(authRequestId);
  if (!authRequest || isAuthRequestExpired(authRequest)) {
    return errorResponse('Not found', 404);
  }

  const id = env.NOTIFICATIONS_HUB.idFromName(authRequestId);
  const stub = env.NOTIFICATIONS_HUB.get(id);
  const forwardedUrl = new URL(request.url);
  forwardedUrl.searchParams.set('nw_auth_request_id', authRequestId);
  return stub.fetch(new Request(forwardedUrl.toString(), request));
}
