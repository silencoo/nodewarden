import type { Env } from './types';
import {
  handleGetAuthorizedDevices,
  handleGetDevice,
  handleGetDevices,
  handleGetDeviceByIdentifier,
  handleUpdateDeviceKeys,
  handleUpdateDeviceTrust,
  handleUntrustDevices,
  handleRetrieveDeviceKeys,
  handleDeactivateDevice,
  handleRevokeAllTrustedDevices,
  handleRevokeTrustedDevice,
  handleTrustDevicePermanently,
  handleDeleteAllDevices,
  handleDeleteDevice,
  handleUpdateDeviceName,
  handleUpdateDeviceToken,
  handleUpdateDeviceWebPushAuth,
  handleClearDeviceToken,
  handleRegisterDevice,
  handleReportLostTrust,
} from './handlers/devices';

const AUTHORIZED_DEVICE_PATH = /^\/(?:api\/)?devices\/authorized\/([^/]+)$/i;
const PERMANENT_AUTHORIZED_DEVICE_PATH = /^\/(?:api\/)?devices\/authorized\/([^/]+)\/permanent$/i;
const DEVICE_PATH = /^\/(?:api\/)?devices\/([^/]+)$/i;
const DEVICE_NAME_PATH = /^\/(?:api\/)?devices\/([^/]+)\/name$/i;
const DEVICE_IDENTIFIER_PATH = /^\/(?:api\/)?devices\/identifier\/([^/]+)$/i;
const DEVICE_KEYS_PATH = /^\/(?:api\/)?devices\/([^/]+)\/keys$/i;
const DEVICE_IDENTIFIER_KEYS_PATH = /^\/(?:api\/)?devices\/identifier\/([^/]+)\/keys$/i;
const DEVICE_IDENTIFIER_TOKEN_PATH = /^\/(?:api\/)?devices\/identifier\/([^/]+)\/token$/i;
const DEVICE_IDENTIFIER_WEB_PUSH_PATH = /^\/(?:api\/)?devices\/identifier\/([^/]+)\/web-push-auth$/i;
const DEVICE_IDENTIFIER_CLEAR_TOKEN_PATH = /^\/(?:api\/)?devices\/identifier\/([^/]+)\/clear-token$/i;
const DEVICE_RETRIEVE_KEYS_PATH = /^\/(?:api\/)?devices\/([^/]+)\/retrieve-keys$/i;
const DEVICE_DEACTIVATE_PATH = /^\/(?:api\/)?devices\/([^/]+)\/deactivate$/i;

export async function handleAuthenticatedDeviceRoute(
  request: Request,
  env: Env,
  userId: string,
  path: string,
  method: string
): Promise<Response | null> {
  if (path === '/api/devices' || path === '/devices') {
    if (method === 'GET') return handleGetDevices(request, env, userId);
    if (method === 'POST') return handleRegisterDevice(request, env, userId);
    if (method === 'DELETE') return handleDeleteAllDevices(request, env, userId);
    return null;
  }

  if ((path === '/api/devices/lost-trust' || path === '/devices/lost-trust') && method === 'POST') {
    return handleReportLostTrust(request, env, userId);
  }

  if (path === '/api/devices/authorized' || path === '/devices/authorized') {
    if (method === 'GET') return handleGetAuthorizedDevices(request, env, userId);
    if (method === 'DELETE') return handleRevokeAllTrustedDevices(request, env, userId);
    return null;
  }

  const authorizedDeviceMatch = path.match(AUTHORIZED_DEVICE_PATH);
  if (authorizedDeviceMatch && method === 'DELETE') {
    const deviceIdentifier = decodeURIComponent(authorizedDeviceMatch[1]);
    return handleRevokeTrustedDevice(request, env, userId, deviceIdentifier);
  }

  const permanentAuthorizedDeviceMatch = path.match(PERMANENT_AUTHORIZED_DEVICE_PATH);
  if (permanentAuthorizedDeviceMatch && method === 'POST') {
    const deviceIdentifier = decodeURIComponent(permanentAuthorizedDeviceMatch[1]);
    return handleTrustDevicePermanently(request, env, userId, deviceIdentifier);
  }

  const deleteDeviceMatch = path.match(DEVICE_PATH);
  if (deleteDeviceMatch && method === 'GET') {
    const deviceIdentifier = decodeURIComponent(deleteDeviceMatch[1]);
    return handleGetDevice(request, env, userId, deviceIdentifier);
  }
  if (deleteDeviceMatch && method === 'DELETE') {
    const deviceIdentifier = decodeURIComponent(deleteDeviceMatch[1]);
    return handleDeleteDevice(request, env, userId, deviceIdentifier);
  }

  const updateDeviceNameMatch = path.match(DEVICE_NAME_PATH);
  if (updateDeviceNameMatch && method === 'PUT') {
    const deviceIdentifier = decodeURIComponent(updateDeviceNameMatch[1]);
    return handleUpdateDeviceName(request, env, userId, deviceIdentifier);
  }

  const identifierMatch = path.match(DEVICE_IDENTIFIER_PATH);
  if (identifierMatch && method === 'GET') {
    const deviceIdentifier = decodeURIComponent(identifierMatch[1]);
    return handleGetDeviceByIdentifier(request, env, userId, deviceIdentifier);
  }

  const deviceKeysMatch = path.match(DEVICE_KEYS_PATH) || path.match(DEVICE_IDENTIFIER_KEYS_PATH);
  if (deviceKeysMatch && (method === 'PUT' || method === 'POST')) {
    const deviceIdentifier = decodeURIComponent(deviceKeysMatch[1]);
    return handleUpdateDeviceKeys(request, env, userId, deviceIdentifier);
  }

  const identifierTokenMatch = path.match(DEVICE_IDENTIFIER_TOKEN_PATH);
  if (identifierTokenMatch && (method === 'PUT' || method === 'POST')) {
    const deviceIdentifier = decodeURIComponent(identifierTokenMatch[1]);
    return handleUpdateDeviceToken(request, env, userId, deviceIdentifier);
  }

  const identifierWebPushMatch = path.match(DEVICE_IDENTIFIER_WEB_PUSH_PATH);
  if (identifierWebPushMatch && (method === 'PUT' || method === 'POST')) {
    const deviceIdentifier = decodeURIComponent(identifierWebPushMatch[1]);
    return handleUpdateDeviceWebPushAuth(request, env, userId, deviceIdentifier);
  }

  const identifierClearTokenMatch = path.match(DEVICE_IDENTIFIER_CLEAR_TOKEN_PATH);
  if (identifierClearTokenMatch && (method === 'PUT' || method === 'POST')) {
    const deviceIdentifier = decodeURIComponent(identifierClearTokenMatch[1]);
    return handleClearDeviceToken(request, env, userId, deviceIdentifier);
  }

  const identifierRetrieveKeysMatch = path.match(DEVICE_RETRIEVE_KEYS_PATH);
  if (identifierRetrieveKeysMatch && method === 'POST') {
    const deviceIdentifier = decodeURIComponent(identifierRetrieveKeysMatch[1]);
    return handleRetrieveDeviceKeys(request, env, userId, deviceIdentifier);
  }

  const identifierDeactivateMatch = path.match(DEVICE_DEACTIVATE_PATH);
  if (identifierDeactivateMatch && (method === 'POST' || method === 'DELETE')) {
    const deviceIdentifier = decodeURIComponent(identifierDeactivateMatch[1]);
    return handleDeactivateDevice(request, env, userId, deviceIdentifier);
  }

  if ((path === '/api/devices/update-trust' || path === '/devices/update-trust') && method === 'POST') {
    return handleUpdateDeviceTrust(request, env, userId);
  }

  if ((path === '/api/devices/untrust' || path === '/devices/untrust') && method === 'POST') {
    return handleUntrustDevices(request, env, userId);
  }

  return null;
}
