import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createAttachmentUploadToken,
  createFileDownloadToken,
  createSendFileDownloadToken,
  createSendFileUploadToken,
  verifyAttachmentUploadToken,
  verifyFileDownloadToken,
  verifySendFileDownloadToken,
  verifySendFileUploadToken,
} from '../src/utils/jwt';

const secret = 'file-token-test-secret-that-is-longer-than-thirty-two-characters';

test('attachment upload and download tokens cannot be substituted for each other', async () => {
  const upload = await createAttachmentUploadToken('user-1', 'cipher-1', 'attachment-1', secret);
  const download = await createFileDownloadToken('cipher-1', 'attachment-1', secret);

  assert.equal((await verifyAttachmentUploadToken(upload, secret))?.typ, 'attachment_upload');
  assert.equal((await verifyFileDownloadToken(download, secret))?.typ, 'attachment_download');
  assert.equal(await verifyFileDownloadToken(upload, secret), null);
  assert.equal(await verifyAttachmentUploadToken(download, secret), null);
});

test('Send upload and download tokens cannot be substituted for each other', async () => {
  const upload = await createSendFileUploadToken('user-1', 'send-1', 'file-1', secret);
  const download = await createSendFileDownloadToken('send-1', 'file-1', secret);

  assert.equal((await verifySendFileUploadToken(upload, secret))?.typ, 'send_file_upload');
  assert.equal((await verifySendFileDownloadToken(download, secret))?.typ, 'send_file_download');
  assert.equal(await verifySendFileDownloadToken(upload, secret), null);
  assert.equal(await verifySendFileUploadToken(download, secret), null);
});
