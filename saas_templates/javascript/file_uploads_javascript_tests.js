const { test } = require('node:test');
const assert = require('node:assert');
const { FileUploads, InMemoryStore } = require('./file_uploads_javascript.js');
const fs = require('fs');
const path = require('path');
const os = require('os');

function createTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'fileuploads-'));
}

function createMembershipChecker(members) {
  return (user, orgId) => members.has(`${user}:${orgId}`);
}

// UPLOAD-01
test('a .exe is rejected', () => {
  const tempDir = createTempDir();
  const members = new Set(['user1:org1']);
  const uploads = new FileUploads({
    storageDir: tempDir,
    membershipChecker: createMembershipChecker(members)
  });

  const exeBytes = Buffer.from([0x4D, 0x5A, 0x90, 0x00]);
  const result = uploads.upload('user1', 'org1', 'malware.exe', exeBytes, 'application/octet-stream');
  assert.ok(result.error, 'Should reject .exe file');
  assert.ok(result.error.includes('not allowed'), 'Error should mention extension not allowed');
});

// UPLOAD-01
test('a .exe renamed to .png is rejected by its magic bytes', () => {
  const tempDir = createTempDir();
  const members = new Set(['user1:org1']);
  const uploads = new FileUploads({
    storageDir: tempDir,
    membershipChecker: createMembershipChecker(members)
  });

  const exeBytes = Buffer.from([0x4D, 0x5A, 0x90, 0x00]);
  const result = uploads.upload('user1', 'org1', 'malware.png', exeBytes, 'image/png');
  assert.ok(result.error, 'Should reject exe renamed to png');
  assert.ok(result.error.includes('Magic bytes'), 'Error should mention magic bytes');
});

// UPLOAD-02
test('a real PNG is accepted and stored under a generated name, not the original', () => {
  const tempDir = createTempDir();
  const members = new Set(['user1:org1']);
  const uploads = new FileUploads({
    storageDir: tempDir,
    membershipChecker: createMembershipChecker(members)
  });

  const pngBytes = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  const result = uploads.upload('user1', 'org1', 'photo.png', pngBytes, 'image/png');
  assert.ok(result.file_id, 'Should accept valid PNG');
  assert.ok(!result.error, 'Should not have error');

  const record = uploads.store.getFileRecord(result.file_id);
  assert.ok(record, 'File record should exist');
  assert.notStrictEqual(record.stored_name, 'photo.png', 'Stored name should be generated, not original');
  assert.ok(record.stored_name.endsWith('.png'), 'Stored name should have .png extension');
});

// UPLOAD-03
test('../../etc/passwd.png is stored safely; the display name has no path parts', () => {
  const tempDir = createTempDir();
  const members = new Set(['user1:org1']);
  const uploads = new FileUploads({
    storageDir: tempDir,
    membershipChecker: createMembershipChecker(members)
  });

  const pngBytes = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  const result = uploads.upload('user1', 'org1', '../../etc/passwd.png', pngBytes, 'image/png');
  assert.ok(result.file_id, 'Should accept file with path traversal in name');

  const record = uploads.store.getFileRecord(result.file_id);
  assert.ok(record, 'File record should exist');
  assert.strictEqual(record.original_name, 'passwd.png', 'Display name should have no path parts');
  assert.ok(!record.original_name.includes('..'), 'Display name should not contain ..');
  assert.ok(!record.original_name.includes('/'), 'Display name should not contain /');
});

// UPLOAD-04
test('a file over the size limit is rejected', () => {
  const tempDir = createTempDir();
  const members = new Set(['user1:org1']);
  const uploads = new FileUploads({
    storageDir: tempDir,
    maxFileSize: 100,
    membershipChecker: createMembershipChecker(members)
  });

  const pngBytes = Buffer.alloc(101, 0x89);
  pngBytes[0] = 0x89;
  pngBytes[1] = 0x50;
  pngBytes[2] = 0x4E;
  pngBytes[3] = 0x47;
  const result = uploads.upload('user1', 'org1', 'large.png', pngBytes, 'image/png');
  assert.ok(result.error, 'Should reject file over size limit');
  assert.ok(result.error.includes('size'), 'Error should mention size');
});

// UPLOAD-05
test('a non-member of the org cannot upload or download', () => {
  const tempDir = createTempDir();
  const members = new Set(['user1:org1']);
  const uploads = new FileUploads({
    storageDir: tempDir,
    membershipChecker: createMembershipChecker(members)
  });

  const pngBytes = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  const uploadResult = uploads.upload('user2', 'org1', 'photo.png', pngBytes, 'image/png');
  assert.ok(uploadResult.error, 'Non-member should not be able to upload');
  assert.ok(uploadResult.error.includes('Unauthorized'), 'Error should mention unauthorized');

  const downloadResult = uploads.download('invalid_token');
  assert.ok(downloadResult.error, 'Invalid token should fail');
});

// UPLOAD-06
test('an expired link is rejected; a link with one changed character is rejected', async () => {
  const tempDir = createTempDir();
  const members = new Set(['user1:org1']);
  const uploads = new FileUploads({
    storageDir: tempDir,
    membershipChecker: createMembershipChecker(members)
  });

  const pngBytes = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  const uploadResult = uploads.upload('user1', 'org1', 'photo.png', pngBytes, 'image/png');
  assert.ok(uploadResult.file_id);

  const linkResult = uploads.createDownloadLink('user1', uploadResult.file_id, 1);
  assert.ok(linkResult.url);

  const token = linkResult.url.split('/').pop();

  await new Promise(resolve => setTimeout(resolve, 1100));

  const expiredResult = uploads.download(token);
  assert.ok(expiredResult.error, 'Expired link should be rejected');
  assert.ok(expiredResult.error.includes('expired'), 'Error should mention expiration');

  const tamperedToken = token.slice(0, -2) + 'XX';
  const tamperedResult = uploads.download(tamperedToken);
  assert.ok(tamperedResult.error, 'Tampered link should be rejected');
});

// UPLOAD-07
test('after delete_file, the file can no longer be linked or downloaded', () => {
  const tempDir = createTempDir();
  const members = new Set(['user1:org1']);
  const uploads = new FileUploads({
    storageDir: tempDir,
    membershipChecker: createMembershipChecker(members)
  });

  const pngBytes = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  const uploadResult = uploads.upload('user1', 'org1', 'photo.png', pngBytes, 'image/png');
  assert.ok(uploadResult.file_id);

  // Create link BEFORE deletion
  const linkBeforeDelete = uploads.createDownloadLink('user1', uploadResult.file_id);
  assert.ok(linkBeforeDelete.url, 'Should create link before deletion');
  const token = linkBeforeDelete.url.split('/').pop();

  // Delete the file
  const deleteResult = uploads.deleteFile('user1', uploadResult.file_id);
  assert.ok(deleteResult.success, 'Delete should succeed');

  // Try to create link AFTER deletion - should fail
  const linkAfterDelete = uploads.createDownloadLink('user1', uploadResult.file_id);
  assert.ok(linkAfterDelete.error, 'Should not create link for deleted file');
  assert.ok(linkAfterDelete.error.includes('not found'), 'Error should mention not found');

  // Try to download with the OLD link (created before deletion) - should fail
  const downloadResult = uploads.download(token);
  assert.ok(downloadResult.error, 'Should not download deleted file');
  assert.ok(downloadResult.error.includes('not found'), 'Error should mention not found');
});