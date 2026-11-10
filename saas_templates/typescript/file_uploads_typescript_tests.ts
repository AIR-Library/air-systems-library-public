import { FileUploads, InMemoryFileStore } from './file_uploads_typescript.ts';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { test } from 'node:test';
import * as assert from 'node:assert';
import * as crypto from 'crypto';

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'fileuploads-test-'));
}

function makeUser(id: string, orgs: string[]): { id: string; orgs: string[] } {
  return { id, orgs };
}

function makePNG(): Uint8Array {
  // Minimal valid PNG header
  return new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d]);
}

function makeJPEG(): Uint8Array {
  return new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46]);
}

function makePDF(): Uint8Array {
  return new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34]);
}

function makeZIP(): Uint8Array {
  return new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]);
}

function makeEXE(): Uint8Array {
  return new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
}

function makeText(): Uint8Array {
  return new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64]);
}

function makeTextWithNull(): Uint8Array {
  return new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x57, 0x6f, 0x72, 0x6c, 0x64]);
}

function makeLargeFile(size: number): Uint8Array {
  return new Uint8Array(size);
}

// UPLOAD-01
test('a .exe is rejected; a .exe renamed to .png is rejected by its magic bytes', () => {
  const dir = makeTempDir();
  const store = new InMemoryFileStore();
  const uploads = new FileUploads({
    store,
    storageDir: dir,
    hmacSecret: 'test-secret',
  });

  const user = makeUser('user1', ['org1']);
  
  // Test 1: .exe is rejected by extension
  const exeResult = uploads.upload(user, 'org1', 'malware.exe', makeEXE(), 'application/octet-stream');
  assert.ok('error' in exeResult, 'EXE should be rejected');
  assert.strictEqual(exeResult.error, 'extension not allowed');
  
  // Test 2: .exe renamed to .png is rejected by magic bytes
  const renamedResult = uploads.upload(user, 'org1', 'malware.png', makeEXE(), 'image/png');
  assert.ok('error' in renamedResult, 'EXE renamed to PNG should be rejected by magic bytes');
  assert.strictEqual(renamedResult.error, 'magic bytes mismatch');
  
  fs.rmSync(dir, { recursive: true, force: true });
});

// UPLOAD-02
test('a real PNG is accepted and stored under a generated name, not the original', () => {
  const dir = makeTempDir();
  const store = new InMemoryFileStore();
  const uploads = new FileUploads({
    store,
    storageDir: dir,
    hmacSecret: 'test-secret',
  });

  const user = makeUser('user1', ['org1']);
  const pngBytes = makePNG();
  const result = uploads.upload(user, 'org1', 'photo.png', pngBytes, 'image/png');
  assert.ok('file_id' in result, 'Real PNG should be accepted');

  const record = store.get(result.file_id);
  assert.ok(record, 'File record should exist');
  assert.notStrictEqual(record.stored_name, 'photo.png', 'Stored name should be generated, not original');
  assert.ok(record.stored_name.endsWith('.png'), 'Stored name should have .png extension');
  assert.strictEqual(record.original_name, 'photo.png', 'Original name should be preserved');

  // Verify file was written to storage
  const storedPath = path.join(dir, record.stored_name);
  assert.ok(fs.existsSync(storedPath), 'File should be written to storage directory');
  
  fs.rmSync(dir, { recursive: true, force: true });
});

// UPLOAD-03
test('../../etc/passwd.png is stored safely; the display name has no path parts', () => {
  const dir = makeTempDir();
  const store = new InMemoryFileStore();
  const uploads = new FileUploads({
    store,
    storageDir: dir,
    hmacSecret: 'test-secret',
  });

  const user = makeUser('user1', ['org1']);
  const pngBytes = makePNG();
  const result = uploads.upload(user, 'org1', '../../etc/passwd.png', pngBytes, 'image/png');
  assert.ok('file_id' in result, 'Path traversal filename should be accepted after sanitization');

  const record = store.get(result.file_id);
  assert.ok(record, 'File record should exist');
  assert.strictEqual(record.original_name, 'passwd.png', 'Display name should have no path parts');
  assert.ok(!record.original_name.includes('..'), 'No path traversal in original name');
  assert.ok(!record.original_name.includes('/'), 'No slashes in original name');
  
  fs.rmSync(dir, { recursive: true, force: true });
});

// UPLOAD-04
test('a file over the size limit is rejected', () => {
  const dir = makeTempDir();
  const store = new InMemoryFileStore();
  const uploads = new FileUploads({
    store,
    storageDir: dir,
    hmacSecret: 'test-secret',
    maxFileSize: 100, // 100 bytes limit for testing
  });

  const user = makeUser('user1', ['org1']);
  const largeFile = makeLargeFile(200); // 200 bytes, over limit
  const result = uploads.upload(user, 'org1', 'big.png', largeFile, 'image/png');
  assert.ok('error' in result, 'File over size limit should be rejected');
  assert.strictEqual(result.error, 'file too large');
  
  fs.rmSync(dir, { recursive: true, force: true });
});

// UPLOAD-05
test('a non-member of the org cannot upload or download', () => {
  const dir = makeTempDir();
  const store = new InMemoryFileStore();
  const uploads = new FileUploads({
    store,
    storageDir: dir,
    hmacSecret: 'test-secret',
  });

  const user = makeUser('user1', ['org1']);
  const pngBytes = makePNG();
  const uploadResult = uploads.upload(user, 'org1', 'photo.png', pngBytes, 'image/png');
  assert.ok('file_id' in uploadResult, 'Upload by member should succeed');

  // Non-member tries to upload
  const nonMember = makeUser('user2', ['org2']);
  const nonMemberUpload = uploads.upload(nonMember, 'org1', 'photo.png', pngBytes, 'image/png');
  assert.ok('error' in nonMemberUpload, 'Non-member upload should fail');
  assert.strictEqual(nonMemberUpload.error, 'unauthorized');

  // Non-member tries to create download link
  const linkResult = uploads.create_download_link(nonMember, uploadResult.file_id);
  assert.ok('error' in linkResult, 'Non-member download link should fail');
  assert.strictEqual(linkResult.error, 'unauthorized');

  // Member can create link and download
  const validLink = uploads.create_download_link(user, uploadResult.file_id);
  assert.ok('url' in validLink, 'Member should get valid link');
  const token = validLink.url.split('/').pop()!;
  const downloadResult = uploads.download(user, token);
  assert.ok('bytes' in downloadResult, 'Member download should succeed');

  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: download is now download(user, token) (spec), so the
  // non-member half of UPLOAD-05 is provable: a valid link that leaks to a non-member is refused.
  const leaked = uploads.download(nonMember, token);
  assert.ok('error' in leaked, 'Non-member download with a valid link should fail');
  assert.strictEqual(leaked.error, 'unauthorized');
  
  fs.rmSync(dir, { recursive: true, force: true });
});

// UPLOAD-06
test('an expired link is rejected; a link with one changed character is rejected', () => {
  const dir = makeTempDir();
  const store = new InMemoryFileStore();
  const uploads = new FileUploads({
    store,
    storageDir: dir,
    hmacSecret: 'test-secret',
  });

  const user = makeUser('user1', ['org1']);
  const pngBytes = makePNG();
  const uploadResult = uploads.upload(user, 'org1', 'photo.png', pngBytes, 'image/png');
  assert.ok('file_id' in uploadResult, 'Upload should succeed');

  // Create link with very short TTL
  const linkResult = uploads.create_download_link(user, uploadResult.file_id, 1);
  assert.ok('url' in linkResult, 'Link creation should succeed');
  const token = linkResult.url.split('/').pop()!;

  // Tamper with one character
  const tamperedToken = token.substring(0, token.length - 1) + (token.substring(token.length - 1) === 'A' ? 'B' : 'A');
  const tamperedResult = uploads.download(user, tamperedToken);
  assert.ok('error' in tamperedResult, 'Tampered link should be rejected');
  assert.strictEqual(tamperedResult.error, 'invalid link');

  // Create an expired link by manually constructing one with past expiry
  const expiredPayload = `${uploadResult.file_id}:${Math.floor(Date.now() / 1000) - 1}`;
  const expiredSig = crypto
    .createHmac('sha256', 'test-secret')
    .update(expiredPayload)
    .digest('hex');
  const expiredToken = Buffer.from(`${expiredPayload}:${expiredSig}`, 'utf8').toString('base64url');

  const expiredResult = uploads.download(user, expiredToken);
  assert.ok('error' in expiredResult, 'Expired link should be rejected');
  assert.strictEqual(expiredResult.error, 'link expired');
  
  fs.rmSync(dir, { recursive: true, force: true });
});

// UPLOAD-07
test('after delete_file, the file can no longer be linked or downloaded', () => {
  const dir = makeTempDir();
  const store = new InMemoryFileStore();
  const uploads = new FileUploads({
    store,
    storageDir: dir,
    hmacSecret: 'test-secret',
  });

  const user = makeUser('user1', ['org1']);
  const pngBytes = makePNG();
  const uploadResult = uploads.upload(user, 'org1', 'photo.png', pngBytes, 'image/png');
  assert.ok('file_id' in uploadResult, 'Upload should succeed');

  const earlyLink = uploads.create_download_link(user, uploadResult.file_id, 300);
  assert.ok('url' in earlyLink, 'Link before delete should succeed');
  const earlyToken = earlyLink.url.split('/').pop()!;
  assert.ok('bytes' in uploads.download(user, earlyToken), 'Download before delete should succeed');

  // Delete the file
  const deleteResult = uploads.delete_file(user, uploadResult.file_id);
  assert.ok('success' in deleteResult, 'Delete should succeed');

  // Try to create download link for deleted file
  const linkResult = uploads.create_download_link(user, uploadResult.file_id);
  assert.ok('error' in linkResult, 'Link creation for deleted file should fail');
  assert.strictEqual(linkResult.error, 'not found');

  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: this half used to call create_download_link again, so it
  // never downloaded anything; it now downloads with a link issued BEFORE the delete, as UPLOAD-07 says.
  const downloaded = uploads.download(user, earlyToken);
  assert.ok('error' in downloaded, 'Download of a deleted file should fail');
  assert.strictEqual(downloaded.error, 'not found');
  
  fs.rmSync(dir, { recursive: true, force: true });
});

/**
 * UPLOAD-06: with an injected clock, a link works until its expiry and is refused one second after; a token
 * whose signature has the wrong length, the wrong number of parts or a non-numeric expiry is an ordinary
 * 'invalid link', never an exception. In: a fixed clock the test advances. Out: assertions only. Why: spec
 * UPLOAD-06 and its malformed-token rule; timingSafeEqual used to throw on a short signature.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: a temporary directory.
 */
// UPLOAD-06
test('links expire on the injected clock; malformed tokens are invalid links, not exceptions', () => {
  const dir = makeTempDir();
  let nowMs = 1_800_000_000_000;
  const uploads = new FileUploads({
    store: new InMemoryFileStore(),
    storageDir: dir,
    hmacSecret: 'test-secret',
    now: () => nowMs,
  });
  const user = makeUser('user1', ['org1']);
  const up = uploads.upload(user, 'org1', 'photo.png', makePNG(), 'image/png');
  assert.ok('file_id' in up);
  const link = uploads.create_download_link(user, up.file_id, 60);
  assert.ok('url' in link);
  const token = link.url.split('/').pop()!;

  nowMs += 60_000;
  assert.ok('bytes' in uploads.download(user, token), 'valid at its expiry second');
  nowMs += 1_000;
  const late = uploads.download(user, token);
  assert.ok('error' in late);
  assert.strictEqual(late.error, 'link expired');

  const enc = (t: string) => Buffer.from(t, 'utf8').toString('base64url');
  for (const bad of [enc(`${up.file_id}:9999999999:abc`), enc('only:two'), enc(`${up.file_id}:soon:${'0'.repeat(64)}`), '!!!']) {
    const r = uploads.download(user, bad);
    assert.ok('error' in r);
    assert.strictEqual(r.error, 'invalid link');
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

/**
 * UPLOAD-01: the full signatures from the spec are required: a PNG with only its first 4 bytes, and a GIF
 * that starts "GIF8" but is neither GIF87a nor GIF89a, are refused; real ones pass. In: byte arrays.
 * Out: assertions only. Why: the spec's amended 2026-09-26 full-signature rule; the TypeScript build still
 * checked 4-byte prefixes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: a temporary directory.
 */
// UPLOAD-01
test('magic bytes use the full signatures', () => {
  const dir = makeTempDir();
  const uploads = new FileUploads({ store: new InMemoryFileStore(), storageDir: dir, hmacSecret: 'test-secret' });
  const user = makeUser('user1', ['org1']);
  const shortPng = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x00, 0x00, 0x00, 0x00]);
  assert.deepStrictEqual(uploads.upload(user, 'org1', 'a.png', shortPng, 'image/png'), { error: 'magic bytes mismatch' });
  const badGif = new Uint8Array(Buffer.from('GIF8xa......', 'latin1'));
  assert.deepStrictEqual(uploads.upload(user, 'org1', 'a.gif', badGif, 'image/gif'), { error: 'magic bytes mismatch' });
  assert.ok('file_id' in uploads.upload(user, 'org1', 'a.gif', new Uint8Array(Buffer.from('GIF89a......', 'latin1')), 'image/gif'));
  assert.ok('file_id' in uploads.upload(user, 'org1', 'a.pdf', makePDF(), 'application/pdf'));
  assert.ok('file_id' in uploads.upload(user, 'org1', 'a.jpg', makeJPEG(), 'image/jpeg'));
  assert.ok('file_id' in uploads.upload(user, 'org1', 'a.docx', makeZIP(), 'application/zip'));
  assert.ok('file_id' in uploads.upload(user, 'org1', 'a.txt', makeText(), 'text/plain'));
  assert.deepStrictEqual(uploads.upload(user, 'org1', 'b.txt', makeTextWithNull(), 'text/plain'), { error: 'magic bytes mismatch' });
  fs.rmSync(dir, { recursive: true, force: true });
});

/**
 * UPLOAD-03: a Windows-style traversal name keeps no path parts either. In: "..\\..\\etc\\passwd.png".
 * Out: the display name is "passwd.png". Why: path.basename on Linux kept backslash paths whole.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: a temporary directory.
 */
// UPLOAD-03
test('backslash traversal names are reduced to the last part', () => {
  const dir = makeTempDir();
  const store = new InMemoryFileStore();
  const uploads = new FileUploads({ store, storageDir: dir, hmacSecret: 'test-secret' });
  const r = uploads.upload(makeUser('user1', ['org1']), 'org1', '..\\..\\etc\\passwd.png', makePNG(), 'image/png');
  assert.ok('file_id' in r);
  assert.strictEqual(store.get(r.file_id)!.original_name, 'passwd.png');
  fs.rmSync(dir, { recursive: true, force: true });
});
