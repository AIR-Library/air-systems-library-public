'use strict';
const { test, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const { inspectArchive, extractArchive } = require('./safe_archive_ingest_javascript.js');

/*
 * Tests for docs/specs/safe_archive_ingest.md (ARCHIVE-01..ARCHIVE-14) with the spec's TEST ARCHIVE BUILDER and
 * TEST VECTORS. Every target is a fresh directory under the OS temp directory, removed after the run.
 * Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches files under the OS temp directory only.
 */

const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'archive-js-'));
after(() => fs.rmSync(ROOT, { recursive: true, force: true }));
let dirCounter = 0;

/**
 * A fresh, empty parent directory and a target path inside it that does not exist yet.
 * Out: {parent, target}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches files (temp).
 */
function freshTarget() {
  const parent = path.join(ROOT, 'p' + (dirCounter++));
  fs.mkdirSync(parent);
  return { parent, target: path.join(parent, 'target') };
}

/**
 * build_zip(entries, comment): the spec's TEST ARCHIVE BUILDER. An entry is {name, data} plus method, usize, crc,
 * flags, external, creator, extra and local_name; names and data may be strings or Buffers.
 * Out: Buffer. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function buildZip(entries, comment = '') {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name);
    const localName = Buffer.from(e.local_name === undefined ? e.name : e.local_name);
    const data = Buffer.from(e.data || '');
    const extra = Buffer.from(e.extra || '');
    const method = e.method || 0;
    const usize = e.usize === undefined ? data.length : e.usize;
    const crc = e.crc === undefined ? zlib.crc32(data) >>> 0 : e.crc;
    const flags = e.flags || 0;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8); local.writeUInt16LE(0, 10); local.writeUInt16LE(0x0021, 12);
    local.writeUInt32LE(crc, 14); local.writeUInt32LE(data.length, 18); local.writeUInt32LE(usize, 22);
    local.writeUInt16LE(localName.length, 26); local.writeUInt16LE(0, 28);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE((e.creator || 0) * 256 + 20, 4);
    central.writeUInt16LE(20, 6); central.writeUInt16LE(flags, 8); central.writeUInt16LE(method, 10);
    central.writeUInt16LE(0, 12); central.writeUInt16LE(0x0021, 14); central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20); central.writeUInt32LE(usize, 24); central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(extra.length, 30); central.writeUInt16LE(0, 32); central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36); central.writeUInt32LE(e.external || 0, 38); central.writeUInt32LE(offset, 42);
    const localRecord = Buffer.concat([local, localName, data]);
    locals.push(localRecord);
    centrals.push(Buffer.concat([central, name, extra]));
    offset += localRecord.length;
  }
  const cd = Buffer.concat(centrals);
  const commentBytes = Buffer.from(comment);
  const endRec = Buffer.alloc(22);
  endRec.writeUInt32LE(0x06054b50, 0); endRec.writeUInt16LE(0, 4); endRec.writeUInt16LE(0, 6);
  endRec.writeUInt16LE(entries.length, 8); endRec.writeUInt16LE(entries.length, 10);
  endRec.writeUInt32LE(cd.length, 12); endRec.writeUInt32LE(offset, 16); endRec.writeUInt16LE(commentBytes.length, 20);
  return Buffer.concat([...locals, cd, endRec, commentBytes]);
}

const BASIC_ENTRIES = [
  { name: 'docs/', external: 0x41ED0000, creator: 3 },
  { name: 'docs/readme.txt', data: 'hello\n' },
  { name: 'data.csv', data: 'a,b\n1,2\n', external: 0x81ED0000, creator: 3 }
];
const BASIC_HEX =
  '504b03041400000000000000210000000000000000000000000005000000646f63732f504b0304140000000000000021' +
  '0020303a3606000000060000000f000000646f63732f726561646d652e74787468656c6c6f0a504b0304140000000000' +
  '000021007b07970a080000000800000008000000646174612e637376612c620a312c320a504b01021403140000000000' +
  '00002100000000000000000000000000050000000000000000000000ed4100000000646f63732f504b01021400140000' +
  '0000000000210020303a3606000000060000000f0000000000000000000000000023000000646f63732f726561646d65' +
  '2e747874504b01021403140000000000000021007b07970a0800000008000000080000000000000000000000ed815600' +
  '0000646174612e637376504b05060000000003000300a6000000840000000000';
const BASIC = buildZip(BASIC_ENTRIES);
const Z = Buffer.from('63601805a360148c8251300a46c1500700', 'hex');
const BAD = Buffer.from('62601805a360148c8251300a46c1500700000000ffff07', 'hex');
const ZEROS = buildZip([{ name: 'zeros.txt', data: Z, method: 8, usize: 2000, crc: 0x02C9F444 }]);

/**
 * Asserts a refusal and that the target does not exist and its parent holds nothing.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches files (reads).
 */
function assertRefusedClean(bytes, limits, error, status, entryIndex, label) {
  const { parent, target } = freshTarget();
  assert.deepStrictEqual(extractArchive(bytes, target, limits), { error, status, entry_index: entryIndex }, label);
  assert.deepStrictEqual(inspectArchive(bytes, limits), { error, status, entry_index: entryIndex }, label);
  assert.strictEqual(fs.existsSync(target), false);
  assert.deepStrictEqual(fs.readdirSync(parent), []);
}

/**
 * Asserts the archive is accepted by inspect and extract. Out: the extract answer.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches files (temp).
 */
function assertAccepted(bytes, limits, label) {
  assert.strictEqual(inspectArchive(bytes, limits).ok, true, label);
  const { target } = freshTarget();
  const r = extractArchive(bytes, target, limits);
  assert.strictEqual(r.ok, true, `${label}: ${JSON.stringify(r)}`);
  return r;
}

/** Writes value as u16 at offset of a copy. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
function setU16(buf, offset, value) {
  const b = Buffer.from(buf);
  b.writeUInt16LE(value, offset);
  return b;
}

/**
 * ARCHIVE-01: the test builder reproduces the spec's BASIC archive byte for byte; extract_archive writes its two
 * files with the right bytes under the target, creates the directory, and returns each path, size and SHA-256.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: ARCHIVE-01, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files under the OS temp directory only.
 */
// ARCHIVE-01
test('ARCHIVE-01 the builder reproduces BASIC; extract writes its files with path, size and sha256', () => {
  assert.strictEqual(BASIC.length, 320);
  assert.strictEqual(BASIC.toString('hex'), BASIC_HEX);
  const { target } = freshTarget();
  const r = extractArchive(BASIC, target);
  assert.deepStrictEqual(r, {
    ok: true, entries: 3, total_bytes: 14, files: [
      { path: 'docs/readme.txt', size: 6, sha256: '5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03' },
      { path: 'data.csv', size: 8, sha256: '492d5ea496056f1a6a6592241032fab764c321596317930b4fa0e1e8bc3b7470' }
    ]
  });
  assert.ok(fs.statSync(path.join(target, 'docs')).isDirectory());
  assert.strictEqual(fs.readFileSync(path.join(target, 'docs', 'readme.txt'), 'utf8'), 'hello\n');
  assert.strictEqual(fs.readFileSync(path.join(target, 'data.csv'), 'utf8'), 'a,b\n1,2\n');
  assert.strictEqual(fs.statSync(path.join(target, 'data.csv')).mode & 0o777, 0o644);
  assert.strictEqual(fs.statSync(target).mode & 0o777, 0o700);
  assert.deepStrictEqual(inspectArchive(BASIC), { ok: true, entries: 3, total_bytes: 14, files: [{ path: 'docs/readme.txt', size: 6 }, { path: 'data.csv', size: 8 }] });
});

/**
 * ARCHIVE-02: zip slip: an entry named ../evil.txt, a/../../evil.txt, /etc/passwd.txt, C:/x.txt, a\b.txt, a//b.txt
 * or ./a.txt, a name with a NUL or control byte, an empty name and a name that is not strict UTF-8 (overlong, a
 * surrogate, above U+10FFFF, cut short) are each 400 unsafe_path with the entry's index; the target does not exist
 * afterwards and nothing was written beside it.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: ARCHIVE-02, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files under the OS temp directory only.
 */
// ARCHIVE-02
test('ARCHIVE-02 zip slip and unsafe names are 400 unsafe_path with the entry index; nothing is written', () => {
  const names = ['../evil.txt', 'a/../../evil.txt', '/etc/passwd.txt', 'C:/x.txt', 'a\\b.txt', 'a//b.txt', './a.txt',
    'a\u0000b.txt', 'a\u0001b.txt', 'a\u007fb.txt', '',
    Buffer.from('61c0af622e747874', 'hex'), Buffer.from('61eda0802e747874', 'hex'),
    Buffer.from('61f49080802e747874', 'hex'), Buffer.from('61e2822e747874', 'hex')];
  for (const name of names) {
    assertRefusedClean(buildZip([{ name: 'ok.txt', data: 'x' }, { name, data: 'y' }]), undefined, 'unsafe_path', 400, 1, String(name));
  }
  assertRefusedClean(buildZip([{ name: '../evil.txt', data: 'y' }]), undefined, 'unsafe_path', 400, 0, 'first entry');
});

/**
 * ARCHIVE-03: a symbolic link entry (mode 0120000) is 400 special_file whatever system the archive says made it
 * (creator 0, 3 and 19), and so is a FIFO; a regular-file mode is accepted.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: ARCHIVE-03, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files under the OS temp directory only.
 */
// ARCHIVE-03
test('ARCHIVE-03 links and FIFOs are 400 special_file whatever the creator; a regular mode is accepted', () => {
  for (const creator of [0, 3, 19]) {
    assertRefusedClean(buildZip([{ name: 'link.txt', data: 'target', external: 0xA1FF0000, creator }]), undefined, 'special_file', 400, 0, 'link');
  }
  assertRefusedClean(buildZip([{ name: 'fifo.txt', data: '', external: 0x11A40000, creator: 3 }]), undefined, 'special_file', 400, 0, 'fifo');
  assertAccepted(buildZip([{ name: 'file.txt', data: 'x', external: 0x81A40000, creator: 3 }]), undefined, 'regular');
});

/**
 * ARCHIVE-04: more entries than max_entries is 413 too_many_entries and more bytes than max_archive_bytes is 413
 * archive_too_large; exactly at each limit the archive is accepted.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: ARCHIVE-04, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files under the OS temp directory only.
 */
// ARCHIVE-04
test('ARCHIVE-04 entry count and archive size limits, exact limits accepted', () => {
  const three = buildZip(['a.txt', 'b.txt', 'c.txt'].map(name => ({ name, data: 'x' })));
  assert.strictEqual(three.length, 283);
  assertAccepted(three, { max_entries: 3, max_archive_bytes: 283 }, 'exact');
  assertRefusedClean(three, { max_entries: 2 }, 'too_many_entries', 413, -1, 'entries');
  assertRefusedClean(three, { max_archive_bytes: 282 }, 'archive_too_large', 413, -1, 'bytes');
});

/**
 * ARCHIVE-05: a declared total over max_total_bytes is 413 total_too_large and one entry over max_file_bytes is
 * 413 entry_too_large; exactly at each limit the archive is accepted; a size of 0x80000000 is read unsigned and is
 * 413, never a negative number.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: ARCHIVE-05, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files under the OS temp directory only.
 */
// ARCHIVE-05
test('ARCHIVE-05 total and per-file size limits, exact limits accepted, sizes read unsigned', () => {
  const two = buildZip([{ name: 'a.txt', data: '12345' }, { name: 'b.txt', data: '67890' }]);
  assert.strictEqual(two.length, 204);
  assertAccepted(two, { max_total_bytes: 10, max_file_bytes: 5 }, 'exact');
  assertRefusedClean(two, { max_total_bytes: 9 }, 'total_too_large', 413, 1, 'total');
  assertRefusedClean(two, { max_file_bytes: 4 }, 'entry_too_large', 413, 0, 'file');
  const huge = buildZip([{ name: 'a.txt', data: Z, method: 8, usize: 0x80000000, crc: 0 }]);
  assertRefusedClean(huge, undefined, 'entry_too_large', 413, 0, 'unsigned');
  assertRefusedClean(huge, { max_file_bytes: 4294967296, max_total_bytes: 4294967296 }, 'compression_ratio_exceeded', 413, -1, 'ratio');
});

/**
 * ARCHIVE-06: compression ratio: the ZEROS archive (133 bytes that declare 2000) is 413 compression_ratio_exceeded
 * with max_ratio 15 and is extracted with max_ratio 16.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: ARCHIVE-06, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files under the OS temp directory only.
 */
// ARCHIVE-06
test('ARCHIVE-06 the ZEROS archive is over a ratio of 15 and extracted with 16', () => {
  assert.strictEqual(ZEROS.length, 133);
  assertRefusedClean(ZEROS, { max_ratio: 15 }, 'compression_ratio_exceeded', 413, -1, 'ratio 15');
  const { target } = freshTarget();
  const r = extractArchive(ZEROS, target, { max_ratio: 16 });
  assert.strictEqual(r.ok, true);
  assert.deepStrictEqual(r.files.map(f => [f.path, f.size]), [['zeros.txt', 2000]]);
  assert.ok(fs.readFileSync(path.join(target, 'zeros.txt')).equals(Buffer.alloc(2000)));
});

/**
 * ARCHIVE-07: lying headers: an entry that declares 10 bytes but inflates to 2000, one that declares 3000 but
 * inflates to 2000, a deflate stream missing its last 4 bytes, a stream that overruns its declared size and then
 * turns invalid, a wrong CRC (stored or deflated) and a stream of invalid data are 400 corrupt_entry; a stored
 * entry whose two sizes differ is 400 size_mismatch; no file is left in any case.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: ARCHIVE-07, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files under the OS temp directory only.
 */
// ARCHIVE-07
test('ARCHIVE-07 lying sizes, cut or invalid streams and wrong CRCs are corrupt_entry; unequal stored sizes are size_mismatch', () => {
  const corrupt = [
    { name: 'zeros.txt', data: Z, method: 8, usize: 10, crc: 0xE38A6876 },
    { name: 'zeros.txt', data: Z, method: 8, usize: 3000, crc: 0x02C9F444 },
    { name: 'zeros.txt', data: Z.subarray(0, Z.length - 4), method: 8, usize: 2000, crc: 0x02C9F444 },
    { name: 'zeros.txt', data: Z, method: 8, usize: 2000, crc: 1 },
    { name: 'a.txt', data: '12345', crc: 0 },
    { name: 'zeros.txt', data: Buffer.from('ffffffff', 'hex'), method: 8, usize: 4, crc: 0 },
    { name: 'zeros.txt', data: BAD, method: 8, usize: 10, crc: 0xE38A6876 }
  ];
  for (const e of corrupt) {
    const { parent, target } = freshTarget();
    assert.deepStrictEqual(extractArchive(buildZip([e]), target, { max_ratio: 1000 }), { error: 'corrupt_entry', status: 400, entry_index: 0 });
    assert.strictEqual(fs.existsSync(target), false);
    assert.deepStrictEqual(fs.readdirSync(parent), []);
  }
  assertRefusedClean(buildZip([{ name: 'a.txt', data: '12345', usize: 4 }]), undefined, 'size_mismatch', 400, 0, 'stored sizes');
});

/**
 * ARCHIVE-08: extensions: run.exe, a.txt.sh, README, .env and inner.zip are 400 extension_not_allowed with the
 * default list; A.TXT and x.Json are accepted; with allowed_extensions ["", "sh"] README and a.sh are accepted.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: ARCHIVE-08, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files under the OS temp directory only.
 */
// ARCHIVE-08
test('ARCHIVE-08 extensions outside the allow-list are refused; case does not matter; the list is configurable', () => {
  for (const name of ['run.exe', 'a.txt.sh', 'README', '.env', 'inner.zip']) {
    assertRefusedClean(buildZip([{ name, data: 'x' }]), undefined, 'extension_not_allowed', 400, 0, name);
  }
  assertAccepted(buildZip([{ name: 'A.TXT', data: 'x' }, { name: 'x.Json', data: '{}' }]), undefined, 'case');
  assertAccepted(buildZip([{ name: 'README', data: 'x' }, { name: 'a.sh', data: 'y' }]), { allowed_extensions: ['', 'sh'] }, 'custom');
});

/**
 * ARCHIVE-09: a.txt twice, A.txt with a.txt, a file with a path under it (in either order) and a directory with a
 * file of the same name (in either order) are 400 duplicate_name with entry_index 1; the same directory named
 * twice is accepted.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: ARCHIVE-09, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files under the OS temp directory only.
 */
// ARCHIVE-09
test('ARCHIVE-09 duplicate names, case-folded, file/dir clashes in either order are duplicate_name at index 1', () => {
  const pairs = [
    ['a.txt', 'a.txt'], ['A.txt', 'a.txt'], ['d.txt/', 'd.txt'], ['d.txt', 'd.txt/'], ['d.txt', 'd.txt/e.txt'], ['d.txt/e.txt', 'd.txt']
  ];
  for (const [first, second] of pairs) {
    assertRefusedClean(buildZip([{ name: first, data: first.endsWith('/') ? '' : 'x' }, { name: second, data: second.endsWith('/') ? '' : 'y' }]),
      undefined, 'duplicate_name', 400, 1, `${first} + ${second}`);
  }
  const r = assertAccepted(buildZip([{ name: 'd/' }, { name: 'd/' }, { name: 'd/e.txt', data: 'x' }]), undefined, 'same dir twice');
  assert.strictEqual(r.entries, 3);
});

/**
 * ARCHIVE-10: empty input is 400 empty_upload; text that is not a zip, a truncated archive, an entry count that
 * disagrees with the directory and a byte after the end record are 400 not_a_zip; a directory offset and size
 * whose 32-bit sum wraps round are 400 not_a_zip too; a disk number and a zip64 marker are 400 unsupported_zip; an
 * input too short to hold a zip64 locator is never read before its start; an archive with only a directory is 400
 * empty_archive; an archive comment is accepted.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: ARCHIVE-10, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files under the OS temp directory only.
 */
// ARCHIVE-10
test('ARCHIVE-10 container faults: empty, not a zip, truncated, wrong counts, trailing byte, wrap, disk, zip64', () => {
  assertRefusedClean(Buffer.alloc(0), undefined, 'empty_upload', 400, -1, 'empty');
  assertRefusedClean(Buffer.from('this is not a zip archive at all'), undefined, 'not_a_zip', 400, -1, 'text');
  assertRefusedClean(BASIC.subarray(0, BASIC.length - 10), undefined, 'not_a_zip', 400, -1, 'truncated');
  assertRefusedClean(setU16(setU16(BASIC, BASIC.length - 14, 4), BASIC.length - 12, 4), undefined, 'not_a_zip', 400, -1, 'count');
  assertRefusedClean(Buffer.concat([BASIC, Buffer.from([0])]), undefined, 'not_a_zip', 400, -1, 'trailing byte');
  const wrap = Buffer.from(BASIC);
  wrap.writeUInt32LE(300, BASIC.length - 10);
  wrap.writeUInt32LE(0xFFFFFFFE, BASIC.length - 6);
  assertRefusedClean(wrap, undefined, 'not_a_zip', 400, -1, 'wrap');
  assertRefusedClean(setU16(BASIC, BASIC.length - 18, 1), undefined, 'unsupported_zip', 400, -1, 'disk');
  assertRefusedClean(setU16(setU16(BASIC, BASIC.length - 14, 0xFFFF), BASIC.length - 12, 0xFFFF), undefined, 'unsupported_zip', 400, -1, 'zip64 count');
  // A zip64 end-of-central-directory locator just before the END record.
  const loc = Buffer.alloc(20);
  loc.writeUInt32LE(0x07064b50, 0);
  const cdStart = BASIC.readUInt32LE(BASIC.length - 6);
  const withLocator = Buffer.concat([BASIC.subarray(0, BASIC.length - 22), loc, BASIC.subarray(BASIC.length - 22)]);
  assert.strictEqual(withLocator.readUInt32LE(withLocator.length - 6), cdStart);
  assertRefusedClean(withLocator, undefined, 'unsupported_zip', 400, -1, 'zip64 locator');
  const tiny = Buffer.from('504b0304504b0506000000000000000000000000040000001000504b0607787878787878787878787878', 'hex');
  assert.strictEqual(tiny.length, 42);
  assertRefusedClean(tiny, undefined, 'empty_archive', 400, -1, 'short input');
  assertRefusedClean(buildZip([{ name: 'docs/' }]), undefined, 'empty_archive', 400, -1, 'only a directory');
  const commented = buildZip(BASIC_ENTRIES, 'c'.repeat(40));
  assert.strictEqual(commented.length, 360);
  assert.strictEqual(assertAccepted(commented, undefined, 'comment').entries, 3);
});

/**
 * ARCHIVE-11: an entry with an encryption flag (bit 0 or bit 6) is 400 encrypted_entry; a compression method other
 * than 0 and 8 is 400 unsupported_compression; an entry with flag bit 3 (a data descriptor) is accepted.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: ARCHIVE-11, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files under the OS temp directory only.
 */
// ARCHIVE-11
test('ARCHIVE-11 encrypted entries and unknown methods are refused; a data descriptor flag is accepted', () => {
  for (const flags of [1, 0x40, 0x2000]) {
    assertRefusedClean(buildZip([{ name: 'a.txt', data: '12345', flags }]), undefined, 'encrypted_entry', 400, 0, String(flags));
  }
  for (const method of [12, 14, 99]) {
    assertRefusedClean(buildZip([{ name: 'a.txt', data: '12345', method }]), undefined, 'unsupported_compression', 400, 0, String(method));
  }
  const r = assertAccepted(buildZip([{ name: 'a.txt', data: '12345', flags: 8 }]), undefined, 'bit 3');
  assert.deepStrictEqual(r.files.map(f => [f.path, f.size]), [['a.txt', 5]]);
});

/**
 * ARCHIVE-12: a local record whose name differs from the central record's is 400 header_mismatch with that entry's
 * index; a Unicode Path extra field that names ../evil.txt is 400 header_mismatch, the same field repeating the
 * entry's own name is accepted, and an extra field that overruns its length is 400 not_a_zip.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: ARCHIVE-12, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files under the OS temp directory only.
 */
// ARCHIVE-12
test('ARCHIVE-12 local/central name mismatch and Unicode Path extra fields; a broken extra field is not_a_zip', () => {
  assertRefusedClean(buildZip([{ name: 'first.txt', data: 'a' }, { name: 'ok.txt', data: 'x', local_name: 'no.txt' }]), undefined, 'header_mismatch', 400, 1, 'local name');
  const evil = Buffer.from('75701000012a0419052e2e2f6576696c2e747874', 'hex');
  const crc = Buffer.alloc(4);
  crc.writeUInt32LE(zlib.crc32('ok.txt') >>> 0);
  assert.ok(evil.subarray(5, 9).equals(crc));
  assertRefusedClean(buildZip([{ name: 'ok.txt', data: 'x', extra: evil }]), undefined, 'header_mismatch', 400, 0, 'unicode path');
  const own = Buffer.concat([Buffer.from([0x75, 0x70, 11, 0, 1]), crc, Buffer.from('ok.txt')]);
  assertAccepted(buildZip([{ name: 'ok.txt', data: 'x', extra: own }]), undefined, 'own name');
  assertRefusedClean(buildZip([{ name: 'ok.txt', data: 'x', extra: Buffer.from('0a0032006162', 'hex') }]), undefined, 'not_a_zip', 400, 0, 'overrun');
});

/**
 * ARCHIVE-13: all or nothing: when the second entry is corrupt the answer names entry_index 1, the target does not
 * exist and no staging directory is left beside it; an existing target is 409 target_exists and keeps its content;
 * a target whose parent directory is missing is 500 target_unwritable.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: ARCHIVE-13, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files under the OS temp directory only.
 */
// ARCHIVE-13
test('ARCHIVE-13 all or nothing; an existing target is 409; a missing parent is 500', () => {
  const bytes = buildZip([{ name: 'a.txt', data: 'good' }, { name: 'b.txt', data: 'bad', crc: 7 }]);
  const { parent, target } = freshTarget();
  assert.deepStrictEqual(extractArchive(bytes, target), { error: 'corrupt_entry', status: 400, entry_index: 1 });
  assert.strictEqual(fs.existsSync(target), false);
  assert.deepStrictEqual(fs.readdirSync(parent), []);
  const existing = freshTarget();
  fs.mkdirSync(existing.target);
  fs.writeFileSync(path.join(existing.target, 'keep.txt'), 'mine');
  assert.deepStrictEqual(extractArchive(BASIC, existing.target), { error: 'target_exists', status: 409, entry_index: -1 });
  assert.deepStrictEqual(fs.readdirSync(existing.target), ['keep.txt']);
  assert.strictEqual(fs.readFileSync(path.join(existing.target, 'keep.txt'), 'utf8'), 'mine');
  const dangling = freshTarget();
  fs.symlinkSync(path.join(dangling.parent, 'nowhere'), dangling.target);
  assert.deepStrictEqual(extractArchive(BASIC, dangling.target), { error: 'target_exists', status: 409, entry_index: -1 });
  const missing = path.join(ROOT, 'no-such-parent', 'target');
  assert.deepStrictEqual(extractArchive(BASIC, missing), { error: 'target_unwritable', status: 500, entry_index: -1 });
  assert.strictEqual(fs.existsSync(path.join(ROOT, 'no-such-parent')), false);
});

/**
 * ARCHIVE-13, short writes: fs.writeSync is made to write at most 3 bytes per call (as a nearly full disk may);
 * every file still lands whole, with the size and SHA-256 the answer reports. A writeSync that writes nothing is
 * an I/O error: 500 target_unwritable naming entry_index 1 (docs/readme.txt, the first file written; the spec's
 * CONVENTIONS: D3 names the entry being written), and no target or staging directory is left.
 * In: the spec's BASIC archive. Out: assertions. Why: review finding 4525344169 (one writeSync call, its count
 * ignored), and the D3 entry index (same gap as finding 4525344113). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files under the OS temp directory; fs.writeSync is replaced for the test and restored.
 */
// ARCHIVE-13
test('ARCHIVE-13 a short write is completed, and a write of nothing is target_unwritable', () => {
  const realWriteSync = fs.writeSync;
  try {
    fs.writeSync = (fd, buf, offset, length) => realWriteSync(fd, buf, offset || 0, Math.min(3, length === undefined ? buf.length - (offset || 0) : length));
    const { target } = freshTarget();
    const r = extractArchive(BASIC, target);
    assert.strictEqual(r.ok, true);
    assert.strictEqual(fs.readFileSync(path.join(target, 'docs', 'readme.txt'), 'utf8'), 'hello\n');
    assert.strictEqual(fs.readFileSync(path.join(target, 'data.csv'), 'utf8'), 'a,b\n1,2\n');
    fs.writeSync = () => 0;
    const stuck = freshTarget();
    const refused = extractArchive(BASIC, stuck.target);
    assert.deepStrictEqual(refused, { error: 'target_unwritable', status: 500, entry_index: 1 });
    assert.strictEqual(fs.existsSync(stuck.target), false);
    assert.deepStrictEqual(fs.readdirSync(stuck.parent), []);
  } finally {
    fs.writeSync = realWriteSync;
  }
});

/**
 * ARCHIVE-14: names that do not unpack everywhere are 400 bad_name: CON.txt, com1.txt, COM0.txt, LPT0.txt, COM
 * followed by a superscript 1, CONIN$.txt, CONOUT$.txt, a name ending in a dot or a space, a?.txt, a segment of
 * 256 bytes, a name with a right-to-left override; a UTF-8 name with an accented letter is accepted; a file whose
 * entry mode is 0755 is written without execute permission.
 * In: the spec's TEST VECTORS for this row. Out: assertions (the test fails on any mismatch).
 * Why: ARCHIVE-14, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files under the OS temp directory only.
 */
// ARCHIVE-14
test('ARCHIVE-14 names that do not unpack everywhere are bad_name; accented names pass; files are never executable', () => {
  const bad = ['CON.txt', 'com1.txt', 'COM0.txt', 'LPT0.txt', 'COM\u00b9.txt', 'CONIN$.txt', 'CONOUT$.txt', 'a.txt.', 'a.txt ',
    'a?.txt', 'x'.repeat(252) + '.txt', 'a\u202etxt.exe.txt', 'nul .txt', 'dir./a.txt', 'a\u200b.txt'];
  for (const name of bad) assertRefusedClean(buildZip([{ name, data: 'x' }]), undefined, 'bad_name', 400, 0, name);
  assertAccepted(buildZip([{ name: 'x'.repeat(251) + '.txt', data: 'x' }]), undefined, '255 bytes');
  for (const name of ['caf\u00e9.txt', 'COM10.txt', 'conin.txt']) assertAccepted(buildZip([{ name, data: 'x' }]), undefined, name);
  const { target } = freshTarget();
  assert.strictEqual(extractArchive(buildZip([{ name: 'tool.txt', data: 'x', external: 0x81ED0000, creator: 3 }]), target).ok, true);
  assert.strictEqual(fs.statSync(path.join(target, 'tool.txt')).mode & 0o111, 0);
  assert.strictEqual(fs.statSync(path.join(target, 'tool.txt')).mode & 0o777, 0o644);
});
