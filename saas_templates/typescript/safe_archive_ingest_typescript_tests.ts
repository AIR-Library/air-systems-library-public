/**
 * Tests for safe_archive_ingest_typescript.ts: one test (or more) per ARCHIVE-01..14 row of
 * docs/specs/safe_archive_ingest.md, with the spec's fixed vectors and its test archive builder. Offline; every
 * extraction goes into a fresh temporary directory that is removed afterwards. Why: Phase D wave 1, owner request
 * 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary files only.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { crc32, extractArchive, inspectArchive, Limits } from './safe_archive_ingest_typescript.ts';

/** One builder entry (spec TEST ARCHIVE BUILDER). */
interface BuildEntry {
  name: string | Buffer;
  data?: string | Buffer;
  method?: number;
  usize?: number;
  crc?: number;
  flags?: number;
  external?: number;
  creator?: number;
  extra?: Buffer;
  local_name?: string | Buffer;
}

/** Text as UTF-8 bytes; bytes as they are. Touches nothing. */
function b(v: string | Buffer | undefined): Buffer {
  return v === undefined ? Buffer.alloc(0) : typeof v === 'string' ? Buffer.from(v, 'utf8') : v;
}

/**
 * build_zip(entries, comment): local records, central records and the end record exactly as the spec describes;
 * it needs no compressor (a method 8 entry's data is already deflated). In: entries, comment. Out: the bytes.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function buildZip(entries: BuildEntry[], comment: string | Buffer = ''): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const data = b(e.data);
    const name = b(e.name);
    const localName = e.local_name === undefined ? name : b(e.local_name);
    const extra = e.extra ?? Buffer.alloc(0);
    const crc = e.crc ?? crc32(data);
    const usize = e.usize ?? data.length;
    const method = e.method ?? 0;
    const flags = e.flags ?? 0;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(flags, 6); lh.writeUInt16LE(method, 8);
    lh.writeUInt16LE(0, 10); lh.writeUInt16LE(0x0021, 12); lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(data.length, 18);
    lh.writeUInt32LE(usize, 22); lh.writeUInt16LE(localName.length, 26); lh.writeUInt16LE(0, 28);
    const local = Buffer.concat([lh, localName, data]);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE((e.creator ?? 0) * 256 + 20, 4); ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(flags, 8); ch.writeUInt16LE(method, 10); ch.writeUInt16LE(0, 12); ch.writeUInt16LE(0x0021, 14);
    ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(usize, 24);
    ch.writeUInt16LE(name.length, 28); ch.writeUInt16LE(extra.length, 30); ch.writeUInt16LE(0, 32);
    ch.writeUInt16LE(0, 34); ch.writeUInt16LE(0, 36); ch.writeUInt32LE(e.external ?? 0, 38); ch.writeUInt32LE(offset, 42);
    centrals.push(Buffer.concat([ch, name, extra]));
    locals.push(local);
    offset += local.length;
  }
  const cd = Buffer.concat(centrals);
  const c = b(comment);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16); end.writeUInt16LE(c.length, 20);
  return Buffer.concat([...locals, cd, end, c]);
}

const BASIC_ENTRIES: BuildEntry[] = [
  { name: 'docs/', external: 0x41ed0000, creator: 3 },
  { name: 'docs/readme.txt', data: 'hello\n' },
  { name: 'data.csv', data: 'a,b\n1,2\n', external: 0x81ed0000, creator: 3 },
];
const BASIC = buildZip(BASIC_ENTRIES);
const Z = Buffer.from('63601805a360148c8251300a46c1500700', 'hex');
const BAD = Buffer.from('62601805a360148c8251300a46c1500700000000ffff07', 'hex');
const ZEROS = buildZip([{ name: 'zeros.txt', data: Z, method: 8, usize: 2000, crc: 0x02c9f444 }]);

const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'archive-ts-'));
after(() => fs.rmSync(ROOT, { recursive: true, force: true }));
let dirCount = 0;

/** A fresh empty parent directory and a target path inside it that does not exist yet. Touches: temp files. */
function target(): { parent: string; dir: string } {
  const parent = path.join(ROOT, 'p' + dirCount++);
  fs.mkdirSync(parent);
  return { parent, dir: path.join(parent, 'out') };
}

/** Asserts a refusal and that nothing was left in the parent directory. Touches: temp files (read). */
function assertRefused(bytes: Buffer, error: string, status: number, entryIndex: number, limits?: Partial<Limits>): void {
  const t = target();
  assert.deepEqual(extractArchive(bytes, t.dir, limits), { error, status, entry_index: entryIndex });
  assert.deepEqual(inspectArchive(bytes, limits), { error, status, entry_index: entryIndex });
  assert.deepEqual(fs.readdirSync(t.parent), []);
}

/** Asserts that extraction succeeds. Out: the result. Touches: temp files. */
function assertExtracted(bytes: Buffer, limits?: Partial<Limits>): { files: { path: string; size: number; sha256: string }[]; dir: string } {
  const t = target();
  const out = extractArchive(bytes, t.dir, limits);
  assert.ok('ok' in out, JSON.stringify(out));
  assert.equal(fs.readdirSync(t.parent).length, 1);
  return { files: (out as any).files, dir: t.dir };
}

/**
 * ARCHIVE-01: the builder reproduces BASIC; extract writes both files, the directory and their SHA-256.
 * In: the spec's vectors and fakes. Out: assertions only. Why: ARCHIVE-01 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary files under the OS temp directory, removed afterwards.
 */
// ARCHIVE-01
test('ARCHIVE-01 the builder reproduces BASIC; extract writes both files, the directory and their SHA-256', () => {
  assert.equal(BASIC.toString('hex'),
    '504b03041400000000000000210000000000000000000000000005000000646f63732f504b0304140000000000000021' +
    '0020303a3606000000060000000f000000646f63732f726561646d652e74787468656c6c6f0a504b0304140000000000' +
    '000021007b07970a080000000800000008000000646174612e637376612c620a312c320a504b01021403140000000000' +
    '00002100000000000000000000000000050000000000000000000000ed4100000000646f63732f504b01021400140000' +
    '0000000000210020303a3606000000060000000f0000000000000000000000000023000000646f63732f726561646d65' +
    '2e747874504b01021403140000000000000021007b07970a0800000008000000080000000000000000000000ed815600' +
    '0000646174612e637376504b05060000000003000300a6000000840000000000');
  assert.equal(BASIC.length, 320);
  const t = target();
  assert.deepEqual(extractArchive(BASIC, t.dir), {
    ok: true, entries: 3, total_bytes: 14, files: [
      { path: 'docs/readme.txt', size: 6, sha256: '5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03' },
      { path: 'data.csv', size: 8, sha256: '492d5ea496056f1a6a6592241032fab764c321596317930b4fa0e1e8bc3b7470' },
    ],
  });
  assert.equal(fs.readFileSync(path.join(t.dir, 'docs/readme.txt'), 'utf8'), 'hello\n');
  assert.equal(fs.readFileSync(path.join(t.dir, 'data.csv'), 'utf8'), 'a,b\n1,2\n');
  assert.ok(fs.lstatSync(path.join(t.dir, 'docs')).isDirectory());
  assert.equal(fs.statSync(path.join(t.dir, 'data.csv')).mode & 0o777, 0o644);
  assert.deepEqual(fs.readdirSync(t.parent), ['out']);
  assert.deepEqual(inspectArchive(BASIC), { ok: true, entries: 3, total_bytes: 14, files: [{ path: 'docs/readme.txt', size: 6 }, { path: 'data.csv', size: 8 }] });
});

/**
 * ARCHIVE-02: zip slip and malformed names are 400 unsafe_path with the entry index; nothing is written.
 * In: the spec's vectors and fakes. Out: assertions only. Why: ARCHIVE-02 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary files under the OS temp directory, removed afterwards.
 */
// ARCHIVE-02
test('ARCHIVE-02 zip slip and malformed names are 400 unsafe_path with the entry index; nothing is written', () => {
  const names: (string | Buffer)[] = ['../evil.txt', 'a/../../evil.txt', '/etc/passwd.txt', 'C:/x.txt', 'a\\b.txt', 'a//b.txt',
    './a.txt', 'a\u0000b.txt', 'a\u0001b.txt', 'a\u001fb.txt', 'a\u007fb.txt', 'a/./b.txt', 'a/..',
    Buffer.from('61c0af622e747874', 'hex'), Buffer.from('61eda0802e747874', 'hex'),
    Buffer.from('61f49080802e747874', 'hex'), Buffer.from('61e2822e747874', 'hex')];
  for (const name of names) {
    assertRefused(buildZip([{ name: 'ok.txt', data: 'x' }, { name, data: 'evil' }]), 'unsafe_path', 400, 1);
  }
  assertRefused(buildZip([{ name: '', data: 'x' }]), 'unsafe_path', 400, 0);
});

/**
 * ARCHIVE-03: a symlink (any creator) and a FIFO are 400 special_file; a regular file mode is accepted.
 * In: the spec's vectors and fakes. Out: assertions only. Why: ARCHIVE-03 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary files under the OS temp directory, removed afterwards.
 */
// ARCHIVE-03
test('ARCHIVE-03 a symlink (any creator) and a FIFO are 400 special_file; a regular file mode is accepted', () => {
  for (const creator of [0, 3, 19]) {
    assertRefused(buildZip([{ name: 'link.txt', data: '/etc/passwd', external: 0xa1ff0000, creator }]), 'special_file', 400, 0);
  }
  assertRefused(buildZip([{ name: 'ok.txt', data: 'x' }, { name: 'fifo.txt', external: 0x11a40000, creator: 3 }]), 'special_file', 400, 1);
  assertExtracted(buildZip([{ name: 'a.txt', data: 'x', external: 0x81a40000, creator: 3 }]));
});

/**
 * ARCHIVE-04: max_entries and max_archive_bytes: over is 413, exactly at the limit is accepted.
 * In: the spec's vectors and fakes. Out: assertions only. Why: ARCHIVE-04 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary files under the OS temp directory, removed afterwards.
 */
// ARCHIVE-04
test('ARCHIVE-04 max_entries and max_archive_bytes: over is 413, exactly at the limit is accepted', () => {
  const three = buildZip([{ name: 'a.txt', data: 'x' }, { name: 'b.txt', data: 'x' }, { name: 'c.txt', data: 'x' }]);
  assert.equal(three.length, 283);
  assertExtracted(three, { max_entries: 3, max_archive_bytes: 283 });
  assertRefused(three, 'too_many_entries', 413, -1, { max_entries: 2 });
  assertRefused(three, 'archive_too_large', 413, -1, { max_archive_bytes: 282 });
});

/**
 * ARCHIVE-05: total and per-entry sizes: over is 413, at the limit accepted, 0x80000000 read unsigned.
 * In: the spec's vectors and fakes. Out: assertions only. Why: ARCHIVE-05 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary files under the OS temp directory, removed afterwards.
 */
// ARCHIVE-05
test('ARCHIVE-05 total and per-entry sizes: over is 413, at the limit accepted, 0x80000000 read unsigned', () => {
  const two = buildZip([{ name: 'a.txt', data: '12345' }, { name: 'b.txt', data: '67890' }]);
  assert.equal(two.length, 204);
  assertExtracted(two, { max_total_bytes: 10, max_file_bytes: 5 });
  assertRefused(two, 'total_too_large', 413, 1, { max_total_bytes: 9 });
  assertRefused(two, 'entry_too_large', 413, 0, { max_file_bytes: 4 });
  const huge = buildZip([{ name: 'a.txt', data: Z, method: 8, usize: 0x80000000, crc: 0 }]);
  assertRefused(huge, 'entry_too_large', 413, 0);
  assertRefused(huge, 'compression_ratio_exceeded', 413, -1, { max_file_bytes: 4294967296, max_total_bytes: 4294967296 });
});

/**
 * ARCHIVE-06: compression ratio: ZEROS is 413 with max_ratio 15 and extracted with max_ratio 16.
 * In: the spec's vectors and fakes. Out: assertions only. Why: ARCHIVE-06 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary files under the OS temp directory, removed afterwards.
 */
// ARCHIVE-06
test('ARCHIVE-06 compression ratio: ZEROS is 413 with max_ratio 15 and extracted with max_ratio 16', () => {
  assert.equal(ZEROS.length, 133);
  assertRefused(ZEROS, 'compression_ratio_exceeded', 413, -1, { max_ratio: 15 });
  const out = assertExtracted(ZEROS, { max_ratio: 16 });
  assert.deepEqual(fs.readFileSync(path.join(out.dir, 'zeros.txt')), Buffer.alloc(2000));
  assert.equal(out.files[0].size, 2000);
});

/**
 * ARCHIVE-07: lying headers and bad streams are 400 corrupt_entry; unequal stored sizes 400 size_mismatch.
 * In: the spec's vectors and fakes. Out: assertions only. Why: ARCHIVE-07 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary files under the OS temp directory, removed afterwards.
 */
// ARCHIVE-07
test('ARCHIVE-07 lying headers and bad streams are 400 corrupt_entry; unequal stored sizes 400 size_mismatch', () => {
  const corrupt: BuildEntry[] = [
    { name: 'zeros.txt', data: Z, method: 8, usize: 10, crc: 0xe38a6876 },
    { name: 'zeros.txt', data: Z, method: 8, usize: 3000, crc: 0x02c9f444 },
    { name: 'zeros.txt', data: Z.subarray(0, Z.length - 4), method: 8, usize: 2000, crc: 0x02c9f444 },
    { name: 'zeros.txt', data: Z, method: 8, usize: 2000, crc: 1 },
    { name: 'a.txt', data: '12345', crc: 0 },
    { name: 'zeros.txt', data: Buffer.from('ffffffff', 'hex'), method: 8, usize: 4, crc: 0 },
    { name: 'zeros.txt', data: BAD, method: 8, usize: 10, crc: 0xe38a6876 },
  ];
  for (const entry of corrupt) {
    const t = target();
    assert.deepEqual(extractArchive(buildZip([entry]), t.dir), { error: 'corrupt_entry', status: 400, entry_index: 0 });
    assert.deepEqual(fs.readdirSync(t.parent), []);
  }
  assertRefused(buildZip([{ name: 'a.txt', data: '12345', usize: 4 }]), 'size_mismatch', 400, 0);
});

/**
 * ARCHIVE-08: extensions: the default list refuses run.exe, a.txt.sh, README, .env, inner.zip.
 * In: the spec's vectors and fakes. Out: assertions only. Why: ARCHIVE-08 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary files under the OS temp directory, removed afterwards.
 */
// ARCHIVE-08
test('ARCHIVE-08 extensions: the default list refuses run.exe, a.txt.sh, README, .env, inner.zip', () => {
  for (const name of ['run.exe', 'a.txt.sh', 'README', '.env', 'inner.zip']) {
    assertRefused(buildZip([{ name, data: 'x' }]), 'extension_not_allowed', 400, 0);
  }
  assertExtracted(buildZip([{ name: 'A.TXT', data: 'x' }, { name: 'x.Json', data: '{}' }]));
  assertExtracted(buildZip([{ name: 'README', data: 'x' }, { name: 'a.sh', data: 'echo' }]), { allowed_extensions: ['', 'sh'] });
});

/**
 * ARCHIVE-09: duplicate names (case, file under file, directory vs file) are 400 duplicate_name index 1.
 * In: the spec's vectors and fakes. Out: assertions only. Why: ARCHIVE-09 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary files under the OS temp directory, removed afterwards.
 */
// ARCHIVE-09
test('ARCHIVE-09 duplicate names (case, file under file, directory vs file) are 400 duplicate_name index 1', () => {
  const pairs: [string, string][] = [['a.txt', 'a.txt'], ['A.txt', 'a.txt'], ['d.txt/', 'd.txt'], ['d.txt', 'd.txt/'],
    ['d.txt', 'd.txt/e.txt'], ['d.txt/e.txt', 'd.txt']];
  for (const [first, second] of pairs) {
    assertRefused(buildZip([{ name: first, data: first.endsWith('/') ? '' : 'x' }, { name: second, data: second.endsWith('/') ? '' : 'y' }]),
      'duplicate_name', 400, 1);
  }
  assertExtracted(buildZip([{ name: 'd/' }, { name: 'd/' }, { name: 'd/a.txt', data: 'x' }]));
});

/**
 * ARCHIVE-10: container faults: empty, not a zip, truncated, bad counts, trailing byte, zip64, disk, comment.
 * In: the spec's vectors and fakes. Out: assertions only. Why: ARCHIVE-10 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary files under the OS temp directory, removed afterwards.
 */
// ARCHIVE-10
test('ARCHIVE-10 container faults: empty, not a zip, truncated, bad counts, trailing byte, zip64, disk, comment', () => {
  assertRefused(Buffer.alloc(0), 'empty_upload', 400, -1);
  assertRefused(Buffer.from('just some text, not a zip'), 'not_a_zip', 400, -1);
  assertRefused(BASIC.subarray(0, BASIC.length - 10), 'not_a_zip', 400, -1);
  const counts = Buffer.from(BASIC);
  counts.writeUInt16LE(4, counts.length - 14);
  counts.writeUInt16LE(4, counts.length - 12);
  assertRefused(counts, 'not_a_zip', 400, -1);
  assertRefused(Buffer.concat([BASIC, Buffer.from([0])]), 'not_a_zip', 400, -1);
  const diskNo = Buffer.from(BASIC);
  diskNo.writeUInt16LE(1, diskNo.length - 18);
  assertRefused(diskNo, 'unsupported_zip', 400, -1);
  const zip64 = Buffer.from(BASIC);
  zip64.writeUInt16LE(0xffff, zip64.length - 14);
  zip64.writeUInt16LE(0xffff, zip64.length - 12);
  assertRefused(zip64, 'unsupported_zip', 400, -1);
  const wrap = Buffer.from(BASIC);
  wrap.writeUInt32LE(300, wrap.length - 10);
  wrap.writeUInt32LE(0xfffffffe, wrap.length - 6);
  assertRefused(wrap, 'not_a_zip', 400, -1);
  assertRefused(buildZip([{ name: 'docs/' }]), 'empty_archive', 400, -1);
  const tiny = Buffer.from('504b0304504b0506000000000000000000000000040000001000504b0607787878787878787878787878', 'hex');
  assert.equal(tiny.length, 42);
  assertRefused(tiny, 'empty_archive', 400, -1);
  const commented = buildZip(BASIC_ENTRIES, 'c'.repeat(40));
  assert.equal(commented.length, 360);
  assertExtracted(commented);
});

/**
 * ARCHIVE-11: encryption flags 400 encrypted_entry; methods other than 0 and 8 refused; flag bit 3 accepted.
 * In: the spec's vectors and fakes. Out: assertions only. Why: ARCHIVE-11 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary files under the OS temp directory, removed afterwards.
 */
// ARCHIVE-11
test('ARCHIVE-11 encryption flags 400 encrypted_entry; methods other than 0 and 8 refused; flag bit 3 accepted', () => {
  assertRefused(buildZip([{ name: 'a.txt', data: '12345', flags: 1 }]), 'encrypted_entry', 400, 0);
  assertRefused(buildZip([{ name: 'ok.txt', data: 'x' }, { name: 'a.txt', data: '12345', flags: 0x40 }]), 'encrypted_entry', 400, 1);
  assertRefused(buildZip([{ name: 'a.txt', data: '12345', flags: 0x2000 }]), 'encrypted_entry', 400, 0);
  assertRefused(buildZip([{ name: 'a.txt', data: '12345', method: 12 }]), 'unsupported_compression', 400, 0);
  const out = assertExtracted(buildZip([{ name: 'a.txt', data: '12345', flags: 8 }]));
  assert.equal(fs.readFileSync(path.join(out.dir, 'a.txt'), 'utf8'), '12345');
});

/**
 * ARCHIVE-12: local name mismatch and a Unicode Path naming ../evil.txt are header_mismatch; overrun extra not_a_zip.
 * In: the spec's vectors and fakes. Out: assertions only. Why: ARCHIVE-12 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary files under the OS temp directory, removed afterwards.
 */
// ARCHIVE-12
test('ARCHIVE-12 local name mismatch and a Unicode Path naming ../evil.txt are header_mismatch; overrun extra not_a_zip', () => {
  assertRefused(buildZip([{ name: 'a.txt', data: 'y' }, { name: 'ok.txt', data: 'x', local_name: 'no.txt' }]), 'header_mismatch', 400, 1);
  const crcOk = crc32(Buffer.from('ok.txt'));
  const evil = Buffer.from('75701000012a0419052e2e2f6576696c2e747874', 'hex');
  assert.equal(evil.readUInt32LE(5), crcOk);
  assertRefused(buildZip([{ name: 'ok.txt', data: 'x', extra: evil }]), 'header_mismatch', 400, 0);
  const same = Buffer.alloc(9);
  same.writeUInt16LE(0x7075, 0); same.writeUInt16LE(11, 2); same[4] = 1; same.writeUInt32LE(crcOk, 5);
  assertExtracted(buildZip([{ name: 'ok.txt', data: 'x', extra: Buffer.concat([same, Buffer.from('ok.txt')]) }]));
  assertRefused(buildZip([{ name: 'ok.txt', data: 'x', extra: Buffer.from('0a0032006162', 'hex') }]), 'not_a_zip', 400, 0);
  assertRefused(buildZip([{ name: 'ok.txt', data: 'x', extra: Buffer.from('0a00', 'hex') }]), 'not_a_zip', 400, 0);
  assertRefused(buildZip([{ name: 'ok.txt', data: 'x', extra: Buffer.from('7570030001aaaa', 'hex') }]), 'not_a_zip', 400, 0);
});

/**
 * ARCHIVE-13: all or nothing: a corrupt second entry leaves no target and no staging; existing target 409; no parent 500.
 * In: the spec's vectors and fakes. Out: assertions only. Why: ARCHIVE-13 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary files under the OS temp directory, removed afterwards.
 */
// ARCHIVE-13
test('ARCHIVE-13 all or nothing: a corrupt second entry leaves no target and no staging; existing target 409; no parent 500', () => {
  const t = target();
  const out = extractArchive(buildZip([{ name: 'a.txt', data: 'fine' }, { name: 'b.txt', data: 'oops', crc: 7 }]), t.dir);
  assert.deepEqual(out, { error: 'corrupt_entry', status: 400, entry_index: 1 });
  assert.equal(fs.existsSync(t.dir), false);
  assert.deepEqual(fs.readdirSync(t.parent), []);

  const e = target();
  fs.mkdirSync(e.dir);
  fs.writeFileSync(path.join(e.dir, 'keep.txt'), 'mine');
  assert.deepEqual(extractArchive(BASIC, e.dir), { error: 'target_exists', status: 409, entry_index: -1 });
  assert.deepEqual(fs.readdirSync(e.dir), ['keep.txt']);
  assert.equal(fs.readFileSync(path.join(e.dir, 'keep.txt'), 'utf8'), 'mine');
  const f = target();
  fs.writeFileSync(f.dir, 'a file');
  assert.deepEqual(extractArchive(BASIC, f.dir), { error: 'target_exists', status: 409, entry_index: -1 });
  const l = target();
  fs.symlinkSync(path.join(l.parent, 'nowhere'), l.dir);
  assert.deepEqual(extractArchive(BASIC, l.dir), { error: 'target_exists', status: 409, entry_index: -1 });

  const m = target();
  assert.deepEqual(extractArchive(BASIC, path.join(m.parent, 'missing', 'out')), { error: 'target_unwritable', status: 500, entry_index: -1 });
  assert.deepEqual(fs.readdirSync(m.parent), []);
});

/**
 * ARCHIVE-14: names that do not unpack everywhere are 400 bad_name; accented names accepted; never executable.
 * In: the spec's vectors and fakes. Out: assertions only. Why: ARCHIVE-14 (Phase D wave 1, owner request
 * 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary files under the OS temp directory, removed afterwards.
 */
// ARCHIVE-14
test('ARCHIVE-14 names that do not unpack everywhere are 400 bad_name; accented names accepted; never executable', () => {
  const bad = ['CON.txt', 'com1.txt', 'COM0.txt', 'LPT0.txt', 'COM\u00b9.txt', 'CONIN$.txt', 'CONOUT$.txt', 'nul.tar.txt',
    'a.txt.', 'a.txt ', 'd./a.txt', 'a?.txt', 'a*.txt', 'ab:c.txt', 'a|b.txt', 'a"b.txt', 'a<b>.txt', 'x'.repeat(252) + '.txt',
    'evil\u202etxt.exe.txt', 'a\u200bb.txt', 'a\u0085.txt', '\ufeffa.txt', 'aux /b.txt'];
  for (const name of bad) assertRefused(buildZip([{ name, data: 'x' }]), 'bad_name', 400, 0);
  assertRefused(buildZip([{ name: 'd/' + 'x'.repeat(1020) + '.txt', data: 'x' }]), 'bad_name', 400, 0);
  for (const name of ['x'.repeat(251) + '.txt', 'caf\u00e9.txt', 'COM10.txt', 'conin.txt', 'console.txt']) {
    const out = assertExtracted(buildZip([{ name, data: 'x' }]));
    assert.ok(fs.existsSync(path.join(out.dir, name)));
  }
  const exe = assertExtracted(buildZip([{ name: 'run.txt', data: '#!/bin/sh\n', external: 0x81ed0000, creator: 3 }]));
  assert.equal(fs.statSync(path.join(exe.dir, 'run.txt')).mode & 0o777, 0o644);
});
