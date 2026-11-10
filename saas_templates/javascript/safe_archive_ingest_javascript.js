'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

/**
 * Safe archive ingest (docs/specs/safe_archive_ingest.md): take a .zip a user uploaded and unpack it into a new
 * directory without trusting anything in it. The END, CENTRAL and LOCAL records are read by hand (no zip library
 * chooses a name), every name, link, size, ratio, extension and duplicate is checked before any byte is written,
 * data is inflated with node:zlib under a hard output cap, and the files are written into a private staging
 * directory that is renamed into place only when every file was written (all or nothing).
 *
 * Why: Phase D wave 1, owner request 2026-11-10 (ARCHIVE-01..ARCHIVE-14).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files (creates target_dir and its staging directory under the caller's storage root, removes the
 * staging directory on any refusal). No database, network or money. A refusal names an entry index, never the
 * entry's name.
 */

const DEFAULT_LIMITS = Object.freeze({
  max_archive_bytes: 20971520,
  max_entries: 1000,
  max_file_bytes: 26214400,
  max_total_bytes: 104857600,
  max_ratio: 100,
  allowed_extensions: ['txt', 'md', 'csv', 'json', 'pdf', 'png', 'jpg', 'jpeg', 'gif']
});
const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_END = 0x06054b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;
const U32_MAX = 0xffffffff;

/**
 * A refusal {error, status, entry_index}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function refuse(error, status, entryIndex = -1) {
  return { error, status, entry_index: entryIndex };
}

/**
 * ASCII lower case (A-Z only). In: string. Out: string. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function asciiLower(s) {
  return s.replace(/[A-Z]/g, c => c.toLowerCase());
}

/**
 * The parts of a name: one trailing "/" removed, then split at "/". In: name. Out: [part].
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function nameParts(name) {
  return (name.endsWith('/') ? name.slice(0, -1) : name).split('/');
}

/**
 * C4: the raw name bytes give a safe relative path. In: name bytes. Out: the decoded name, or null (unsafe_path).
 * Why: ARCHIVE-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function safeName(bytes) {
  if (bytes.length === 0) return null;
  let name;
  try {
    name = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch (err) {
    return null;
  }
  for (const b of bytes) if (b < 0x20 || b === 0x7f || b === 0x5c) return null;
  if (name.startsWith('/')) return null;
  if (/^[A-Za-z]:/.test(name)) return null;
  for (const part of nameParts(name)) if (part === '' || part === '.' || part === '..') return null;
  return name;
}

const BAD_CHARS = /[\u0080-\u009f؜​-‏‪-‮⁠-⁤⁦-⁩﻿]/;
const RESERVED = /^(?:con|prn|aux|nul|conin\$|conout\$|com[0-9¹²³]|lpt[0-9¹²³])$/;

/**
 * C5: a name every file system can hold (length, invisible and bidi characters, Windows-reserved characters and
 * device names, trailing dot or space). In: decoded name. Out: bool (false = bad_name). Why: ARCHIVE-14.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function portableName(name) {
  if (Buffer.byteLength(name, 'utf8') > 1024 || BAD_CHARS.test(name)) return false;
  for (const part of nameParts(name)) {
    if (Buffer.byteLength(part, 'utf8') > 255) return false;
    if (/[:*?"<>|]/.test(part)) return false;
    if (part.endsWith('.') || part.endsWith(' ')) return false;
    const dot = part.indexOf('.');
    const stem = asciiLower(dot === -1 ? part : part.slice(0, dot)).replace(/ +$/, '');
    if (RESERVED.test(stem)) return false;
  }
  return true;
}

/**
 * EXTENSION of a file: its last part's text after the last ".", ASCII lower case; "" when the part has no "." or
 * only a leading one. In: name. Out: string. Why: ARCHIVE-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches nothing.
 */
function extensionOf(name) {
  const parts = nameParts(name);
  const last = parts[parts.length - 1];
  const dot = last.lastIndexOf('.');
  if (dot <= 0) return '';
  return asciiLower(last.slice(dot + 1));
}

/**
 * C6: walks the extra field. Out: null when fine, else "not_a_zip" or "header_mismatch" (a version-1 Unicode Path
 * block naming something else). In: extra bytes, the name bytes. Why: ARCHIVE-12.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function checkExtra(extra, nameBytes) {
  let pos = 0;
  while (pos < extra.length) {
    if (extra.length - pos < 4) return 'not_a_zip';
    const id = extra.readUInt16LE(pos);
    const size = extra.readUInt16LE(pos + 2);
    if (pos + 4 + size > extra.length) return 'not_a_zip';
    if (id === 0x7075) {
      if (size < 5) return 'not_a_zip';
      const block = extra.subarray(pos + 4, pos + 4 + size);
      if (block[0] === 1 && !block.subarray(5).equals(nameBytes)) return 'header_mismatch';
    }
    pos += 4 + size;
  }
  return null;
}

/**
 * Checks A, B and C (shared by inspect and extract). In: bytes, limits. Out: {ok: true, entries: [entry],
 * total, cdOffset} or a refusal. Each entry: {index, name, isDir, method, crc, csize, usize, dataStart}.
 * Why: ARCHIVE-02..ARCHIVE-12, ARCHIVE-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function check(input, limits) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input || []);
  const len = buf.length;
  // A. The container.
  if (len === 0) return refuse('empty_upload', 400);
  if (len > limits.max_archive_bytes) return refuse('archive_too_large', 413);
  if (len < 4 || buf.readUInt32LE(0) !== SIG_LOCAL) return refuse('not_a_zip', 400);
  let end = -1;
  for (let i = len - 22; i >= Math.max(0, len - 65557); i--) {
    if (buf.readUInt32LE(i) === SIG_END && i + 22 + buf.readUInt16LE(i + 20) === len) { end = i; break; }
  }
  if (end < 0) return refuse('not_a_zip', 400);
  const disk = buf.readUInt16LE(end + 4);
  const cdDisk = buf.readUInt16LE(end + 6);
  const entriesHere = buf.readUInt16LE(end + 8);
  const count = buf.readUInt16LE(end + 10);
  const cdSize = buf.readUInt32LE(end + 12);
  const cdOffset = buf.readUInt32LE(end + 16);
  if (disk !== 0 || cdDisk !== 0 || entriesHere !== count || count === 0xffff || cdSize === U32_MAX ||
      cdOffset === U32_MAX || (end >= 20 && buf.readUInt32LE(end - 20) === SIG_ZIP64_LOCATOR)) {
    return refuse('unsupported_zip', 400);
  }
  if (cdOffset + cdSize !== end) return refuse('not_a_zip', 400);
  if (count === 0) return refuse('empty_archive', 400);
  if (count > limits.max_entries) return refuse('too_many_entries', 413);

  // B. The central directory.
  const records = [];
  let p = cdOffset;
  for (let k = 0; k < count; k++) {
    if (p + 46 > end || buf.readUInt32LE(p) !== SIG_CENTRAL) return refuse('not_a_zip', 400);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const next = p + 46 + nameLen + extraLen + commentLen;
    if (next > end) return refuse('not_a_zip', 400);
    records.push({
      flags: buf.readUInt16LE(p + 8), method: buf.readUInt16LE(p + 10), crc: buf.readUInt32LE(p + 16),
      csize: buf.readUInt32LE(p + 20), usize: buf.readUInt32LE(p + 24), diskStart: buf.readUInt16LE(p + 34),
      external: buf.readUInt32LE(p + 38), localOffset: buf.readUInt32LE(p + 42),
      nameBytes: buf.subarray(p + 46, p + 46 + nameLen), extra: buf.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen)
    });
    p = next;
  }
  if (p !== end) return refuse('not_a_zip', 400);

  // C. Each entry.
  const allowed = limits.allowed_extensions;
  const fileKeys = new Set();
  const dirKeys = new Set();
  const entries = [];
  let total = 0;
  let files = 0;
  for (let k = 0; k < records.length; k++) {
    const r = records[k];
    if (r.csize === U32_MAX || r.usize === U32_MAX || r.localOffset === U32_MAX || r.diskStart !== 0) return refuse('unsupported_zip', 400, k);
    if (r.flags & 0x2041) return refuse('encrypted_entry', 400, k);
    if (r.method !== 0 && r.method !== 8) return refuse('unsupported_compression', 400, k);
    const name = safeName(r.nameBytes);
    if (name === null) return refuse('unsafe_path', 400, k);
    if (!portableName(name)) return refuse('bad_name', 400, k);
    const extraFault = checkExtra(r.extra, r.nameBytes);
    if (extraFault) return refuse(extraFault, 400, k);
    const type = (r.external >>> 16) & 0xf000;
    if (type !== 0 && type !== 0x8000 && type !== 0x4000) return refuse('special_file', 400, k);
    const isDir = name.endsWith('/');
    if ((isDir && r.usize !== 0) || (!isDir && r.method === 0 && r.csize !== r.usize)) return refuse('size_mismatch', 400, k);
    if (!isDir && !allowed.includes(extensionOf(name))) return refuse('extension_not_allowed', 400, k);
    const key = asciiLower(isDir ? name.slice(0, -1) : name);
    let dup = fileKeys.has(key) || (!isDir && dirKeys.has(key));
    for (let s = key.indexOf('/'); !dup && s !== -1; s = key.indexOf('/', s + 1)) {
      if (fileKeys.has(key.slice(0, s))) dup = true;
    }
    if (dup) return refuse('duplicate_name', 400, k);
    if (r.usize > limits.max_file_bytes) return refuse('entry_too_large', 413, k);
    total += r.usize;
    if (total > limits.max_total_bytes) return refuse('total_too_large', 413, k);
    if (isDir) dirKeys.add(key); else { fileKeys.add(key); files++; }
    for (let s = key.indexOf('/'); s !== -1; s = key.indexOf('/', s + 1)) dirKeys.add(key.slice(0, s));
    entries.push({ index: k, name, isDir, method: r.method, flags: r.flags, crc: r.crc, csize: r.csize, usize: r.usize, record: r });
  }
  if (files === 0) return refuse('empty_archive', 400);
  if (total > limits.max_ratio * len) return refuse('compression_ratio_exceeded', 413);

  // C15. The local records.
  for (const e of entries) {
    const r = e.record;
    const lo = r.localOffset;
    if (lo + 30 > cdOffset || buf.readUInt32LE(lo) !== SIG_LOCAL) return refuse('not_a_zip', 400, e.index);
    const lNameLen = buf.readUInt16LE(lo + 26);
    const lExtraLen = buf.readUInt16LE(lo + 28);
    const dataStart = lo + 30 + lNameLen + lExtraLen;
    if (dataStart + r.csize > cdOffset) return refuse('not_a_zip', 400, e.index);
    const lFlags = buf.readUInt16LE(lo + 6);
    const lMethod = buf.readUInt16LE(lo + 8);
    if (!buf.subarray(lo + 30, lo + 30 + lNameLen).equals(r.nameBytes) || lFlags !== r.flags || lMethod !== r.method) {
      return refuse('header_mismatch', 400, e.index);
    }
    if (!(r.flags & 0x08) && (buf.readUInt32LE(lo + 14) !== r.crc || buf.readUInt32LE(lo + 18) !== r.csize ||
        buf.readUInt32LE(lo + 22) !== r.usize)) {
      return refuse('header_mismatch', 400, e.index);
    }
    e.dataStart = dataStart;
  }
  return { ok: true, buf, entries, total };
}

/**
 * The limits with the defaults filled in. In: partial limits. Out: limits.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function withDefaults(limits) {
  return { ...DEFAULT_LIMITS, ...(limits || {}) };
}

/**
 * inspect_archive(bytes, limits) -> {ok: true, entries, total_bytes, files: [{path, size}]} or a refusal. Runs
 * checks A, B and C; reads no file data and writes nothing. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches nothing.
 */
function inspectArchive(bytes, limits) {
  const c = check(bytes, withDefaults(limits));
  if (!c.ok) return c;
  return {
    ok: true, entries: c.entries.length, total_bytes: c.total,
    files: c.entries.filter(e => !e.isDir).map(e => ({ path: e.name, size: e.usize }))
  };
}

/**
 * One entry's bytes, checked: inflate (method 8) asking for at most usize + 1 bytes, then the size and CRC-32.
 * In: archive buffer, entry. Out: Buffer, or null (corrupt_entry). Why: ARCHIVE-06, ARCHIVE-07.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function readEntry(buf, e) {
  const data = buf.subarray(e.dataStart, e.dataStart + e.csize);
  let out;
  if (e.method === 0) {
    out = data;
  } else {
    try {
      out = zlib.inflateRawSync(data, { maxOutputLength: e.usize + 1, finishFlush: zlib.constants.Z_SYNC_FLUSH });
    } catch (err) {
      return null;
    }
  }
  if (out.length !== e.usize) return null;
  if ((zlib.crc32(out) >>> 0) !== e.crc) return null;
  return out;
}

/**
 * Writes every byte of data to the open file fd, calling fs.writeSync again after a short write, and throws when a
 * write makes no progress, so a short write can never pass as success.
 * In: an open file descriptor, a Buffer. Out: nothing (throws on an I/O error or a write of 0 bytes).
 * Why: review finding 4525344169: extractArchive made ONE fs.writeSync call and ignored its count, so a short write
 * (a nearly full disk) left a truncated file that was renamed into place and reported with the full size and
 * SHA-256. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the file behind fd.
 */
function writeWhole(fd, data) {
  let offset = 0;
  while (offset < data.length) {
    const written = fs.writeSync(fd, data, offset, data.length - offset);
    if (!(written > 0)) throw new Error('short_write');
    offset += written;
  }
}

/**
 * extract_archive(bytes, target_dir, limits) -> {ok: true, entries, total_bytes, files: [{path, size, sha256}]}
 * or a refusal. Checks A-C, then D: target must not exist (409), a 0700 staging directory beside it (500 when it
 * cannot be made), every entry written there (files exclusive-created, mode 0644), then one rename. Any refusal or
 * error after D2 removes the staging directory, so target_dir exists only when every file was written.
 * Why: ARCHIVE-01, ARCHIVE-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches files.
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (review finding 4525344169): each file is written whole
 * through writeWhole (it was one fs.writeSync whose short count was ignored).
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (same gap as review finding 4525344113): an I/O error while
 * an entry is written is 500 target_unwritable naming that entry's index, as the spec's CONVENTIONS say for D3; the
 * index goes back to -1 before the D4 rename (it was always -1).
 */
function extractArchive(bytes, targetDir, limits) {
  const c = check(bytes, withDefaults(limits));
  if (!c.ok) return c;
  try {
    fs.lstatSync(targetDir);
    return refuse('target_exists', 409);
  } catch (err) {
    if (err.code !== 'ENOENT') return refuse('target_unwritable', 500);
  }
  const staging = targetDir + '.partial-' + crypto.randomBytes(8).toString('hex');
  try {
    fs.mkdirSync(staging, { mode: 0o700 });
    fs.chmodSync(staging, 0o700);
  } catch (err) {
    return refuse('target_unwritable', 500);
  }
  const cleanup = () => { try { fs.rmSync(staging, { recursive: true, force: true }); } catch (e) { /* best effort */ } };
  let current = -1;
  try {
    const root = path.resolve(staging);
    const files = [];
    for (const e of c.entries) {
      current = e.index;
      const dest = path.resolve(path.join(staging, ...nameParts(e.name)));
      if (!dest.startsWith(root + path.sep)) { cleanup(); return refuse('unsafe_path', 400, e.index); }
      if (e.isDir) {
        fs.mkdirSync(dest, { recursive: true, mode: 0o755 });
        fs.chmodSync(dest, 0o755);
        continue;
      }
      const data = readEntry(c.buf, e);
      if (data === null) { cleanup(); return refuse('corrupt_entry', 400, e.index); }
      fs.mkdirSync(path.dirname(dest), { recursive: true, mode: 0o755 });
      let fd;
      try {
        fd = fs.openSync(dest, 'wx', 0o644);
      } catch (err) {
        cleanup();
        return err.code === 'EEXIST' ? refuse('duplicate_name', 400, e.index) : refuse('target_unwritable', 500, e.index);
      }
      try {
        fs.fchmodSync(fd, 0o644);
        writeWhole(fd, data);
      } finally {
        fs.closeSync(fd);
      }
      files.push({ path: e.name, size: data.length, sha256: crypto.createHash('sha256').update(data).digest('hex') });
    }
    current = -1;
    fs.renameSync(staging, targetDir);
    return { ok: true, entries: c.entries.length, total_bytes: c.total, files };
  } catch (err) {
    cleanup();
    return refuse('target_unwritable', 500, current);
  }
}

module.exports = { inspectArchive, extractArchive, DEFAULT_LIMITS, extensionOf };
