/**
 * Safe archive ingest (docs/specs/safe_archive_ingest.md): takes a .zip a user uploaded and unpacks it into a new
 * directory without trusting anything in it. The three zip record types are read here (never a zip library's
 * extract), every name, size, link, extension and duplicate check runs before any byte is inflated, the inflater is
 * capped at usize + 1 bytes, and the files are written into a staging directory that is renamed into place only when
 * every file was written (all or nothing).
 *
 * Exports: Limits and DEFAULT_LIMITS, inspectArchive, extractArchive, crc32.
 *
 * Why: Phase D wave 1, owner request 2026-11-10 (six new systems). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the file system under the target directory's parent (extractArchive only); nothing else. No network, no
 * database, no money.
 */
import { createHash, randomBytes } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as zlib from 'zlib';

/** The injected limits (spec LIMITS). */
export interface Limits {
  max_archive_bytes: number;
  max_entries: number;
  max_file_bytes: number;
  max_total_bytes: number;
  max_ratio: number;
  allowed_extensions: string[];
}

/** The spec's default limits. */
export const DEFAULT_LIMITS: Readonly<Limits> = Object.freeze({
  max_archive_bytes: 20971520,
  max_entries: 1000,
  max_file_bytes: 26214400,
  max_total_bytes: 104857600,
  max_ratio: 100,
  allowed_extensions: ['txt', 'md', 'csv', 'json', 'pdf', 'png', 'jpg', 'jpeg', 'gif'],
});

/** A refusal: the spec error code, the HTTP status, and the refused entry's index (-1 for the whole archive). */
export interface ArchiveRefusal {
  error: string;
  status: number;
  entry_index: number;
}

/** inspect_archive's answer. */
export interface InspectResult {
  ok: true;
  entries: number;
  total_bytes: number;
  files: { path: string; size: number }[];
}

/** extract_archive's answer. */
export interface ExtractResult {
  ok: true;
  entries: number;
  total_bytes: number;
  files: { path: string; size: number; sha256: string }[];
}

/** One central-directory entry, as read and checked. */
interface Entry {
  index: number;
  flags: number;
  method: number;
  crc: number;
  csize: number;
  usize: number;
  nameBytes: Buffer;
  name: string;
  parts: string[];
  isDir: boolean;
  localOffset: number;
  dataStart: number;
}

/** The archive after checks A, B and C. */
interface Checked {
  entries: Entry[];
  totalBytes: number;
}

/** Thrown inside the checks with the refusal to return; never escapes this module. */
class Refuse extends Error {
  constructor(readonly refusal: ArchiveRefusal) {
    super(refusal.error);
  }
}

/** Throws the refusal (error, status, entry_index). Touches nothing. */
function refuse(error: string, status: number, entryIndex = -1): never {
  throw new Refuse({ error, status, entry_index: entryIndex });
}

let CRC_TABLE: Uint32Array | null = null;

/**
 * CRC-32 (IEEE) of the bytes: node:zlib crc32 where the runtime has it (Node 22.2+), else a 256-entry table.
 * In: bytes. Out: the unsigned 32-bit CRC. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function crc32(data: Uint8Array): number {
  const native = (zlib as unknown as { crc32?: (d: Uint8Array) => number }).crc32;
  if (typeof native === 'function') return native(data) >>> 0;
  if (CRC_TABLE === null) {
    CRC_TABLE = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      CRC_TABLE[n] = c >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (const b of data) crc = CRC_TABLE[(crc ^ b) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

/** Strict UTF-8 decode (no replacement, BOM kept): the text, or null. Touches nothing. */
function strictUtf8(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
}

/** ASCII lower case: A-Z to a-z, nothing else. Touches nothing. */
function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}

/** The characters C5 refuses anywhere in a name (controls, bidi and invisible formatting characters). */
const BAD_NAME_CHARS = /[\u0080-\u009f؜​-‏‪-‮⁠-⁤⁦-⁩﻿]/;

/** Windows reserved device names (C5), compared with the text before the first "." in ASCII lower case. */
const RESERVED = new Set(['con', 'prn', 'aux', 'nul', 'conin$', 'conout$',
  ...Array.from({ length: 10 }, (_, i) => 'com' + i), ...Array.from({ length: 10 }, (_, i) => 'lpt' + i),
  ...['¹', '²', '³'].flatMap((s) => ['com' + s, 'lpt' + s])]);

/**
 * The EXTENSION of a file: the text after the last "." of its last part, in ASCII lower case; "" when the part has
 * no "." or its only "." is its first character. In: the last part. Out: the extension. Touches nothing.
 */
function extensionOf(part: string): string {
  const dot = part.lastIndexOf('.');
  return dot <= 0 ? '' : asciiLower(part.slice(dot + 1));
}

/**
 * Checks A, B and C (spec CHECKS) on the bytes, in order; the first that fails throws its Refuse.
 * In: the archive bytes, the limits. Out: the checked entries and the sum of usize. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function check(input: Uint8Array, limits: Limits): Checked {
  const buf = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  const len = buf.length;
  // A. The container
  if (len === 0) refuse('empty_upload', 400);
  if (len > limits.max_archive_bytes) refuse('archive_too_large', 413);
  if (len < 4 || buf.readUInt32LE(0) !== 0x04034b50) refuse('not_a_zip', 400);
  let end = -1;
  for (let i = len - 22; i >= Math.max(0, len - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50 && i + 22 + buf.readUInt16LE(i + 20) === len) {
      end = i;
      break;
    }
  }
  if (end < 0) refuse('not_a_zip', 400);
  const disk = buf.readUInt16LE(end + 4);
  const cdDisk = buf.readUInt16LE(end + 6);
  const entriesHere = buf.readUInt16LE(end + 8);
  const count = buf.readUInt16LE(end + 10);
  const cdSize = buf.readUInt32LE(end + 12);
  const cdOffset = buf.readUInt32LE(end + 16);
  if (disk !== 0 || cdDisk !== 0 || entriesHere !== count || count === 0xffff || cdSize === 0xffffffff ||
      cdOffset === 0xffffffff || (end >= 20 && buf.readUInt32LE(end - 20) === 0x07064b50)) {
    refuse('unsupported_zip', 400);
  }
  if (cdOffset + cdSize !== end) refuse('not_a_zip', 400);
  if (count === 0) refuse('empty_archive', 400);
  if (count > limits.max_entries) refuse('too_many_entries', 413);

  // B. The central directory
  const raw: { p: number; nameLen: number; extraLen: number }[] = [];
  let p = cdOffset;
  for (let k = 0; k < count; k++) {
    if (p + 46 > end || buf.readUInt32LE(p) !== 0x02014b50) refuse('not_a_zip', 400);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    if (p + 46 + nameLen + extraLen + commentLen > end) refuse('not_a_zip', 400);
    raw.push({ p, nameLen, extraLen });
    p += 46 + nameLen + extraLen + commentLen;
  }
  if (p !== end) refuse('not_a_zip', 400);

  // C. Each entry
  const entries: Entry[] = [];
  const fileKeys = new Set<string>();
  const dirKeys = new Set<string>();
  const allowed = new Set(limits.allowed_extensions);
  let total = 0;
  raw.forEach(({ p: q, nameLen, extraLen }, index) => {
    const flags = buf.readUInt16LE(q + 8);
    const method = buf.readUInt16LE(q + 10);
    const crc = buf.readUInt32LE(q + 16);
    const csize = buf.readUInt32LE(q + 20);
    const usize = buf.readUInt32LE(q + 24);
    const diskStart = buf.readUInt16LE(q + 34);
    const external = buf.readUInt32LE(q + 38);
    const localOffset = buf.readUInt32LE(q + 42);
    const nameBytes = Buffer.from(buf.subarray(q + 46, q + 46 + nameLen));
    const extra = buf.subarray(q + 46 + nameLen, q + 46 + nameLen + extraLen);
    // C1
    if (csize === 0xffffffff || usize === 0xffffffff || localOffset === 0xffffffff || diskStart !== 0) refuse('unsupported_zip', 400, index);
    // C2
    if (flags & 0x2041) refuse('encrypted_entry', 400, index);
    // C3
    if (method !== 0 && method !== 8) refuse('unsupported_compression', 400, index);
    // C4
    const name = nameBytes.length ? strictUtf8(nameBytes) : null;
    if (name === null || name === '') refuse('unsafe_path', 400, index);
    for (const b of nameBytes) if (b < 0x20 || b === 0x7f || b === 0x5c) refuse('unsafe_path', 400, index);
    if (name.startsWith('/') || /^[A-Za-z]:/.test(name)) refuse('unsafe_path', 400, index);
    const isDir = name.endsWith('/');
    const parts = (isDir ? name.slice(0, -1) : name).split('/');
    if (parts.some((part) => part === '' || part === '.' || part === '..')) refuse('unsafe_path', 400, index);
    // C5
    if (nameBytes.length > 1024 || BAD_NAME_CHARS.test(name)) refuse('bad_name', 400, index);
    for (const part of parts) {
      const stem = asciiLower(part.split('.')[0]).replace(/ +$/, '');
      if (Buffer.byteLength(part, 'utf8') > 255 || /[:*?"<>|]/.test(part) || part.endsWith('.') || part.endsWith(' ') ||
          RESERVED.has(stem)) {
        refuse('bad_name', 400, index);
      }
    }
    // C6
    const unicodePaths: Buffer[] = [];
    let e = 0;
    while (e < extra.length) {
      if (extra.length - e < 4) refuse('not_a_zip', 400, index);
      const id = extra.readUInt16LE(e);
      const size = extra.readUInt16LE(e + 2);
      if (e + 4 + size > extra.length) refuse('not_a_zip', 400, index);
      if (id === 0x7075) {
        if (size < 5) refuse('not_a_zip', 400, index);
        if (extra[e + 4] === 1) unicodePaths.push(Buffer.from(extra.subarray(e + 9, e + 4 + size)));
      }
      e += 4 + size;
    }
    if (unicodePaths.some((u) => !u.equals(nameBytes))) refuse('header_mismatch', 400, index);
    // C7
    const type = (external >>> 16) & 0xf000;
    if (type !== 0 && type !== 0x8000 && type !== 0x4000) refuse('special_file', 400, index);
    // C8
    if ((isDir && usize !== 0) || (!isDir && method === 0 && csize !== usize)) refuse('size_mismatch', 400, index);
    // C9
    if (!isDir && !allowed.has(extensionOf(parts[parts.length - 1]))) refuse('extension_not_allowed', 400, index);
    // C10
    const key = asciiLower(parts.join('/'));
    const prefixes: string[] = [];
    for (let i = key.indexOf('/'); i >= 0; i = key.indexOf('/', i + 1)) prefixes.push(key.slice(0, i));
    if (fileKeys.has(key) || prefixes.some((pre) => fileKeys.has(pre)) || (!isDir && dirKeys.has(key))) {
      refuse('duplicate_name', 400, index);
    }
    (isDir ? dirKeys : fileKeys).add(key);
    for (const pre of prefixes) dirKeys.add(pre);
    // C11, C12
    if (usize > limits.max_file_bytes) refuse('entry_too_large', 413, index);
    total += usize;
    if (total > limits.max_total_bytes) refuse('total_too_large', 413, index);
    entries.push({ index, flags, method, crc, csize, usize, nameBytes, name, parts, isDir, localOffset, dataStart: 0 });
  });
  // C13, C14
  if (!entries.some((en) => !en.isDir)) refuse('empty_archive', 400);
  if (total > limits.max_ratio * len) refuse('compression_ratio_exceeded', 413);
  // C15
  for (const en of entries) {
    const o = en.localOffset;
    if (o + 30 > cdOffset || buf.readUInt32LE(o) !== 0x04034b50) refuse('not_a_zip', 400, en.index);
    const lFlags = buf.readUInt16LE(o + 6);
    const lMethod = buf.readUInt16LE(o + 8);
    const lCrc = buf.readUInt32LE(o + 14);
    const lCsize = buf.readUInt32LE(o + 18);
    const lUsize = buf.readUInt32LE(o + 22);
    const lNameLen = buf.readUInt16LE(o + 26);
    const lExtraLen = buf.readUInt16LE(o + 28);
    if (o + 30 + lNameLen + lExtraLen + en.csize > cdOffset) refuse('not_a_zip', 400, en.index);
    const lName = buf.subarray(o + 30, o + 30 + lNameLen);
    if (!lName.equals(en.nameBytes) || lFlags !== en.flags || lMethod !== en.method ||
        ((en.flags & 8) === 0 && (lCrc !== en.crc || lCsize !== en.csize || lUsize !== en.usize))) {
      refuse('header_mismatch', 400, en.index);
    }
    en.dataStart = o + 30 + lNameLen + lExtraLen;
  }
  return { entries, totalBytes: total };
}

/** The limits with the defaults filled in. Touches nothing. */
function withDefaults(limits?: Partial<Limits>): Limits {
  return { ...DEFAULT_LIMITS, ...(limits ?? {}), allowed_extensions: [...(limits?.allowed_extensions ?? DEFAULT_LIMITS.allowed_extensions)] };
}

/**
 * Runs checks A, B and C; reads no file data and writes nothing. In: the archive bytes, the limits (defaults filled
 * in). Out: {ok: true, entries, total_bytes, files: [{path, size}]} or {error, status, entry_index}. Never throws.
 * Why: spec inspect_archive (ARCHIVE-02..12, 14). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function inspectArchive(bytes: Uint8Array, limits?: Partial<Limits>): InspectResult | ArchiveRefusal {
  try {
    const c = check(bytes, withDefaults(limits));
    return {
      ok: true, entries: c.entries.length, total_bytes: c.totalBytes,
      files: c.entries.filter((e) => !e.isDir).map((e) => ({ path: e.name, size: e.usize })),
    };
  } catch (err) {
    if (err instanceof Refuse) return err.refusal;
    return { error: 'not_a_zip', status: 400, entry_index: -1 };
  }
}

/**
 * D3's data step for one file entry: method 0 as stored, method 8 inflated as raw DEFLATE asking for at most
 * usize + 1 bytes (Z_SYNC_FLUSH, so input that runs out gives fewer bytes). Any fault (invalid data, more or fewer
 * than usize bytes, a CRC that differs) is the one answer corrupt_entry. In: the archive, the entry. Out: the bytes.
 * Throws Refuse. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function entryData(buf: Buffer, en: Entry): Buffer {
  const data = buf.subarray(en.dataStart, en.dataStart + en.csize);
  let out: Buffer;
  if (en.method === 0) {
    out = Buffer.from(data);
  } else {
    try {
      out = zlib.inflateRawSync(data, { maxOutputLength: en.usize + 1, finishFlush: zlib.constants.Z_SYNC_FLUSH });
    } catch {
      refuse('corrupt_entry', 400, en.index);
    }
  }
  if (out.length !== en.usize || crc32(out) !== en.crc) refuse('corrupt_entry', 400, en.index);
  return out;
}

/**
 * Checks A, B and C (the same answers as inspectArchive), then D: target_dir must not exist (409 target_exists,
 * tested with lstat, so a dangling link counts); a staging directory target_dir + ".partial-" + 16 random hex
 * characters is made with mode 0700 (500 target_unwritable); every entry is written there in directory order
 * (directories 0755, files 0644 with exclusive create, never a link, never executable; corrupt data 400
 * corrupt_entry; an existing file 400 duplicate_name; an I/O error 500 target_unwritable); then the staging
 * directory is renamed to target_dir. Any refusal or error in D2-D4 removes the staging directory first. An I/O
 * error while an entry is written (D3) names that entry's index; one in D2 or D4 names -1.
 * In: the archive bytes, the target directory (from the server, never the upload), the limits. Out: {ok: true,
 * entries, total_bytes, files: [{path, size, sha256}]} or {error, status, entry_index}. Never throws.
 * Why: spec extract_archive (ARCHIVE-01, 06, 07, 13, 14). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the file system (target_dir and its staging directory only).
 */
export function extractArchive(bytes: Uint8Array, targetDir: string, limits?: Partial<Limits>): ExtractResult | ArchiveRefusal {
  let checked: Checked;
  try {
    checked = check(bytes, withDefaults(limits));
  } catch (err) {
    if (err instanceof Refuse) return err.refusal;
    return { error: 'not_a_zip', status: 400, entry_index: -1 };
  }
  const buf = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // D1
  try {
    fs.lstatSync(targetDir);
    return { error: 'target_exists', status: 409, entry_index: -1 };
  } catch (err: any) {
    if (err?.code !== 'ENOENT') return { error: 'target_unwritable', status: 500, entry_index: -1 };
  }
  // D2
  const staging = targetDir + '.partial-' + randomBytes(8).toString('hex');
  try {
    fs.mkdirSync(staging, { mode: 0o700 });
    fs.chmodSync(staging, 0o700);
  } catch {
    return { error: 'target_unwritable', status: 500, entry_index: -1 };
  }
  const files: { path: string; size: number; sha256: string }[] = [];
  let current = -1; // the entry being written: an I/O error in D3 names it, one in D4 names none
  try {
    const root = path.resolve(staging);
    for (const en of checked.entries) {
      current = en.index;
      // D3
      const dest = path.resolve(path.join(staging, ...en.parts));
      if (!dest.startsWith(root + path.sep)) refuse('unsafe_path', 400, en.index);
      if (en.isDir) {
        fs.mkdirSync(dest, { recursive: true, mode: 0o755 });
        continue;
      }
      const out = entryData(buf, en);
      fs.mkdirSync(path.dirname(dest), { recursive: true, mode: 0o755 });
      try {
        fs.writeFileSync(dest, out, { flag: 'wx', mode: 0o644 });
      } catch (err: any) {
        if (err?.code === 'EEXIST') refuse('duplicate_name', 400, en.index);
        throw err;
      }
      fs.chmodSync(dest, 0o644);
      files.push({ path: en.name, size: out.length, sha256: createHash('sha256').update(out).digest('hex') });
    }
    // D4
    current = -1;
    fs.renameSync(staging, targetDir);
  } catch (err) {
    fs.rmSync(staging, { recursive: true, force: true });
    if (err instanceof Refuse) return err.refusal;
    return { error: 'target_unwritable', status: 500, entry_index: current };
  }
  return { ok: true, entries: checked.entries.length, total_bytes: checked.totalBytes, files };
}
