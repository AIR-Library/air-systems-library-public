"""Safe archive ingest (docs/specs/safe_archive_ingest.md): take an uploaded .zip and unpack it into a new
directory without trusting anything in it. The records are read by hand (no zip library chooses a name), every
name, link, size, ratio and checksum is checked, and either every file is written or none is.

Why: Phase D wave 1, owner request 2026-11-10 (ARCHIVE-01 to ARCHIVE-14). 2026-11-10,
session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files only, under the server-chosen target_dir (a staging directory
beside it while writing). No database, network or money. A refusal names an entry index, never the entry's name.

Inputs and outputs: inspect_archive(data, limits) and extract_archive(data, target_dir, limits); each returns
{ok: true, entries, total_bytes, files} or a refusal {error, status, entry_index}.
"""
import hashlib
import os
import secrets
import shutil
import struct
import zlib
from typing import List, Optional

DEFAULT_LIMITS = {
    "max_archive_bytes": 20971520,
    "max_entries": 1000,
    "max_file_bytes": 26214400,
    "max_total_bytes": 104857600,
    "max_ratio": 100,
    "allowed_extensions": ["txt", "md", "csv", "json", "pdf", "png", "jpg", "jpeg", "gif"],
}
SIG_LOCAL = b"PK\x03\x04"
SIG_CENTRAL = b"PK\x01\x02"
SIG_END = b"PK\x05\x06"
SIG_ZIP64_LOCATOR = b"PK\x06\x07"
U16_MAX = 0xFFFF
U32_MAX = 0xFFFFFFFF
_BAD_NAME_CHARS = set(range(0x80, 0xA0)) | {0x061C, 0xFEFF} | set(range(0x200B, 0x2010)) | \
    set(range(0x202A, 0x202F)) | set(range(0x2060, 0x2065)) | set(range(0x2066, 0x206A))
_RESERVED = {"con", "prn", "aux", "nul", "conin$", "conout$"} | {"com%d" % i for i in range(10)} | \
    {"lpt%d" % i for i in range(10)} | {p + s for p in ("com", "lpt") for s in ("¹", "²", "³")}


class _Refusal(Exception):
    """Internal: carries one refusal out of the checks. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""

    def __init__(self, error: str, status: int, entry_index: int = -1):
        """In: the error, its HTTP status, the entry index (-1 for the archive). 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP."""
        super().__init__(error)
        self.answer = {"error": error, "status": status, "entry_index": entry_index}


def _u16(b: bytes, off: int) -> int:
    """An unsigned little-endian u16 (a Python int never wraps). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    return struct.unpack_from("<H", b, off)[0]


def _u32(b: bytes, off: int) -> int:
    """An unsigned little-endian u32. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    return struct.unpack_from("<I", b, off)[0]


def _limits(limits: Optional[dict]) -> dict:
    """The defaults overlaid with the caller's limits. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    out = dict(DEFAULT_LIMITS)
    out.update(limits or {})
    return out


def _ascii_lower(s: str) -> str:
    """A-Z to a-z only. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def extension_of(name: str) -> str:
    """EXTENSION: the last part's text after its last ".", ASCII lower case; "" for a part with no "." or whose
    only "." is its first character. Why: C9 (ARCHIVE-08). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    last = name.rstrip("/").split("/")[-1]
    dot = last.rfind(".")
    if dot <= 0:
        return ""
    return _ascii_lower(last[dot + 1:])


def _check_name(raw: bytes, idx: int) -> List[str]:
    """C4 (unsafe_path) and C5 (bad_name) for one entry name. Out: the name's parts (without the trailing "/").
    Why: ARCHIVE-02, ARCHIVE-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    if not raw:
        raise _Refusal("unsafe_path", 400, idx)
    try:
        name = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _Refusal("unsafe_path", 400, idx)
    if any(b < 0x20 or b == 0x7F or b == 0x5C for b in raw):
        raise _Refusal("unsafe_path", 400, idx)
    if name.startswith("/") or (len(name) >= 2 and ("A" <= name[0] <= "Z" or "a" <= name[0] <= "z")
                                 and name[1] == ":"):
        raise _Refusal("unsafe_path", 400, idx)
    body = name[:-1] if name.endswith("/") else name
    parts = body.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise _Refusal("unsafe_path", 400, idx)
    # C5
    if len(raw) > 1024 or any(ord(c) in _BAD_NAME_CHARS for c in name):
        raise _Refusal("bad_name", 400, idx)
    for p in parts:
        if len(p.encode("utf-8")) > 255 or any(c in ':*?"<>|' for c in p) or p.endswith(".") or p.endswith(" "):
            raise _Refusal("bad_name", 400, idx)
        stem = _ascii_lower(p.split(".", 1)[0]).rstrip(" ")
        if stem in _RESERVED:
            raise _Refusal("bad_name", 400, idx)
    return parts


def _check_extra(extra: bytes, raw_name: bytes, idx: int) -> None:
    """C6: the extra field is (id u16, size u16, size bytes)*. Overruns, 1-3 bytes left over or a Unicode Path
    block under 5 bytes -> not_a_zip; a version-1 Unicode Path whose name differs -> header_mismatch. The whole
    structure is checked before any name. Why: ARCHIVE-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    blocks = []
    pos = 0
    n = len(extra)
    while pos < n:
        if n - pos < 4:
            raise _Refusal("not_a_zip", 400, idx)
        bid, size = _u16(extra, pos), _u16(extra, pos + 2)
        if pos + 4 + size > n:
            raise _Refusal("not_a_zip", 400, idx)
        block = extra[pos + 4:pos + 4 + size]
        if bid == 0x7075 and size < 5:
            raise _Refusal("not_a_zip", 400, idx)
        blocks.append((bid, block))
        pos += 4 + size
    for bid, block in blocks:
        if bid == 0x7075 and block[0] == 1 and block[5:] != raw_name:
            raise _Refusal("header_mismatch", 400, idx)


def _read(data: bytes, limits: dict) -> dict:
    """Checks A, B and C in order. Out: {entries: [...], total, cd_offset}; raises _Refusal.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
        raise _Refusal("empty_upload", 400)
    data = bytes(data)
    length = len(data)
    if length > limits["max_archive_bytes"]:
        raise _Refusal("archive_too_large", 413)
    if not data.startswith(SIG_LOCAL):
        raise _Refusal("not_a_zip", 400)
    end = -1
    for i in range(length - 22, max(0, length - 65557) - 1, -1):
        if data[i:i + 4] == SIG_END and i + 22 + _u16(data, i + 20) == length:
            end = i
            break
    if end < 0:
        raise _Refusal("not_a_zip", 400)
    disk, cd_disk = _u16(data, end + 4), _u16(data, end + 6)
    entries_here, count = _u16(data, end + 8), _u16(data, end + 10)
    cd_size, cd_offset = _u32(data, end + 12), _u32(data, end + 16)
    if (disk != 0 or cd_disk != 0 or entries_here != count or count == U16_MAX or cd_size == U32_MAX
            or cd_offset == U32_MAX or (end >= 20 and data[end - 20:end - 16] == SIG_ZIP64_LOCATOR)):
        raise _Refusal("unsupported_zip", 400)
    if cd_offset + cd_size != end:
        raise _Refusal("not_a_zip", 400)
    if count == 0:
        raise _Refusal("empty_archive", 400)
    if count > limits["max_entries"]:
        raise _Refusal("too_many_entries", 413)
    # B: the central directory
    records = []
    p = cd_offset
    for _ in range(count):
        if p + 46 > end or data[p:p + 4] != SIG_CENTRAL:
            raise _Refusal("not_a_zip", 400)
        nlen, elen, clen = _u16(data, p + 28), _u16(data, p + 30), _u16(data, p + 32)
        if p + 46 + nlen + elen + clen > end:
            raise _Refusal("not_a_zip", 400)
        records.append({
            "made_by": _u16(data, p + 4), "flags": _u16(data, p + 8), "method": _u16(data, p + 10),
            "crc": _u32(data, p + 16), "csize": _u32(data, p + 20), "usize": _u32(data, p + 24),
            "disk_start": _u16(data, p + 34), "external": _u32(data, p + 38), "local_offset": _u32(data, p + 42),
            "raw_name": data[p + 46:p + 46 + nlen], "extra": data[p + 46 + nlen:p + 46 + nlen + elen]})
        p += 46 + nlen + elen + clen
    if p != end:
        raise _Refusal("not_a_zip", 400)
    # C: each entry
    allowed = limits["allowed_extensions"]
    file_keys, dir_keys = set(), set()
    total = 0
    any_file = False
    for idx, r in enumerate(records):
        if (r["csize"] == U32_MAX or r["usize"] == U32_MAX or r["local_offset"] == U32_MAX
                or r["disk_start"] != 0):
            raise _Refusal("unsupported_zip", 400, idx)
        if r["flags"] & 0x2041:
            raise _Refusal("encrypted_entry", 400, idx)
        if r["method"] not in (0, 8):
            raise _Refusal("unsupported_compression", 400, idx)
        parts = _check_name(r["raw_name"], idx)
        name = r["raw_name"].decode("utf-8")
        is_dir = name.endswith("/")
        _check_extra(r["extra"], r["raw_name"], idx)
        ftype = (r["external"] >> 16) & 0xF000
        if ftype not in (0, 0x8000, 0x4000):
            raise _Refusal("special_file", 400, idx)
        if (is_dir and r["usize"] != 0) or (not is_dir and r["method"] == 0 and r["csize"] != r["usize"]):
            raise _Refusal("size_mismatch", 400, idx)
        if not is_dir and extension_of(name) not in allowed:
            raise _Refusal("extension_not_allowed", 400, idx)
        key = _ascii_lower("/".join(parts))
        key_parts = key.split("/")
        prefixes = ["/".join(key_parts[:k]) for k in range(1, len(key_parts))]
        if key in file_keys or any(px in file_keys for px in prefixes) or (not is_dir and key in dir_keys):
            raise _Refusal("duplicate_name", 400, idx)
        (dir_keys if is_dir else file_keys).add(key)
        dir_keys.update(prefixes)
        if r["usize"] > limits["max_file_bytes"]:
            raise _Refusal("entry_too_large", 413, idx)
        total += r["usize"]
        if total > limits["max_total_bytes"]:
            raise _Refusal("total_too_large", 413, idx)
        r["name"], r["parts"], r["is_dir"] = name, parts, is_dir
        any_file = any_file or not is_dir
    if not any_file:
        raise _Refusal("empty_archive", 400)
    if total > limits["max_ratio"] * length:
        raise _Refusal("compression_ratio_exceeded", 413)
    for idx, r in enumerate(records):
        lo = r["local_offset"]
        if lo + 30 > cd_offset or data[lo:lo + 4] != SIG_LOCAL:
            raise _Refusal("not_a_zip", 400, idx)
        lnlen, lelen = _u16(data, lo + 26), _u16(data, lo + 28)
        if lo + 30 + lnlen + lelen + r["csize"] > cd_offset:
            raise _Refusal("not_a_zip", 400, idx)
        if (data[lo + 30:lo + 30 + lnlen] != r["raw_name"] or _u16(data, lo + 6) != r["flags"]
                or _u16(data, lo + 8) != r["method"]):
            raise _Refusal("header_mismatch", 400, idx)
        if not (r["flags"] & 0x0008) and (_u32(data, lo + 14) != r["crc"] or _u32(data, lo + 18) != r["csize"]
                                          or _u32(data, lo + 22) != r["usize"]):
            raise _Refusal("header_mismatch", 400, idx)
        r["data_start"] = lo + 30 + lnlen + lelen
    return {"entries": records, "total": total}


def inspect_archive(data: bytes, limits: Optional[dict] = None) -> dict:
    """inspect_archive: checks A, B and C; reads no file data and writes nothing.

    In: the uploaded bytes and limits (defaults: DEFAULT_LIMITS). Out: {ok: true, entries, total_bytes,
    files: [{path, size}]} or {error, status, entry_index}. Why: ARCHIVE-04..12, 14. 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    try:
        info = _read(data, _limits(limits))
    except _Refusal as r:
        return r.answer
    return {"ok": True, "entries": len(info["entries"]), "total_bytes": info["total"],
            "files": [{"path": r["name"], "size": r["usize"]} for r in info["entries"] if not r["is_dir"]]}


def _entry_bytes(data: bytes, r: dict, idx: int) -> bytes:
    """D3's data check: stored bytes, or raw DEFLATE inflated to at most usize + 1 bytes; invalid data, more or
    fewer than usize bytes, or a CRC-32 other than the central crc -> corrupt_entry. Why: ARCHIVE-06, 07.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    raw = data[r["data_start"]:r["data_start"] + r["csize"]]
    usize = r["usize"]
    if r["method"] == 0:
        out = raw
    else:
        try:
            out = zlib.decompressobj(-15).decompress(raw, usize + 1)
        except zlib.error:
            raise _Refusal("corrupt_entry", 400, idx)
    if len(out) != usize or (zlib.crc32(out) & 0xFFFFFFFF) != r["crc"]:
        raise _Refusal("corrupt_entry", 400, idx)
    return out


def _make_dirs(path: str, stop: str) -> None:
    """Create path and its missing parents below stop, each with mode 0755 (set explicitly, whatever the umask).
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files (directories under the staging directory)."""
    missing = []
    p = path
    while p != stop and not os.path.isdir(p):
        missing.append(p)
        p = os.path.dirname(p)
    for d in reversed(missing):
        os.mkdir(d, 0o755)
        os.chmod(d, 0o755)


def extract_archive(data: bytes, target_dir: str, limits: Optional[dict] = None) -> dict:
    """extract_archive: checks A, B and C (the same answers as inspect_archive), then D: a fresh 0700 staging
    directory beside target_dir, every entry written there (files 0644, exclusive create, never a link), then one
    rename. Any refusal or error removes the staging directory, so target_dir exists only when every file was
    written. Out: {ok: true, entries, total_bytes, files: [{path, size, sha256}]} or {error, status, entry_index}.
    Why: ARCHIVE-01, 02, 07, 13, 14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    Touches: files (target_dir and its staging directory)."""
    try:
        info = _read(data, _limits(limits))
    except _Refusal as r:
        return r.answer
    data = bytes(data)
    if os.path.lexists(target_dir):
        return {"error": "target_exists", "status": 409, "entry_index": -1}
    staging = target_dir + ".partial-" + secrets.token_hex(8)
    try:
        os.mkdir(staging, 0o700)
        os.chmod(staging, 0o700)
    except OSError:
        return {"error": "target_unwritable", "status": 500, "entry_index": -1}
    files = []
    idx = -1
    try:
        root = os.path.normpath(os.path.abspath(staging))
        for idx, r in enumerate(info["entries"]):
            dest = os.path.normpath(os.path.abspath(os.path.join(staging, *r["parts"])))
            if not dest.startswith(root + os.sep):
                raise _Refusal("unsafe_path", 400, idx)
            if r["is_dir"]:
                _make_dirs(dest, root)
                continue
            content = _entry_bytes(data, r, idx)
            _make_dirs(os.path.dirname(dest), root)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
            try:
                fd = os.open(dest, flags, 0o644)
            except FileExistsError:
                raise _Refusal("duplicate_name", 400, idx)
            try:
                view = memoryview(content)
                while view:
                    view = view[os.write(fd, view):]
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o644)
            finally:
                os.close(fd)
            files.append({"path": r["name"], "size": len(content), "sha256": hashlib.sha256(content).hexdigest()})
        idx = -1  # D4
        os.rename(staging, target_dir)
    except _Refusal as r:
        shutil.rmtree(staging, ignore_errors=True)
        return r.answer
    except OSError:  # an I/O error: in D3 it names the entry being written, in D4 -1
        shutil.rmtree(staging, ignore_errors=True)
        return {"error": "target_unwritable", "status": 500, "entry_index": idx}
    return {"ok": True, "entries": len(info["entries"]), "total_bytes": info["total"], "files": files}
