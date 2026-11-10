"""Tests for safe_archive_ingest_python (docs/specs/safe_archive_ingest.md), with the spec's test archive builder and
fixed vectors.

Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
Touches: files, only under pytest's temporary directory. No database, network or money.
"""
import os
import stat
import struct
import zlib

from safe_archive_ingest_python import extract_archive, inspect_archive

BASIC_HEX = (
    "504b03041400000000000000210000000000000000000000000005000000646f63732f504b0304140000000000000021"
    "0020303a3606000000060000000f000000646f63732f726561646d652e74787468656c6c6f0a504b0304140000000000"
    "000021007b07970a080000000800000008000000646174612e637376612c620a312c320a504b01021403140000000000"
    "00002100000000000000000000000000050000000000000000000000ed4100000000646f63732f504b01021400140000"
    "0000000000210020303a3606000000060000000f0000000000000000000000000023000000646f63732f726561646d65"
    "2e747874504b01021403140000000000000021007b07970a0800000008000000080000000000000000000000ed815600"
    "0000646174612e637376504b05060000000003000300a6000000840000000000")
Z = bytes.fromhex("63601805a360148c8251300a46c1500700")
BAD = bytes.fromhex("62601805a360148c8251300a46c1500700000000ffff07")
CRC_2000 = 0x02C9F444
CRC_10 = 0xE38A6876


def build_zip(entries, comment=b""):
    """The spec's TEST ARCHIVE BUILDER: local records, central records, end record. An entry is a dict with name
    (str or bytes) and data, plus method, usize, crc, flags, external, creator, extra and local_name.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    def b(x):
        """Text as UTF-8 bytes, bytes unchanged. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return x.encode("utf-8") if isinstance(x, str) else bytes(x)

    local = bytearray()
    central = bytearray()
    for e in entries:
        name = b(e["name"])
        data = b(e.get("data", b""))
        local_name = b(e.get("local_name", e["name"]))
        method, flags = e.get("method", 0), e.get("flags", 0)
        usize = e.get("usize", len(data))
        crc = e.get("crc", zlib.crc32(data) & 0xFFFFFFFF)
        extra = b(e.get("extra", b""))
        offset = len(local)
        local += b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20, flags, method, 0, 0x0021, crc, len(data), usize,
                                             len(local_name), 0) + local_name + data
        central += b"PK\x01\x02" + struct.pack("<HHHHHHIIIHHHHHII", e.get("creator", 0) * 256 + 20, 20, flags,
                                               method, 0, 0x0021, crc, len(data), usize, len(name), len(extra), 0,
                                               0, 0, e.get("external", 0), offset) + name + extra
    comment = b(comment)
    end = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, len(entries), len(entries), len(central), len(local),
                                      len(comment)) + comment
    return bytes(local + central + end)


BASIC_ENTRIES = [{"name": "docs/", "external": 0x41ED0000, "creator": 3},
                 {"name": "docs/readme.txt", "data": "hello\n"},
                 {"name": "data.csv", "data": "a,b\n1,2\n", "external": 0x81ED0000, "creator": 3}]
BASIC = build_zip(BASIC_ENTRIES)


def refused(error, status, idx):
    """A refusal dict. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    return {"error": error, "status": status, "entry_index": idx}


def put_u16(data, off, v):
    """data with the u16 at off (negative: from the end) set to v. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    d = bytearray(data)
    struct.pack_into("<H", d, off % len(d), v)
    return bytes(d)


def put_u32(data, off, v):
    """data with the u32 at off (negative: from the end) set to v. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    d = bytearray(data)
    struct.pack_into("<I", d, off % len(d), v)
    return bytes(d)


def assert_nothing_written(tmp_path, target):
    """The target does not exist and nothing (no staging directory) is beside it. 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the temporary directory."""
    assert not os.path.lexists(target)
    assert os.listdir(tmp_path) == []


def check(entries, want, tmp_path, limits=None):
    """inspect_archive and extract_archive both give want (a refusal); nothing is left behind.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the temporary directory."""
    data = entries if isinstance(entries, bytes) else build_zip(entries)
    assert inspect_archive(data, limits) == want
    target = str(tmp_path / "out")
    assert extract_archive(data, target, limits) == want
    assert_nothing_written(tmp_path, target)


def accepted(entries, tmp_path, limits=None, name="out"):
    """extract_archive accepts the archive. Out: the result. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    data = entries if isinstance(entries, bytes) else build_zip(entries)
    assert inspect_archive(data, limits)["ok"] is True
    r = extract_archive(data, str(tmp_path / name), limits)
    assert r.get("ok") is True, r
    return r


# ARCHIVE-01
def test_archive_01_basic(tmp_path):
    """The builder reproduces BASIC byte for byte; extract_archive writes its two files under the target, creates
    the directory, returns each path, size and SHA-256; data.csv is 0644 though its entry says 0755. ARCHIVE-01.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the temporary directory."""
    assert BASIC == bytes.fromhex(BASIC_HEX) and len(BASIC) == 320
    target = tmp_path / "out"
    r = extract_archive(BASIC, str(target))
    assert r == {"ok": True, "entries": 3, "total_bytes": 14, "files": [
        {"path": "docs/readme.txt", "size": 6,
         "sha256": "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"},
        {"path": "data.csv", "size": 8, "sha256": "492d5ea496056f1a6a6592241032fab764c321596317930b4fa0e1e8bc3b7470"}]}
    assert (target / "docs").is_dir()
    assert (target / "docs" / "readme.txt").read_bytes() == b"hello\n"
    assert (target / "data.csv").read_bytes() == b"a,b\n1,2\n"
    assert stat.S_IMODE(os.stat(target / "data.csv").st_mode) == 0o644
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o700
    assert sorted(os.listdir(tmp_path)) == ["out"]
    assert inspect_archive(BASIC) == {"ok": True, "entries": 3, "total_bytes": 14, "files": [
        {"path": "docs/readme.txt", "size": 6}, {"path": "data.csv", "size": 8}]}


# ARCHIVE-02
def test_archive_02_zip_slip_names(tmp_path):
    """Path escapes, absolute and drive names, back-slashes, empty and "." parts, control bytes, an empty name and
    names that are not strict UTF-8 are 400 unsafe_path with the entry's index; nothing is written. ARCHIVE-02.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the temporary directory."""
    names = ["../evil.txt", "a/../../evil.txt", "/etc/passwd.txt", "C:/x.txt", "a\\b.txt", "a//b.txt", "./a.txt",
             "a\x00b.txt", "a\x01.txt", "a\x7f.txt", "",
             bytes.fromhex("61C0AF622E747874"), bytes.fromhex("61EDA0802E747874"),
             bytes.fromhex("61F49080802E747874"), bytes.fromhex("61E2822E747874")]
    for n in names:
        check([{"name": "ok.txt", "data": "x"}, {"name": n, "data": "y"}], refused("unsafe_path", 400, 1), tmp_path)
    check([{"name": "../evil.txt", "data": "y"}], refused("unsafe_path", 400, 0), tmp_path)


# ARCHIVE-03
def test_archive_03_special_files(tmp_path):
    """A symbolic link (whatever creator: 0, 3, 19) and a FIFO are 400 special_file; a regular-file mode is
    accepted. ARCHIVE-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the temporary directory."""
    for creator in (0, 3, 19):
        check([{"name": "link.txt", "data": "/etc/passwd", "external": 0xA1FF0000, "creator": creator}],
              refused("special_file", 400, 0), tmp_path)
    check([{"name": "fifo.txt", "data": "", "external": 0x11A40000, "creator": 3}],
          refused("special_file", 400, 0), tmp_path)
    r = accepted([{"name": "plain.txt", "data": "x", "external": 0x81A40000, "creator": 3}], tmp_path)
    assert r["files"][0]["path"] == "plain.txt"
    assert not os.path.islink(tmp_path / "out" / "plain.txt")


# ARCHIVE-04
def test_archive_04_entry_and_archive_limits(tmp_path):
    """Three one-byte files (283 bytes): max_entries 3 and max_archive_bytes 283 accept; 2 entries -> 413
    too_many_entries; 282 bytes -> 413 archive_too_large. ARCHIVE-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    data = build_zip([{"name": n, "data": "x"} for n in ("a.txt", "b.txt", "c.txt")])
    assert len(data) == 283
    accepted(data, tmp_path, {"max_entries": 3, "max_archive_bytes": 283})
    check(data, refused("too_many_entries", 413, -1), _fresh(tmp_path, "t1"), {"max_entries": 2})
    check(data, refused("archive_too_large", 413, -1), _fresh(tmp_path, "t2"), {"max_archive_bytes": 282})


def _fresh(tmp_path, name):
    """An empty sub-directory of the temporary directory. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    d = tmp_path / name
    d.mkdir()
    return d


# ARCHIVE-05
def test_archive_05_size_limits(tmp_path):
    """max_total_bytes 10 and max_file_bytes 5 accept the 204-byte archive; 9 -> total_too_large (index 1); 4 ->
    entry_too_large (index 0); a usize of 0x80000000 is unsigned (entry_too_large), and with 4294967296 limits it
    is compression_ratio_exceeded. ARCHIVE-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    data = build_zip([{"name": "a.txt", "data": "12345"}, {"name": "b.txt", "data": "67890"}])
    assert len(data) == 204
    accepted(data, tmp_path, {"max_total_bytes": 10, "max_file_bytes": 5})
    check(data, refused("total_too_large", 413, 1), _fresh(tmp_path, "t1"), {"max_total_bytes": 9})
    check(data, refused("entry_too_large", 413, 0), _fresh(tmp_path, "t2"), {"max_file_bytes": 4})
    big = [{"name": "a.txt", "data": Z, "method": 8, "usize": 0x80000000, "crc": 0}]
    check(big, refused("entry_too_large", 413, 0), _fresh(tmp_path, "t3"))
    check(big, refused("compression_ratio_exceeded", 413, -1), _fresh(tmp_path, "t4"),
          {"max_file_bytes": 4294967296, "max_total_bytes": 4294967296})


# ARCHIVE-06
def test_archive_06_compression_ratio(tmp_path):
    """ZEROS (133 bytes declaring 2000) is 413 compression_ratio_exceeded with max_ratio 15 and extracted with 16.
    ARCHIVE-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the temporary directory."""
    zeros = build_zip([{"name": "zeros.txt", "data": Z, "method": 8, "usize": 2000, "crc": CRC_2000}])
    assert len(zeros) == 133
    check(zeros, refused("compression_ratio_exceeded", 413, -1), _fresh(tmp_path, "t1"), {"max_ratio": 15})
    accepted(zeros, tmp_path, {"max_ratio": 16})
    assert (tmp_path / "out" / "zeros.txt").read_bytes() == bytes(2000)


# ARCHIVE-07
def test_archive_07_lying_headers(tmp_path):
    """Declared sizes that do not match the inflated data, a cut stream, a stream that overruns then turns invalid,
    a wrong CRC (stored or deflated) and invalid data are 400 corrupt_entry; a stored entry with two sizes is 400
    size_mismatch; no file is left. ARCHIVE-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    corrupt = [
        {"name": "zeros.txt", "data": Z, "method": 8, "usize": 10, "crc": CRC_10},
        {"name": "zeros.txt", "data": Z, "method": 8, "usize": 3000, "crc": CRC_2000},
        {"name": "zeros.txt", "data": Z[:-4], "method": 8, "usize": 2000, "crc": CRC_2000},
        {"name": "zeros.txt", "data": Z, "method": 8, "usize": 2000, "crc": 1},
        {"name": "a.txt", "data": "12345", "crc": 0},
        {"name": "zeros.txt", "data": b"\xff\xff\xff\xff", "method": 8, "usize": 4, "crc": 0},
        {"name": "zeros.txt", "data": BAD, "method": 8, "usize": 10, "crc": CRC_10},
    ]
    for i, e in enumerate(corrupt):
        d = _fresh(tmp_path, "c%d" % i)
        data = build_zip([e])
        assert inspect_archive(data)["ok"] is True
        assert extract_archive(data, str(d / "out")) == refused("corrupt_entry", 400, 0), i
        assert_nothing_written(d, str(d / "out"))
    check([{"name": "a.txt", "data": "12345", "usize": 4}], refused("size_mismatch", 400, 0), _fresh(tmp_path, "s"))


# ARCHIVE-08
def test_archive_08_extensions(tmp_path):
    """run.exe, a.txt.sh, README, .env and inner.zip are 400 extension_not_allowed by default; A.TXT and x.Json are
    accepted; with ["", "sh"] README and a.sh are accepted. ARCHIVE-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    for i, n in enumerate(("run.exe", "a.txt.sh", "README", ".env", "inner.zip")):
        check([{"name": n, "data": "x"}], refused("extension_not_allowed", 400, 0), _fresh(tmp_path, "e%d" % i))
    accepted([{"name": "A.TXT", "data": "x"}, {"name": "x.Json", "data": "{}"}], tmp_path, name="ok1")
    accepted([{"name": "README", "data": "x"}, {"name": "a.sh", "data": "x"}], tmp_path,
             {"allowed_extensions": ["", "sh"]}, name="ok2")


# ARCHIVE-09
def test_archive_09_duplicate_names(tmp_path):
    """a.txt twice, A.txt with a.txt, a file with a path under it (either order) and a directory with a file of
    the same name (either order) are 400 duplicate_name with entry_index 1; the same directory twice is accepted.
    ARCHIVE-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the temporary directory."""
    pairs = [("a.txt", "a.txt"), ("A.txt", "a.txt"), ("d.txt/", "d.txt"), ("d.txt", "d.txt/"),
             ("d.txt", "d.txt/e.txt"), ("d.txt/e.txt", "d.txt")]
    for i, (first, second) in enumerate(pairs):
        check([{"name": first, "data": "" if first.endswith("/") else "x"},
               {"name": second, "data": "" if second.endswith("/") else "y"}],
              refused("duplicate_name", 400, 1), _fresh(tmp_path, "d%d" % i))
    r = accepted([{"name": "dir/"}, {"name": "dir/"}, {"name": "dir/f.txt", "data": "x"}], tmp_path)
    assert r["entries"] == 3 and (tmp_path / "out" / "dir" / "f.txt").read_bytes() == b"x"


# ARCHIVE-10
def test_archive_10_container_checks(tmp_path):
    """empty_upload, not_a_zip (not a zip, truncated, wrong counts, a trailing byte, a wrapping offset + size),
    unsupported_zip (a disk number, zip64 counts, a zip64 locator), empty_archive (only a directory; the 42-byte
    archive whose comment starts with the zip64 mark is never read before its start), and a comment is accepted.
    ARCHIVE-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the temporary directory."""
    n = len(BASIC)
    cases = [
        (b"", refused("empty_upload", 400, -1)),
        (b"this is plain text, not a zip archive", refused("not_a_zip", 400, -1)),
        (BASIC[:-10], refused("not_a_zip", 400, -1)),
        (put_u16(put_u16(BASIC, n - 14, 4), n - 12, 4), refused("not_a_zip", 400, -1)),
        (BASIC + b"\x00", refused("not_a_zip", 400, -1)),
        (put_u16(BASIC, n - 18, 1), refused("unsupported_zip", 400, -1)),
        (put_u16(put_u16(BASIC, n - 14, 0xFFFF), n - 12, 0xFFFF), refused("unsupported_zip", 400, -1)),
        (BASIC[:-22] + b"PK\x06\x07" + bytes(16) + BASIC[-22:], refused("unsupported_zip", 400, -1)),
        (put_u32(put_u32(BASIC, n - 10, 300), n - 6, 0xFFFFFFFE), refused("not_a_zip", 400, -1)),
        (build_zip([{"name": "docs/"}]), refused("empty_archive", 400, -1)),
        (bytes.fromhex("504b0304504b0506000000000000000000000000040000001000504b0607787878787878787878787878"),
         refused("empty_archive", 400, -1)),
        (b"PK\x03\x04" + b"PK\x05\x06", refused("not_a_zip", 400, -1)),
    ]
    for i, (data, want) in enumerate(cases):
        check(data, want, _fresh(tmp_path, "c%d" % i))
    r = accepted(build_zip(BASIC_ENTRIES, comment=b"c" * 40), tmp_path)
    assert r["entries"] == 3


# ARCHIVE-11
def test_archive_11_flags_and_methods(tmp_path):
    """Encryption flag bit 0 or bit 6 is 400 encrypted_entry; a method other than 0 and 8 is 400
    unsupported_compression; flag bit 3 (data descriptor) is accepted. ARCHIVE-11. 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the temporary directory."""
    check([{"name": "a.txt", "data": "12345", "flags": 1}], refused("encrypted_entry", 400, 0), _fresh(tmp_path, "f1"))
    check([{"name": "a.txt", "data": "12345", "flags": 0x40}], refused("encrypted_entry", 400, 0),
          _fresh(tmp_path, "f2"))
    check([{"name": "a.txt", "data": "12345", "method": 12}], refused("unsupported_compression", 400, 0),
          _fresh(tmp_path, "f3"))
    r = accepted([{"name": "a.txt", "data": "12345", "flags": 8}], tmp_path)
    assert (tmp_path / "out" / "a.txt").read_bytes() == b"12345" and r["files"][0]["size"] == 5


# ARCHIVE-12
def test_archive_12_local_and_unicode_path_names(tmp_path):
    """A local name that differs from the central one is 400 header_mismatch with that index; a Unicode Path extra
    naming ../evil.txt is header_mismatch, one repeating the own name is accepted; an overrunning extra field is
    400 not_a_zip. ARCHIVE-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the temporary directory."""
    check([{"name": "first.txt", "data": "1"}, {"name": "ok.txt", "data": "x", "local_name": "no.txt"}],
          refused("header_mismatch", 400, 1), _fresh(tmp_path, "h1"))
    evil = bytes.fromhex("75701000012a0419052e2e2f6576696c2e747874")
    assert evil == b"\x75\x70" + struct.pack("<H", 16) + b"\x01" + struct.pack("<I", zlib.crc32(b"ok.txt")) + \
        b"../evil.txt"
    check([{"name": "ok.txt", "data": "x", "extra": evil}], refused("header_mismatch", 400, 0), _fresh(tmp_path, "h2"))
    own = b"\x75\x70" + struct.pack("<H", 11) + b"\x01" + struct.pack("<I", zlib.crc32(b"ok.txt")) + b"ok.txt"
    accepted([{"name": "ok.txt", "data": "x", "extra": own}], tmp_path)
    check([{"name": "ok.txt", "data": "x", "extra": bytes.fromhex("0A0032006162")}], refused("not_a_zip", 400, 0),
          _fresh(tmp_path, "h3"))


# ARCHIVE-13
def test_archive_13_all_or_nothing(tmp_path):
    """A corrupt second entry names entry_index 1 and leaves neither the target nor a staging directory; an
    existing target is 409 target_exists and keeps its content; a missing parent is 500 target_unwritable.
    ARCHIVE-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the temporary directory."""
    data = build_zip([{"name": "good.txt", "data": "fine"}, {"name": "bad.txt", "data": "12345", "crc": 0}])
    d = _fresh(tmp_path, "a")
    assert extract_archive(data, str(d / "out")) == refused("corrupt_entry", 400, 1)
    assert_nothing_written(d, str(d / "out"))
    d = _fresh(tmp_path, "b")
    (d / "out").mkdir()
    (d / "out" / "keep.txt").write_bytes(b"keep")
    assert extract_archive(BASIC, str(d / "out")) == refused("target_exists", 409, -1)
    assert os.listdir(d / "out") == ["keep.txt"] and (d / "out" / "keep.txt").read_bytes() == b"keep"
    (d / "file").write_bytes(b"f")
    assert extract_archive(BASIC, str(d / "file")) == refused("target_exists", 409, -1)
    os.symlink(str(d / "nowhere"), str(d / "dangling"))
    assert extract_archive(BASIC, str(d / "dangling")) == refused("target_exists", 409, -1)
    assert sorted(os.listdir(d)) == ["dangling", "file", "out"]
    d = _fresh(tmp_path, "c")
    assert extract_archive(BASIC, str(d / "missing" / "out")) == refused("target_unwritable", 500, -1)
    assert os.listdir(d) == []


# ARCHIVE-14
def test_archive_14_names_that_do_not_unpack_everywhere(tmp_path):
    """Windows device names, a trailing dot or space, a?.txt, a 256-byte segment and a right-to-left override are
    400 bad_name; a 255-byte segment, an accented name, COM10.txt and conin.txt are accepted; a 0755 entry is
    written without execute permission. ARCHIVE-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    bad = ["CON.txt", "com1.txt", "COM0.txt", "LPT0.txt", "COM\u00b9.txt", "CONIN$.txt", "CONOUT$.txt", "a.txt.",
           "a.txt ", "a?.txt", "x" * 252 + ".txt", "a\u202etxt.exe.txt", "nul .txt", "dir/aux.txt"]
    for i, n in enumerate(bad):
        check([{"name": n, "data": "x"}], refused("bad_name", 400, 0), _fresh(tmp_path, "b%d" % i))
    r = accepted([{"name": "x" * 251 + ".txt", "data": "1"}, {"name": "caf\u00e9.txt", "data": "2"},
                  {"name": "COM10.txt", "data": "3"}, {"name": "conin.txt", "data": "4"},
                  {"name": "run.txt", "data": "#!/bin/sh\n", "external": 0x81ED0000, "creator": 3}], tmp_path)
    assert [f["path"] for f in r["files"]] == ["x" * 251 + ".txt", "caf\u00e9.txt", "COM10.txt", "conin.txt", "run.txt"]
    assert (tmp_path / "out" / "caf\u00e9.txt").read_bytes() == b"2"
    mode = stat.S_IMODE(os.stat(tmp_path / "out" / "run.txt").st_mode)
    assert mode == 0o644 and not mode & 0o111
