//! Safe archive ingest: check an uploaded .zip without trusting anything in it, then extract it all or nothing.
//!
//! What: reads the end record, the central directory and each local record itself (never a zip library's
//! extract, never a library's choice of name), runs the spec's checks A, B, C in order (container, directory,
//! each entry: zip64, encryption, method, unsafe and Windows-reserved names, extra fields, links and devices,
//! sizes, extensions, duplicates, limits, ratio, local-record agreement), then extracts into a 0700 staging
//! directory with exclusive creates and an inflate capped at usize + 1 bytes, and renames it into place.
//! Every refusal is a returned `Refusal {error, status, entry_index}`, never a panic; every number from the
//! archive is read unsigned into u64.
//! Why: Phase D wave 1, owner request 2026-11-10 (docs/specs/safe_archive_ingest.md, ARCHIVE-01..14).
//! 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: files: creates target_dir (and a staging directory beside it, removed on any failure) under a
//! directory the caller chooses; reads the OS random source for the staging name. No network, no database,
//! no money. A refusal names an entry index, never an entry's name.

use flate2::{Crc, Decompress, FlushDecompress, Status};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// What: the injected limits (spec LIMITS); `Default` gives the spec's defaults.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_archive_bytes: u64,
    pub max_entries: u64,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_ratio: u64,
    pub allowed_extensions: Vec<String>,
}

/// What: the spec's default limits. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_archive_bytes: 20_971_520,
            max_entries: 1000,
            max_file_bytes: 26_214_400,
            max_total_bytes: 104_857_600,
            max_ratio: 100,
            allowed_extensions: ["txt", "md", "csv", "json", "pdf", "png", "jpg", "jpeg", "gif"].iter().map(|s| s.to_string()).collect(),
        }
    }
}

/// What: a refusal {error, status, entry_index} (-1 for checks of the whole archive).
/// Why: spec CONVENTIONS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub error: String,
    pub status: u16,
    pub entry_index: i64,
}

/// What: build a refusal. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn refuse(error: &str, status: u16, entry_index: i64) -> Refusal {
    Refusal { error: error.to_string(), status, entry_index }
}

/// What: one file of the answer; sha256 is set by extract_archive only. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub sha256: Option<String>,
}

/// What: the answer {ok: true, entries, total_bytes, files}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveResult {
    pub ok: bool,
    pub entries: u64,
    pub total_bytes: u64,
    pub files: Vec<FileInfo>,
}

/// One checked entry: its name, whether it is a directory, its sizes and crc, and where its data starts.
#[derive(Debug, Clone)]
struct Entry {
    name: String,
    is_dir: bool,
    method: u64,
    crc: u64,
    csize: u64,
    usize_: u64,
    data_start: u64,
}

/// What: little-endian u16 at offset, as u64. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn u16_at(b: &[u8], o: u64) -> u64 {
    let o = o as usize;
    u16::from_le_bytes([b[o], b[o + 1]]) as u64
}

/// What: little-endian u32 at offset, as u64 (never signed). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn u32_at(b: &[u8], o: u64) -> u64 {
    let o = o as usize;
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as u64
}

/// What: true when the 4 bytes at o are PK + c + d. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn sig(b: &[u8], o: u64, c: u8, d: u8) -> bool {
    let o = o as usize;
    o + 4 <= b.len() && b[o] == 0x50 && b[o + 1] == 0x4B && b[o + 2] == c && b[o + 3] == d
}

/// What: C4, a name that could leave the target: empty, not strict UTF-8, control byte, 0x7F or back-slash,
/// absolute, a drive letter, or an empty, "." or ".." part. Out: the name as text when it is safe.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn safe_name(raw: &[u8]) -> Option<String> {
    if raw.is_empty() || raw.iter().any(|&x| x < 0x20 || x == 0x7F || x == b'\\') {
        return None;
    }
    let name = std::str::from_utf8(raw).ok()?;
    let nb = name.as_bytes();
    if nb[0] == b'/' || (nb.len() >= 2 && nb[0].is_ascii_alphabetic() && nb[1] == b':') {
        return None;
    }
    let body = name.strip_suffix('/').unwrap_or(name);
    if body.split('/').any(|p| p.is_empty() || p == "." || p == "..") {
        return None;
    }
    Some(name.to_string())
}

/// What: C5, a name that does not unpack everywhere (length, invisible or direction characters, Windows
/// reserved characters and device names, a trailing dot or space). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
fn bad_name(name: &str) -> bool {
    if name.len() > 1024 {
        return true;
    }
    let invisible = |c: char| {
        let u = c as u32;
        (0x80..=0x9F).contains(&u) || u == 0x61C || (0x200B..=0x200F).contains(&u) || (0x202A..=0x202E).contains(&u)
            || (0x2060..=0x2064).contains(&u) || (0x2066..=0x2069).contains(&u) || u == 0xFEFF
    };
    if name.chars().any(invisible) {
        return true;
    }
    let body = name.strip_suffix('/').unwrap_or(name);
    body.split('/').any(|part| {
        if part.len() > 255 || part.chars().any(|c| ":*?\"<>|".contains(c)) || part.ends_with('.') || part.ends_with(' ') {
            return true;
        }
        let stem = part.split('.').next().unwrap_or("");
        let stem: String = stem.chars().map(|c| c.to_ascii_lowercase()).collect();
        let stem = stem.trim_end_matches(' ');
        if ["con", "prn", "aux", "nul", "conin$", "conout$"].contains(&stem) {
            return true;
        }
        for dev in ["com", "lpt"] {
            if let Some(rest) = stem.strip_prefix(dev) {
                let mut cs = rest.chars();
                if let (Some(c), None) = (cs.next(), cs.next()) {
                    if c.is_ascii_digit() || c == '\u{00B9}' || c == '\u{00B2}' || c == '\u{00B3}' {
                        return true;
                    }
                }
            }
        }
        false
    })
}

/// What: EXTENSION of a file: its last part's text after the last ".", ASCII lower case; "" when the part has
/// no "." or only a leading one. Why: spec EXTENSION. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn extension(name: &str) -> String {
    let last = name.rsplit('/').next().unwrap_or("");
    match last.rfind('.') {
        Some(i) if i > 0 => last[i + 1..].to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// What: C6, the extra field: (id, size, data) blocks; a block that overruns, 1-3 bytes left over, or a short
/// Unicode Path block is not_a_zip; a version-1 Unicode Path naming anything but the entry's name is
/// header_mismatch. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn check_extra(extra: &[u8], name: &[u8], idx: i64) -> Result<(), Refusal> {
    let len = extra.len() as u64;
    let mut pos = 0u64;
    while pos < len {
        if len - pos < 4 {
            return Err(refuse("not_a_zip", 400, idx));
        }
        let id = u16_at(extra, pos);
        let size = u16_at(extra, pos + 2);
        if pos + 4 + size > len {
            return Err(refuse("not_a_zip", 400, idx));
        }
        if id == 0x7075 {
            if size < 5 {
                return Err(refuse("not_a_zip", 400, idx));
            }
            let data = &extra[(pos + 4) as usize..(pos + 4 + size) as usize];
            if data[0] == 1 && &data[5..] != name {
                return Err(refuse("header_mismatch", 400, idx));
            }
        }
        pos += 4 + size;
    }
    Ok(())
}

/// What: checks A, B and C in the spec's order. Out: the entries, the declared total, or the first refusal.
/// Why: spec CHECKS, ARCHIVE-02..12, ARCHIVE-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn check(b: &[u8], limits: &Limits) -> Result<(Vec<Entry>, u64), Refusal> {
    let len = b.len() as u64;
    // A. the container
    if len == 0 {
        return Err(refuse("empty_upload", 400, -1));
    }
    if len > limits.max_archive_bytes {
        return Err(refuse("archive_too_large", 413, -1));
    }
    if !sig(b, 0, 3, 4) {
        return Err(refuse("not_a_zip", 400, -1));
    }
    let mut end: Option<u64> = None;
    if len >= 22 {
        let lo = len.saturating_sub(65557);
        let mut i = len - 22;
        loop {
            if sig(b, i, 5, 6) && i + 22 + u16_at(b, i + 20) == len {
                end = Some(i);
                break;
            }
            if i == lo {
                break;
            }
            i -= 1;
        }
    }
    let i = end.ok_or_else(|| refuse("not_a_zip", 400, -1))?;
    let (disk, cd_disk, here, entries) = (u16_at(b, i + 4), u16_at(b, i + 6), u16_at(b, i + 8), u16_at(b, i + 10));
    let (cd_size, cd_offset) = (u32_at(b, i + 12), u32_at(b, i + 16));
    if disk != 0 || cd_disk != 0 || here != entries || entries == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF || (i >= 20 && sig(b, i - 20, 6, 7)) {
        return Err(refuse("unsupported_zip", 400, -1));
    }
    if cd_offset + cd_size != i {
        return Err(refuse("not_a_zip", 400, -1));
    }
    if entries == 0 {
        return Err(refuse("empty_archive", 400, -1));
    }
    if entries > limits.max_entries {
        return Err(refuse("too_many_entries", 413, -1));
    }
    // B. the central directory
    struct Central {
        flags: u64,
        method: u64,
        crc: u64,
        csize: u64,
        usize_: u64,
        name: Vec<u8>,
        extra: Vec<u8>,
        disk_start: u64,
        external: u64,
        local_offset: u64,
    }
    let mut central = Vec::new();
    let mut pos = cd_offset;
    for _ in 0..entries {
        if pos + 46 > i || !sig(b, pos, 1, 2) {
            return Err(refuse("not_a_zip", 400, -1));
        }
        let (n, m, k) = (u16_at(b, pos + 28), u16_at(b, pos + 30), u16_at(b, pos + 32));
        if pos + 46 + n + m + k > i {
            return Err(refuse("not_a_zip", 400, -1));
        }
        let s = (pos + 46) as usize;
        central.push(Central {
            flags: u16_at(b, pos + 8),
            method: u16_at(b, pos + 10),
            crc: u32_at(b, pos + 16),
            csize: u32_at(b, pos + 20),
            usize_: u32_at(b, pos + 24),
            name: b[s..s + n as usize].to_vec(),
            extra: b[s + n as usize..s + (n + m) as usize].to_vec(),
            disk_start: u16_at(b, pos + 34),
            external: u32_at(b, pos + 38),
            local_offset: u32_at(b, pos + 42),
        });
        pos += 46 + n + m + k;
    }
    if pos != i {
        return Err(refuse("not_a_zip", 400, -1));
    }
    // C. each entry
    let mut out: Vec<Entry> = Vec::new();
    let (mut files, mut dirs): (HashSet<String>, HashSet<String>) = (HashSet::new(), HashSet::new());
    let mut total = 0u64;
    let mut any_file = false;
    for (n, c) in central.iter().enumerate() {
        let idx = n as i64;
        if c.csize == 0xFFFF_FFFF || c.usize_ == 0xFFFF_FFFF || c.local_offset == 0xFFFF_FFFF || c.disk_start != 0 {
            return Err(refuse("unsupported_zip", 400, idx));
        }
        if c.flags & 0x2041 != 0 {
            return Err(refuse("encrypted_entry", 400, idx));
        }
        if c.method != 0 && c.method != 8 {
            return Err(refuse("unsupported_compression", 400, idx));
        }
        let name = safe_name(&c.name).ok_or_else(|| refuse("unsafe_path", 400, idx))?;
        if bad_name(&name) {
            return Err(refuse("bad_name", 400, idx));
        }
        check_extra(&c.extra, &c.name, idx)?;
        let kind = (c.external >> 16) & 0xF000;
        if kind != 0 && kind != 0x8000 && kind != 0x4000 {
            return Err(refuse("special_file", 400, idx));
        }
        let is_dir = name.ends_with('/');
        if (is_dir && c.usize_ != 0) || (!is_dir && c.method == 0 && c.csize != c.usize_) {
            return Err(refuse("size_mismatch", 400, idx));
        }
        if !is_dir && !limits.allowed_extensions.iter().any(|e| *e == extension(&name)) {
            return Err(refuse("extension_not_allowed", 400, idx));
        }
        let key: String = name.strip_suffix('/').unwrap_or(&name).chars().map(|ch| ch.to_ascii_lowercase()).collect();
        let prefix_is_file = key.match_indices('/').any(|(j, _)| files.contains(&key[..j]));
        if files.contains(&key) || prefix_is_file || (!is_dir && dirs.contains(&key)) {
            return Err(refuse("duplicate_name", 400, idx));
        }
        for (j, _) in key.match_indices('/') {
            dirs.insert(key[..j].to_string());
        }
        if is_dir {
            dirs.insert(key);
        } else {
            files.insert(key);
            any_file = true;
        }
        if c.usize_ > limits.max_file_bytes {
            return Err(refuse("entry_too_large", 413, idx));
        }
        total += c.usize_;
        if total > limits.max_total_bytes {
            return Err(refuse("total_too_large", 413, idx));
        }
        out.push(Entry { name, is_dir, method: c.method, crc: c.crc, csize: c.csize, usize_: c.usize_, data_start: 0 });
    }
    if !any_file {
        return Err(refuse("empty_archive", 400, -1));
    }
    if total as u128 > limits.max_ratio as u128 * len as u128 {
        return Err(refuse("compression_ratio_exceeded", 413, -1));
    }
    // C15. each local record against its central record
    for (n, c) in central.iter().enumerate() {
        let idx = n as i64;
        let lo = c.local_offset;
        if lo + 30 > cd_offset || !sig(b, lo, 3, 4) {
            return Err(refuse("not_a_zip", 400, idx));
        }
        let (ln, le) = (u16_at(b, lo + 26), u16_at(b, lo + 28));
        if lo + 30 + ln + le + c.csize > cd_offset {
            return Err(refuse("not_a_zip", 400, idx));
        }
        let lname = &b[(lo + 30) as usize..(lo + 30 + ln) as usize];
        let (lflags, lmethod) = (u16_at(b, lo + 6), u16_at(b, lo + 8));
        let sizes_differ = lflags & 0x8 == 0 && (u32_at(b, lo + 14) != c.crc || u32_at(b, lo + 18) != c.csize || u32_at(b, lo + 22) != c.usize_);
        if lname != c.name.as_slice() || lflags != c.flags || lmethod != c.method || sizes_differ {
            return Err(refuse("header_mismatch", 400, idx));
        }
        out[n].data_start = lo + 30 + ln + le;
    }
    Ok((out, total))
}

/// What: inspect_archive(bytes, limits): checks A, B and C; reads no file data and writes nothing.
/// Out: {ok, entries, total_bytes, files [{path, size}]}, or the refusal.
/// Why: spec inspect_archive. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn inspect_archive(bytes: &[u8], limits: &Limits) -> Result<ArchiveResult, Refusal> {
    let (entries, total) = check(bytes, limits)?;
    let files = entries.iter().filter(|e| !e.is_dir).map(|e| FileInfo { path: e.name.clone(), size: e.usize_, sha256: None }).collect();
    Ok(ArchiveResult { ok: true, entries: entries.len() as u64, total_bytes: total, files })
}

/// What: inflate a raw DEFLATE stream, producing at most `cap` bytes. Out: the bytes, or None when the inflater
/// reports invalid data. Input that runs out simply ends the output. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
fn inflate_capped(input: &[u8], cap: usize) -> Option<Vec<u8>> {
    let mut d = Decompress::new(false);
    let mut out = Vec::new();
    let mut buf = vec![0u8; 65536];
    while out.len() < cap {
        let want = buf.len().min(cap - out.len());
        let (in0, out0) = (d.total_in(), d.total_out());
        let status = d.decompress(&input[in0 as usize..], &mut buf[..want], FlushDecompress::None).ok()?;
        out.extend_from_slice(&buf[..(d.total_out() - out0) as usize]);
        if status == Status::StreamEnd || (d.total_in() == in0 && d.total_out() == out0) {
            break;
        }
    }
    Some(out)
}

/// What: CRC-32 of bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn crc32(data: &[u8]) -> u64 {
    let mut c = Crc::new();
    c.update(data);
    c.sum() as u64
}

/// What: the staging directory's name: target + ".partial-" + 16 random hex characters.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the OS random source.
fn staging_path(target: &Path) -> PathBuf {
    use rand::RngCore;
    let mut r = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut r);
    let mut s = OsString::from(target.as_os_str());
    s.push(".partial-");
    s.push(r.iter().map(|x| format!("{:02x}", x)).collect::<String>());
    PathBuf::from(s)
}

/// What: D3 for every entry inside the staging directory. Out: the files with their sha256, or the refusal.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files under the staging directory.
fn write_entries(bytes: &[u8], entries: &[Entry], staging: &Path) -> Result<Vec<FileInfo>, Refusal> {
    let mut files = Vec::new();
    for (n, e) in entries.iter().enumerate() {
        let idx = n as i64;
        let io = |_| refuse("target_unwritable", 500, idx);
        let mut dest = staging.to_path_buf();
        for part in e.name.strip_suffix('/').unwrap_or(&e.name).split('/') {
            dest.push(part);
        }
        if !dest.starts_with(staging) || dest == staging {
            return Err(refuse("unsafe_path", 400, idx));
        }
        let mkdirs = |p: &Path| fs::DirBuilder::new().recursive(true).mode(0o755).create(p);
        if e.is_dir {
            mkdirs(&dest).map_err(io)?;
            fs::set_permissions(&dest, fs::Permissions::from_mode(0o755)).map_err(io)?;
            continue;
        }
        let raw = &bytes[e.data_start as usize..(e.data_start + e.csize) as usize];
        let data = if e.method == 8 {
            inflate_capped(raw, e.usize_ as usize + 1).ok_or_else(|| refuse("corrupt_entry", 400, idx))?
        } else {
            raw.to_vec()
        };
        if data.len() as u64 != e.usize_ || crc32(&data) != e.crc {
            return Err(refuse("corrupt_entry", 400, idx));
        }
        if let Some(parent) = dest.parent() {
            mkdirs(parent).map_err(io)?;
        }
        let mut f = match fs::OpenOptions::new().write(true).create_new(true).mode(0o644).open(&dest) {
            Ok(f) => f,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => return Err(refuse("duplicate_name", 400, idx)),
            Err(_) => return Err(refuse("target_unwritable", 500, idx)),
        };
        f.write_all(&data).map_err(io)?;
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o644)).map_err(io)?;
        let sha: String = Sha256::digest(&data).iter().map(|x| format!("{:02x}", x)).collect();
        files.push(FileInfo { path: e.name.clone(), size: e.usize_, sha256: Some(sha) });
    }
    Ok(files)
}

/// What: extract_archive(bytes, target_dir, limits): checks A, B, C, then D: target_dir must not exist (not even
/// as a dangling link), files go to a 0700 staging directory beside it, which is renamed into place only when
/// every file was written; any refusal or error removes the staging directory first.
/// Out: {ok, entries, total_bytes, files [{path, size, sha256}]}, or the refusal.
/// Why: spec extract_archive, ARCHIVE-01, 07, 13, 14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: files (target_dir and its staging directory), the OS random source.
pub fn extract_archive(bytes: &[u8], target_dir: &Path, limits: &Limits) -> Result<ArchiveResult, Refusal> {
    let (entries, total) = check(bytes, limits)?;
    if fs::symlink_metadata(target_dir).is_ok() {
        return Err(refuse("target_exists", 409, -1));
    }
    let staging = staging_path(target_dir);
    if fs::DirBuilder::new().mode(0o700).create(&staging).is_err() {
        return Err(refuse("target_unwritable", 500, -1));
    }
    let written = write_entries(bytes, &entries, &staging).and_then(|files| {
        fs::rename(&staging, target_dir).map(|_| files).map_err(|_| refuse("target_unwritable", 500, -1))
    });
    match written {
        Ok(files) => Ok(ArchiveResult { ok: true, entries: entries.len() as u64, total_bytes: total, files }),
        Err(r) => {
            let _ = fs::remove_dir_all(&staging);
            Err(r)
        }
    }
}
