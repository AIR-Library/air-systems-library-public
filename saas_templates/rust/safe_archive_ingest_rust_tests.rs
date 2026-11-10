//! Safe archive ingest tests (docs/specs/safe_archive_ingest.md, ARCHIVE-01..14). Archives come from the spec's
//! test builder (`build_zip`, no compressor needed); extraction goes to a fresh temporary directory per test.
//! Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: files under the system temporary directory (created and removed by each test).
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

/// What: one entry for build_zip, with the spec's options and defaults. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Clone)]
struct Z {
    name: Vec<u8>,
    data: Vec<u8>,
    method: u16,
    usize_: Option<u32>,
    crc: Option<u32>,
    flags: u16,
    external: u32,
    creator: u16,
    extra: Vec<u8>,
    local_name: Option<Vec<u8>>,
}

/// What: an entry with the defaults. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn z(name: &str, data: &[u8]) -> Z {
    zb(name.as_bytes(), data)
}

/// What: an entry whose name is raw bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn zb(name: &[u8], data: &[u8]) -> Z {
    Z { name: name.to_vec(), data: data.to_vec(), method: 0, usize_: None, crc: None, flags: 0, external: 0, creator: 0, extra: vec![], local_name: None }
}

/// What: CRC-32 for the builder. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn crc(data: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(data);
    c.sum()
}

/// What: build_zip(entries, comment), exactly as the spec's TEST ARCHIVE BUILDER says.
/// Why: ARCHIVE-01 and every other test. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn build_zip(entries: &[Z], comment: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut offsets = Vec::new();
    let le16 = |v: &mut Vec<u8>, x: u16| v.extend_from_slice(&x.to_le_bytes());
    let le32 = |v: &mut Vec<u8>, x: u32| v.extend_from_slice(&x.to_le_bytes());
    for e in entries {
        offsets.push(out.len() as u32);
        let ln = e.local_name.clone().unwrap_or_else(|| e.name.clone());
        out.extend_from_slice(&[0x50, 0x4B, 3, 4]);
        le16(&mut out, 20);
        le16(&mut out, e.flags);
        le16(&mut out, e.method);
        le16(&mut out, 0);
        le16(&mut out, 0x0021);
        le32(&mut out, e.crc.unwrap_or_else(|| crc(&e.data)));
        le32(&mut out, e.data.len() as u32);
        le32(&mut out, e.usize_.unwrap_or(e.data.len() as u32));
        le16(&mut out, ln.len() as u16);
        le16(&mut out, 0);
        out.extend_from_slice(&ln);
        out.extend_from_slice(&e.data);
    }
    let cd_offset = out.len() as u32;
    for (e, off) in entries.iter().zip(&offsets) {
        out.extend_from_slice(&[0x50, 0x4B, 1, 2]);
        le16(&mut out, e.creator * 256 + 20);
        le16(&mut out, 20);
        le16(&mut out, e.flags);
        le16(&mut out, e.method);
        le16(&mut out, 0);
        le16(&mut out, 0x0021);
        le32(&mut out, e.crc.unwrap_or_else(|| crc(&e.data)));
        le32(&mut out, e.data.len() as u32);
        le32(&mut out, e.usize_.unwrap_or(e.data.len() as u32));
        le16(&mut out, e.name.len() as u16);
        le16(&mut out, e.extra.len() as u16);
        le16(&mut out, 0);
        le16(&mut out, 0);
        le16(&mut out, 0);
        le32(&mut out, e.external);
        le32(&mut out, *off);
        out.extend_from_slice(&e.name);
        out.extend_from_slice(&e.extra);
    }
    let cd_size = out.len() as u32 - cd_offset;
    out.extend_from_slice(&[0x50, 0x4B, 5, 6]);
    le16(&mut out, 0);
    le16(&mut out, 0);
    le16(&mut out, entries.len() as u16);
    le16(&mut out, entries.len() as u16);
    le32(&mut out, cd_size);
    le32(&mut out, cd_offset);
    le16(&mut out, comment.len() as u16);
    out.extend_from_slice(comment);
    out
}

/// What: hex text to bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// What: the BASIC archive of the spec. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn basic(comment: &[u8]) -> Vec<u8> {
    build_zip(
        &[
            Z { external: 0x41ED_0000, creator: 3, ..z("docs/", b"") },
            z("docs/readme.txt", b"hello\n"),
            Z { external: 0x81ED_0000, creator: 3, ..z("data.csv", b"a,b\n1,2\n") },
        ],
        comment,
    )
}

/// What: Z, the raw DEFLATE stream of 2000 zero bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn zstream() -> Vec<u8> {
    unhex("63601805a360148c8251300a46c1500700")
}

/// What: the ZEROS entry with its overrides. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn zeros_entry(data: Vec<u8>, usize_: u32, crc_: u32) -> Z {
    Z { method: 8, usize_: Some(usize_), crc: Some(crc_), ..z("zeros.txt", &data) }
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// What: a fresh empty directory; removed when dropped. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files.
struct TempDir(PathBuf);

/// What: create and name the directory. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files.
impl TempDir {
    fn new() -> TempDir {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let p = std::env::temp_dir().join(format!("aoi_archive_{}_{}_{}", std::process::id(), n, nanos));
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    /// What: the target path inside. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn target(&self) -> PathBuf {
        self.0.join("target")
    }
    /// What: the names in the directory. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files (read).
    fn listing(&self) -> Vec<String> {
        fs::read_dir(&self.0).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect()
    }
}

/// What: remove the directory. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files.
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// What: extract into a fresh directory and expect a refusal that leaves nothing behind.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files.
fn refused(bytes: &[u8], limits: &Limits, error: &str, status: u16, idx: i64) {
    let d = TempDir::new();
    let r = extract_archive(bytes, &d.target(), limits).unwrap_err();
    assert_eq!(r, Refusal { error: error.into(), status, entry_index: idx });
    assert!(d.listing().is_empty(), "left behind: {:?}", d.listing());
    assert_eq!(inspect_archive(bytes, limits).err().map(|x| x.error).unwrap_or_default(), if matches!(error, "corrupt_entry" | "target_exists" | "target_unwritable") { String::new() } else { error.to_string() });
}

/// What: extract into a fresh directory and expect success. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files.
fn accepted(bytes: &[u8], limits: &Limits) -> ArchiveResult {
    let d = TempDir::new();
    let r = extract_archive(bytes, &d.target(), limits).unwrap_or_else(|e| panic!("refused: {:?}", e));
    assert!(d.target().is_dir());
    r
}

/// What: ARCHIVE-01, the builder reproduces BASIC; extraction writes its files, the directory, sizes, SHA-256.
/// Why: ARCHIVE-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files.
// ARCHIVE-01
#[test]
fn test_archive_01_basic() {
    let want = [
        "504b03041400000000000000210000000000000000000000000005000000646f63732f504b0304140000000000000021",
        "0020303a3606000000060000000f000000646f63732f726561646d652e74787468656c6c6f0a504b0304140000000000",
        "000021007b07970a080000000800000008000000646174612e637376612c620a312c320a504b01021403140000000000",
        "00002100000000000000000000000000050000000000000000000000ed4100000000646f63732f504b01021400140000",
        "0000000000210020303a3606000000060000000f0000000000000000000000000023000000646f63732f726561646d65",
        "2e747874504b01021403140000000000000021007b07970a0800000008000000080000000000000000000000ed815600",
        "0000646174612e637376504b05060000000003000300a6000000840000000000",
    ]
    .concat();
    let b = basic(b"");
    assert_eq!(b.len(), 320);
    assert_eq!(b, unhex(&want));
    let d = TempDir::new();
    let t = d.target();
    let r = extract_archive(&b, &t, &Limits::default()).unwrap();
    assert_eq!((r.ok, r.entries, r.total_bytes), (true, 3, 14));
    assert_eq!(
        r.files,
        vec![
            FileInfo { path: "docs/readme.txt".into(), size: 6, sha256: Some("5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03".into()) },
            FileInfo { path: "data.csv".into(), size: 8, sha256: Some("492d5ea496056f1a6a6592241032fab764c321596317930b4fa0e1e8bc3b7470".into()) },
        ]
    );
    assert!(t.join("docs").is_dir());
    assert_eq!(fs::read(t.join("docs/readme.txt")).unwrap(), b"hello\n");
    assert_eq!(fs::read(t.join("data.csv")).unwrap(), b"a,b\n1,2\n");
    assert_eq!(fs::metadata(&t).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(d.listing(), vec!["target".to_string()]);
    let i = inspect_archive(&b, &Limits::default()).unwrap();
    assert_eq!(i.files.iter().map(|f| (f.path.as_str(), f.size, f.sha256.clone())).collect::<Vec<_>>(), vec![("docs/readme.txt", 6, None), ("data.csv", 8, None)]);
}

/// What: ARCHIVE-02, zip slip and unsafe names are 400 unsafe_path with the entry's index, nothing written.
/// Why: ARCHIVE-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files.
// ARCHIVE-02
#[test]
fn test_archive_02_unsafe_paths() {
    let names: Vec<Vec<u8>> = vec![
        b"../evil.txt".to_vec(), b"a/../../evil.txt".to_vec(), b"/etc/passwd.txt".to_vec(), b"C:/x.txt".to_vec(),
        b"a\\b.txt".to_vec(), b"a//b.txt".to_vec(), b"./a.txt".to_vec(), b"a\x00b.txt".to_vec(), b"a\x01b.txt".to_vec(),
        b"a\x7fb.txt".to_vec(), b"".to_vec(),
        unhex("61c0af622e747874"), unhex("61eda0802e747874"), unhex("61f4908080 2e747874".replace(' ', "").as_str()), unhex("61e2822e747874"),
    ];
    for n in names {
        let b = build_zip(&[z("ok.txt", b"x"), zb(&n, b"evil")], b"");
        refused(&b, &Limits::default(), "unsafe_path", 400, 1);
    }
}

/// What: ARCHIVE-03, links and FIFOs are special_file whatever made them; a regular mode is accepted.
/// Why: ARCHIVE-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files.
// ARCHIVE-03
#[test]
fn test_archive_03_special_files() {
    for creator in [0u16, 3, 19] {
        let b = build_zip(&[Z { external: 0xA1FF_0000, creator, ..z("link.txt", b"/etc/passwd") }], b"");
        refused(&b, &Limits::default(), "special_file", 400, 0);
    }
    refused(&build_zip(&[Z { external: 0x11A4_0000, creator: 3, ..z("fifo.txt", b"") }], b""), &Limits::default(), "special_file", 400, 0);
    accepted(&build_zip(&[Z { external: 0x81A4_0000, creator: 3, ..z("plain.txt", b"x") }], b""), &Limits::default());
}

/// What: ARCHIVE-04, entry count and archive size limits, exactly at each limit accepted.
/// Why: ARCHIVE-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files.
// ARCHIVE-04
#[test]
fn test_archive_04_count_and_size() {
    let b = build_zip(&[z("a.txt", b"x"), z("b.txt", b"x"), z("c.txt", b"x")], b"");
    assert_eq!(b.len(), 283);
    accepted(&b, &Limits { max_entries: 3, max_archive_bytes: 283, ..Limits::default() });
    refused(&b, &Limits { max_entries: 2, ..Limits::default() }, "too_many_entries", 413, -1);
    refused(&b, &Limits { max_archive_bytes: 282, ..Limits::default() }, "archive_too_large", 413, -1);
}

/// What: ARCHIVE-05, total and per-entry limits, exact limits accepted, sizes read unsigned.
/// Why: ARCHIVE-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files.
// ARCHIVE-05
#[test]
fn test_archive_05_declared_sizes() {
    let b = build_zip(&[z("a.txt", b"12345"), z("b.txt", b"67890")], b"");
    assert_eq!(b.len(), 204);
    accepted(&b, &Limits { max_total_bytes: 10, max_file_bytes: 5, ..Limits::default() });
    refused(&b, &Limits { max_total_bytes: 9, ..Limits::default() }, "total_too_large", 413, 1);
    refused(&b, &Limits { max_file_bytes: 4, ..Limits::default() }, "entry_too_large", 413, 0);
    let big = build_zip(&[Z { method: 8, usize_: Some(0x8000_0000), crc: Some(0), ..z("a.txt", &zstream()) }], b"");
    refused(&big, &Limits::default(), "entry_too_large", 413, 0);
    refused(&big, &Limits { max_file_bytes: 4_294_967_296, max_total_bytes: 4_294_967_296, ..Limits::default() }, "compression_ratio_exceeded", 413, -1);
}

/// What: ARCHIVE-06, the compression ratio cap on ZEROS. Why: ARCHIVE-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: files.
// ARCHIVE-06
#[test]
fn test_archive_06_ratio() {
    let b = build_zip(&[zeros_entry(zstream(), 2000, 0x02C9_F444)], b"");
    assert_eq!(b.len(), 133);
    refused(&b, &Limits { max_ratio: 15, ..Limits::default() }, "compression_ratio_exceeded", 413, -1);
    let d = TempDir::new();
    let r = extract_archive(&b, &d.target(), &Limits { max_ratio: 16, ..Limits::default() }).unwrap();
    assert_eq!((r.total_bytes, r.files[0].size), (2000, 2000));
    assert_eq!(fs::read(d.target().join("zeros.txt")).unwrap(), vec![0u8; 2000]);
}

/// What: ARCHIVE-07, lying headers are corrupt_entry (or size_mismatch for a stored entry with two sizes) and
/// leave no file. Why: ARCHIVE-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files.
// ARCHIVE-07
#[test]
fn test_archive_07_lying_headers() {
    let zs = zstream();
    let cases = vec![
        zeros_entry(zs.clone(), 10, 0xE38A_6876),
        zeros_entry(zs.clone(), 3000, 0x02C9_F444),
        zeros_entry(zs[..zs.len() - 4].to_vec(), 2000, 0x02C9_F444),
        zeros_entry(zs.clone(), 2000, 1),
        Z { crc: Some(0), ..z("a.txt", b"12345") },
        Z { method: 8, usize_: Some(4), crc: Some(0), ..z("zeros.txt", &[0xFF, 0xFF, 0xFF, 0xFF]) },
        zeros_entry(unhex("62601805a360148c8251300a46c1500700000000ffff07"), 10, 0xE38A_6876),
    ];
    for e in cases {
        refused(&build_zip(&[e], b""), &Limits::default(), "corrupt_entry", 400, 0);
    }
    refused(&build_zip(&[Z { usize_: Some(4), ..z("a.txt", b"12345") }], b""), &Limits::default(), "size_mismatch", 400, 0);
}

/// What: ARCHIVE-08, the extension allow-list. Why: ARCHIVE-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: files.
// ARCHIVE-08
#[test]
fn test_archive_08_extensions() {
    for n in ["run.exe", "a.txt.sh", "README", ".env", "inner.zip"] {
        refused(&build_zip(&[z(n, b"x")], b""), &Limits::default(), "extension_not_allowed", 400, 0);
    }
    accepted(&build_zip(&[z("A.TXT", b"x"), z("x.Json", b"{}")], b""), &Limits::default());
    let l = Limits { allowed_extensions: vec!["".into(), "sh".into()], ..Limits::default() };
    accepted(&build_zip(&[z("README", b"x"), z("a.sh", b"echo")], b""), &l);
    assert_eq!((extension(".env"), extension("d/x.TaR.Gz"), extension("noext")), ("".to_string(), "gz".to_string(), "".to_string()));
}

/// What: ARCHIVE-09, duplicate names (case folded, file under file, file versus directory) are entry_index 1;
/// one directory named twice is accepted. Why: ARCHIVE-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files.
// ARCHIVE-09
#[test]
fn test_archive_09_duplicates() {
    for (a, b) in [("a.txt", "a.txt"), ("A.txt", "a.txt"), ("d.txt/", "d.txt"), ("d.txt", "d.txt/"), ("d.txt", "d.txt/e.txt"), ("d.txt/e.txt", "d.txt")] {
        refused(&build_zip(&[z(a, b""), z(b, b"")], b""), &Limits::default(), "duplicate_name", 400, 1);
    }
    accepted(&build_zip(&[z("d/", b""), z("d/", b""), z("d/x.txt", b"x")], b""), &Limits::default());
}

/// What: ARCHIVE-10, the container: empty, not a zip, truncated, count mismatch, trailing byte, wrapped offset,
/// disk number, zip64, only a directory, a comment, and a too-short input never read before its start.
/// Why: ARCHIVE-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files.
// ARCHIVE-10
#[test]
fn test_archive_10_container() {
    let l = Limits::default();
    let b = basic(b"");
    let n = b.len();
    let set16 = |v: &mut Vec<u8>, o: usize, x: u16| v[o..o + 2].copy_from_slice(&x.to_le_bytes());
    let set32 = |v: &mut Vec<u8>, o: usize, x: u32| v[o..o + 4].copy_from_slice(&x.to_le_bytes());
    refused(b"", &l, "empty_upload", 400, -1);
    refused(b"hello, this is not a zip archive at all", &l, "not_a_zip", 400, -1);
    refused(&b[..n - 10], &l, "not_a_zip", 400, -1);
    let mut c = b.clone();
    set16(&mut c, n - 14, 4);
    set16(&mut c, n - 12, 4);
    refused(&c, &l, "not_a_zip", 400, -1);
    let mut c = b.clone();
    c.push(0);
    refused(&c, &l, "not_a_zip", 400, -1);
    let mut c = b.clone();
    set32(&mut c, n - 10, 300);
    set32(&mut c, n - 6, 0xFFFF_FFFE);
    refused(&c, &l, "not_a_zip", 400, -1);
    let mut c = b.clone();
    set16(&mut c, n - 18, 1);
    refused(&c, &l, "unsupported_zip", 400, -1);
    let mut c = b.clone();
    set16(&mut c, n - 14, 0xFFFF);
    set16(&mut c, n - 12, 0xFFFF);
    refused(&c, &l, "unsupported_zip", 400, -1);
    refused(&build_zip(&[z("docs/", b"")], b""), &l, "empty_archive", 400, -1);
    refused(&unhex("504b0304504b0506000000000000000000000000040000001000504b0607787878787878787878787878"), &l, "empty_archive", 400, -1);
    let r = accepted(&basic(&[b'c'; 40]), &l);
    assert_eq!(r.entries, 3);
}

/// What: ARCHIVE-11, encryption flags, other methods, and a data descriptor (flag bit 3) accepted.
/// Why: ARCHIVE-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files.
// ARCHIVE-11
#[test]
fn test_archive_11_flags_and_methods() {
    for flags in [0x0001u16, 0x0040] {
        refused(&build_zip(&[Z { flags, ..z("a.txt", b"12345") }], b""), &Limits::default(), "encrypted_entry", 400, 0);
    }
    refused(&build_zip(&[Z { method: 12, ..z("a.txt", b"12345") }], b""), &Limits::default(), "unsupported_compression", 400, 0);
    let r = accepted(&build_zip(&[Z { flags: 8, ..z("a.txt", b"12345") }], b""), &Limits::default());
    assert_eq!(r.files[0].size, 5);
}

/// What: ARCHIVE-12, local and central records must agree; the Unicode Path extra field; an overrunning extra.
/// Why: ARCHIVE-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files.
// ARCHIVE-12
#[test]
fn test_archive_12_header_agreement() {
    let l = Limits::default();
    refused(&build_zip(&[z("a.txt", b"y"), Z { local_name: Some(b"no.txt".to_vec()), ..z("ok.txt", b"x") }], b""), &l, "header_mismatch", 400, 1);
    let evil = unhex("75701000012a0419052e2e2f6576696c2e747874");
    assert_eq!(&evil[5..9], &crc(b"ok.txt").to_le_bytes());
    refused(&build_zip(&[Z { extra: evil, ..z("ok.txt", b"x") }], b""), &l, "header_mismatch", 400, 0);
    let mut own = vec![0x75, 0x70, 11, 0, 1];
    own.extend_from_slice(&crc(b"ok.txt").to_le_bytes());
    own.extend_from_slice(b"ok.txt");
    accepted(&build_zip(&[Z { extra: own, ..z("ok.txt", b"x") }], b""), &l);
    refused(&build_zip(&[Z { extra: unhex("0a0032006162"), ..z("ok.txt", b"x") }], b""), &l, "not_a_zip", 400, 0);
}

/// What: ARCHIVE-13, all or nothing: a corrupt second entry leaves no target and no staging directory; an
/// existing target is 409 and kept; a missing parent is 500. Why: ARCHIVE-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: files.
// ARCHIVE-13
#[test]
fn test_archive_13_all_or_nothing() {
    let l = Limits::default();
    let b = build_zip(&[z("a.txt", b"first"), zeros_entry(zstream(), 2000, 1)], b"");
    refused(&b, &l, "corrupt_entry", 400, 1);
    let d = TempDir::new();
    fs::create_dir(d.target()).unwrap();
    fs::write(d.target().join("keep.txt"), b"mine").unwrap();
    assert_eq!(extract_archive(&basic(b""), &d.target(), &l).unwrap_err(), refuse("target_exists", 409, -1));
    assert_eq!(fs::read(d.target().join("keep.txt")).unwrap(), b"mine");
    assert_eq!(d.listing(), vec!["target".to_string()]);
    // a link that points nowhere also exists
    let d2 = TempDir::new();
    std::os::unix::fs::symlink(d2.0.join("nowhere"), d2.target()).unwrap();
    assert_eq!(extract_archive(&basic(b""), &d2.target(), &l).unwrap_err(), refuse("target_exists", 409, -1));
    let d3 = TempDir::new();
    assert_eq!(extract_archive(&basic(b""), &d3.0.join("missing").join("target"), &l).unwrap_err(), refuse("target_unwritable", 500, -1));
    assert!(d3.listing().is_empty());
}

/// What: ARCHIVE-14, names that do not unpack everywhere are bad_name; their near neighbours are accepted; a
/// 0755 entry is written 0644. Why: ARCHIVE-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files.
// ARCHIVE-14
#[test]
fn test_archive_14_portable_names() {
    let l = Limits::default();
    let long_bad = ["x".repeat(252), ".txt".into()].concat();
    let long_ok = ["x".repeat(251), ".txt".into()].concat();
    for n in ["CON.txt", "com1.txt", "COM0.txt", "LPT0.txt", "COM\u{00b9}.txt", "CONIN$.txt", "CONOUT$.txt", "a.", "a ", "a?.txt", &long_bad, "a\u{202e}b.txt", "d/aux.txt"] {
        refused(&build_zip(&[z(n, b"x")], b""), &l, "bad_name", 400, 0);
    }
    let d = TempDir::new();
    let r = extract_archive(&build_zip(&[z(&long_ok, b"x"), z("caf\u{00e9}.txt", b"x"), z("COM10.txt", b"x"), z("conin.txt", b"x"), Z { external: 0x81ED_0000, creator: 3, ..z("run.txt", b"x") }], b""), &d.target(), &l).unwrap();
    assert_eq!(r.files.len(), 5);
    assert!(d.target().join("caf\u{00e9}.txt").is_file());
    assert_eq!(fs::metadata(d.target().join("run.txt")).unwrap().permissions().mode() & 0o777, 0o644);
}
