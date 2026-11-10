// Package archiveingest checks an uploaded .zip and unpacks it into a new directory without trusting anything in
// it (docs/specs/safe_archive_ingest.md): no path leaves the directory, no link or device is created, no count,
// size or ratio limit is passed, and either every file is written or none is.
//
// The three zip record types are read here byte by byte; only raw DEFLATE (compress/flate) and CRC-32
// (hash/crc32) come from the standard library. No zip library chooses a name or extracts anything.
//
// Why: Phase D wave 1, owner request 2026-11-10 (spec ARCHIVE-01 to ARCHIVE-14).
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: files (a staging directory beside target_dir, renamed to target_dir on success) and the OS random
// source (the staging name). No network, no database, no money.
package archiveingest

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Limits are the injected caps; DefaultLimits gives the spec's defaults.
// Why: ARCHIVE-04 to -06, -08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type Limits struct {
	MaxArchiveBytes   int64
	MaxEntries        int64
	MaxFileBytes      int64
	MaxTotalBytes     int64
	MaxRatio          int64
	AllowedExtensions []string
}

// DefaultLimits returns the spec's default limits.
// In: none. Out: limits. Why: spec LIMITS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func DefaultLimits() Limits {
	return Limits{MaxArchiveBytes: 20971520, MaxEntries: 1000, MaxFileBytes: 26214400, MaxTotalBytes: 104857600,
		MaxRatio: 100, AllowedExtensions: []string{"txt", "md", "csv", "json", "pdf", "png", "jpg", "jpeg", "gif"}}
}

// FileInfo is one written (or, for inspect, listed) file; SHA256 is empty for inspect.
// Why: ARCHIVE-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type FileInfo struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
}

// Result is the answer of inspect_archive and extract_archive: ok with entries, total_bytes and files, or a
// refusal {error, status, entry_index}. A refusal names an index, never the entry's name.
// Why: spec CONVENTIONS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type Result struct {
	OK         bool       `json:"ok"`
	Entries    int64      `json:"entries,omitempty"`
	TotalBytes int64      `json:"total_bytes,omitempty"`
	Files      []FileInfo `json:"files,omitempty"`
	Error      string     `json:"error,omitempty"`
	Status     int        `json:"status,omitempty"`
	EntryIndex int        `json:"-"`
}

// MarshalJSON writes an ok answer as {ok, entries, total_bytes, files} and a refusal as {ok: false, error,
// status, entry_index}, so entry_index 0 is never dropped and never appears on an ok answer.
// In: none. Out: JSON. Why: spec CONVENTIONS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func (r Result) MarshalJSON() ([]byte, error) {
	if r.OK {
		return json.Marshal(map[string]any{"ok": true, "entries": r.Entries, "total_bytes": r.TotalBytes, "files": r.Files})
	}
	return json.Marshal(map[string]any{"ok": false, "error": r.Error, "status": r.Status, "entry_index": r.EntryIndex})
}

// refuse builds a refusal.
// In: error code, status, entry index (-1 for the whole archive). Out: result. Why: spec CONVENTIONS.
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func refuse(code string, status, index int) Result {
	return Result{Error: code, Status: status, EntryIndex: index}
}

// entry is one central-directory record, every number read unsigned into 64 bits.
// Why: READING THE ARCHIVE. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type entry struct {
	flags, method, crc, csize, usize int64
	diskStart, external, localOffset int64
	name, extra                      []byte
	isDir                            bool
}

// u16 and u32 read little-endian unsigned numbers into int64.
// In: bytes, offset. Out: value. Why: never a signed 32-bit int. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func u16(b []byte, o int64) int64 { return int64(binary.LittleEndian.Uint16(b[o : o+2])) }

// u32: see u16.
// In: bytes, offset. Out: value. Why: as u16. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func u32(b []byte, o int64) int64 { return int64(binary.LittleEndian.Uint32(b[o : o+4])) }

var (
	sigLocal   = []byte{0x50, 0x4B, 0x03, 0x04}
	sigCentral = []byte{0x50, 0x4B, 0x01, 0x02}
	sigEnd     = []byte{0x50, 0x4B, 0x05, 0x06}
	sigZip64   = []byte{0x50, 0x4B, 0x06, 0x07}
)

// checked is the outcome of checks A, B and C: the entries, cd_offset and the declared total.
// Why: shared by inspect and extract. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type checked struct {
	entries  []entry
	cdOffset int64
	total    int64
}

// check runs checks A, B and C in the spec's order; the first that fails answers.
// In: archive bytes, limits. Out: the checked archive, or a refusal. Why: ARCHIVE-02 to -12, -14.
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func check(data []byte, lim Limits) (*checked, *Result) {
	fail := func(code string, status, idx int) (*checked, *Result) {
		r := refuse(code, status, idx)
		return nil, &r
	}
	n := int64(len(data))
	if n == 0 {
		return fail("empty_upload", 400, -1)
	}
	if n > lim.MaxArchiveBytes {
		return fail("archive_too_large", 413, -1)
	}
	if n < 4 || !bytes.Equal(data[:4], sigLocal) {
		return fail("not_a_zip", 400, -1)
	}
	end := int64(-1)
	lowest := n - 65557
	if lowest < 0 {
		lowest = 0
	}
	for i := n - 22; i >= lowest; i-- {
		if bytes.Equal(data[i:i+4], sigEnd) && i+22+u16(data, i+20) == n {
			end = i
			break
		}
	}
	if end < 0 {
		return fail("not_a_zip", 400, -1)
	}
	disk, cdDisk := u16(data, end+4), u16(data, end+6)
	entriesHere, entries := u16(data, end+8), u16(data, end+10)
	cdSize, cdOffset := u32(data, end+12), u32(data, end+16)
	if disk != 0 || cdDisk != 0 || entriesHere != entries || entries == 0xFFFF || cdSize == 0xFFFFFFFF ||
		cdOffset == 0xFFFFFFFF || (end >= 20 && bytes.Equal(data[end-20:end-16], sigZip64)) {
		return fail("unsupported_zip", 400, -1)
	}
	if cdOffset+cdSize != end {
		return fail("not_a_zip", 400, -1)
	}
	if entries == 0 {
		return fail("empty_archive", 400, -1)
	}
	if entries > lim.MaxEntries {
		return fail("too_many_entries", 413, -1)
	}
	list := make([]entry, 0, entries)
	p := cdOffset
	for k := int64(0); k < entries; k++ {
		if p+46 > end || !bytes.Equal(data[p:p+4], sigCentral) {
			return fail("not_a_zip", 400, -1)
		}
		nl, el, cl := u16(data, p+28), u16(data, p+30), u16(data, p+32)
		if p+46+nl+el+cl > end {
			return fail("not_a_zip", 400, -1)
		}
		e := entry{flags: u16(data, p+8), method: u16(data, p+10), crc: u32(data, p+16), csize: u32(data, p+20),
			usize: u32(data, p+24), diskStart: u16(data, p+34), external: u32(data, p+38), localOffset: u32(data, p+42),
			name: data[p+46 : p+46+nl], extra: data[p+46+nl : p+46+nl+el]}
		e.isDir = len(e.name) > 0 && e.name[len(e.name)-1] == '/'
		list = append(list, e)
		p += 46 + nl + el + cl
	}
	if p != end {
		return fail("not_a_zip", 400, -1)
	}
	allowed := map[string]bool{}
	for _, x := range lim.AllowedExtensions {
		allowed[x] = true
	}
	files, dirs := map[string]bool{}, map[string]bool{}
	total, fileCount := int64(0), 0
	for idx, e := range list {
		if code, status := checkEntry(e, allowed, files, dirs); code != "" {
			return fail(code, status, idx)
		}
		if e.usize > lim.MaxFileBytes {
			return fail("entry_too_large", 413, idx)
		}
		total += e.usize
		if total > lim.MaxTotalBytes {
			return fail("total_too_large", 413, idx)
		}
		if !e.isDir {
			fileCount++
		}
	}
	if fileCount == 0 {
		return fail("empty_archive", 400, -1)
	}
	if total > lim.MaxRatio*n {
		return fail("compression_ratio_exceeded", 413, -1)
	}
	for idx, e := range list {
		if code := checkLocal(data, e, cdOffset); code != "" {
			return fail(code, 400, idx)
		}
	}
	return &checked{entries: list, cdOffset: cdOffset, total: total}, nil
}

// checkEntry runs C1 to C10 for one entry and records its KEY for later C10 checks.
// In: entry, allowed extensions, file and directory KEYs seen. Out: error code and status, or "".
// Why: ARCHIVE-02, -03, -07 (C8), -08, -09, -11, -12, -14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func checkEntry(e entry, allowed, files, dirs map[string]bool) (string, int) {
	if e.csize == 0xFFFFFFFF || e.usize == 0xFFFFFFFF || e.localOffset == 0xFFFFFFFF || e.diskStart != 0 {
		return "unsupported_zip", 400
	}
	if e.flags&0x2041 != 0 {
		return "encrypted_entry", 400
	}
	if e.method != 0 && e.method != 8 {
		return "unsupported_compression", 400
	}
	parts, ok := safeParts(e.name)
	if !ok {
		return "unsafe_path", 400
	}
	if badName(string(e.name), parts) {
		return "bad_name", 400
	}
	if code := checkExtra(e); code != "" {
		return code, 400
	}
	if t := (e.external >> 16) & 0xF000; t != 0 && t != 0x8000 && t != 0x4000 {
		return "special_file", 400
	}
	if (e.isDir && e.usize != 0) || (!e.isDir && e.method == 0 && e.csize != e.usize) {
		return "size_mismatch", 400
	}
	if !e.isDir && !allowed[extension(parts[len(parts)-1])] {
		return "extension_not_allowed", 400
	}
	key := asciiLower(strings.Join(parts, "/"))
	if files[key] || (!e.isDir && dirs[key]) {
		return "duplicate_name", 400
	}
	for i := 1; i < len(parts); i++ {
		if files[asciiLower(strings.Join(parts[:i], "/"))] {
			return "duplicate_name", 400
		}
	}
	if e.isDir {
		dirs[key] = true
	} else {
		files[key] = true
	}
	for i := 1; i < len(parts); i++ {
		dirs[asciiLower(strings.Join(parts[:i], "/"))] = true
	}
	return "", 0
}

// safeParts is C4: the name is non-empty strict UTF-8 with no byte under 0x20, no 0x7F or back-slash, no
// leading "/" or drive letter, and after one trailing "/" is removed, no part that is empty, "." or "..".
// In: raw name. Out: its parts, ok. Why: ARCHIVE-02 (zip slip). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func safeParts(name []byte) ([]string, bool) {
	if len(name) == 0 || !utf8.Valid(name) {
		return nil, false
	}
	for _, c := range name {
		if c < 0x20 || c == 0x7F || c == '\\' {
			return nil, false
		}
	}
	if name[0] == '/' {
		return nil, false
	}
	if len(name) >= 2 && name[1] == ':' && ((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z')) {
		return nil, false
	}
	s := strings.TrimSuffix(string(name), "/")
	parts := strings.Split(s, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return nil, false
		}
	}
	return parts, true
}

// badName is C5: names that do not unpack everywhere (length, invisible or direction characters, Windows'
// forbidden characters, trailing dot or space, reserved device names).
// In: name, its parts. Out: refused. Why: ARCHIVE-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func badName(name string, parts []string) bool {
	if len(name) > 1024 {
		return true
	}
	for _, r := range name {
		if (r >= 0x80 && r <= 0x9F) || r == 0x061C || (r >= 0x200B && r <= 0x200F) || (r >= 0x202A && r <= 0x202E) ||
			(r >= 0x2060 && r <= 0x2064) || (r >= 0x2066 && r <= 0x2069) || r == 0xFEFF {
			return true
		}
	}
	for _, p := range parts {
		if len(p) > 255 || strings.ContainsAny(p, ":*?\"<>|") || strings.HasSuffix(p, ".") || strings.HasSuffix(p, " ") {
			return true
		}
		base := p
		if i := strings.IndexByte(base, '.'); i >= 0 {
			base = base[:i]
		}
		base = strings.TrimRight(asciiLower(base), " ")
		switch base {
		case "con", "prn", "aux", "nul", "conin$", "conout$":
			return true
		}
		if len(base) >= 3 && (base[:3] == "com" || base[:3] == "lpt") {
			rest := base[3:]
			if (len(rest) == 1 && rest[0] >= '0' && rest[0] <= '9') || rest == "¹" || rest == "²" || rest == "³" {
				return true
			}
		}
	}
	return false
}

// checkExtra is C6: the extra field is a well-formed list of (id, size, data) blocks; a Unicode Path block
// (0x7075) of version 1 must name the entry byte for byte. Structure faults (not_a_zip) are found first.
// In: entry. Out: "", "not_a_zip" or "header_mismatch". Why: ARCHIVE-12. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func checkExtra(e entry) string {
	x := e.extra
	type block struct {
		id   int64
		data []byte
	}
	blocks := []block{}
	for p := int64(0); p < int64(len(x)); {
		left := int64(len(x)) - p
		if left < 4 {
			return "not_a_zip"
		}
		id, size := u16(x, p), u16(x, p+2)
		if size > left-4 {
			return "not_a_zip"
		}
		if id == 0x7075 && size < 5 {
			return "not_a_zip"
		}
		blocks = append(blocks, block{id, x[p+4 : p+4+size]})
		p += 4 + size
	}
	for _, b := range blocks {
		if b.id == 0x7075 && b.data[0] == 1 && !bytes.Equal(b.data[5:], e.name) {
			return "header_mismatch"
		}
	}
	return ""
}

// extension is the text after the last "." of the last part, ASCII lower case; "" when the part has no "." or
// its only "." is its first character.
// In: last part. Out: extension. Why: C9 (ARCHIVE-08). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func extension(part string) string {
	i := strings.LastIndexByte(part, '.')
	if i <= 0 {
		return ""
	}
	return asciiLower(part[i+1:])
}

// asciiLower maps A-Z to a-z and changes nothing else.
// In: text. Out: text. Why: KEY and reserved names. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// checkLocal is C15: the local record must lie before the central directory and agree with the central record.
// In: archive, entry, cd_offset. Out: "", "not_a_zip" or "header_mismatch". Why: ARCHIVE-12. 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func checkLocal(data []byte, e entry, cdOffset int64) string {
	lo := e.localOffset
	if lo+30 > cdOffset || !bytes.Equal(data[lo:lo+4], sigLocal) {
		return "not_a_zip"
	}
	nl, el := u16(data, lo+26), u16(data, lo+28)
	if lo+30+nl+el+e.csize > cdOffset {
		return "not_a_zip"
	}
	if !bytes.Equal(data[lo+30:lo+30+nl], e.name) || u16(data, lo+6) != e.flags || u16(data, lo+8) != e.method {
		return "header_mismatch"
	}
	if e.flags&0x8 == 0 && (u32(data, lo+14) != e.crc || u32(data, lo+18) != e.csize || u32(data, lo+22) != e.usize) {
		return "header_mismatch"
	}
	return ""
}

// InspectArchive runs checks A, B and C; it reads no file data and writes nothing.
// In: archive bytes, limits. Out: {ok, entries, total_bytes, files [{path, size}]} or a refusal.
// Why: ARCHIVE-02 to -12, -14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func InspectArchive(data []byte, lim Limits) Result {
	c, ref := check(data, lim)
	if ref != nil {
		return *ref
	}
	files := []FileInfo{}
	for _, e := range c.entries {
		if !e.isDir {
			files = append(files, FileInfo{Path: string(e.name), Size: e.usize})
		}
	}
	return Result{OK: true, Entries: int64(len(c.entries)), TotalBytes: c.total, Files: files}
}

// errCorrupt marks an entry whose data is wrong (D3).
// Why: ARCHIVE-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
var errCorrupt = errors.New("corrupt_entry")

// readEntry returns an entry's bytes: stored as is, or raw DEFLATE inflated to at most usize + 1 bytes. Too
// many or too few bytes, invalid data, or a CRC that differs is errCorrupt. Input that runs out only ends the
// output; the size and the CRC then decide.
// In: archive, entry. Out: bytes or errCorrupt. Why: ARCHIVE-06, -07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches nothing.
func readEntry(data []byte, e entry) ([]byte, error) {
	lo := e.localOffset
	start := lo + 30 + u16(data, lo+26) + u16(data, lo+28)
	raw := data[start : start+e.csize]
	var out []byte
	if e.method == 0 {
		out = raw
	} else {
		r := flate.NewReader(bytes.NewReader(raw))
		got, err := io.ReadAll(io.LimitReader(r, e.usize+1))
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errCorrupt
		}
		out = got
	}
	if int64(len(out)) != e.usize || int64(crc32.ChecksumIEEE(out)) != e.crc {
		return nil, errCorrupt
	}
	return out, nil
}

// randomHex returns n random hex characters.
// In: n (even). Out: text. Why: the STAGING name (D2). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: the OS random source.
func randomHex(n int) (string, error) {
	b := make([]byte, n/2)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ExtractArchive runs checks A, B and C, then writes every entry into a staging directory beside targetDir and
// renames it to targetDir. On any refusal or error the staging directory is removed, so targetDir exists only
// when every file was written. targetDir comes from the server, never from the upload.
// In: archive bytes, target directory (must not exist; its parent must), limits. Out: {ok, entries,
// total_bytes, files [{path, size, sha256}]} or a refusal (409 target_exists, 500 target_unwritable,
// 400 unsafe_path / corrupt_entry / duplicate_name, or any check's answer).
// Why: ARCHIVE-01, -06, -07, -13, -14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: files under the target's parent directory, the OS random source.
func ExtractArchive(data []byte, targetDir string, lim Limits) Result {
	c, ref := check(data, lim)
	if ref != nil {
		return *ref
	}
	if _, err := os.Lstat(targetDir); err == nil || !errors.Is(err, os.ErrNotExist) {
		return refuse("target_exists", 409, -1)
	}
	suffix, err := randomHex(16)
	if err != nil {
		return refuse("target_unwritable", 500, -1)
	}
	staging := targetDir + ".partial-" + suffix
	if err := os.Mkdir(staging, 0o700); err != nil {
		return refuse("target_unwritable", 500, -1)
	}
	files, res := writeAll(data, c, staging)
	if res != nil {
		_ = os.RemoveAll(staging)
		return *res
	}
	if err := os.Rename(staging, targetDir); err != nil {
		_ = os.RemoveAll(staging)
		return refuse("target_unwritable", 500, -1)
	}
	return Result{OK: true, Entries: int64(len(c.entries)), TotalBytes: c.total, Files: files}
}

// writeAll is D3: each entry in directory order, directories 0755, files created exclusively with 0644.
// In: archive, checked archive, staging directory. Out: the files written, or a refusal.
// Why: ARCHIVE-01, -07, -13, -14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files under staging.
func writeAll(data []byte, c *checked, staging string) ([]FileInfo, *Result) {
	fail := func(code string, status, idx int) ([]FileInfo, *Result) {
		r := refuse(code, status, idx)
		return nil, &r
	}
	root := filepath.Clean(staging) + string(filepath.Separator)
	files := []FileInfo{}
	for idx, e := range c.entries {
		parts, _ := safeParts(e.name)
		dest := filepath.Join(append([]string{staging}, parts...)...)
		if !strings.HasPrefix(filepath.Clean(dest), root) {
			return fail("unsafe_path", 400, idx)
		}
		if e.isDir {
			if err := os.MkdirAll(dest, 0o755); err != nil {
				return fail("target_unwritable", 500, -1)
			}
			continue
		}
		body, err := readEntry(data, e)
		if err != nil {
			return fail("corrupt_entry", 400, idx)
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return fail("target_unwritable", 500, -1)
		}
		f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				return fail("duplicate_name", 400, idx)
			}
			return fail("target_unwritable", 500, -1)
		}
		_, werr := f.Write(body)
		cerr := f.Close()
		if werr != nil || cerr != nil || os.Chmod(dest, 0o644) != nil {
			return fail("target_unwritable", 500, -1)
		}
		sum := sha256.Sum256(body)
		files = append(files, FileInfo{Path: string(e.name), Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])})
	}
	return files, nil
}
