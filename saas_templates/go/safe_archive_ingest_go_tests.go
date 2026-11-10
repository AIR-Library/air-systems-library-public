package archiveingest

// Tests for safe_archive_ingest_go.go against docs/specs/safe_archive_ingest.md.
// Phase D wave 1, owner request 2026-11-10. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: files in per-test temporary directories (t.TempDir); no network.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// zentry is one build_zip entry; nil pointers take the spec's defaults (usize = len(data), crc = CRC-32 of
// data, local_name = name).
// Why: TEST ARCHIVE BUILDER. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
type zentry struct {
	name      string
	data      []byte
	method    uint16
	usize     *uint32
	crc       *uint32
	flags     uint16
	external  uint32
	creator   uint16
	extra     []byte
	localName *string
}

// u32p returns a pointer to v.
// In: v. Out: pointer. Why: builder options. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func u32p(v uint32) *uint32 { return &v }

// strp returns a pointer to s.
// In: s. Out: pointer. Why: builder options. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func strp(s string) *string { return &s }

// buildZip is build_zip: local records, central records and the end record, exactly as the spec lays them out.
// In: entries, comment. Out: archive bytes. Why: ARCHIVE-01 (byte-for-byte BASIC). 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func buildZip(entries []zentry, comment string) []byte {
	var out, cd bytes.Buffer
	le := func(b *bytes.Buffer, v any) { _ = binary.Write(b, binary.LittleEndian, v) }
	offsets := []uint32{}
	for _, e := range entries {
		usize, crc, local := uint32(len(e.data)), crc32.ChecksumIEEE(e.data), e.name
		if e.usize != nil {
			usize = *e.usize
		}
		if e.crc != nil {
			crc = *e.crc
		}
		if e.localName != nil {
			local = *e.localName
		}
		offsets = append(offsets, uint32(out.Len()))
		out.Write([]byte{0x50, 0x4B, 0x03, 0x04})
		le(&out, uint16(20))
		le(&out, e.flags)
		le(&out, e.method)
		le(&out, uint16(0))
		le(&out, uint16(0x0021))
		le(&out, crc)
		le(&out, uint32(len(e.data)))
		le(&out, usize)
		le(&out, uint16(len(local)))
		le(&out, uint16(0))
		out.WriteString(local)
		out.Write(e.data)
	}
	for i, e := range entries {
		usize, crc := uint32(len(e.data)), crc32.ChecksumIEEE(e.data)
		if e.usize != nil {
			usize = *e.usize
		}
		if e.crc != nil {
			crc = *e.crc
		}
		cd.Write([]byte{0x50, 0x4B, 0x01, 0x02})
		le(&cd, e.creator*256+20)
		le(&cd, uint16(20))
		le(&cd, e.flags)
		le(&cd, e.method)
		le(&cd, uint16(0))
		le(&cd, uint16(0x0021))
		le(&cd, crc)
		le(&cd, uint32(len(e.data)))
		le(&cd, usize)
		le(&cd, uint16(len(e.name)))
		le(&cd, uint16(len(e.extra)))
		le(&cd, uint16(0))
		le(&cd, uint16(0))
		le(&cd, uint16(0))
		le(&cd, e.external)
		le(&cd, offsets[i])
		cd.WriteString(e.name)
		cd.Write(e.extra)
	}
	cdOffset := uint32(out.Len())
	cdSize := uint32(cd.Len())
	out.Write(cd.Bytes())
	out.Write([]byte{0x50, 0x4B, 0x05, 0x06})
	le(&out, uint16(0))
	le(&out, uint16(0))
	le(&out, uint16(len(entries)))
	le(&out, uint16(len(entries)))
	le(&out, cdSize)
	le(&out, cdOffset)
	le(&out, uint16(len(comment)))
	out.WriteString(comment)
	return out.Bytes()
}

// basicEntries are the entries of the spec's BASIC archive.
// In: none. Out: entries. Why: ARCHIVE-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func basicEntries() []zentry {
	return []zentry{{name: "docs/", external: 0x41ED0000, creator: 3}, {name: "docs/readme.txt", data: []byte("hello\n")},
		{name: "data.csv", data: []byte("a,b\n1,2\n"), external: 0x81ED0000, creator: 3}}
}

// basic is the spec's BASIC archive.
// In: none. Out: bytes. Why: ARCHIVE-01, -10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func basic() []byte { return buildZip(basicEntries(), "") }

// mustHex decodes a hex vector.
// In: hex. Out: bytes. Why: vectors. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// zStream is Z, the raw DEFLATE stream of 2000 zero bytes.
// Why: ARCHIVE-06, -07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
var zStream = mustHex("63601805a360148c8251300a46c1500700")

// zeros is the spec's ZEROS archive with the given usize and crc.
// In: usize, crc. Out: bytes. Why: ARCHIVE-06, -07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func zeros(data []byte, usize, crc uint32) []byte {
	return buildZip([]zentry{{name: "zeros.txt", data: data, method: 8, usize: u32p(usize), crc: u32p(crc)}}, "")
}

// expectRefusal extracts into a fresh temporary directory and checks the refusal, that the target is absent
// and that nothing was left beside it.
// In: archive, limits, code, status, index. Out: none (fails the test). Why: ARCHIVE-02, -07, -13.
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: a temporary directory.
func expectRefusal(t *testing.T, label string, data []byte, lim Limits, code string, status, index int) {
	t.Helper()
	parent := t.TempDir()
	target := filepath.Join(parent, "out")
	got := ExtractArchive(data, target, lim)
	want := Result{Error: code, Status: status, EntryIndex: index}
	if got.OK || got.Error != want.Error || got.Status != want.Status || got.EntryIndex != want.EntryIndex {
		t.Fatalf("%s: got %+v, want %+v", label, got, want)
	}
	if ins := InspectArchive(data, lim); !(ins.Error == code && ins.EntryIndex == index) && code != "corrupt_entry" && code != "target_exists" {
		t.Fatalf("%s: inspect = %+v", label, ins)
	}
	left, _ := os.ReadDir(parent)
	if len(left) != 0 {
		t.Fatalf("%s: left %d entries beside the target", label, len(left))
	}
}

// expectOK extracts into a fresh temporary directory and returns the result and target.
// In: archive, limits. Out: result, target. Why: accepted cases. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: a temporary directory.
func expectOK(t *testing.T, label string, data []byte, lim Limits) (Result, string) {
	t.Helper()
	target := filepath.Join(t.TempDir(), "out")
	got := ExtractArchive(data, target, lim)
	if !got.OK {
		t.Fatalf("%s: refused %+v", label, got)
	}
	return got, target
}

// TestArchive01BasicArchive proves the builder's bytes and the extraction of BASIC.
// ARCHIVE-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: a temporary directory.
func TestArchive01BasicArchive(t *testing.T) {
	want := "504b03041400000000000000210000000000000000000000000005000000646f63732f504b0304140000000000000021" +
		"0020303a3606000000060000000f000000646f63732f726561646d652e74787468656c6c6f0a504b0304140000000000" +
		"000021007b07970a080000000800000008000000646174612e637376612c620a312c320a504b01021403140000000000" +
		"00002100000000000000000000000000050000000000000000000000ed4100000000646f63732f504b01021400140000" +
		"0000000000210020303a3606000000060000000f0000000000000000000000000023000000646f63732f726561646d65" +
		"2e747874504b01021403140000000000000021007b07970a0800000008000000080000000000000000000000ed815600" +
		"0000646174612e637376504b05060000000003000300a6000000840000000000"
	if got := hex.EncodeToString(basic()); got != want || len(basic()) != 320 {
		t.Fatalf("BASIC = %s", got)
	}
	res, target := expectOK(t, "basic", basic(), DefaultLimits())
	if res.Entries != 3 || res.TotalBytes != 14 || len(res.Files) != 2 ||
		res.Files[0] != (FileInfo{Path: "docs/readme.txt", Size: 6, SHA256: "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"}) ||
		res.Files[1] != (FileInfo{Path: "data.csv", Size: 8, SHA256: "492d5ea496056f1a6a6592241032fab764c321596317930b4fa0e1e8bc3b7470"}) {
		t.Fatalf("result = %+v", res)
	}
	if b, _ := os.ReadFile(filepath.Join(target, "docs", "readme.txt")); string(b) != "hello\n" {
		t.Fatalf("readme = %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(target, "data.csv")); string(b) != "a,b\n1,2\n" {
		t.Fatalf("data.csv = %q", b)
	}
	if st, err := os.Stat(filepath.Join(target, "docs")); err != nil || !st.IsDir() {
		t.Fatal("docs is not a directory")
	}
	ins := InspectArchive(basic(), DefaultLimits())
	if !ins.OK || ins.Entries != 3 || ins.TotalBytes != 14 || ins.Files[1] != (FileInfo{Path: "data.csv", Size: 8}) {
		t.Fatalf("inspect = %+v", ins)
	}
}

// TestArchive02ZipSlip proves every traversal and malformed name is 400 unsafe_path with its index.
// ARCHIVE-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary directories.
func TestArchive02ZipSlip(t *testing.T) {
	names := []string{"../evil.txt", "a/../../evil.txt", "/etc/passwd.txt", "C:/x.txt", "a\\b.txt", "a//b.txt", "./a.txt",
		"a\x00b.txt", "a\x01b.txt", "",
		string([]byte{0x61, 0xC0, 0xAF, 0x62, 0x2E, 0x74, 0x78, 0x74}),
		string([]byte{0x61, 0xED, 0xA0, 0x80, 0x2E, 0x74, 0x78, 0x74}),
		string([]byte{0x61, 0xF4, 0x90, 0x80, 0x80, 0x2E, 0x74, 0x78, 0x74}),
		string([]byte{0x61, 0xE2, 0x82, 0x2E, 0x74, 0x78, 0x74})}
	for i, n := range names {
		z := buildZip([]zentry{{name: "ok.txt", data: []byte("ok")}, {name: n, data: []byte("evil")}}, "")
		expectRefusal(t, "name "+string(rune('a'+i)), z, DefaultLimits(), "unsafe_path", 400, 1)
	}
}

// TestArchive03SpecialFiles proves links and FIFOs are refused whatever the creator, and regular files pass.
// ARCHIVE-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary directories.
func TestArchive03SpecialFiles(t *testing.T) {
	for _, creator := range []uint16{0, 3, 19} {
		z := buildZip([]zentry{{name: "link.txt", data: []byte("/etc/passwd"), external: 0xA1FF0000, creator: creator}}, "")
		expectRefusal(t, "link", z, DefaultLimits(), "special_file", 400, 0)
	}
	expectRefusal(t, "fifo", buildZip([]zentry{{name: "f.txt", data: []byte("x"), external: 0x11A40000, creator: 3}}, ""),
		DefaultLimits(), "special_file", 400, 0)
	expectOK(t, "regular", buildZip([]zentry{{name: "f.txt", data: []byte("x"), external: 0x81A40000, creator: 3}}, ""), DefaultLimits())
}

// TestArchive04EntryAndArchiveLimits proves max_entries and max_archive_bytes, exactly at and over the limit.
// ARCHIVE-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary directories.
func TestArchive04EntryAndArchiveLimits(t *testing.T) {
	z := buildZip([]zentry{{name: "a.txt", data: []byte("x")}, {name: "b.txt", data: []byte("x")}, {name: "c.txt", data: []byte("x")}}, "")
	if len(z) != 283 {
		t.Fatalf("size = %d", len(z))
	}
	lim := DefaultLimits()
	lim.MaxEntries, lim.MaxArchiveBytes = 3, 283
	expectOK(t, "at limits", z, lim)
	lim.MaxEntries = 2
	expectRefusal(t, "entries", z, lim, "too_many_entries", 413, -1)
	lim.MaxEntries, lim.MaxArchiveBytes = 3, 282
	expectRefusal(t, "bytes", z, lim, "archive_too_large", 413, -1)
}

// TestArchive05SizeLimits proves max_total_bytes and max_file_bytes, and that sizes are read unsigned.
// ARCHIVE-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary directories.
func TestArchive05SizeLimits(t *testing.T) {
	z := buildZip([]zentry{{name: "a.txt", data: []byte("12345")}, {name: "b.txt", data: []byte("67890")}}, "")
	if len(z) != 204 {
		t.Fatalf("size = %d", len(z))
	}
	lim := DefaultLimits()
	lim.MaxTotalBytes, lim.MaxFileBytes = 10, 5
	expectOK(t, "at limits", z, lim)
	lim.MaxTotalBytes = 9
	expectRefusal(t, "total", z, lim, "total_too_large", 413, 1)
	lim.MaxTotalBytes, lim.MaxFileBytes = 10, 4
	expectRefusal(t, "file", z, lim, "entry_too_large", 413, 0)
	big := buildZip([]zentry{{name: "a.txt", data: zStream, method: 8, usize: u32p(0x80000000), crc: u32p(0)}}, "")
	expectRefusal(t, "unsigned", big, DefaultLimits(), "entry_too_large", 413, 0)
	lim = DefaultLimits()
	lim.MaxFileBytes, lim.MaxTotalBytes = 4294967296, 4294967296
	expectRefusal(t, "unsigned ratio", big, lim, "compression_ratio_exceeded", 413, -1)
}

// TestArchive06CompressionRatio proves the ratio cap on ZEROS: 15 refuses, 16 extracts 2000 zero bytes.
// ARCHIVE-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary directories.
func TestArchive06CompressionRatio(t *testing.T) {
	z := zeros(zStream, 2000, 0x02C9F444)
	if len(z) != 133 {
		t.Fatalf("ZEROS size = %d", len(z))
	}
	lim := DefaultLimits()
	lim.MaxRatio = 15
	expectRefusal(t, "ratio 15", z, lim, "compression_ratio_exceeded", 413, -1)
	lim.MaxRatio = 16
	_, target := expectOK(t, "ratio 16", z, lim)
	if b, _ := os.ReadFile(filepath.Join(target, "zeros.txt")); !bytes.Equal(b, make([]byte, 2000)) {
		t.Fatalf("zeros.txt has %d bytes", len(b))
	}
}

// TestArchive07LyingHeaders proves every data fault is 400 corrupt_entry, a stored size mismatch is
// size_mismatch, and no file is left.
// ARCHIVE-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary directories.
func TestArchive07LyingHeaders(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxRatio = 1000
	bad := mustHex("62601805a360148c8251300a46c1500700000000ffff07")
	cases := map[string][]byte{
		"declares 10":       zeros(zStream, 10, 0xE38A6876),
		"declares 3000":     zeros(zStream, 3000, 0x02C9F444),
		"cut stream":        zeros(zStream[:len(zStream)-4], 2000, 0x02C9F444),
		"deflated bad crc":  zeros(zStream, 2000, 1),
		"stored bad crc":    buildZip([]zentry{{name: "a.txt", data: []byte("12345"), crc: u32p(0)}}, ""),
		"invalid data":      buildZip([]zentry{{name: "zeros.txt", data: []byte{0xFF, 0xFF, 0xFF, 0xFF}, method: 8, usize: u32p(4), crc: u32p(0)}}, ""),
		"overrun then junk": zeros(bad, 10, 0xE38A6876),
	}
	for label, z := range cases {
		expectRefusal(t, label, z, lim, "corrupt_entry", 400, 0)
	}
	expectRefusal(t, "stored sizes differ", buildZip([]zentry{{name: "a.txt", data: []byte("12345"), usize: u32p(4)}}, ""),
		lim, "size_mismatch", 400, 0)
}

// TestArchive08Extensions proves the extension allow-list, its case rule and a custom list.
// ARCHIVE-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary directories.
func TestArchive08Extensions(t *testing.T) {
	one := func(name string) []byte { return buildZip([]zentry{{name: name, data: []byte("x")}}, "") }
	for _, n := range []string{"run.exe", "a.txt.sh", "README", ".env", "inner.zip"} {
		expectRefusal(t, n, one(n), DefaultLimits(), "extension_not_allowed", 400, 0)
	}
	for _, n := range []string{"A.TXT", "x.Json"} {
		expectOK(t, n, one(n), DefaultLimits())
	}
	lim := DefaultLimits()
	lim.AllowedExtensions = []string{"", "sh"}
	for _, n := range []string{"README", "a.sh"} {
		expectOK(t, n, one(n), lim)
	}
}

// TestArchive09DuplicateNames proves every duplicate pair is refused at index 1 and a repeated directory is not.
// ARCHIVE-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary directories.
func TestArchive09DuplicateNames(t *testing.T) {
	pairs := [][2]string{{"a.txt", "a.txt"}, {"A.txt", "a.txt"}, {"d.txt/", "d.txt"}, {"d.txt", "d.txt/"},
		{"d.txt", "d.txt/e.txt"}, {"d.txt/e.txt", "d.txt"}}
	for _, p := range pairs {
		z := buildZip([]zentry{{name: p[0], data: dataFor(p[0])}, {name: p[1], data: dataFor(p[1])}}, "")
		expectRefusal(t, p[0]+" then "+p[1], z, DefaultLimits(), "duplicate_name", 400, 1)
	}
	expectOK(t, "same directory twice", buildZip([]zentry{{name: "d/"}, {name: "d/"}, {name: "d/a.txt", data: []byte("x")}}, ""), DefaultLimits())
}

// dataFor gives a file entry one byte and a directory entry none.
// In: name. Out: data. Why: ARCHIVE-09 helper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func dataFor(name string) []byte {
	if strings.HasSuffix(name, "/") {
		return nil
	}
	return []byte("x")
}

// TestArchive10Container proves the container checks: empty, not a zip, truncation, counts, trailing bytes,
// wrapping offsets, disks, zip64, the short input, a directory only, and a comment.
// ARCHIVE-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary directories.
func TestArchive10Container(t *testing.T) {
	lim := DefaultLimits()
	expectRefusal(t, "empty", []byte{}, lim, "empty_upload", 400, -1)
	expectRefusal(t, "text", []byte("this is plain text, not a zip archive"), lim, "not_a_zip", 400, -1)
	b := basic()
	n := len(b)
	expectRefusal(t, "truncated", b[:n-10], lim, "not_a_zip", 400, -1)
	counts := append([]byte{}, b...)
	binary.LittleEndian.PutUint16(counts[n-14:], 4)
	binary.LittleEndian.PutUint16(counts[n-12:], 4)
	expectRefusal(t, "count", counts, lim, "not_a_zip", 400, -1)
	expectRefusal(t, "trailing byte", append(append([]byte{}, b...), 0), lim, "not_a_zip", 400, -1)
	disk := append([]byte{}, b...)
	binary.LittleEndian.PutUint16(disk[n-18:], 1)
	expectRefusal(t, "disk", disk, lim, "unsupported_zip", 400, -1)
	ff := append([]byte{}, b...)
	binary.LittleEndian.PutUint16(ff[n-14:], 0xFFFF)
	binary.LittleEndian.PutUint16(ff[n-12:], 0xFFFF)
	expectRefusal(t, "zip64 count", ff, lim, "unsupported_zip", 400, -1)
	wrap := append([]byte{}, b...)
	binary.LittleEndian.PutUint32(wrap[n-10:], 300)
	binary.LittleEndian.PutUint32(wrap[n-6:], 0xFFFFFFFE)
	expectRefusal(t, "wrap", wrap, lim, "not_a_zip", 400, -1)
	expectRefusal(t, "directory only", buildZip([]zentry{{name: "docs/"}}, ""), lim, "empty_archive", 400, -1)
	short := mustHex("504b0304504b0506000000000000000000000000040000001000504b0607787878787878787878787878")
	if len(short) != 42 {
		t.Fatal("vector length")
	}
	expectRefusal(t, "short zip64 mark", short, lim, "empty_archive", 400, -1)
	expectOK(t, "comment", buildZip(basicEntries(), strings.Repeat("c", 40)), lim)
}

// TestArchive11FlagsAndMethods proves encryption flags and unknown methods are refused, and bit 3 is accepted.
// ARCHIVE-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary directories.
func TestArchive11FlagsAndMethods(t *testing.T) {
	for _, f := range []uint16{0x1, 0x40} {
		expectRefusal(t, "flag", buildZip([]zentry{{name: "a.txt", data: []byte("12345"), flags: f}}, ""), DefaultLimits(), "encrypted_entry", 400, 0)
	}
	expectRefusal(t, "method", buildZip([]zentry{{name: "a.txt", data: []byte("12345"), method: 12}}, ""), DefaultLimits(), "unsupported_compression", 400, 0)
	_, target := expectOK(t, "bit 3", buildZip([]zentry{{name: "a.txt", data: []byte("12345"), flags: 8}}, ""), DefaultLimits())
	if b, _ := os.ReadFile(filepath.Join(target, "a.txt")); string(b) != "12345" {
		t.Fatalf("a.txt = %q", b)
	}
}

// TestArchive12HeaderMismatch proves local/central disagreement, the Unicode Path field rules and an extra
// field that overruns.
// ARCHIVE-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary directories.
func TestArchive12HeaderMismatch(t *testing.T) {
	expectRefusal(t, "local name", buildZip([]zentry{{name: "ok.txt", data: []byte("x"), localName: strp("no.txt")}}, ""),
		DefaultLimits(), "header_mismatch", 400, 0)
	expectRefusal(t, "local name second", buildZip([]zentry{{name: "a.txt", data: []byte("x")},
		{name: "ok.txt", data: []byte("x"), localName: strp("no.txt")}}, ""), DefaultLimits(), "header_mismatch", 400, 1)
	evil := mustHex("75701000012a0419052e2e2f6576696c2e747874")
	expectRefusal(t, "unicode path", buildZip([]zentry{{name: "ok.txt", data: []byte("x"), extra: evil}}, ""),
		DefaultLimits(), "header_mismatch", 400, 0)
	same := mustHex("75700b0001") // id 0x7075, size 11, version 1
	crc := make([]byte, 4)
	binary.LittleEndian.PutUint32(crc, crc32.ChecksumIEEE([]byte("ok.txt")))
	same = append(append(same, crc...), []byte("ok.txt")...)
	expectOK(t, "unicode path same name", buildZip([]zentry{{name: "ok.txt", data: []byte("x"), extra: same}}, ""), DefaultLimits())
	expectRefusal(t, "overrun", buildZip([]zentry{{name: "ok.txt", data: []byte("x"), extra: mustHex("0a0032006162")}}, ""),
		DefaultLimits(), "not_a_zip", 400, 0)
}

// TestArchive13AllOrNothing proves a corrupt second entry leaves nothing, and the target_exists and
// target_unwritable answers.
// ARCHIVE-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary directories.
func TestArchive13AllOrNothing(t *testing.T) {
	z := buildZip([]zentry{{name: "a.txt", data: []byte("good")}, {name: "b.txt", data: []byte("bad!"), crc: u32p(1)}}, "")
	expectRefusal(t, "corrupt second", z, DefaultLimits(), "corrupt_entry", 400, 1)
	parent := t.TempDir()
	target := filepath.Join(parent, "out")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep.txt"), []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ExtractArchive(basic(), target, DefaultLimits()); got.Error != "target_exists" || got.Status != 409 || got.EntryIndex != -1 {
		t.Fatalf("existing target = %+v", got)
	}
	if b, _ := os.ReadFile(filepath.Join(target, "keep.txt")); string(b) != "mine" {
		t.Fatal("the existing target changed")
	}
	link := filepath.Join(parent, "dangling")
	if err := os.Symlink(filepath.Join(parent, "nowhere"), link); err == nil {
		if got := ExtractArchive(basic(), link, DefaultLimits()); got.Error != "target_exists" {
			t.Fatalf("dangling link = %+v", got)
		}
	}
	if got := ExtractArchive(basic(), filepath.Join(parent, "missing", "out"), DefaultLimits()); got.Error != "target_unwritable" || got.Status != 500 || got.EntryIndex != -1 {
		t.Fatalf("missing parent = %+v", got)
	}
}

// TestArchive13D3IoFailureNamesTheEntry proves a D3 I/O failure names the entry being written. The target's
// parent sits deep enough that the first entry fits but the second entry's full path is longer than the system's
// path limit (its name passes every check of C: 4 parts of 200 bytes), so creating it fails with an I/O error. The
// answer is 500 target_unwritable with entry_index 1, the target does not exist and no staging directory is left.
// In: t. Out: pass/fail. Why: ARCHIVE-13 and the spec's CONVENTIONS (D3 names the entry being written; Go answered
// -1, the same gap as review finding 4525344113). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: temporary directories.
func TestArchive13D3IoFailureNamesTheEntry(t *testing.T) {
	limit := 4096 // Linux PATH_MAX
	if runtime.GOOS == "darwin" {
		limit = 1024
	}
	deep := t.TempDir()
	for len(deep) < limit-600 {
		deep = filepath.Join(deep, strings.Repeat("p", 200))
		if err := os.Mkdir(deep, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	part := strings.Repeat("d", 200)
	longName := strings.Join([]string{part, part, part, part, "f.txt"}, "/")
	z := buildZip([]zentry{{name: "first.txt", data: []byte("ok")}, {name: longName, data: []byte("x")}}, "")
	target := filepath.Join(deep, "target")
	got := ExtractArchive(z, target, DefaultLimits())
	if got.Error != "target_unwritable" || got.Status != 500 || got.EntryIndex != 1 {
		t.Fatalf("D3 I/O failure = %+v, want target_unwritable 500 entry_index 1", got)
	}
	if _, err := os.Lstat(target); err == nil {
		t.Fatal("the target exists")
	}
	left, err := os.ReadDir(deep)
	if err != nil || len(left) != 0 {
		t.Fatalf("left behind: %v %v", left, err)
	}
}

// TestArchive14BadNames proves names that do not unpack everywhere are bad_name, the accepted near-misses, and
// that a 0755 entry is written without execute permission.
// ARCHIVE-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temporary directories.
func TestArchive14BadNames(t *testing.T) {
	bad := []string{"CON.txt", "com1.txt", "COM0.txt", "LPT0.txt", "COM\u00b9.txt", "CONIN$.txt", "CONOUT$.txt", "a.", "a ",
		"a?.txt", strings.Repeat("x", 252) + ".txt", "a\u202eb.txt"}
	for _, n := range bad {
		expectRefusal(t, n, buildZip([]zentry{{name: n, data: []byte("x")}}, ""), DefaultLimits(), "bad_name", 400, 0)
	}
	for _, n := range []string{"caf\u00e9.txt", strings.Repeat("x", 251) + ".txt", "COM10.txt", "conin.txt"} {
		expectOK(t, n, buildZip([]zentry{{name: n, data: []byte("x")}}, ""), DefaultLimits())
	}
	_, target := expectOK(t, "basic", basic(), DefaultLimits())
	st, err := os.Stat(filepath.Join(target, "data.csv"))
	if err != nil || st.Mode().Perm()&0o111 != 0 || st.Mode().Perm() != 0o644 {
		t.Fatalf("data.csv mode = %v", st.Mode())
	}
}
