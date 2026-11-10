import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.CRC32;

/**
 * Tests for SafeArchiveIngest (spec docs/specs/safe_archive_ingest.md, ARCHIVE-01 to ARCHIVE-14), with the spec's
 * test archive builder (no compressor needed) and a temporary directory as the storage root. Run through main(); a
 * failed check exits 1. Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files in a temporary directory, removed at the end. No database, network or money.
 */
public class safe_archive_ingest_java_tests {

    static Path root;

    /**
     * Runs every test, then removes the temporary root. ARCHIVE-14 writes a UTF-8 file name (caf\u00e9.txt), which a
     * JVM can only do when its file-name encoding (sun.jnu.encoding, fixed at start-up from the locale) is UTF-8. Under
     * the POSIX locale it is ASCII, so the suite then runs itself once more in a child JVM with LC_ALL=C.UTF-8 and
     * exits with the child's code: every test still runs, nothing is skipped.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files in a temporary directory; may start one child JVM.
     */
    public static void main(String[] args) {
        if (!"UTF-8".equalsIgnoreCase(System.getProperty("sun.jnu.encoding")) && System.getenv("ARCHIVE_TESTS_CHILD") == null) {
            try {
                ProcessBuilder pb = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                        "-cp", System.getProperty("java.class.path"), "safe_archive_ingest_java_tests");
                pb.environment().put("LC_ALL", "C.UTF-8");
                pb.environment().put("ARCHIVE_TESTS_CHILD", "1");
                pb.inheritIO();
                System.exit(pb.start().waitFor());
            } catch (IOException | InterruptedException e) {
                e.printStackTrace();
                System.exit(1);
            }
        }
        try {
            root = Files.createTempDirectory("archive-tests");
            testBasic();
            testZipSlip();
            testSpecialFiles();
            testEntryAndArchiveLimits();
            testSizeLimits();
            testRatio();
            testLyingHeaders();
            testExtensions();
            testDuplicates();
            testContainer();
            testFlagsAndMethods();
            testHeaderMismatch();
            testAllOrNothing();
            testBadNames();
            System.out.println("All tests passed");
        } catch (Throwable e) {
            e.printStackTrace();
            System.exit(1);
        } finally {
            removeTree(root);
        }
    }

    // ------------------------------------------------------------------------------------------------ helpers
    /** Fails with msg unless cond holds. */
    static void check(boolean cond, String msg) {
        if (!cond) throw new AssertionError(msg);
    }

    /** Test helper: deletes a temporary directory tree. Touches: files (the test's temporary root). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static void removeTree(Path p) {
        if (p == null || !Files.exists(p)) return;
        try (Stream<Path> s = Files.walk(p)) {
            for (Path x : s.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(x);
        } catch (IOException ignored) {
            // temporary files; nothing else to do
        }
    }

    /** Test helper: hex text (whitespace ignored) to bytes. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static byte[] hex(String h) {
        h = h.replaceAll("\\s", "");
        byte[] b = new byte[h.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    /** Test helper: CRC-32 of bytes. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static long crc(byte[] d) {
        CRC32 c = new CRC32();
        c.update(d);
        return c.getValue();
    }

    /** A build_zip entry with the spec's defaults: method 0, usize = data length, crc of data, flags 0, ... */
    static final class E {
        byte[] name;
        byte[] data = new byte[0];
        long method = 0, flags = 0, external = 0, creator = 0;
        Long usize = null, crc = null;
        byte[] extra = new byte[0];
        byte[] localName = null;

        E(String n) {
            name = n.getBytes(StandardCharsets.UTF_8);
        }

        E(byte[] n) {
            name = n;
        }

        E data(String d) { data = d.getBytes(StandardCharsets.UTF_8); return this; }
        E data(byte[] d) { data = d; return this; }
        E method(long m) { method = m; return this; }
        E usize(long u) { usize = u; return this; }
        E crc(long c) { crc = c; return this; }
        E flags(long f) { flags = f; return this; }
        E external(long x) { external = x; return this; }
        E creator(long c) { creator = c; return this; }
        E extra(byte[] x) { extra = x; return this; }
        E localName(String n) { localName = n.getBytes(StandardCharsets.UTF_8); return this; }
    }

    /** Test helper: writes an unsigned little-endian 16-bit number. Touches: memory only. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static void u16(ByteArrayOutputStream o, long v) {
        o.write((int) (v & 0xff));
        o.write((int) ((v >> 8) & 0xff));
    }

    /** Test helper: writes an unsigned little-endian 32-bit number. Touches: memory only. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static void u32(ByteArrayOutputStream o, long v) {
        u16(o, v & 0xffff);
        u16(o, (v >> 16) & 0xffff);
    }

    /** build_zip(entries, comment): local records, central records, end record, as the spec describes. */
    static byte[] buildZip(List<E> entries, byte[] comment) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        long[] offsets = new long[entries.size()];
        for (int i = 0; i < entries.size(); i++) {
            E e = entries.get(i);
            offsets[i] = o.size();
            byte[] ln = e.localName != null ? e.localName : e.name;
            o.writeBytes(new byte[] {0x50, 0x4B, 3, 4});
            u16(o, 20); u16(o, e.flags); u16(o, e.method); u16(o, 0); u16(o, 0x0021);
            u32(o, e.crc != null ? e.crc : crc(e.data)); u32(o, e.data.length); u32(o, e.usize != null ? e.usize : e.data.length);
            u16(o, ln.length); u16(o, 0);
            o.writeBytes(ln);
            o.writeBytes(e.data);
        }
        long cdOffset = o.size();
        for (int i = 0; i < entries.size(); i++) {
            E e = entries.get(i);
            o.writeBytes(new byte[] {0x50, 0x4B, 1, 2});
            u16(o, e.creator * 256 + 20); u16(o, 20); u16(o, e.flags); u16(o, e.method); u16(o, 0); u16(o, 0x0021);
            u32(o, e.crc != null ? e.crc : crc(e.data)); u32(o, e.data.length); u32(o, e.usize != null ? e.usize : e.data.length);
            u16(o, e.name.length); u16(o, e.extra.length); u16(o, 0); u16(o, 0); u16(o, 0); u32(o, e.external); u32(o, offsets[i]);
            o.writeBytes(e.name);
            o.writeBytes(e.extra);
        }
        long cdSize = o.size() - cdOffset;
        o.writeBytes(new byte[] {0x50, 0x4B, 5, 6});
        u16(o, 0); u16(o, 0); u16(o, entries.size()); u16(o, entries.size()); u32(o, cdSize); u32(o, cdOffset); u16(o, comment.length);
        o.writeBytes(comment);
        return o.toByteArray();
    }

    /** Test helper: build_zip with no comment. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static byte[] zip(E... entries) {
        return buildZip(Arrays.asList(entries), new byte[0]);
    }

    /** Test helper: the default limits. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static SafeArchiveIngest.Limits lim() {
        return new SafeArchiveIngest.Limits();
    }

    static int counter = 0;

    /** A fresh target path (not created) under its own fresh parent directory. */
    static Path target() throws IOException {
        Path parent = Files.createDirectory(root.resolve("p" + (counter++)));
        return parent.resolve("target");
    }

    /** Test helper: true for a refusal with this status, error and entry_index. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static boolean refused(Map<String, Object> r, int status, String error, int index) {
        return Integer.valueOf(status).equals(r.get("status")) && error.equals(r.get("error")) && Integer.valueOf(index).equals(r.get("entry_index"));
    }

    /** Test helper: true for {ok: true, ...}. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static boolean accepted(Map<String, Object> r) {
        return Boolean.TRUE.equals(r.get("ok"));
    }

    /** Extracts into a fresh target and asserts the refusal; the parent holds nothing afterwards. */
    static void refusedExtract(byte[] zip, SafeArchiveIngest.Limits l, int status, String error, int index, String what) throws IOException {
        Path t = target();
        Map<String, Object> r = SafeArchiveIngest.extractArchive(zip, t, l);
        check(refused(r, status, error, index), what + ": want " + error + "@" + index + ", got " + r);
        check(refused(SafeArchiveIngest.inspectArchive(zip, l), status, error, index) || error.equals("corrupt_entry"), what + ": inspect agrees");
        try (Stream<Path> s = Files.list(t.getParent())) {
            check(s.count() == 0, what + ": nothing written beside the target");
        }
    }

    static final String BASIC_HEX = "504b03041400000000000000210000000000000000000000000005000000646f63732f504b0304140000000000000021"
            + "0020303a3606000000060000000f000000646f63732f726561646d652e74787468656c6c6f0a504b0304140000000000"
            + "000021007b07970a080000000800000008000000646174612e637376612c620a312c320a504b01021403140000000000"
            + "00002100000000000000000000000000050000000000000000000000ed4100000000646f63732f504b01021400140000"
            + "0000000000210020303a3606000000060000000f0000000000000000000000000023000000646f63732f726561646d65"
            + "2e747874504b01021403140000000000000021007b07970a0800000008000000080000000000000000000000ed815600"
            + "0000646174612e637376504b05060000000003000300a6000000840000000000";
    static final byte[] Z = hex("63601805a360148c8251300a46c1500700");
    static final long CRC2000 = 0x02C9F444L, CRC10 = 0xE38A6876L;

    /** Test helper: the entries of the spec's BASIC archive. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static List<E> basicEntries() {
        return List.of(new E("docs/").external(0x41ED0000L).creator(3), new E("docs/readme.txt").data("hello\n"),
                new E("data.csv").data("a,b\n1,2\n").external(0x81ED0000L).creator(3));
    }

    /** Test helper: the spec's BASIC archive (320 bytes). Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static byte[] basic() {
        return buildZip(basicEntries(), new byte[0]);
    }

    /** Test helper: the spec's ZEROS archive (133 bytes, 2000 declared). Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static byte[] zeros() {
        return zip(new E("zeros.txt").data(Z).method(8).usize(2000).crc(CRC2000));
    }

    // ------------------------------------------------------------------------------------------------ tests
    // ARCHIVE-01
    /** The builder reproduces BASIC; extract writes its files, creates docs/, returns sizes and SHA-256, mode 0644. */
    @SuppressWarnings("unchecked")
    static void testBasic() throws IOException {
        byte[] b = basic();
        check(b.length == 320 && Arrays.equals(b, hex(BASIC_HEX)), "builder reproduces BASIC byte for byte");
        Path t = target();
        Map<String, Object> r = SafeArchiveIngest.extractArchive(b, t, lim());
        check(accepted(r) && Integer.valueOf(3).equals(r.get("entries")) && Long.valueOf(14).equals(r.get("total_bytes")), "extract " + r);
        List<Map<String, Object>> f = (List<Map<String, Object>>) r.get("files");
        check(f.size() == 2, "two files");
        check("docs/readme.txt".equals(f.get(0).get("path")) && Long.valueOf(6).equals(f.get(0).get("size"))
                && "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03".equals(f.get(0).get("sha256")), "readme " + f.get(0));
        check("data.csv".equals(f.get(1).get("path")) && Long.valueOf(8).equals(f.get(1).get("size"))
                && "492d5ea496056f1a6a6592241032fab764c321596317930b4fa0e1e8bc3b7470".equals(f.get(1).get("sha256")), "csv " + f.get(1));
        check(Files.isDirectory(t.resolve("docs")), "target/docs is a directory");
        check(Arrays.equals(Files.readAllBytes(t.resolve("docs/readme.txt")), "hello\n".getBytes(StandardCharsets.UTF_8)), "readme bytes");
        check(Arrays.equals(Files.readAllBytes(t.resolve("data.csv")), "a,b\n1,2\n".getBytes(StandardCharsets.UTF_8)), "csv bytes");
        Set<PosixFilePermission> m = Files.getPosixFilePermissions(t.resolve("data.csv"));
        check(m.equals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--")), "data.csv is 0644, got " + m);
        try (Stream<Path> s = Files.list(t.getParent())) {
            check(s.count() == 1, "no staging directory left");
        }
        Map<String, Object> ins = SafeArchiveIngest.inspectArchive(b, lim());
        check(accepted(ins) && ((List<?>) ins.get("files")).size() == 2 && !((Map<String, Object>) ((List<?>) ins.get("files")).get(0)).containsKey("sha256"), "inspect " + ins);
    }

    // ARCHIVE-02
    /** Zip slip names, control bytes, empty and non-strict UTF-8 names are 400 unsafe_path with the entry's index. */
    static void testZipSlip() throws IOException {
        String[] names = {"../evil.txt", "a/../../evil.txt", "/etc/passwd.txt", "C:/x.txt", "a\\b.txt", "a//b.txt", "./a.txt", "a\u0000b.txt", "a\u0001b.txt", ""};
        for (String n : names) {
            refusedExtract(zip(new E("ok.txt").data("x"), new E(n).data("evil")), lim(), 400, "unsafe_path", 1, "name " + n.replace("\u0000", "NUL"));
        }
        String[] badUtf8 = {"61C0AF622E747874", "61EDA0802E747874", "61F49080802E747874", "61E2822E747874"};
        for (String h : badUtf8) {
            refusedExtract(zip(new E("ok.txt").data("x"), new E(hex(h)).data("evil")), lim(), 400, "unsafe_path", 1, "UTF-8 " + h);
        }
        check(!Files.exists(root.resolve("evil.txt")), "nothing escaped");
    }

    // ARCHIVE-03
    /** A link entry is special_file whatever the creator says, and so is a FIFO; a regular-file mode is accepted. */
    static void testSpecialFiles() throws IOException {
        for (long creator : new long[] {0, 3, 19}) {
            refusedExtract(zip(new E("a.txt").data("x").external(0xA1FF0000L).creator(creator)), lim(), 400, "special_file", 0, "link, creator " + creator);
        }
        refusedExtract(zip(new E("a.txt").data("x").external(0x11A40000L).creator(3)), lim(), 400, "special_file", 0, "FIFO");
        check(accepted(SafeArchiveIngest.extractArchive(zip(new E("a.txt").data("x").external(0x81A40000L).creator(3)), target(), lim())), "regular file accepted");
    }

    // ARCHIVE-04
    /** max_entries and max_archive_bytes: exactly at the limit accepted, one over refused (283-byte vector). */
    static void testEntryAndArchiveLimits() throws IOException {
        byte[] z = zip(new E("a.txt").data("x"), new E("b.txt").data("x"), new E("c.txt").data("x"));
        check(z.length == 283, "283 bytes");
        check(accepted(SafeArchiveIngest.extractArchive(z, target(), lim().entries(3).archiveBytes(283))), "at both limits");
        refusedExtract(z, lim().entries(2), 413, "too_many_entries", -1, "max_entries 2");
        refusedExtract(z, lim().archiveBytes(282), 413, "archive_too_large", -1, "max_archive_bytes 282");
    }

    // ARCHIVE-05
    /** max_total_bytes and max_file_bytes at and over the limit; 0x80000000 read unsigned. */
    static void testSizeLimits() throws IOException {
        byte[] z = zip(new E("a.txt").data("12345"), new E("b.txt").data("67890"));
        check(z.length == 204, "204 bytes");
        check(accepted(SafeArchiveIngest.extractArchive(z, target(), lim().totalBytes(10).fileBytes(5))), "at both limits");
        refusedExtract(z, lim().totalBytes(9), 413, "total_too_large", 1, "max_total_bytes 9");
        refusedExtract(z, lim().fileBytes(4), 413, "entry_too_large", 0, "max_file_bytes 4");
        byte[] big = zip(new E("a.txt").data(Z).method(8).usize(0x80000000L).crc(0));
        refusedExtract(big, lim(), 413, "entry_too_large", 0, "0x80000000 is unsigned");
        refusedExtract(big, lim().fileBytes(4294967296L).totalBytes(4294967296L), 413, "compression_ratio_exceeded", -1, "then the ratio");
    }

    // ARCHIVE-06
    /** ZEROS (133 bytes, 2000 declared): ratio 15 refused, ratio 16 extracted to 2000 zero bytes. */
    static void testRatio() throws IOException {
        byte[] z = zeros();
        check(z.length == 133, "133 bytes");
        refusedExtract(z, lim().ratio(15), 413, "compression_ratio_exceeded", -1, "ratio 15");
        Path t = target();
        check(accepted(SafeArchiveIngest.extractArchive(z, t, lim().ratio(16))), "ratio 16");
        check(Arrays.equals(Files.readAllBytes(t.resolve("zeros.txt")), new byte[2000]), "2000 zero bytes");
    }

    // ARCHIVE-07
    /** Lying sizes, a cut stream, an overrun into invalid data, wrong CRCs and invalid data are corrupt_entry. */
    static void testLyingHeaders() throws IOException {
        byte[] bad = hex("62601805a360148c8251300a46c1500700000000ffff07");
        byte[][] zips = {
            zip(new E("zeros.txt").data(Z).method(8).usize(10).crc(CRC10)),
            zip(new E("zeros.txt").data(Z).method(8).usize(3000).crc(CRC2000)),
            zip(new E("zeros.txt").data(Arrays.copyOf(Z, Z.length - 4)).method(8).usize(2000).crc(CRC2000)),
            zip(new E("zeros.txt").data(Z).method(8).usize(2000).crc(1)),
            zip(new E("a.txt").data("12345").crc(0)),
            zip(new E("zeros.txt").data(hex("FFFFFFFF")).method(8).usize(4).crc(0)),
            zip(new E("zeros.txt").data(bad).method(8).usize(10).crc(CRC10))};
        int i = 0;
        for (byte[] z : zips) refusedExtract(z, lim(), 400, "corrupt_entry", 0, "lying header " + (i++));
        refusedExtract(zip(new E("a.txt").data("12345").usize(4)), lim(), 400, "size_mismatch", 0, "stored sizes differ");
    }

    // ARCHIVE-08
    /** Extensions outside the allow-list are refused; case does not matter; a custom list allows "" and "sh". */
    static void testExtensions() throws IOException {
        for (String n : new String[] {"run.exe", "a.txt.sh", "README", ".env", "inner.zip"}) {
            refusedExtract(zip(new E(n).data("x")), lim(), 400, "extension_not_allowed", 0, "extension of " + n);
        }
        check(accepted(SafeArchiveIngest.extractArchive(zip(new E("A.TXT").data("x"), new E("x.Json").data("{}")), target(), lim())), "A.TXT and x.Json");
        check(accepted(SafeArchiveIngest.extractArchive(zip(new E("README").data("x"), new E("a.sh").data("x")), target(), lim().extensions(List.of("", "sh")))), "custom list");
    }

    // ARCHIVE-09
    /** Duplicate names (case-folded), a file under a file, a directory and a file of one name: entry_index 1. */
    static void testDuplicates() throws IOException {
        String[][] pairs = {{"a.txt", "a.txt"}, {"A.txt", "a.txt"}, {"d.txt/", "d.txt"}, {"d.txt", "d.txt/"}, {"d.txt", "d.txt/e.txt"}, {"d.txt/e.txt", "d.txt"}};
        for (String[] p : pairs) {
            refusedExtract(zip(new E(p[0]).data(p[0].endsWith("/") ? "" : "x"), new E(p[1]).data(p[1].endsWith("/") ? "" : "y")), lim(),
                    400, "duplicate_name", 1, "duplicate " + p[0] + " / " + p[1]);
        }
        check(accepted(SafeArchiveIngest.extractArchive(zip(new E("d/"), new E("d/"), new E("d/a.txt").data("x")), target(), lim())), "the same directory twice");
    }

    /** Test helper: a copy with a u16 written at off. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static byte[] withU16(byte[] b, int off, int v) {
        byte[] c = b.clone();
        c[off] = (byte) v;
        c[off + 1] = (byte) (v >> 8);
        return c;
    }

    /** Test helper: a copy with a u32 written at off. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static byte[] withU32(byte[] b, int off, long v) {
        return withU16(withU16(b, off, (int) (v & 0xffff)), off + 2, (int) ((v >> 16) & 0xffff));
    }

    // ARCHIVE-10
    /** The container: empty, not a zip, truncated, bad counts, trailing byte, wrapping offsets, zip64, comments. */
    static void testContainer() throws IOException {
        byte[] b = basic();
        int n = b.length;
        refusedExtract(new byte[0], lim(), 400, "empty_upload", -1, "empty input");
        refusedExtract("hello, this is not a zip".getBytes(StandardCharsets.UTF_8), lim(), 400, "not_a_zip", -1, "text");
        refusedExtract(Arrays.copyOf(b, n - 10), lim(), 400, "not_a_zip", -1, "truncated");
        refusedExtract(withU16(withU16(b, n - 14, 4), n - 12, 4), lim(), 400, "not_a_zip", -1, "counts disagree with the directory");
        refusedExtract(Arrays.copyOf(b, n + 1), lim(), 400, "not_a_zip", -1, "a byte after the end record");
        refusedExtract(withU32(withU32(b, n - 10, 300), n - 6, 0xFFFFFFFEL), lim(), 400, "not_a_zip", -1, "32-bit sum wraps");
        refusedExtract(withU16(b, n - 18, 1), lim(), 400, "unsupported_zip", -1, "disk number");
        refusedExtract(withU16(withU16(b, n - 14, 0xFFFF), n - 12, 0xFFFF), lim(), 400, "unsupported_zip", -1, "zip64 count marker");
        refusedExtract(zip(new E("docs/")), lim(), 400, "empty_archive", -1, "only a directory");
        refusedExtract(hex("504b0304504b0506000000000000000000000000040000001000504b0607787878787878787878787878"), lim(), 400, "empty_archive", -1,
                "too short for a zip64 locator: never read before the start");
        byte[] commented = buildZip(basicEntries(), "c".repeat(40).getBytes(StandardCharsets.UTF_8));
        check(accepted(SafeArchiveIngest.extractArchive(commented, target(), lim())), "an archive comment is accepted");
    }

    // ARCHIVE-11
    /** Encryption flags are encrypted_entry; other methods unsupported_compression; flag bit 3 is accepted. */
    static void testFlagsAndMethods() throws IOException {
        refusedExtract(zip(new E("a.txt").data("12345").flags(1)), lim(), 400, "encrypted_entry", 0, "bit 0");
        refusedExtract(zip(new E("a.txt").data("12345").flags(64)), lim(), 400, "encrypted_entry", 0, "bit 6");
        refusedExtract(zip(new E("a.txt").data("12345").method(12)), lim(), 400, "unsupported_compression", 0, "method 12");
        check(accepted(SafeArchiveIngest.extractArchive(zip(new E("a.txt").data("12345").flags(8)), target(), lim())), "flag bit 3 accepted");
    }

    // ARCHIVE-12
    /** A local name that differs and a Unicode Path naming ../evil.txt are header_mismatch; a bad extra is not_a_zip. */
    static void testHeaderMismatch() throws IOException {
        refusedExtract(zip(new E("a.txt").data("1"), new E("ok.txt").data("x").localName("no.txt")), lim(), 400, "header_mismatch", 1, "local name differs");
        byte[] evil = hex("75701000012a0419052e2e2f6576696c2e747874");
        refusedExtract(zip(new E("ok.txt").data("x").extra(evil)), lim(), 400, "header_mismatch", 0, "Unicode Path ../evil.txt");
        ByteArrayOutputStream same = new ByteArrayOutputStream();
        same.writeBytes(hex("75700b0001"));
        u32(same, crc("ok.txt".getBytes(StandardCharsets.UTF_8)));
        same.writeBytes("ok.txt".getBytes(StandardCharsets.UTF_8));
        check(accepted(SafeArchiveIngest.extractArchive(zip(new E("ok.txt").data("x").extra(same.toByteArray())), target(), lim())), "Unicode Path repeating the name");
        refusedExtract(zip(new E("ok.txt").data("x").extra(hex("0A0032006162"))), lim(), 400, "not_a_zip", 0, "extra overruns");
    }

    // ARCHIVE-13
    /** All or nothing: a corrupt second entry leaves no target and no staging; existing target 409; no parent 500. */
    static void testAllOrNothing() throws IOException {
        byte[] z = zip(new E("a.txt").data("good"), new E("b.txt").data("12345").crc(0));
        refusedExtract(z, lim(), 400, "corrupt_entry", 1, "second entry corrupt");
        Path t = target();
        Files.createDirectory(t);
        Files.writeString(t.resolve("keep.txt"), "mine");
        check(refused(SafeArchiveIngest.extractArchive(basic(), t, lim()), 409, "target_exists", -1), "existing target");
        check(Files.readString(t.resolve("keep.txt")).equals("mine"), "the existing target keeps its content");
        Path link = target();
        Files.createSymbolicLink(link, link.getParent().resolve("nowhere"));
        check(refused(SafeArchiveIngest.extractArchive(basic(), link, lim()), 409, "target_exists", -1), "a link that points nowhere");
        Path orphan = root.resolve("missing-parent").resolve("target");
        check(refused(SafeArchiveIngest.extractArchive(basic(), orphan, lim()), 500, "target_unwritable", -1), "missing parent");
        check(!Files.exists(root.resolve("missing-parent")), "nothing created");
    }

    // ARCHIVE-14
    /** Names that do not unpack everywhere are bad_name; an accented name is accepted; 0755 is written as 0644. */
    static void testBadNames() throws IOException {
        String[] bad = {"CON.txt", "com1.txt", "COM0.txt", "LPT0.txt", "COM\u00b9.txt", "CONIN$.txt", "CONOUT$.txt", "a.txt.", "a.txt ",
            "a?.txt", "x".repeat(252) + ".txt", "a\u202Eb.txt", "d/nul.txt"};
        for (String n : bad) refusedExtract(zip(new E(n).data("x")), lim(), 400, "bad_name", 0, "bad name " + n.substring(0, Math.min(12, n.length())));
        for (String n : new String[] {"x".repeat(251) + ".txt", "caf\u00e9.txt", "COM10.txt", "conin.txt"}) {
            check(accepted(SafeArchiveIngest.extractArchive(zip(new E(n).data("x")), target(), lim())), "accepted " + n.substring(0, Math.min(12, n.length())));
        }
        Path t = target();
        check(accepted(SafeArchiveIngest.extractArchive(zip(new E("run.txt").data("x").external(0x81ED0000L).creator(3)), t, lim())), "0755 entry");
        Set<PosixFilePermission> m = Files.getPosixFilePermissions(t.resolve("run.txt"));
        check(!m.contains(PosixFilePermission.OWNER_EXECUTE) && !m.contains(PosixFilePermission.GROUP_EXECUTE) && !m.contains(PosixFilePermission.OTHERS_EXECUTE),
                "written without execute permission: " + m);
    }
}
