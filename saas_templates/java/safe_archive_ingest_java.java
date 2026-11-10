import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Safe archive ingest (spec docs/specs/safe_archive_ingest.md): takes the bytes of an uploaded .zip and unpacks it
 * into a new directory without trusting anything in it. The three zip record types are read here (no zip library
 * chooses a name), every name, link, size, ratio, extension and checksum is checked (checks A, B, C), and the files
 * are written to a staging directory that is renamed to the target only when every file was written (check D).
 *
 * In: the archive bytes, a server-chosen target directory and the limits. Out: a result map: {ok: true, entries,
 * total_bytes, files} or a refusal {error, status, entry_index}; never an unhandled exception.
 * Why: Phase D wave 1, owner request 2026-11-10 (ARCHIVE-01 to ARCHIVE-14). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files (creates target_dir and a staging directory beside it; removes the staging directory on any
 * refusal). No database, no network, no money. A refusal names an index, never the entry's name.
 */
public final class SafeArchiveIngest {
    /** Not instantiable: the API is static. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private SafeArchiveIngest() {}

    /**
     * The injected limits, with the spec's defaults. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public static final class Limits {
        public long maxArchiveBytes = 20971520L;
        public long maxEntries = 1000;
        public long maxFileBytes = 26214400L;
        public long maxTotalBytes = 104857600L;
        public long maxRatio = 100;
        public List<String> allowedExtensions = List.of("txt", "md", "csv", "json", "pdf", "png", "jpg", "jpeg", "gif");

        /** Out: a copy with max_archive_bytes set. */
        public Limits archiveBytes(long v) { Limits l = copy(); l.maxArchiveBytes = v; return l; }
        /** Out: a copy with max_entries set. */
        public Limits entries(long v) { Limits l = copy(); l.maxEntries = v; return l; }
        /** Out: a copy with max_file_bytes set. */
        public Limits fileBytes(long v) { Limits l = copy(); l.maxFileBytes = v; return l; }
        /** Out: a copy with max_total_bytes set. */
        public Limits totalBytes(long v) { Limits l = copy(); l.maxTotalBytes = v; return l; }
        /** Out: a copy with max_ratio set. */
        public Limits ratio(long v) { Limits l = copy(); l.maxRatio = v; return l; }
        /** Out: a copy with allowed_extensions set. */
        public Limits extensions(List<String> v) { Limits l = copy(); l.allowedExtensions = List.copyOf(v); return l; }

        /** In: none. Out: a copy of these limits. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        private Limits copy() {
            Limits l = new Limits();
            l.maxArchiveBytes = maxArchiveBytes;
            l.maxEntries = maxEntries;
            l.maxFileBytes = maxFileBytes;
            l.maxTotalBytes = maxTotalBytes;
            l.maxRatio = maxRatio;
            l.allowedExtensions = allowedExtensions;
            return l;
        }
    }

    /** One central-directory record, every number read unsigned into a long. */
    private record Central(int index, long flags, long method, long crc, long csize, long usize, byte[] nameBytes,
                           String name, byte[] extra, long diskStart, long external, long localOffset, boolean dir) {}

    /** A refusal carried out of the checks. */
    private static final class Refusal extends Exception {
        final int status;
        final String error;
        final int index;

        Refusal(int status, String error, int index) {
            super(error, null, false, false);
            this.status = status;
            this.error = error;
            this.index = index;
        }
    }

    /** The checked archive: its records and where the central directory starts. */
    private record Checked(List<Central> entries, long cdOffset, long total) {}

    /** In: bytes, offset. Out: the unsigned little-endian 16-bit number there, as a long. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static long u16(byte[] b, long off) {
        int o = (int) off;
        return (b[o] & 0xffL) | ((b[o + 1] & 0xffL) << 8);
    }

    /** In: bytes, offset. Out: the unsigned little-endian 32-bit number there, as a long. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static long u32(byte[] b, long off) {
        int o = (int) off;
        return (b[o] & 0xffL) | ((b[o + 1] & 0xffL) << 8) | ((b[o + 2] & 0xffL) << 16) | ((b[o + 3] & 0xffL) << 24);
    }

    /** In: bytes, offset, the signature's last two bytes. Out: true when 50 4B x y is there (never reads outside the input). Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean sig(byte[] b, long off, int third, int fourth) {
        if (off < 0 || off + 4 > b.length) return false;
        int o = (int) off;
        return b[o] == 0x50 && b[o + 1] == 0x4B && b[o + 2] == third && b[o + 3] == fourth;
    }

    /** In: a refusal. Out: {error, status, entry_index}. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static Map<String, Object> refusal(Refusal r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("error", r.error);
        m.put("status", r.status);
        m.put("entry_index", r.index);
        return m;
    }

    // ------------------------------------------------------------------------------------------------ public API
    /**
     * inspect_archive(bytes, limits) -> {ok: true, entries, total_bytes, files: [{path, size}]}: checks A, B and C.
     * Reads no file data and writes nothing. ARCHIVE-02..12, ARCHIVE-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: nothing.
     */
    public static Map<String, Object> inspectArchive(byte[] bytes, Limits limits) {
        try {
            Checked c = check(bytes, limits);
            List<Map<String, Object>> files = new ArrayList<>();
            for (Central e : c.entries()) {
                if (e.dir()) continue;
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("path", e.name());
                f.put("size", e.usize());
                files.add(f);
            }
            return ok(c, files);
        } catch (Refusal r) {
            return refusal(r);
        }
    }

    /** In: the checked archive and its file list. Out: {ok: true, entries, total_bytes, files}. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static Map<String, Object> ok(Checked c, List<Map<String, Object>> files) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", true);
        m.put("entries", c.entries().size());
        m.put("total_bytes", c.total());
        m.put("files", files);
        return m;
    }

    /**
     * extract_archive(bytes, target_dir, limits) -> {ok: true, entries, total_bytes, files: [{path, size, sha256}]}:
     * checks A, B and C, then D: target_dir must not exist (409 target_exists); files go to a 0700 staging directory
     * beside it (500 target_unwritable), each inflated with a cap of usize + 1 bytes and its CRC checked (400
     * corrupt_entry), created exclusively with mode 0644 (400 duplicate_name), then the staging directory is renamed.
     * Any refusal removes the staging directory first. ARCHIVE-01, 06, 07, 13, 14.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files under target_dir's parent.
     */
    public static Map<String, Object> extractArchive(byte[] bytes, Path targetDir, Limits limits) {
        Checked c;
        try {
            c = check(bytes, limits);
        } catch (Refusal r) {
            return refusal(r);
        }
        if (Files.exists(targetDir, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(targetDir)) {
            return refusal(new Refusal(409, "target_exists", -1));
        }
        byte[] rnd = new byte[8];
        new SecureRandom().nextBytes(rnd);
        StringBuilder hex = new StringBuilder();
        for (byte b : rnd) hex.append(String.format("%02x", b & 0xff));
        Path staging = targetDir.resolveSibling(targetDir.getFileName().toString() + ".partial-" + hex);
        try {
            Files.createDirectory(staging);
            setMode(staging, "rwx------");
        } catch (IOException | RuntimeException e) {
            removeTree(staging);
            return refusal(new Refusal(500, "target_unwritable", -1));
        }
        int current = -1;
        try {
            List<Map<String, Object>> files = new ArrayList<>();
            Path base = staging.toAbsolutePath().normalize();
            for (Central e : c.entries()) {
                current = e.index();
                Path dest = base;
                for (String part : partsOf(e.name())) dest = dest.resolve(part);
                dest = dest.normalize();
                if (!dest.toString().startsWith(base.toString() + java.io.File.separator)) {
                    throw new Refusal(400, "unsafe_path", e.index());
                }
                if (e.dir()) {
                    makeDirs(dest, base);
                    continue;
                }
                byte[] data = readData(bytes, e);
                makeDirs(dest.getParent(), base);
                try {
                    Files.write(dest, data, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
                } catch (FileAlreadyExistsException x) {
                    throw new Refusal(400, "duplicate_name", e.index());
                }
                setMode(dest, "rw-r--r--");
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("path", e.name());
                f.put("size", e.usize());
                f.put("sha256", sha256(data));
                files.add(f);
            }
            current = -1;
            Files.move(staging, targetDir, StandardCopyOption.ATOMIC_MOVE);
            return ok(c, files);
        } catch (Refusal r) {
            removeTree(staging);
            return refusal(r);
        } catch (IOException | RuntimeException e) {
            removeTree(staging);
            return refusal(new Refusal(500, "target_unwritable", current));
        }
    }

    // ------------------------------------------------------------------------------------------------ checks A-C
    /** Checks A, B and C in the spec's order. In: the archive, the limits. Out: the checked entries, or the first refusal (thrown). Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static Checked check(byte[] b, Limits lim) throws Refusal {
        // A. The container
        if (b == null || b.length == 0) throw new Refusal(400, "empty_upload", -1);
        long len = b.length;
        if (len > lim.maxArchiveBytes) throw new Refusal(413, "archive_too_large", -1);
        if (!sig(b, 0, 0x03, 0x04)) throw new Refusal(400, "not_a_zip", -1);
        long i = -1;
        for (long k = len - 22; k >= Math.max(0, len - 65557); k--) {
            if (sig(b, k, 0x05, 0x06) && k + 22 + u16(b, k + 20) == len) {
                i = k;
                break;
            }
        }
        if (i < 0) throw new Refusal(400, "not_a_zip", -1);
        long disk = u16(b, i + 4), cdDisk = u16(b, i + 6), here = u16(b, i + 8), entries = u16(b, i + 10);
        long cdSize = u32(b, i + 12), cdOffset = u32(b, i + 16);
        if (disk != 0 || cdDisk != 0 || here != entries || entries == 0xFFFF || cdSize == 0xFFFFFFFFL || cdOffset == 0xFFFFFFFFL
                || (i >= 20 && sig(b, i - 20, 0x06, 0x07))) {
            throw new Refusal(400, "unsupported_zip", -1);
        }
        if (cdOffset + cdSize != i) throw new Refusal(400, "not_a_zip", -1);
        if (entries == 0) throw new Refusal(400, "empty_archive", -1);
        if (entries > lim.maxEntries) throw new Refusal(413, "too_many_entries", -1);

        // B. The central directory
        List<Central> list = new ArrayList<>();
        long p = cdOffset;
        for (int n = 0; n < entries; n++) {
            if (p + 46 > i || !sig(b, p, 0x01, 0x02)) throw new Refusal(400, "not_a_zip", -1);
            long nameLen = u16(b, p + 28), extraLen = u16(b, p + 30), commentLen = u16(b, p + 32);
            long end = p + 46 + nameLen + extraLen + commentLen;
            if (end > i) throw new Refusal(400, "not_a_zip", -1);
            byte[] nameBytes = Arrays.copyOfRange(b, (int) (p + 46), (int) (p + 46 + nameLen));
            byte[] extra = Arrays.copyOfRange(b, (int) (p + 46 + nameLen), (int) (p + 46 + nameLen + extraLen));
            boolean dir = nameBytes.length > 0 && nameBytes[nameBytes.length - 1] == '/';
            list.add(new Central(n, u16(b, p + 8), u16(b, p + 10), u32(b, p + 16), u32(b, p + 20), u32(b, p + 24),
                    nameBytes, null, extra, u16(b, p + 34), u32(b, p + 38), u32(b, p + 42), dir));
            p = end;
        }
        if (p != i) throw new Refusal(400, "not_a_zip", -1);

        // C. Each entry
        Set<String> fileKeys = new HashSet<>(), dirKeys = new HashSet<>();
        Set<String> allowed = new HashSet<>(lim.allowedExtensions);
        List<Central> named = new ArrayList<>();
        long total = 0;
        boolean anyFile = false;
        for (Central e : list) {
            int x = e.index();
            if (e.csize() == 0xFFFFFFFFL || e.usize() == 0xFFFFFFFFL || e.localOffset() == 0xFFFFFFFFL || e.diskStart() != 0) {
                throw new Refusal(400, "unsupported_zip", x);
            }
            if ((e.flags() & 0x2041) != 0) throw new Refusal(400, "encrypted_entry", x);
            if (e.method() != 0 && e.method() != 8) throw new Refusal(400, "unsupported_compression", x);
            String name = unsafePathCheck(e.nameBytes(), x);
            badNameCheck(name, e.nameBytes().length, x);
            extraCheck(e.extra(), e.nameBytes(), x);
            long type = (e.external() >>> 16) & 0xF000;
            if (type != 0 && type != 0x8000 && type != 0x4000) throw new Refusal(400, "special_file", x);
            if ((e.dir() && e.usize() != 0) || (!e.dir() && e.method() == 0 && e.csize() != e.usize())) {
                throw new Refusal(400, "size_mismatch", x);
            }
            if (!e.dir() && !allowed.contains(extension(name))) throw new Refusal(400, "extension_not_allowed", x);
            String key = asciiLower(e.dir() ? name.substring(0, name.length() - 1) : name);
            if (fileKeys.contains(key)) throw new Refusal(400, "duplicate_name", x);
            for (int s = key.indexOf('/'); s >= 0; s = key.indexOf('/', s + 1)) {
                if (fileKeys.contains(key.substring(0, s))) throw new Refusal(400, "duplicate_name", x);
            }
            if (!e.dir() && dirKeys.contains(key)) throw new Refusal(400, "duplicate_name", x);
            if (e.dir()) dirKeys.add(key);
            else fileKeys.add(key);
            for (int s = key.indexOf('/'); s >= 0; s = key.indexOf('/', s + 1)) dirKeys.add(key.substring(0, s));
            if (e.usize() > lim.maxFileBytes) throw new Refusal(413, "entry_too_large", x);
            total += e.usize();
            if (total > lim.maxTotalBytes) throw new Refusal(413, "total_too_large", x);
            if (!e.dir()) anyFile = true;
            named.add(new Central(x, e.flags(), e.method(), e.crc(), e.csize(), e.usize(), e.nameBytes(), name, e.extra(),
                    e.diskStart(), e.external(), e.localOffset(), e.dir()));
        }
        if (!anyFile) throw new Refusal(400, "empty_archive", -1);
        if (java.math.BigInteger.valueOf(total).compareTo(
                java.math.BigInteger.valueOf(lim.maxRatio).multiply(java.math.BigInteger.valueOf(len))) > 0) {
            throw new Refusal(413, "compression_ratio_exceeded", -1);
        }
        for (Central e : named) {
            int x = e.index();
            long lo = e.localOffset();
            if (lo + 30 > cdOffset || !sig(b, lo, 0x03, 0x04)) throw new Refusal(400, "not_a_zip", x);
            long lNameLen = u16(b, lo + 26), lExtraLen = u16(b, lo + 28);
            if (lo + 30 + lNameLen + lExtraLen + e.csize() > cdOffset) throw new Refusal(400, "not_a_zip", x);
            byte[] lName = Arrays.copyOfRange(b, (int) (lo + 30), (int) (lo + 30 + lNameLen));
            long lFlags = u16(b, lo + 6), lMethod = u16(b, lo + 8);
            if (!Arrays.equals(lName, e.nameBytes()) || lFlags != e.flags() || lMethod != e.method()) {
                throw new Refusal(400, "header_mismatch", x);
            }
            if ((e.flags() & 8) == 0 && (u32(b, lo + 14) != e.crc() || u32(b, lo + 18) != e.csize() || u32(b, lo + 22) != e.usize())) {
                throw new Refusal(400, "header_mismatch", x);
            }
        }
        return new Checked(named, cdOffset, total);
    }

    /** C4: the name as strict UTF-8 text, or unsafe_path. */
    private static String unsafePathCheck(byte[] nb, int x) throws Refusal {
        if (nb.length == 0) throw new Refusal(400, "unsafe_path", x);
        String name;
        try {
            name = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(nb)).toString();
        } catch (CharacterCodingException e) {
            throw new Refusal(400, "unsafe_path", x);
        }
        for (byte v : nb) {
            int c = v & 0xff;
            if (c < 0x20 || c == 0x7F || c == '\\') throw new Refusal(400, "unsafe_path", x);
        }
        if (name.startsWith("/")) throw new Refusal(400, "unsafe_path", x);
        if (name.length() >= 2 && name.charAt(1) == ':' && isAsciiLetter(name.charAt(0))) throw new Refusal(400, "unsafe_path", x);
        for (String part : partsOf(name)) {
            if (part.isEmpty() || part.equals(".") || part.equals("..")) throw new Refusal(400, "unsafe_path", x);
        }
        return name;
    }

    /** In: a character. Out: true for A-Z or a-z. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean isAsciiLetter(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }

    /** The name without ONE trailing "/", split at "/". */
    private static String[] partsOf(String name) {
        String n = name.endsWith("/") ? name.substring(0, name.length() - 1) : name;
        return n.split("/", -1);
    }

    private static final Set<String> RESERVED = new HashSet<>(Arrays.asList("con", "prn", "aux", "nul", "conin$", "conout$"));

    /** C5: names that do not unpack everywhere (Windows reserved names, invisible or bidi characters, long parts). */
    private static void badNameCheck(String name, int byteLen, int x) throws Refusal {
        if (byteLen > 1024) throw new Refusal(400, "bad_name", x);
        for (int k = 0; k < name.length(); k++) {
            char c = name.charAt(k);
            if ((c >= 0x80 && c <= 0x9F) || c == 0x061C || (c >= 0x200B && c <= 0x200F) || (c >= 0x202A && c <= 0x202E)
                    || (c >= 0x2060 && c <= 0x2064) || (c >= 0x2066 && c <= 0x2069) || c == 0xFEFF) {
                throw new Refusal(400, "bad_name", x);
            }
        }
        for (String part : partsOf(name)) {
            if (part.getBytes(StandardCharsets.UTF_8).length > 255) throw new Refusal(400, "bad_name", x);
            for (int k = 0; k < part.length(); k++) {
                if (":*?\"<>|".indexOf(part.charAt(k)) >= 0) throw new Refusal(400, "bad_name", x);
            }
            if (part.endsWith(".") || part.endsWith(" ")) throw new Refusal(400, "bad_name", x);
            int dot = part.indexOf('.');
            String stem = asciiLower(dot >= 0 ? part.substring(0, dot) : part);
            int e = stem.length();
            while (e > 0 && stem.charAt(e - 1) == ' ') e--;
            stem = stem.substring(0, e);
            if (RESERVED.contains(stem)) throw new Refusal(400, "bad_name", x);
            if (stem.length() == 4 && (stem.startsWith("com") || stem.startsWith("lpt"))) {
                char d = stem.charAt(3);
                if ((d >= '0' && d <= '9') || d == '¹' || d == '²' || d == '³') throw new Refusal(400, "bad_name", x);
            }
        }
    }

    /** C6: the extra field's blocks; a Unicode Path block (0x7075, version 1) must repeat the entry's name. */
    private static void extraCheck(byte[] extra, byte[] nameBytes, int x) throws Refusal {
        int p = 0;
        while (p < extra.length) {
            if (extra.length - p < 4) throw new Refusal(400, "not_a_zip", x);
            long id = u16(extra, p), size = u16(extra, p + 2);
            if (p + 4 + size > extra.length) throw new Refusal(400, "not_a_zip", x);
            if (id == 0x7075) {
                if (size < 5) throw new Refusal(400, "not_a_zip", x);
                if (extra[p + 4] == 1) {
                    byte[] up = Arrays.copyOfRange(extra, p + 9, (int) (p + 4 + size));
                    if (!Arrays.equals(up, nameBytes)) throw new Refusal(400, "header_mismatch", x);
                }
            }
            p += 4 + (int) size;
        }
    }

    /** EXTENSION: the last part's text after its last ".", ASCII lower case; "" when there is none or it starts the part. */
    static String extension(String name) {
        String[] parts = partsOf(name);
        String last = parts[parts.length - 1];
        int dot = last.lastIndexOf('.');
        if (dot <= 0) return "";
        return asciiLower(last.substring(dot + 1));
    }

    /** ASCII lower case: A-Z to a-z only. In: text. Out: text of the same length. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static String asciiLower(String s) {
        char[] a = s.toCharArray();
        for (int k = 0; k < a.length; k++) if (a[k] >= 'A' && a[k] <= 'Z') a[k] = (char) (a[k] + 32);
        return new String(a);
    }

    // ------------------------------------------------------------------------------------------------ D helpers
    /**
     * The entry's bytes: stored as they are, or raw DEFLATE inflated with a cap of usize + 1 bytes. Any fault (invalid
     * data, too many or too few bytes, a wrong CRC-32) is 400 corrupt_entry.
     */
    private static byte[] readData(byte[] b, Central e) throws Refusal {
        long lo = e.localOffset();
        long start = lo + 30 + u16(b, lo + 26) + u16(b, lo + 28);
        byte[] comp = Arrays.copyOfRange(b, (int) start, (int) (start + e.csize()));
        byte[] out;
        if (e.method() == 0) {
            out = comp;
        } else {
            Inflater inf = new Inflater(true);
            try {
                inf.setInput(comp);
                long cap = e.usize() + 1;
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                long got = 0;
                while (got < cap) {
                    int n = inf.inflate(buf, 0, (int) Math.min(buf.length, cap - got));
                    if (n == 0) break;   // finished, input used up, or a dictionary asked for: what came out decides
                    bos.write(buf, 0, n);
                    got += n;
                }
                out = bos.toByteArray();
            } catch (DataFormatException ex) {
                throw new Refusal(400, "corrupt_entry", e.index());
            } finally {
                inf.end();
            }
        }
        if (out.length != e.usize()) throw new Refusal(400, "corrupt_entry", e.index());
        CRC32 crc = new CRC32();
        crc.update(out);
        if (crc.getValue() != e.crc()) throw new Refusal(400, "corrupt_entry", e.index());
        return out;
    }

    /** Creates dir and its missing parents up to base, each with mode 0755. */
    private static void makeDirs(Path dir, Path base) throws IOException {
        List<Path> missing = new ArrayList<>();
        for (Path d = dir; d != null && !d.equals(base) && !Files.exists(d, LinkOption.NOFOLLOW_LINKS); d = d.getParent()) {
            missing.add(d);
        }
        Collections.reverse(missing);
        for (Path d : missing) {
            Files.createDirectory(d);
            setMode(d, "rwxr-xr-x");
        }
    }

    /** Sets POSIX permissions where the file system has them (umask-independent). */
    private static void setMode(Path p, String perms) throws IOException {
        try {
            Set<PosixFilePermission> s = PosixFilePermissions.fromString(perms);
            Files.setPosixFilePermissions(p, s);
        } catch (UnsupportedOperationException e) {
            // not a POSIX file system: modes do not apply
        }
    }

    /** Removes a directory tree without following links; ignores what is already gone. */
    private static void removeTree(Path root) {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return;
        try (Stream<Path> s = Files.walk(root)) {
            List<Path> all = new ArrayList<>(s.toList());
            all.sort(Comparator.reverseOrder());
            for (Path p : all) {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // best effort; the next entry is still tried
                }
            }
        } catch (IOException ignored) {
            // nothing more can be removed
        }
    }

    /** In: bytes. Out: lower-case hex SHA-256. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static String sha256(byte[] data) {
        try {
            StringBuilder sb = new StringBuilder();
            for (byte v : MessageDigest.getInstance("SHA-256").digest(data)) sb.append(String.format("%02x", v & 0xff));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("sha-256 unavailable");
        }
    }
}
