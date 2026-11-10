// Tests for the safe archive ingest template (docs/specs/safe_archive_ingest.md, ARCHIVE-01..ARCHIVE-14), with the
// spec's test archive builder and fixed vectors. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave
// 1, owner request 2026-11-10). Offline. Touches: a temporary directory per test under the system temp folder, removed
// at the end.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using AOI.SafeArchiveIngest;

/// <summary>The ARCHIVE-01..ARCHIVE-14 tests, run by Main (a console harness). Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temp folders.</summary>
public static class SafeArchiveIngestTests
{
    private static int _failures;
    private static int _checks;
    private static readonly List<string> _temps = new List<string>();

    /// <summary>Runs every test, removes the temporary folders and returns 1 when any check failed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the console, temp folders.</summary>
    public static int Main()
    {
        try
        {
            TestBasicArchive();
            TestZipSlip();
            TestSpecialFiles();
            TestCountAndSizeLimits();
            TestDeclaredSizes();
            TestCompressionRatio();
            TestLyingHeaders();
            TestExtensions();
            TestDuplicateNames();
            TestContainer();
            TestFlagsAndMethods();
            TestHeaderMismatch();
            TestAllOrNothing();
            TestBadNames();
        }
        finally
        {
            foreach (var t in _temps) try { Directory.Delete(t, true); } catch (Exception) { }
        }
        Console.WriteLine($"\n=== Results: {_checks} checks, {_failures} failures ===");
        return _failures > 0 ? 1 : 0;
    }

    /// <summary>Counts one check; prints FAIL with the message when it is false. Touches: the console. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static void Check(bool condition, string message)
    {
        _checks++;
        if (!condition) { _failures++; Console.WriteLine("FAIL: " + message); }
    }

    /// <summary>Counts one equality check; prints both values on failure. Touches: the console. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static void Eq<T>(T expected, T actual, string message)
    {
        _checks++;
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            _failures++;
            Console.WriteLine($"FAIL: {message} -- expected <{expected}>, got <{actual}>");
        }
    }

    // ------------------------------------------------------------------ the spec's test archive builder

    /// <summary>A builder entry: name and data plus the spec's options (null = the default). Pure data. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private sealed class Z
    {
        public byte[] Name;
        public byte[] Data = Array.Empty<byte>();
        public long Method;
        public long? USize;
        public long? Crc;
        public long Flags;
        public long External;
        public long Creator;
        public byte[] Extra = Array.Empty<byte>();
        public byte[] LocalName;
        /// <summary>An entry named by text, with text data. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public Z(string name, string data = "") { Name = Encoding.UTF8.GetBytes(name); Data = Encoding.UTF8.GetBytes(data); }
        /// <summary>An entry named by raw bytes (names that are not UTF-8). Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public Z(byte[] name) { Name = name; }
    }

    /// <summary>Appends a little-endian u16. Touches: the list. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static void W16(List<byte> o, long v) { o.Add((byte)(v & 0xFF)); o.Add((byte)((v >> 8) & 0xFF)); }
    /// <summary>Appends a little-endian u32. Touches: the list. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static void W32(List<byte> o, long v) { for (var i = 0; i < 4; i++) o.Add((byte)((v >> (8 * i)) & 0xFF)); }

    /// <summary>
    /// build_zip(entries, comment): LOCAL RECORDs (needed 20, date 0x0021, extra_len 0), then CENTRAL RECORDs (made_by =
    /// creator * 256 + 20), then the END RECORD, as the spec lays out. Pure. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    private static byte[] BuildZip(IList<Z> entries, string comment = "")
    {
        var o = new List<byte>();
        var offsets = new List<long>();
        foreach (var e in entries)
        {
            var local = e.LocalName ?? e.Name;
            offsets.Add(o.Count);
            W32(o, 0x04034B50); W16(o, 20); W16(o, e.Flags); W16(o, e.Method); W16(o, 0); W16(o, 0x0021);
            W32(o, e.Crc ?? SafeArchiveIngest.Crc32(e.Data)); W32(o, e.Data.Length); W32(o, e.USize ?? e.Data.Length);
            W16(o, local.Length); W16(o, 0); o.AddRange(local); o.AddRange(e.Data);
        }
        var cdOffset = o.Count;
        for (var i = 0; i < entries.Count; i++)
        {
            var e = entries[i];
            W32(o, 0x02014B50); W16(o, e.Creator * 256 + 20); W16(o, 20); W16(o, e.Flags); W16(o, e.Method); W16(o, 0); W16(o, 0x0021);
            W32(o, e.Crc ?? SafeArchiveIngest.Crc32(e.Data)); W32(o, e.Data.Length); W32(o, e.USize ?? e.Data.Length);
            W16(o, e.Name.Length); W16(o, e.Extra.Length); W16(o, 0); W16(o, 0); W16(o, 0); W32(o, e.External); W32(o, offsets[i]);
            o.AddRange(e.Name); o.AddRange(e.Extra);
        }
        var cdSize = o.Count - cdOffset;
        var c = Encoding.UTF8.GetBytes(comment);
        W32(o, 0x06054B50); W16(o, 0); W16(o, 0); W16(o, entries.Count); W16(o, entries.Count); W32(o, cdSize); W32(o, cdOffset); W16(o, c.Length);
        o.AddRange(c);
        return o.ToArray();
    }

    /// <summary>Bytes from hex. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static byte[] FromHex(string hex) => Convert.FromHexString(hex);
    /// <summary>Lower-case hex of bytes. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
    private static readonly byte[] ZStream = FromHex("63601805a360148c8251300a46c1500700");

    /// <summary>The spec's BASIC archive (optionally with a comment). Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static byte[] Basic(string comment = "") => BuildZip(new[]
    {
        new Z("docs/") { External = 0x41ED0000, Creator = 3 },
        new Z("docs/readme.txt", "hello\n"),
        new Z("data.csv", "a,b\n1,2\n") { External = 0x81ED0000, Creator = 3 },
    }, comment);

    /// <summary>A new empty parent folder under the system temp folder; removed when the run ends. Touches: the file system. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static string Parent()
    {
        var p = Path.Combine(Path.GetTempPath(), "aoi-archive-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(p);
        _temps.Add(p);
        return p;
    }

    /// <summary>Asserts a refusal (error, status, entry_index), from inspect and from extract, and that extract left nothing. Touches: temp folders. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static void Refused(byte[] zip, string error, int status, long index, string name, ArchiveLimits limits = null)
    {
        var r = SafeArchiveIngest.InspectArchive(zip, limits);
        Eq((error, status, index), (r.Error, r.Status, r.EntryIndex), "inspect: " + name);
        var parent = Parent();
        var target = Path.Combine(parent, "out");
        var x = SafeArchiveIngest.ExtractArchive(zip, target, limits);
        Eq((error, status, index), (x.Error, x.Status, x.EntryIndex), "extract: " + name);
        Eq(0, Directory.GetFileSystemEntries(parent).Length, "nothing was written: " + name);
    }

    /// <summary>
    /// Asserts a refusal that only extraction can find (D3: the data is read only there): inspect accepts the archive,
    /// extract refuses it and leaves nothing. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temp folders.
    /// </summary>
    private static void RefusedOnExtract(byte[] zip, string error, int status, long index, string name)
    {
        Check(SafeArchiveIngest.InspectArchive(zip).Ok, "inspect reads no data and accepts: " + name);
        var parent = Parent();
        var x = SafeArchiveIngest.ExtractArchive(zip, Path.Combine(parent, "out"));
        Eq((error, status, index), (x.Error, x.Status, x.EntryIndex), "extract: " + name);
        Eq(0, Directory.GetFileSystemEntries(parent).Length, "no file is left: " + name);
    }

    /// <summary>Asserts that inspect and extract accept the archive. Out: the extract result. Touches: temp folders. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static ArchiveResult Accepted(byte[] zip, string name, ArchiveLimits limits = null)
    {
        var r = SafeArchiveIngest.InspectArchive(zip, limits);
        Check(r.Ok, $"inspect accepts {name} (got {r.Error} {r.EntryIndex})");
        var target = Path.Combine(Parent(), "out");
        var x = SafeArchiveIngest.ExtractArchive(zip, target, limits);
        Check(x.Ok, $"extract accepts {name} (got {x.Error} {x.EntryIndex})");
        return x;
    }

    // ------------------------------------------------------------------ tests

    /// <summary>
    /// The builder reproduces BASIC byte for byte; extract writes its two files with the right bytes, creates docs/,
    /// returns each path, size and SHA-256, writes data.csv 0644 although its entry says 0755, and leaves the target 0700.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: a temp folder.
    /// </summary>
    // ARCHIVE-01
    public static void TestBasicArchive()
    {
        var basic = Basic();
        Eq("504b03041400000000000000210000000000000000000000000005000000646f63732f504b0304140000000000000021" +
           "0020303a3606000000060000000f000000646f63732f726561646d652e74787468656c6c6f0a504b0304140000000000" +
           "000021007b07970a080000000800000008000000646174612e637376612c620a312c320a504b01021403140000000000" +
           "00002100000000000000000000000000050000000000000000000000ed4100000000646f63732f504b01021400140000" +
           "0000000000210020303a3606000000060000000f0000000000000000000000000023000000646f63732f726561646d65" +
           "2e747874504b01021403140000000000000021007b07970a0800000008000000080000000000000000000000ed815600" +
           "0000646174612e637376504b05060000000003000300a6000000840000000000", Hex(basic), "BASIC byte for byte");
        Eq(320, basic.Length, "320 bytes");
        var target = Path.Combine(Parent(), "target");
        var r = SafeArchiveIngest.ExtractArchive(basic, target);
        Eq((true, 3L, 14L), (r.Ok, r.Entries, r.TotalBytes), "entries and total");
        Eq("docs/readme.txt 6 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03|data.csv 8 492d5ea496056f1a6a6592241032fab764c321596317930b4fa0e1e8bc3b7470",
            string.Join("|", r.Files.Select(f => $"{f.Path} {f.Size} {f.Sha256}")), "files in directory order");
        Eq("hello\n", File.ReadAllText(Path.Combine(target, "docs", "readme.txt")), "readme bytes");
        Eq("a,b\n1,2\n", File.ReadAllText(Path.Combine(target, "data.csv")), "csv bytes");
        Check(Directory.Exists(Path.Combine(target, "docs")), "docs is a directory");
        if (!OperatingSystem.IsWindows())
        {
            Eq(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead,
                File.GetUnixFileMode(Path.Combine(target, "data.csv")), "data.csv is 0644, not executable");
            Eq(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(target), "target keeps 0700");
        }
        var inspect = SafeArchiveIngest.InspectArchive(basic);
        Eq("docs/readme.txt 6|data.csv 8", string.Join("|", inspect.Files.Select(f => $"{f.Path} {f.Size}")), "inspect lists the files");
        Eq(1, Directory.GetFileSystemEntries(Path.GetDirectoryName(target)).Length, "no staging directory is left");
    }

    /// <summary>
    /// Zip slip: ../evil.txt, a/../../evil.txt, /etc/passwd.txt, C:/x.txt, a\b.txt, a//b.txt, ./a.txt, NUL and control
    /// bytes, an empty name and four non-strict-UTF-8 names are 400 unsafe_path with the entry's index; nothing exists
    /// afterwards. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temp folders.
    /// </summary>
    // ARCHIVE-02
    public static void TestZipSlip()
    {
        var names = new List<byte[]>
        {
            Encoding.UTF8.GetBytes("../evil.txt"), Encoding.UTF8.GetBytes("a/../../evil.txt"), Encoding.UTF8.GetBytes("/etc/passwd.txt"),
            Encoding.UTF8.GetBytes("C:/x.txt"), Encoding.UTF8.GetBytes("a\\b.txt"), Encoding.UTF8.GetBytes("a//b.txt"),
            Encoding.UTF8.GetBytes("./a.txt"), Encoding.UTF8.GetBytes("a\0b.txt"), Encoding.UTF8.GetBytes("a\u0001b.txt"),
            Encoding.UTF8.GetBytes("a\u007fb.txt"), Array.Empty<byte>(),
            FromHex("61C0AF622E747874"), FromHex("61EDA0802E747874"), FromHex("61F49080802E747874"), FromHex("61E2822E747874"),
        };
        foreach (var n in names)
            Refused(BuildZip(new[] { new Z("ok.txt", "x"), new Z(n) { Data = Encoding.UTF8.GetBytes("evil") } }), "unsafe_path", 400, 1, "name " + Hex(n));
        Refused(BuildZip(new[] { new Z("../evil.txt", "x") }), "unsafe_path", 400, 0, "first entry");
    }

    /// <summary>
    /// A symbolic link (mode 0120000) is special_file whatever the creator (0, 3, 19), and so is a FIFO; a regular-file
    /// mode is accepted. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temp folders.
    /// </summary>
    // ARCHIVE-03
    public static void TestSpecialFiles()
    {
        foreach (var creator in new long[] { 0, 3, 19 })
            Refused(BuildZip(new[] { new Z("link.txt", "/etc/passwd") { External = 0xA1FF0000, Creator = creator } }), "special_file", 400, 0, "link, creator " + creator);
        Refused(BuildZip(new[] { new Z("ok.txt", "x"), new Z("fifo.txt", "") { External = 0x11A40000, Creator = 3 } }), "special_file", 400, 1, "FIFO");
        Accepted(BuildZip(new[] { new Z("file.txt", "x") { External = 0x81A40000, Creator = 3 } }), "a regular file");
    }

    /// <summary>
    /// More entries than max_entries is 413 too_many_entries, more bytes than max_archive_bytes 413 archive_too_large;
    /// exactly at each limit the archive is accepted (the spec's 283-byte archive). 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temp folders.
    /// </summary>
    // ARCHIVE-04
    public static void TestCountAndSizeLimits()
    {
        var zip = BuildZip(new[] { new Z("a.txt", "x"), new Z("b.txt", "x"), new Z("c.txt", "x") });
        Eq(283, zip.Length, "283 bytes");
        Accepted(zip, "at both limits", new ArchiveLimits { MaxEntries = 3, MaxArchiveBytes = 283 });
        Refused(zip, "too_many_entries", 413, -1, "max_entries 2", new ArchiveLimits { MaxEntries = 2 });
        Refused(zip, "archive_too_large", 413, -1, "max_archive_bytes 282", new ArchiveLimits { MaxArchiveBytes = 282 });
    }

    /// <summary>
    /// A declared total over max_total_bytes is total_too_large (index 1), one entry over max_file_bytes entry_too_large
    /// (index 0); exactly at each limit it is accepted; 0x80000000 is read unsigned (413, never negative).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temp folders.
    /// </summary>
    // ARCHIVE-05
    public static void TestDeclaredSizes()
    {
        var zip = BuildZip(new[] { new Z("a.txt", "12345"), new Z("b.txt", "67890") });
        Eq(204, zip.Length, "204 bytes");
        Accepted(zip, "at both limits", new ArchiveLimits { MaxTotalBytes = 10, MaxFileBytes = 5 });
        Refused(zip, "total_too_large", 413, 1, "max_total_bytes 9", new ArchiveLimits { MaxTotalBytes = 9 });
        Refused(zip, "entry_too_large", 413, 0, "max_file_bytes 4", new ArchiveLimits { MaxFileBytes = 4 });
        var huge = BuildZip(new[] { new Z("a.txt") { Data = ZStream, Method = 8, USize = 0x80000000, Crc = 0 } });
        Refused(huge, "entry_too_large", 413, 0, "usize 0x80000000");
        Refused(huge, "compression_ratio_exceeded", 413, -1, "usize 0x80000000 under 4 GiB limits",
            new ArchiveLimits { MaxFileBytes = 4294967296, MaxTotalBytes = 4294967296 });
    }

    /// <summary>
    /// The ZEROS archive (133 bytes declaring 2000) is 413 compression_ratio_exceeded with max_ratio 15 and is extracted
    /// with max_ratio 16 (2000 zero bytes). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temp folders.
    /// </summary>
    // ARCHIVE-06
    public static void TestCompressionRatio()
    {
        Eq(0x02C9F444L, SafeArchiveIngest.Crc32(new byte[2000]), "CRC-32 of 2000 zeros");
        Eq(0xE38A6876L, SafeArchiveIngest.Crc32(new byte[10]), "CRC-32 of 10 zeros");
        var zeros = BuildZip(new[] { new Z("zeros.txt") { Data = ZStream, Method = 8, USize = 2000, Crc = 0x02C9F444 } });
        Eq(133, zeros.Length, "133 bytes");
        Refused(zeros, "compression_ratio_exceeded", 413, -1, "max_ratio 15", new ArchiveLimits { MaxRatio = 15 });
        var x = Accepted(zeros, "max_ratio 16", new ArchiveLimits { MaxRatio = 16 });
        Eq((2000L, 2000L), (x.TotalBytes, x.Files.Single().Size), "2000 bytes");
    }

    /// <summary>
    /// Lying headers: declares 10 but inflates to 2000; declares 3000; a stream missing its last 4 bytes; a stream that
    /// overruns and then turns invalid; a wrong CRC (deflated and stored); invalid data: 400 corrupt_entry; a stored
    /// entry whose sizes differ: 400 size_mismatch; no file is left. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: temp folders.
    /// </summary>
    // ARCHIVE-07
    public static void TestLyingHeaders()
    {
        var bad = FromHex("62601805a360148c8251300a46c1500700000000ffff07");
        var cases = new List<(string Name, Z Entry)>
        {
            ("declares 10, inflates to 2000", new Z("zeros.txt") { Data = ZStream, Method = 8, USize = 10, Crc = 0xE38A6876 }),
            ("declares 3000", new Z("zeros.txt") { Data = ZStream, Method = 8, USize = 3000, Crc = 0x02C9F444 }),
            ("stream missing its last 4 bytes", new Z("zeros.txt") { Data = ZStream.Take(ZStream.Length - 4).ToArray(), Method = 8, USize = 2000, Crc = 0x02C9F444 }),
            ("deflated, crc 1", new Z("zeros.txt") { Data = ZStream, Method = 8, USize = 2000, Crc = 1 }),
            ("stored, crc 0", new Z("a.txt", "12345") { Crc = 0 }),
            ("invalid data", new Z("zeros.txt") { Data = FromHex("FFFFFFFF"), Method = 8, USize = 4, Crc = 0 }),
            ("overruns then turns invalid", new Z("zeros.txt") { Data = bad, Method = 8, USize = 10, Crc = 0xE38A6876 }),
        };
        foreach (var (name, entry) in cases)
            RefusedOnExtract(BuildZip(new[] { entry }), "corrupt_entry", 400, 0, name);
        Refused(BuildZip(new[] { new Z("a.txt", "12345") { USize = 4 } }), "size_mismatch", 400, 0, "stored, usize 4");
    }

    /// <summary>
    /// Extensions: run.exe, a.txt.sh, README, .env and inner.zip are extension_not_allowed with the default list; A.TXT
    /// and x.Json are accepted; with ["", "sh"] README and a.sh are accepted. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: temp folders.
    /// </summary>
    // ARCHIVE-08
    public static void TestExtensions()
    {
        foreach (var n in new[] { "run.exe", "a.txt.sh", "README", ".env", "inner.zip" })
            Refused(BuildZip(new[] { new Z(n, "x") }), "extension_not_allowed", 400, 0, n);
        Accepted(BuildZip(new[] { new Z("A.TXT", "x"), new Z("x.Json", "{}") }), "A.TXT and x.Json");
        Accepted(BuildZip(new[] { new Z("README", "x"), new Z("a.sh", "echo") }), "README and a.sh with [\"\", \"sh\"]",
            new ArchiveLimits { AllowedExtensions = new List<string> { "", "sh" } });
    }

    /// <summary>
    /// a.txt twice, A.txt with a.txt, a file with a path under it (either order) and a directory with a file of the same
    /// name (either order) are 400 duplicate_name with entry_index 1; the same directory twice is accepted. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temp folders.
    /// </summary>
    // ARCHIVE-09
    public static void TestDuplicateNames()
    {
        var pairs = new[] { ("a.txt", "a.txt"), ("A.txt", "a.txt"), ("d.txt/", "d.txt"), ("d.txt", "d.txt/"), ("d.txt", "d.txt/e.txt"), ("d.txt/e.txt", "d.txt") };
        foreach (var (first, second) in pairs)
            Refused(BuildZip(new[] { new Z(first, first.EndsWith("/") ? "" : "x"), new Z(second, second.EndsWith("/") ? "" : "y") }), "duplicate_name", 400, 1, first + " then " + second);
        Accepted(BuildZip(new[] { new Z("d/"), new Z("d/"), new Z("d/a.txt", "x") }), "the same directory twice");
    }

    /// <summary>Returns a copy with the little-endian value written at an offset from the end. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    private static byte[] Patch(byte[] zip, int fromEnd, long value, int width)
    {
        var copy = (byte[])zip.Clone();
        for (var i = 0; i < width; i++) copy[copy.Length - fromEnd + i] = (byte)((value >> (8 * i)) & 0xFF);
        return copy;
    }

    /// <summary>
    /// The container: empty is empty_upload; not a zip, truncated, a count that disagrees with the directory, a byte
    /// after the end record and a wrapping offset + size are not_a_zip; a disk number and a zip64 marker are
    /// unsupported_zip; a 42-byte input is never read before its start; only a directory is empty_archive; a comment is
    /// accepted. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temp folders.
    /// </summary>
    // ARCHIVE-10
    public static void TestContainer()
    {
        var basic = Basic();
        Refused(Array.Empty<byte>(), "empty_upload", 400, -1, "empty");
        Refused(Encoding.ASCII.GetBytes("this is plain text, not a zip at all"), "not_a_zip", 400, -1, "text");
        Refused(basic.Take(basic.Length - 10).ToArray(), "not_a_zip", 400, -1, "truncated");
        Refused(Patch(Patch(basic, 14, 4, 2), 12, 4, 2), "not_a_zip", 400, -1, "4 entries declared, 3 in the directory");
        Refused(basic.Concat(new byte[] { 0 }).ToArray(), "not_a_zip", 400, -1, "a byte after the end record");
        Refused(Patch(Patch(basic, 10, 300, 4), 6, 0xFFFFFFFE, 4), "not_a_zip", 400, -1, "offset + size wraps in 32 bits");
        Refused(Patch(basic, 18, 1, 2), "unsupported_zip", 400, -1, "disk 1");
        Refused(Patch(Patch(basic, 14, 0xFFFF, 2), 12, 0xFFFF, 2), "unsupported_zip", 400, -1, "zip64 marker counts");
        Refused(FromHex("504b0304504b0506000000000000000000000000040000001000504b0607787878787878787878787878"), "empty_archive", 400, -1, "42 bytes, comment starting with the zip64 mark");
        Refused(BuildZip(new[] { new Z("docs/") }), "empty_archive", 400, -1, "only a directory");
        var withComment = Basic(new string('c', 40));
        Accepted(withComment, "a 40-byte comment");
    }

    /// <summary>
    /// Flag bit 0 or 6 is 400 encrypted_entry; a method other than 0 and 8 is 400 unsupported_compression; flag bit 3 (a
    /// data descriptor) is accepted. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temp folders.
    /// </summary>
    // ARCHIVE-11
    public static void TestFlagsAndMethods()
    {
        Refused(BuildZip(new[] { new Z("a.txt", "12345") { Flags = 1 } }), "encrypted_entry", 400, 0, "flag bit 0");
        Refused(BuildZip(new[] { new Z("ok.txt", "x"), new Z("a.txt", "12345") { Flags = 0x40 } }), "encrypted_entry", 400, 1, "flag bit 6");
        Refused(BuildZip(new[] { new Z("a.txt", "12345") { Method = 12 } }), "unsupported_compression", 400, 0, "method 12 (bzip2)");
        var x = Accepted(BuildZip(new[] { new Z("a.txt", "12345") { Flags = 8 } }), "flag bit 3");
        Eq("a.txt 5", string.Join("", x.Files.Select(f => f.Path + " " + f.Size)), "sizes from the central record");
    }

    /// <summary>
    /// A local name that differs from the central one is header_mismatch with its index; a Unicode Path field naming
    /// ../evil.txt is header_mismatch, the same field naming the entry is accepted, and an extra field that overruns is
    /// not_a_zip. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temp folders.
    /// </summary>
    // ARCHIVE-12
    public static void TestHeaderMismatch()
    {
        Refused(BuildZip(new[] { new Z("ok.txt", "x") { LocalName = Encoding.UTF8.GetBytes("no.txt") } }), "header_mismatch", 400, 0, "local name differs");
        Refused(BuildZip(new[] { new Z("a.txt", "x"), new Z("ok.txt", "x") { LocalName = Encoding.UTF8.GetBytes("no.txt") } }), "header_mismatch", 400, 1, "local name differs, second entry");
        var crc = SafeArchiveIngest.Crc32(Encoding.UTF8.GetBytes("ok.txt"));
        var evil = FromHex("75701000012a0419052e2e2f6576696c2e747874");
        Eq(0x0519042AL, crc, "CRC-32 of ok.txt as in the spec's block");
        Refused(BuildZip(new[] { new Z("ok.txt", "x") { Extra = evil } }), "header_mismatch", 400, 0, "Unicode Path ../evil.txt");
        var same = new List<byte> { 0x75, 0x70, 11, 0, 1 };
        for (var i = 0; i < 4; i++) same.Add((byte)((crc >> (8 * i)) & 0xFF));
        same.AddRange(Encoding.UTF8.GetBytes("ok.txt"));
        Accepted(BuildZip(new[] { new Z("ok.txt", "x") { Extra = same.ToArray() } }), "Unicode Path naming the entry");
        Refused(BuildZip(new[] { new Z("ok.txt", "x") { Extra = FromHex("0A0032006162") } }), "not_a_zip", 400, 0, "an extra field that overruns");
        Refused(BuildZip(new[] { new Z("ok.txt", "x") { Extra = FromHex("757003000100") } }), "not_a_zip", 400, 0, "a Unicode Path block under 5 bytes");
    }

    /// <summary>
    /// All or nothing: a corrupt second entry names entry_index 1, the target does not exist and no staging directory is
    /// left; an existing target (directory, file or dangling link) is 409 target_exists and keeps its content; a missing
    /// parent is 500 target_unwritable. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temp folders.
    /// </summary>
    // ARCHIVE-13
    public static void TestAllOrNothing()
    {
        var zip = BuildZip(new[] { new Z("good.txt", "fine"), new Z("zeros.txt") { Data = ZStream, Method = 8, USize = 2000, Crc = 1 } });
        var parent = Parent();
        var target = Path.Combine(parent, "t");
        var r = SafeArchiveIngest.ExtractArchive(zip, target);
        Eq(("corrupt_entry", 400, 1L), (r.Error, r.Status, r.EntryIndex), "the second entry is corrupt");
        Check(!Directory.Exists(target), "the target does not exist");
        Eq(0, Directory.GetFileSystemEntries(parent).Length, "no staging directory is left");

        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "keep.txt"), "mine");
        var exists = SafeArchiveIngest.ExtractArchive(Basic(), target);
        Eq(("target_exists", 409, -1L), (exists.Error, exists.Status, exists.EntryIndex), "an existing directory");
        Eq("mine", File.ReadAllText(Path.Combine(target, "keep.txt")), "keeps its content");
        Eq(1, Directory.GetFileSystemEntries(target).Length, "nothing added");
        var file = Path.Combine(parent, "file");
        File.WriteAllText(file, "x");
        Eq("target_exists", SafeArchiveIngest.ExtractArchive(Basic(), file).Error, "an existing file");
        if (!OperatingSystem.IsWindows())
        {
            var link = Path.Combine(parent, "dangling");
            File.CreateSymbolicLink(link, Path.Combine(parent, "nowhere"));
            Eq("target_exists", SafeArchiveIngest.ExtractArchive(Basic(), link).Error, "a link that points nowhere");
        }
        var orphan = Path.Combine(parent, "missing-parent", "t");
        var unwritable = SafeArchiveIngest.ExtractArchive(Basic(), orphan);
        Eq(("target_unwritable", 500, -1L), (unwritable.Error, unwritable.Status, unwritable.EntryIndex), "a missing parent");
        Check(!Directory.Exists(Path.Combine(parent, "missing-parent")), "the parent was not created");
    }

    /// <summary>
    /// Names that do not unpack everywhere are bad_name: CON.txt, com1.txt, COM0.txt, LPT0.txt, COM + superscript 1,
    /// CONIN$.txt, CONOUT$.txt, a trailing dot or space, a?.txt, a 256-byte segment, a right-to-left override; an
    /// accented UTF-8 name, a 255-byte segment, COM10.txt and conin.txt are accepted; a 0755 entry is written without
    /// execute permission. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temp folders.
    /// </summary>
    // ARCHIVE-14
    public static void TestBadNames()
    {
        var bad = new[]
        {
            "CON.txt", "com1.txt", "COM0.txt", "LPT0.txt", "COM\u00b9.txt", "CONIN$.txt", "CONOUT$.txt", "a.txt.", "a.txt ",
            "a?.txt", new string('x', 252) + ".txt", "a\u202eb.txt", "d/nul.txt", "con .txt",
        };
        foreach (var n in bad)
            Refused(BuildZip(new[] { new Z("ok.txt", "x"), new Z(n, "x") }), "bad_name", 400, 1, "bad name " + n.Length + " " + n.Substring(0, Math.Min(10, n.Length)));
        var x = Accepted(BuildZip(new[]
        {
            new Z("caf\u00e9.txt", "x"), new Z(new string('x', 251) + ".txt", "y"), new Z("COM10.txt", "z"), new Z("conin.txt", "w"),
            new Z("run.txt", "#!/bin/sh") { External = 0x81ED0000, Creator = 3 },
        }), "good names");
        Eq("caf\u00e9.txt", x.Files[0].Path, "the accented name is kept");
        var target = Path.Combine(Parent(), "modes");
        SafeArchiveIngest.ExtractArchive(BuildZip(new[] { new Z("run.txt", "#!/bin/sh") { External = 0x81ED0000, Creator = 3 } }), target);
        if (!OperatingSystem.IsWindows())
            Check((File.GetUnixFileMode(Path.Combine(target, "run.txt")) & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) == 0,
                "a 0755 entry is written without execute permission");
    }
}
