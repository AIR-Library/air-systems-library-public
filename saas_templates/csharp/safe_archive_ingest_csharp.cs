// Safe archive ingest template (docs/specs/safe_archive_ingest.md): takes an uploaded .zip and unpacks it into a new
// directory without trusting anything in it. The zip records (END, CENTRAL, LOCAL) are read here byte by byte, never
// by a zip library's extract function; names are strict UTF-8 and checked for zip slip, links, devices and names that
// do not unpack everywhere; counts, sizes and the compression ratio are capped; data is inflated with a cap of usize +
// 1 bytes and its CRC-32 checked; files are written into a 0700 staging directory with exclusive create and mode 0644,
// and the staging directory is renamed into place only when every file was written (all or nothing).
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1, owner request 2026-11-10).
// Touches: the file system under target_dir's parent (extract only). No network, no database, no money.
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AOI.SafeArchiveIngest
{
    /// <summary>
    /// The injected limits; the defaults are the spec's. Pure data. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    public sealed class ArchiveLimits
    {
        public long MaxArchiveBytes { get; set; } = 20971520;
        public long MaxEntries { get; set; } = 1000;
        public long MaxFileBytes { get; set; } = 26214400;
        public long MaxTotalBytes { get; set; } = 104857600;
        public long MaxRatio { get; set; } = 100;
        public List<string> AllowedExtensions { get; set; } = new List<string> { "txt", "md", "csv", "json", "pdf", "png", "jpg", "jpeg", "gif" };
    }

    /// <summary>One file of a result: its path ("/" separators), size and, after extraction, its SHA-256. Pure data. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public sealed class ArchiveFile
    {
        public string Path { get; set; }
        public long Size { get; set; }
        public string Sha256 { get; set; }
    }

    /// <summary>
    /// The answer of inspect_archive and extract_archive: {ok, entries, total_bytes, files} or a refusal {error, status,
    /// entry_index}. The refusal names an index, never the entry's name. Pure data. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    public sealed class ArchiveResult
    {
        public bool Ok => Error == null;
        public int Status { get; set; } = 200;
        public string Error { get; set; }
        public long EntryIndex { get; set; } = -1;
        public long Entries { get; set; }
        public long TotalBytes { get; set; }
        public List<ArchiveFile> Files { get; set; } = new List<ArchiveFile>();

        /// <summary>A refusal. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public static ArchiveResult Fail(int status, string error, long entryIndex = -1) =>
            new ArchiveResult { Status = status, Error = error, EntryIndex = entryIndex };
    }

    /// <summary>
    /// inspect_archive and extract_archive with checks A, B, C and D of the spec. Written 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1, owner request 2026-11-10). Touches: the file system (extract).
    /// </summary>
    public static class SafeArchiveIngest
    {
        /// <summary>One central-directory entry as read (every number a 64-bit integer). Pure data. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private sealed class Entry
        {
            public long Flags, Method, Crc, CSize, USize, DiskStart, External, LocalOffset, MadeBy;
            public byte[] NameBytes, Extra;
            public string Name;
            public bool IsDir;
            public string[] Parts;
        }

        /// <summary>The checks A, B and C passed: the entries and the archive's numbers. Pure data. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private sealed class Parsed
        {
            public List<Entry> Entries;
            public long Total;
            public long CdOffset;
        }

        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        /// <summary>
        /// inspect_archive: runs checks A, B and C; reads no file data and writes nothing. In: the upload's bytes and the
        /// limits (null = defaults). Out: {ok, entries, total_bytes, files [{path, size}]} or the refusal. Why: ARCHIVE-02..12,
        /// 14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Pure.
        /// </summary>
        public static ArchiveResult InspectArchive(byte[] bytes, ArchiveLimits limits = null)
        {
            var (parsed, refusal) = Check(bytes, limits ?? new ArchiveLimits());
            if (refusal != null) return refusal;
            return new ArchiveResult
            {
                Entries = parsed.Entries.Count, TotalBytes = parsed.Total,
                Files = parsed.Entries.Where(e => !e.IsDir).Select(e => new ArchiveFile { Path = e.Name, Size = e.USize }).ToList(),
            };
        }

        /// <summary>
        /// extract_archive: checks A, B and C (the same answers as inspect_archive), then D: 409 target_exists (also a
        /// dangling link), a 0700 staging directory beside the target (500 target_unwritable when it cannot be made), each
        /// entry written (directories 0755, files 0644 with exclusive create; data inflated with a cap of usize + 1 and its
        /// CRC checked: 400 corrupt_entry), then the staging directory renamed to the target. Any refusal or error removes
        /// the staging directory first. In: the bytes, target_dir (from the server, never the upload), the limits and an
        /// optional source of 16 hex characters for the staging name. Out: {ok, entries, total_bytes, files [{path, size,
        /// sha256}]} or the refusal. Why: ARCHIVE-01, 06, 07, 13, 14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// Touches: the file system under target_dir's parent.
        /// </summary>
        public static ArchiveResult ExtractArchive(byte[] bytes, string targetDir, ArchiveLimits limits = null, Func<string> stagingSuffix = null)
        {
            var (parsed, refusal) = Check(bytes, limits ?? new ArchiveLimits());
            if (refusal != null) return refusal;

            // D1: the name itself, without following links
            if (string.IsNullOrEmpty(targetDir) || PathExists(targetDir)) return ArchiveResult.Fail(409, "target_exists");
            var target = Path.GetFullPath(targetDir).TrimEnd(Path.DirectorySeparatorChar);
            var parent = Path.GetDirectoryName(target);
            var staging = target + ".partial-" + (stagingSuffix?.Invoke() ?? Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant());
            // D2
            try
            {
                if (parent == null || !Directory.Exists(parent) || PathExists(staging)) return ArchiveResult.Fail(500, "target_unwritable");
                if (OperatingSystem.IsWindows()) Directory.CreateDirectory(staging);
                else Directory.CreateDirectory(staging, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
            catch (Exception)
            {
                return ArchiveResult.Fail(500, "target_unwritable");
            }

            try
            {
                var files = new List<ArchiveFile>();
                var root = Path.GetFullPath(staging) + Path.DirectorySeparatorChar;
                for (var idx = 0; idx < parsed.Entries.Count; idx++)
                {
                    var e = parsed.Entries[idx];
                    // D3
                    var dest = Path.GetFullPath(Path.Combine(new[] { staging }.Concat(e.Parts).ToArray()));
                    if (!dest.StartsWith(root, StringComparison.Ordinal)) return Abort(staging, ArchiveResult.Fail(400, "unsafe_path", idx));
                    if (e.IsDir)
                    {
                        MakeDirs(dest);
                        continue;
                    }
                    var data = ReadData(bytes, e);
                    if (data == null || Crc32(data) != e.Crc) return Abort(staging, ArchiveResult.Fail(400, "corrupt_entry", idx));
                    MakeDirs(Path.GetDirectoryName(dest));
                    if (PathExists(dest)) return Abort(staging, ArchiveResult.Fail(400, "duplicate_name", idx));
                    try
                    {
                        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
                        if (!OperatingSystem.IsWindows())
                            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
                        using var fs = new FileStream(dest, options);
                        fs.Write(data, 0, data.Length);
                    }
                    catch (IOException) when (PathExists(dest))
                    {
                        return Abort(staging, ArchiveResult.Fail(400, "duplicate_name", idx));
                    }
                    files.Add(new ArchiveFile { Path = e.Name, Size = data.Length, Sha256 = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant() });
                }
                // D4
                Directory.Move(staging, target);
                return new ArchiveResult { Entries = parsed.Entries.Count, TotalBytes = parsed.Total, Files = files };
            }
            catch (Exception)
            {
                return Abort(staging, ArchiveResult.Fail(500, "target_unwritable"));
            }
        }

        // ------------------------------------------------------------------ checks A, B, C

        /// <summary>Checks A, B and C in the spec's order. Out: the parsed entries, or the first refusal. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static (Parsed, ArchiveResult) Check(byte[] b, ArchiveLimits limits)
        {
            long len = b?.Length ?? 0;
            // A1-A3
            if (len == 0) return (null, ArchiveResult.Fail(400, "empty_upload"));
            if (len > limits.MaxArchiveBytes) return (null, ArchiveResult.Fail(413, "archive_too_large"));
            if (len < 4 || U32(b, 0) != 0x04034B50) return (null, ArchiveResult.Fail(400, "not_a_zip"));
            // A4
            long end = -1;
            for (var i = len - 22; i >= Math.Max(0, len - 65557); i--)
                if (U32(b, i) == 0x06054B50 && i + 22 + U16(b, i + 20) == len) { end = i; break; }
            if (end < 0) return (null, ArchiveResult.Fail(400, "not_a_zip"));
            long disk = U16(b, end + 4), cdDisk = U16(b, end + 6), here = U16(b, end + 8), entries = U16(b, end + 10);
            long cdSize = U32(b, end + 12), cdOffset = U32(b, end + 16);
            // A5
            if (disk != 0 || cdDisk != 0 || here != entries || entries == 0xFFFF || cdSize == 0xFFFFFFFFL || cdOffset == 0xFFFFFFFFL ||
                (end >= 20 && U32(b, end - 20) == 0x07064B50))
                return (null, ArchiveResult.Fail(400, "unsupported_zip"));
            // A6-A8
            if (cdOffset + cdSize != end) return (null, ArchiveResult.Fail(400, "not_a_zip"));
            if (entries == 0) return (null, ArchiveResult.Fail(400, "empty_archive"));
            if (entries > limits.MaxEntries) return (null, ArchiveResult.Fail(413, "too_many_entries"));

            // B
            var list = new List<Entry>();
            var p = cdOffset;
            for (var n = 0; n < entries; n++)
            {
                if (p + 46 > end || U32(b, p) != 0x02014B50) return (null, ArchiveResult.Fail(400, "not_a_zip"));
                long nameLen = U16(b, p + 28), extraLen = U16(b, p + 30), commentLen = U16(b, p + 32);
                var next = p + 46 + nameLen + extraLen + commentLen;
                if (next > end) return (null, ArchiveResult.Fail(400, "not_a_zip"));
                list.Add(new Entry
                {
                    MadeBy = U16(b, p + 4), Flags = U16(b, p + 8), Method = U16(b, p + 10), Crc = U32(b, p + 16), CSize = U32(b, p + 20),
                    USize = U32(b, p + 24), DiskStart = U16(b, p + 34), External = U32(b, p + 38), LocalOffset = U32(b, p + 42),
                    NameBytes = Slice(b, p + 46, nameLen), Extra = Slice(b, p + 46 + nameLen, extraLen),
                });
                p = next;
            }
            if (p != end) return (null, ArchiveResult.Fail(400, "not_a_zip"));

            // C1-C12
            var allowed = new HashSet<string>(limits.AllowedExtensions ?? new List<string>(), StringComparer.Ordinal);
            var fileKeys = new HashSet<string>(StringComparer.Ordinal);
            var dirKeys = new HashSet<string>(StringComparer.Ordinal);
            long total = 0;
            for (var idx = 0; idx < list.Count; idx++)
            {
                var e = list[idx];
                if (e.CSize == 0xFFFFFFFFL || e.USize == 0xFFFFFFFFL || e.LocalOffset == 0xFFFFFFFFL || e.DiskStart != 0)
                    return (null, ArchiveResult.Fail(400, "unsupported_zip", idx));
                if ((e.Flags & 0x2041) != 0) return (null, ArchiveResult.Fail(400, "encrypted_entry", idx));
                if (e.Method != 0 && e.Method != 8) return (null, ArchiveResult.Fail(400, "unsupported_compression", idx));
                if (!SafePath(e)) return (null, ArchiveResult.Fail(400, "unsafe_path", idx));
                if (BadName(e)) return (null, ArchiveResult.Fail(400, "bad_name", idx));
                var extra = CheckExtra(e);
                if (extra != null) return (null, ArchiveResult.Fail(400, extra, idx));
                var type = (e.External >> 16) & 0xF000;
                if (type != 0 && type != 0x8000 && type != 0x4000) return (null, ArchiveResult.Fail(400, "special_file", idx));
                if ((e.IsDir && e.USize != 0) || (!e.IsDir && e.Method == 0 && e.CSize != e.USize))
                    return (null, ArchiveResult.Fail(400, "size_mismatch", idx));
                if (!e.IsDir && !allowed.Contains(Extension(e.Parts[e.Parts.Length - 1]))) return (null, ArchiveResult.Fail(400, "extension_not_allowed", idx));
                var key = AsciiLower(string.Join("/", e.Parts));
                var duplicate = fileKeys.Contains(key) || (!e.IsDir && dirKeys.Contains(key));
                for (var j = key.IndexOf('/'); j >= 0 && !duplicate; j = key.IndexOf('/', j + 1))
                    duplicate = fileKeys.Contains(key.Substring(0, j));
                if (duplicate) return (null, ArchiveResult.Fail(400, "duplicate_name", idx));
                (e.IsDir ? dirKeys : fileKeys).Add(key);
                for (var j = key.IndexOf('/'); j >= 0; j = key.IndexOf('/', j + 1)) dirKeys.Add(key.Substring(0, j));
                if (e.USize > limits.MaxFileBytes) return (null, ArchiveResult.Fail(413, "entry_too_large", idx));
                total += e.USize;
                if (total > limits.MaxTotalBytes) return (null, ArchiveResult.Fail(413, "total_too_large", idx));
            }
            // C13, C14
            if (list.All(e => e.IsDir)) return (null, ArchiveResult.Fail(400, "empty_archive"));
            if (total > limits.MaxRatio * len) return (null, ArchiveResult.Fail(413, "compression_ratio_exceeded"));
            // C15
            for (var idx = 0; idx < list.Count; idx++)
            {
                var e = list[idx];
                var lo = e.LocalOffset;
                if (lo + 30 > cdOffset || U32(b, lo) != 0x04034B50) return (null, ArchiveResult.Fail(400, "not_a_zip", idx));
                long lNameLen = U16(b, lo + 26), lExtraLen = U16(b, lo + 28);
                if (lo + 30 + lNameLen + lExtraLen + e.CSize > cdOffset) return (null, ArchiveResult.Fail(400, "not_a_zip", idx));
                var lName = Slice(b, lo + 30, lNameLen);
                if (!lName.SequenceEqual(e.NameBytes) || U16(b, lo + 6) != e.Flags || U16(b, lo + 8) != e.Method ||
                    ((e.Flags & 8) == 0 && (U32(b, lo + 14) != e.Crc || U32(b, lo + 18) != e.CSize || U32(b, lo + 22) != e.USize)))
                    return (null, ArchiveResult.Fail(400, "header_mismatch", idx));
            }
            return (new Parsed { Entries = list, Total = total, CdOffset = cdOffset }, null);
        }

        /// <summary>
        /// C4: the name is not empty, is strict UTF-8, holds no byte under 0x20, no 0x7F and no back-slash, does not start
        /// with "/" or a drive letter and ":", and, without ONE trailing "/", has no empty, "." or ".." part. Sets Name,
        /// IsDir and Parts. Pure.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        private static bool SafePath(Entry e)
        {
            var nb = e.NameBytes;
            if (nb.Length == 0) return false;
            if (nb.Any(x => x < 0x20 || x == 0x7F || x == (byte)'\\')) return false;
            try { e.Name = StrictUtf8.GetString(nb); }
            catch (ArgumentException) { return false; }
            var name = e.Name;
            if (name.StartsWith("/", StringComparison.Ordinal)) return false;
            if (name.Length >= 2 && name[1] == ':' && ((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z'))) return false;
            e.IsDir = name.EndsWith("/", StringComparison.Ordinal);
            var body = e.IsDir ? name.Substring(0, name.Length - 1) : name;
            e.Parts = body.Split('/');
            return e.Parts.All(part => part.Length > 0 && part != "." && part != "..");
        }

        /// <summary>
        /// C5: over 1024 bytes; an invisible or bidi control character; or a part over 255 bytes, holding : * ? " &lt; &gt; |,
        /// ending in "." or a space, or whose stem is a Windows reserved name. Pure.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        private static bool BadName(Entry e)
        {
            if (e.NameBytes.Length > 1024) return true;
            foreach (var ch in e.Name)
            {
                if ((ch >= '\u0080' && ch <= '\u009f') || ch == '؜' || (ch >= '​' && ch <= '‏') || (ch >= '‪' && ch <= '‮') ||
                    (ch >= '⁠' && ch <= '⁤') || (ch >= '⁦' && ch <= '⁩') || ch == '﻿')
                    return true;
            }
            foreach (var part in e.Parts)
            {
                if (Encoding.UTF8.GetByteCount(part) > 255) return true;
                if (part.IndexOfAny(new[] { ':', '*', '?', '"', '<', '>', '|' }) >= 0) return true;
                if (part.EndsWith(".", StringComparison.Ordinal) || part.EndsWith(" ", StringComparison.Ordinal)) return true;
                var dot = part.IndexOf('.');
                var stem = AsciiLower(dot >= 0 ? part.Substring(0, dot) : part).TrimEnd(' ');
                if (stem is "con" or "prn" or "aux" or "nul" or "conin$" or "conout$") return true;
                if (stem.Length == 4 && (stem.StartsWith("com", StringComparison.Ordinal) || stem.StartsWith("lpt", StringComparison.Ordinal)) &&
                    ((stem[3] >= '0' && stem[3] <= '9') || stem[3] == '¹' || stem[3] == '²' || stem[3] == '³'))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// C6: the extra field as (id u16, size u16, data) blocks: a size past the field, 1-3 bytes left over or a 0x7075
        /// block under 5 bytes is not_a_zip; a version-1 Unicode Path block whose name is not byte for byte the entry's is
        /// header_mismatch. Out: the error, or null. Pure.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        private static string CheckExtra(Entry e)
        {
            var x = e.Extra;
            long pos = 0, n = x.Length;
            while (pos < n)
            {
                if (n - pos < 4) return "not_a_zip";
                long id = U16(x, pos), size = U16(x, pos + 2);
                if (pos + 4 + size > n) return "not_a_zip";
                if (id == 0x7075)
                {
                    if (size < 5) return "not_a_zip";
                    if (x[pos + 4] == 1 && !Slice(x, pos + 9, size - 5).SequenceEqual(e.NameBytes)) return "header_mismatch";
                }
                pos += 4 + size;
            }
            return null;
        }

        /// <summary>EXTENSION of a last part: after its last ".", ASCII lower case; "" without a "." or when the only "." is first. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static string Extension(string part)
        {
            var dot = part.LastIndexOf('.');
            return dot <= 0 ? "" : AsciiLower(part.Substring(dot + 1));
        }

        // ------------------------------------------------------------------ data and files

        /// <summary>
        /// The entry's bytes: stored as is, or raw DEFLATE inflated asking for at most usize + 1 bytes. Out: exactly usize
        /// bytes, or null (invalid data, more than usize, or fewer when the input ran out). Pure.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        private static byte[] ReadData(byte[] b, Entry e)
        {
            var lo = e.LocalOffset;
            var start = lo + 30 + U16(b, lo + 26) + U16(b, lo + 28);
            var raw = Slice(b, start, e.CSize);
            if (e.Method == 0) return raw.LongLength == e.USize ? raw : null;
            try
            {
                using var input = new MemoryStream(raw);
                using var inflater = new DeflateStream(input, CompressionMode.Decompress);
                var cap = e.USize + 1;
                var output = new MemoryStream();
                var buffer = new byte[8192];
                while (output.Length < cap)
                {
                    var want = (int)Math.Min(buffer.Length, cap - output.Length);
                    var got = inflater.Read(buffer, 0, want);
                    if (got == 0) break;
                    output.Write(buffer, 0, got);
                }
                return output.Length == e.USize ? output.ToArray() : null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>Creates a directory and its parents with mode 0755. Touches: the file system. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static void MakeDirs(string path)
        {
            if (OperatingSystem.IsWindows()) Directory.CreateDirectory(path);
            else Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        }

        /// <summary>True when the name exists as a file, a directory or a link, also a link that points nowhere (lstat). Touches: the file system (read). Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static bool PathExists(string path)
        {
            try
            {
                if (File.Exists(path) || Directory.Exists(path)) return true;
                var info = new FileInfo(path);
                return info.LinkTarget != null;
            }
            catch (Exception)
            {
                return true; // cannot tell: fail closed
            }
        }

        /// <summary>Removes the staging directory and everything in it, then returns the answer. Touches: the file system. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static ArchiveResult Abort(string staging, ArchiveResult answer)
        {
            try { if (Directory.Exists(staging)) Directory.Delete(staging, true); }
            catch (Exception) { return ArchiveResult.Fail(500, "target_unwritable"); }
            return answer;
        }

        // ------------------------------------------------------------------ primitives (pure)

        /// <summary>The unsigned little-endian 16-bit number at i, as a 64-bit integer (-1 out of range). Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static long U16(byte[] b, long i) => i < 0 || i + 2 > b.LongLength ? -1 : b[i] | (b[i + 1] << 8);
        /// <summary>The unsigned little-endian 32-bit number at i, as a 64-bit integer (-1 out of range). Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static long U32(byte[] b, long i) => i < 0 || i + 4 > b.LongLength ? -1 : (long)((uint)b[i] | ((uint)b[i + 1] << 8) | ((uint)b[i + 2] << 16) | ((uint)b[i + 3] << 24));

        /// <summary>count bytes from start (both 64-bit; caller checked the bounds). Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static byte[] Slice(byte[] b, long start, long count)
        {
            var r = new byte[count];
            Array.Copy(b, start, r, 0, count);
            return r;
        }

        /// <summary>Maps A-Z to a-z and nothing else. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static string AsciiLower(string s) => new string(s.Select(c => c >= 'A' && c <= 'Z' ? (char)(c + 32) : c).ToArray());

        private static readonly uint[] CrcTable = Enumerable.Range(0, 256).Select(n =>
        {
            var c = (uint)n;
            for (var k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            return c;
        }).ToArray();

        /// <summary>CRC-32 (IEEE, the zip checksum) with the 256-entry table. Out: the value as a 64-bit integer. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public static long Crc32(byte[] data)
        {
            var c = 0xFFFFFFFFu;
            foreach (var x in data) c = CrcTable[(c ^ x) & 0xFF] ^ (c >> 8);
            return c ^ 0xFFFFFFFFu;
        }
    }
}
