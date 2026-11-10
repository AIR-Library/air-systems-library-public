# Safe Archive Ingest (Zip Upload, Checked and Extracted)

Reference contract for `saas_templates/<lang>/safe_archive_ingest_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# ARCHIVE-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `ARCHIVE-01` | the test builder reproduces the spec's BASIC archive byte for byte; extract_archive writes its two files with the right bytes under the target, creates the directory, and returns each path, size and SHA-256 |
| `ARCHIVE-02` | zip slip: an entry named ../evil.txt, a/../../evil.txt, /etc/passwd.txt, C:/x.txt, a\b.txt, a//b.txt or ./a.txt, a name with a NUL or control byte, an empty name and a name that is not strict UTF-8 (overlong, a surrogate, above U+10FFFF, cut short) are each 400 unsafe_path with the entry's index; the target does not exist afterwards and nothing was written beside it |
| `ARCHIVE-03` | a symbolic link entry (mode 0120000) is 400 special_file whatever system the archive says made it (creator 0, 3 and 19), and so is a FIFO; a regular-file mode is accepted |
| `ARCHIVE-04` | more entries than max_entries is 413 too_many_entries and more bytes than max_archive_bytes is 413 archive_too_large; exactly at each limit the archive is accepted |
| `ARCHIVE-05` | a declared total over max_total_bytes is 413 total_too_large and one entry over max_file_bytes is 413 entry_too_large; exactly at each limit the archive is accepted; a size of 0x80000000 is read unsigned and is 413, never a negative number |
| `ARCHIVE-06` | compression ratio: the ZEROS archive (133 bytes that declare 2000) is 413 compression_ratio_exceeded with max_ratio 15 and is extracted with max_ratio 16 |
| `ARCHIVE-07` | lying headers: an entry that declares 10 bytes but inflates to 2000, one that declares 3000 but inflates to 2000, a deflate stream missing its last 4 bytes, a stream that overruns its declared size and then turns invalid, a wrong CRC (stored or deflated) and a stream of invalid data are 400 corrupt_entry; a stored entry whose two sizes differ is 400 size_mismatch; no file is left in any case |
| `ARCHIVE-08` | extensions: run.exe, a.txt.sh, README, .env and inner.zip are 400 extension_not_allowed with the default list; A.TXT and x.Json are accepted; with allowed_extensions ["", "sh"] README and a.sh are accepted |
| `ARCHIVE-09` | a.txt twice, A.txt with a.txt, a file with a path under it (in either order) and a directory with a file of the same name (in either order) are 400 duplicate_name with entry_index 1; the same directory named twice is accepted |
| `ARCHIVE-10` | empty input is 400 empty_upload; text that is not a zip, a truncated archive, an entry count that disagrees with the directory and a byte after the end record are 400 not_a_zip; a directory offset and size whose 32-bit sum wraps round are 400 not_a_zip too; a disk number and a zip64 marker are 400 unsupported_zip; an input too short to hold a zip64 locator is never read before its start; an archive with only a directory is 400 empty_archive; an archive comment is accepted |
| `ARCHIVE-11` | an entry with an encryption flag (bit 0 or bit 6) is 400 encrypted_entry; a compression method other than 0 and 8 is 400 unsupported_compression; an entry with flag bit 3 (a data descriptor) is accepted |
| `ARCHIVE-12` | a local record whose name differs from the central record's is 400 header_mismatch with that entry's index; a Unicode Path extra field that names ../evil.txt is 400 header_mismatch, the same field repeating the entry's own name is accepted, and an extra field that overruns its length is 400 not_a_zip |
| `ARCHIVE-13` | all or nothing: when the second entry is corrupt the answer names entry_index 1, the target does not exist and no staging directory is left beside it; an existing target is 409 target_exists and keeps its content; a target whose parent directory is missing is 500 target_unwritable |
| `ARCHIVE-14` | names that do not unpack everywhere are 400 bad_name: CON.txt, com1.txt, COM0.txt, LPT0.txt, COM followed by a superscript 1, CONIN$.txt, CONOUT$.txt, a name ending in a dot or a space, a?.txt, a segment of 256 bytes, a name with a right-to-left override; a UTF-8 name with an accented letter is accepted; a file whose entry mode is 0755 is written without execute permission |

## Contract

```text
Source: PKWARE APPNOTE.TXT (the .ZIP file format); OWASP File Upload Cheat Sheet (rules applied, text not
reproduced); the "Zip Slip" disclosure (Snyk, 2018). The name, link, size and checksum checks come from a
production upload checker and its tests. Extraction into a directory, the ratio cap and the extension
allow-list are NEW in this spec.

PURPOSE:
  Take a .zip a user uploaded and unpack it into a new directory without trusting anything in it: no path leaves
  the directory, no link or device is created, no limit of count, size or ratio is passed, and either every file
  is written or none is.

SCHEMA:
  None. The archive arrives as bytes; the files go under target_dir on the injected storage root (tests use a
  temporary directory). Recording them is the caller's job (see file_uploads).

CONVENTIONS:
  - Names are snake_case here; each language spells them its own way (extractArchive, ExtractArchive).
  - A refusal is a RETURNED value {error, status, entry_index}, never an unhandled exception. `status` is the
    HTTP status a route serves it with.
    entry_index is the refused entry's position in the central directory, from 0: for every check of C1 to
    C12, for C15 (the entry whose local record is wrong) and for D3 (the entry being written). It is -1 for
    A, B, C13, C14, D1, D2 and D4.
  - Numbers in the archive are little-endian. u16 and u32 are UNSIGNED 16- and 32-bit numbers. Read each one
    into a 64-bit integer before using it (Java: Integer.toUnsignedLong, or `& 0xFFFFFFFFL`; never keep a u32
    in a signed 32-bit int). Every offset, length, sum and product is computed in 64-bit integers, so nothing
    wraps: cd_offset + cd_size, local_offset + 30 + name_len + extra_len + csize, the sum of usize, and
    max_ratio times the archive's length. JavaScript numbers are exact here (every value stays under 2^53).
  - "Missing" is the language's own absent value where the parameter can carry one; otherwise the empty value.

LIMITS (injected; these are the defaults):
  max_archive_bytes 20971520 | max_entries 1000 | max_file_bytes 26214400 | max_total_bytes 104857600 |
  max_ratio 100 | allowed_extensions ["txt", "md", "csv", "json", "pdf", "png", "jpg", "jpeg", "gif"]

ENDPOINTS / FUNCTIONS:
  inspect_archive(bytes, limits) -> {ok: true, entries, total_bytes, files: [{path, size}]}
      Runs checks A, B and C. Reads no file data and writes nothing.
  extract_archive(bytes, target_dir, limits) -> {ok: true, entries, total_bytes, files: [{path, size, sha256}]}
      Runs checks A, B and C (the same answers as inspect_archive), then D. target_dir must not exist yet; its
      parent must. `files` lists the files in central-directory order; path uses "/".

READING THE ARCHIVE:
  The system reads the three record types below itself and inflates with the standard library. It never calls
  a zip library's extract function, and never lets a library choose a name: zip libraries disagree about names
  (code pages, a second "Unicode Path" name, NUL bytes, back-slashes), and each disagreement has been a way out
  of the target directory.
  END RECORD (22 bytes + comment), offsets: 0 signature 50 4B 05 06 | 4 disk u16 | 6 cd_disk u16 |
      8 entries_here u16 | 10 entries u16 | 12 cd_size u32 | 16 cd_offset u32 | 20 comment_len u16
  CENTRAL RECORD (46 bytes + name + extra + comment): 0 signature 50 4B 01 02 | 4 made_by u16 | 6 needed u16 |
      8 flags u16 | 10 method u16 | 12 time u16 | 14 date u16 | 16 crc u32 | 20 csize u32 | 24 usize u32 |
      28 name_len u16 | 30 extra_len u16 | 32 comment_len u16 | 34 disk_start u16 | 36 internal u16 |
      38 external u32 | 42 local_offset u32
  LOCAL RECORD (30 bytes + name + extra, then csize bytes of data): 0 signature 50 4B 03 04 | 4 needed u16 |
      6 flags u16 | 8 method u16 | 10 time u16 | 12 date u16 | 14 crc u32 | 18 csize u32 | 22 usize u32 |
      26 name_len u16 | 28 extra_len u16

CHECKS (in this order; the first that fails answers):
  A. The container
     A1 the input is empty                                              -> 400 empty_upload
     A2 it is longer than max_archive_bytes                             -> 413 archive_too_large
     A3 it does not start with 50 4B 03 04                              -> 400 not_a_zip
     A4 END RECORD: for i from length - 22 down to max(0, length - 65557), the first i where the signature is at
        i and i + 22 + comment_len = length. None                       -> 400 not_a_zip
     A5 disk or cd_disk is not 0; entries_here differs from entries; entries is 0xFFFF; cd_size or cd_offset
        is 0xFFFFFFFF; or i >= 20 and the 4 bytes at i - 20 are 50 4B 06 07 (when i < 20 there is no room
        for that record: never read before the start of the input)     -> 400 unsupported_zip
     A6 cd_offset + cd_size is not i                                    -> 400 not_a_zip
     A7 entries is 0                                                    -> 400 empty_archive
     A8 entries is over max_entries                                     -> 413 too_many_entries
  B. The central directory: read `entries` CENTRAL RECORDS from cd_offset. A wrong signature, a record that
     runs past i, or records that do not end exactly at i               -> 400 not_a_zip
  C. Each entry, in directory order (all of C1-C12 for one entry, then the next)
     C1  csize, usize or local_offset is 0xFFFFFFFF, or disk_start is not 0 -> 400 unsupported_zip
     C2  flags has bit 0, bit 6 or bit 13 set (flags AND 0x2041)        -> 400 encrypted_entry
     C3  method is not 0 (stored) and not 8 (deflate)                   -> 400 unsupported_compression
     C4  the name: is empty; is not valid UTF-8; holds a byte under 0x20, 0x7F or a back-slash; starts with
         "/"; starts with a letter A-Z a-z followed by ":"; or, after ONE trailing "/" is removed (that "/"
         marks a directory) and it is split at "/", has a part that is empty, "." or ".."
                                                                        -> 400 unsafe_path
         An entry is a directory exactly when its name ends in "/". The mode's type never decides it.
     C5  the name is longer than 1024 bytes; holds one of U+0080-009F, U+061C, U+200B-200F, U+202A-202E,
         U+2060-2064, U+2066-2069, U+FEFF; or has a part that: is longer than 255 bytes; holds one of
         : * ? " < > |; ends in "." or a space; or whose text before its first ".", in ASCII lower case with
         trailing spaces removed, is con, prn, aux, nul, conin$, conout$, com0-com9, lpt0-lpt9, or com or
         lpt followed by U+00B9, U+00B2 or U+00B3 (Windows reserves all of these)
                                                                        -> 400 bad_name
     C6  the extra field is a list of (id u16, size u16, size bytes). A size that runs past the field, 1 to 3
         bytes left over, or an id 0x7075 block shorter than 5 bytes    -> 400 not_a_zip
         An id 0x7075 block (Unicode Path: version byte, u32, a name) with version 1 whose name is not byte
         for byte the entry's name                                      -> 400 header_mismatch
     C7  type = (external shifted right 16) AND 0xF000. It is not 0, not 0x8000 (regular file) and not
         0x4000 (directory), whatever made_by says                      -> 400 special_file
     C8  a directory entry with usize not 0, or a file entry with method 0 and csize different from usize
                                                                        -> 400 size_mismatch
     C9  a file entry whose EXTENSION is not in allowed_extensions      -> 400 extension_not_allowed
     C10 KEY = the name without its trailing "/", in ASCII lower case. Refused when: KEY is a file's KEY already
         seen; a proper prefix of KEY that ends before a "/" is a file's KEY already seen; or this is a file and
         KEY is a directory already seen (named, or the parent of an earlier entry)
                                                                        -> 400 duplicate_name
         The same directory may be named more than once.
     C11 usize is over max_file_bytes                                   -> 413 entry_too_large
     C12 the sum of usize so far is over max_total_bytes                -> 413 total_too_large
     Then, for the whole archive (entry_index -1):
     C13 no file entry at all                                           -> 400 empty_archive
     C14 the sum of usize is over max_ratio times the archive's length  -> 413 compression_ratio_exceeded
     Then each entry again, in directory order (entry_index = that entry):
     C15 its LOCAL RECORD: local_offset + 30 is past cd_offset, the signature is
         wrong, or the data (30 + name_len + extra_len + the central csize) runs past cd_offset
                                                                        -> 400 not_a_zip
         its name, flags or method differ from the central record's, or (flags bit 3 clear) its crc, csize
         or usize do                                                    -> 400 header_mismatch
  D. Extraction (extract_archive only)
     D1 target_dir exists: a file, a directory or a link, also a link that points nowhere (test the name
        itself without following links: lstat, Python os.path.lexists)  -> 409 target_exists
     D2 create STAGING = target_dir + ".partial-" + 16 random hex characters, mode 0700. It cannot be created
        (the parent is missing or not writable)                         -> 500 target_unwritable
     D3 each entry, in directory order. dest = STAGING joined with the name's parts. The normalised dest must
        start with the normalised STAGING + separator (it always does after C4; the check stays so that a later
        change cannot write outside)                                    -> 400 unsafe_path
        A directory entry: create it (and its parents), mode 0755.
        A file entry: read the data. Method 8: inflate it as a raw DEFLATE stream, asking for at most
        usize + 1 bytes. ONE answer for everything that can be wrong with an entry's data, because the
        libraries do not agree on which fault they meet first (Node and PHP report invalid data that lies
        beyond the size cap; Python, Go, Java and .NET stop at the cap and never see it):
          the inflater reports invalid data; or more than usize bytes came out; or fewer came out when the
          input is used up; or the CRC-32 of the bytes is not the central crc -> 400 corrupt_entry
        (size_mismatch is C8 only: it reads no data.)
        Create the parents (0755) and the file with EXCLUSIVE create (it must not exist), mode 0644 whatever the
        entry's mode says. It exists already (a file system that folds case or normalises names)
                                                                        -> 400 duplicate_name
     D4 rename STAGING to target_dir                                    -> the result
        target_dir keeps STAGING's mode, 0700: the caller widens it if others must read the files.
     Any refusal or error in D2-D4 removes STAGING and everything in it first; an I/O error is 500
     target_unwritable. So target_dir exists only when every file was written.
  EXTENSION of a file: its last part; the text after its last ".", in ASCII lower case. A part with no ".", or
  whose only "." is its first character (".env"), has the extension "" (empty).

IMPLEMENTATION -- RULES:
  - Sizes in the headers are claims. The caps of C11, C12 and C14 refuse early; the inflate cap of D3 is what
    stops a bomb: never more than usize + 1 bytes are produced for an entry, whatever the stream holds.
  - Whether the deflate stream reached its end marker is NOT checked: the libraries report a missing marker
    differently, so the size and the CRC decide. Input that runs out is not an exception to catch separately:
    it gives fewer bytes, and that is corrupt_entry like every other fault (Node: finishFlush Z_SYNC_FLUSH;
    Go and Rust: an unexpected-EOF error ends the output).
  - What was checked is the set of files written, not the upload. Do not keep or serve the uploaded archive
    as "checked": bytes that no central record points to were never read.
  - Nothing inside the archive is ever unpacked again: an inner .zip is one file, and only when the caller
    put "zip" in allowed_extensions.
  - No entry's mode, owner or time is applied. Links are never created. Files are never executable.
  - target_dir comes from the server (a generated id under the storage root), never from the upload. The
    refusal names an index, not the entry's name, so a hostile name is never echoed into a page or a log.
  - The caller is a signed-in member allowed to upload (see file_uploads) and stores the files' sha256.

PRIMITIVES (standard library unless a package is named):
  raw DEFLATE      Python zlib.decompressobj(-15).decompress(data, max_length) | JavaScript, TypeScript
                   node:zlib inflateRawSync(data, {maxOutputLength, finishFlush}) | Java java.util.zip.Inflater
                   (nowrap true) | C# System.IO.Compression.DeflateStream | PHP inflate_init(ZLIB_ENCODING_RAW)
                   + inflate_add in chunks of at most 4096 input bytes | Go compress/flate | Rust flate2
                   crate (to add)
  CRC-32           Python zlib.crc32 | Node zlib.crc32 | Java java.util.zip.CRC32 | PHP crc32 | Go hash/crc32 |
                   Rust flate2::Crc | C#: a 256-entry table in the file (System.IO.Hashing is a package)
  strict UTF-8     Python bytes.decode("utf-8") | Node new TextDecoder("utf-8", {fatal: true}) | Java
                   CharsetDecoder with CodingErrorAction.REPORT | C# new UTF8Encoding(false, true) | PHP
                   preg_match('//u', name) === 1 | Go utf8.Valid | Rust std::str::from_utf8. The default
                   decoders of Java, C# and Node REPLACE bad bytes and do not fail: do not use them here.
  SHA-256, exclusive create, rename: every standard library

TEST ARCHIVE BUILDER (every language's tests carry this helper, about 30 lines; it needs no compressor):
  build_zip(entries, comment = "") -> bytes. An entry is {name, data} plus the options method = 0,
  usize = length of data, crc = CRC-32 of data, flags = 0, external = 0, creator = 0, extra = "",
  local_name = name. `data` is what is stored in the archive: for method 8 an already deflated stream.
    for each entry, a LOCAL RECORD: needed 20, flags, method, time 0, date 0x0021, crc, csize = length of data,
      usize, name_len of local_name, extra_len 0, then local_name and data
    then for each entry a CENTRAL RECORD: made_by = creator * 256 + 20, needed 20, flags, method, time 0,
      date 0x0021, crc, csize, usize, name_len, extra_len, comment_len 0, disk_start 0, internal 0, external,
      local_offset, then name and extra
    then the END RECORD: disk 0, cd_disk 0, entries_here and entries = the count, cd_size, cd_offset,
      comment_len, then the comment

TEST VECTORS (every language asserts these):
  BASIC = build_zip([{name: "docs/", external: 0x41ED0000, creator: 3},
                     {name: "docs/readme.txt", data: "hello\n"},
                     {name: "data.csv", data: "a,b\n1,2\n", external: 0x81ED0000, creator: 3}])
        = these 320 bytes (hex):
      504b03041400000000000000210000000000000000000000000005000000646f63732f504b0304140000000000000021
      0020303a3606000000060000000f000000646f63732f726561646d652e74787468656c6c6f0a504b0304140000000000
      000021007b07970a080000000800000008000000646174612e637376612c620a312c320a504b01021403140000000000
      00002100000000000000000000000000050000000000000000000000ed4100000000646f63732f504b01021400140000
      0000000000210020303a3606000000060000000f0000000000000000000000000023000000646f63732f726561646d65
      2e747874504b01021403140000000000000021007b07970a0800000008000000080000000000000000000000ed815600
      0000646174612e637376504b05060000000003000300a6000000840000000000
      extract_archive(BASIC, target) -> entries 3, total_bytes 14, files:
        docs/readme.txt  6 bytes  sha256 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
        data.csv         8 bytes  sha256 492d5ea496056f1a6a6592241032fab764c321596317930b4fa0e1e8bc3b7470
      and target/docs is a directory. data.csv is written with mode 0644 although its entry says 0755.
  Z = the raw DEFLATE stream of 2000 zero bytes = hex 63601805a360148c8251300a46c1500700 (17 bytes).
      CRC-32 of 2000 zero bytes = 0x02C9F444; of 10 zero bytes = 0xE38A6876.
  ZEROS = build_zip([{name: "zeros.txt", data: Z, method: 8, usize: 2000, crc: 0x02C9F444}]) = 133 bytes.
      max_ratio 15 -> 413 compression_ratio_exceeded (2000 > 15 x 133); max_ratio 16 -> extracted, 2000 zero bytes.
      ARCHIVE-07: the same entry with usize 10 and crc 0xE38A6876; with usize 3000; with data = Z without its
      last 4 bytes; with crc 1; {name: "a.txt", data: "12345", crc: 0}; {name: "zeros.txt", data: FF FF FF FF,
      method: 8, usize: 4, crc: 0} -> all corrupt_entry. {name: "a.txt", data: "12345", usize: 4} ->
      size_mismatch.
      BAD = hex 62601805a360148c8251300a46c1500700000000ffff07 (2000 zero bytes, then a block of the reserved
      type). {name: "zeros.txt", data: BAD, method: 8, usize: 10, crc: 0xE38A6876} -> corrupt_entry.
  ARCHIVE-04: three files a.txt, b.txt, c.txt of data "x" = 283 bytes: max_entries 3 and max_archive_bytes 283
      accept it; max_entries 2 -> too_many_entries; max_archive_bytes 282 -> archive_too_large.
  ARCHIVE-05: a.txt "12345" and b.txt "67890" (204 bytes): max_total_bytes 10 and max_file_bytes 5 accept it;
      max_total_bytes 9 -> total_too_large (entry_index 1); max_file_bytes 4 -> entry_too_large (entry_index 0).
      {name: "a.txt", data: Z, method: 8, usize: 0x80000000, crc: 0} -> entry_too_large (the size is unsigned);
      the same with max_file_bytes and max_total_bytes 4294967296 -> compression_ratio_exceeded.
  ARCHIVE-03: external 0xA1FF0000 (link), 0x11A40000 (FIFO) -> special_file; 0x81A40000 (regular) -> accepted.
  ARCHIVE-10, from BASIC: without its last 10 bytes; with the two u16 at length - 14 and length - 12 set to 4;
      BASIC + one 00 byte -> not_a_zip. The u16 at length - 18 set to 1; those two counts set to 0xFFFF ->
      unsupported_zip. build_zip([{name: "docs/"}]) -> empty_archive. BASIC built with a 40-byte comment ->
      accepted. BASIC with the u32 at length - 10 set to 300 and the u32 at length - 6 set to 0xFFFFFFFE (their
      32-bit sum is 298, the END RECORD's offset) -> not_a_zip.
      hex 504b0304504b0506000000000000000000000000040000001000504b0607787878787878787878787878 (42 bytes: no
      entry, and a comment that starts with the zip64 mark) -> empty_archive.
  ARCHIVE-02, names that are not strict UTF-8, each as the second entry after "ok.txt" -> unsafe_path,
      entry_index 1: 61 C0 AF 62 2E 74 78 74 (an overlong "/"), 61 ED A0 80 2E 74 78 74 (a surrogate),
      61 F4 90 80 80 2E 74 78 74 (above U+10FFFF), 61 E2 82 2E 74 78 74 (cut short).
  ARCHIVE-09 (C9, the extension, runs before C10, so use names that pass it): "d.txt/" then "d.txt";
      "d.txt" then "d.txt/"; "d.txt" then "d.txt/e.txt"; "d.txt/e.txt" then "d.txt" -> duplicate_name,
      entry_index 1.
  ARCHIVE-11: {name: "a.txt", data: "12345", flags: 8} -> accepted (flag bit 3; sizes come from the central
      record).
  ARCHIVE-12: {name: "ok.txt", data: "x", local_name: "no.txt"} -> header_mismatch. extra = 75 70, u16 16,
      01, u32 CRC-32 of "ok.txt", then "../evil.txt" (hex 75701000012a0419052e2e2f6576696c2e747874) -> header_mismatch;
      the same block naming "ok.txt" (u16 11) -> accepted; extra = 0A 00 32 00 61 62 (a size of 50 with 2 bytes
      left) -> not_a_zip.
  ARCHIVE-14: "x" * 252 + ".txt" (256 bytes) -> bad_name; "x" * 251 + ".txt" -> accepted. The override
      character is U+202E; the accepted accented name is "caf\u00e9.txt". "COM\u00b9.txt" -> bad_name;
      "COM10.txt" and "conin.txt" -> accepted.

TESTS:
  - **ARCHIVE-01** the test builder reproduces the spec's BASIC archive byte for byte; extract_archive writes its two files with the right bytes under the target, creates the directory, and returns each path, size and SHA-256
  - **ARCHIVE-02** zip slip: an entry named ../evil.txt, a/../../evil.txt, /etc/passwd.txt, C:/x.txt, a\b.txt, a//b.txt or ./a.txt, a name with a NUL or control byte, an empty name and a name that is not strict UTF-8 (overlong, a surrogate, above U+10FFFF, cut short) are each 400 unsafe_path with the entry's index; the target does not exist afterwards and nothing was written beside it
  - **ARCHIVE-03** a symbolic link entry (mode 0120000) is 400 special_file whatever system the archive says made it (creator 0, 3 and 19), and so is a FIFO; a regular-file mode is accepted
  - **ARCHIVE-04** more entries than max_entries is 413 too_many_entries and more bytes than max_archive_bytes is 413 archive_too_large; exactly at each limit the archive is accepted
  - **ARCHIVE-05** a declared total over max_total_bytes is 413 total_too_large and one entry over max_file_bytes is 413 entry_too_large; exactly at each limit the archive is accepted; a size of 0x80000000 is read unsigned and is 413, never a negative number
  - **ARCHIVE-06** compression ratio: the ZEROS archive (133 bytes that declare 2000) is 413 compression_ratio_exceeded with max_ratio 15 and is extracted with max_ratio 16
  - **ARCHIVE-07** lying headers: an entry that declares 10 bytes but inflates to 2000, one that declares 3000 but inflates to 2000, a deflate stream missing its last 4 bytes, a stream that overruns its declared size and then turns invalid, a wrong CRC (stored or deflated) and a stream of invalid data are 400 corrupt_entry; a stored entry whose two sizes differ is 400 size_mismatch; no file is left in any case
  - **ARCHIVE-08** extensions: run.exe, a.txt.sh, README, .env and inner.zip are 400 extension_not_allowed with the default list; A.TXT and x.Json are accepted; with allowed_extensions ["", "sh"] README and a.sh are accepted
  - **ARCHIVE-09** a.txt twice, A.txt with a.txt, a file with a path under it (in either order) and a directory with a file of the same name (in either order) are 400 duplicate_name with entry_index 1; the same directory named twice is accepted
  - **ARCHIVE-10** empty input is 400 empty_upload; text that is not a zip, a truncated archive, an entry count that disagrees with the directory and a byte after the end record are 400 not_a_zip; a directory offset and size whose 32-bit sum wraps round are 400 not_a_zip too; a disk number and a zip64 marker are 400 unsupported_zip; an input too short to hold a zip64 locator is never read before its start; an archive with only a directory is 400 empty_archive; an archive comment is accepted
  - **ARCHIVE-11** an entry with an encryption flag (bit 0 or bit 6) is 400 encrypted_entry; a compression method other than 0 and 8 is 400 unsupported_compression; an entry with flag bit 3 (a data descriptor) is accepted
  - **ARCHIVE-12** a local record whose name differs from the central record's is 400 header_mismatch with that entry's index; a Unicode Path extra field that names ../evil.txt is 400 header_mismatch, the same field repeating the entry's own name is accepted, and an extra field that overruns its length is 400 not_a_zip
  - **ARCHIVE-13** all or nothing: when the second entry is corrupt the answer names entry_index 1, the target does not exist and no staging directory is left beside it; an existing target is 409 target_exists and keeps its content; a target whose parent directory is missing is 500 target_unwritable
  - **ARCHIVE-14** names that do not unpack everywhere are 400 bad_name: CON.txt, com1.txt, COM0.txt, LPT0.txt, COM followed by a superscript 1, CONIN$.txt, CONOUT$.txt, a name ending in a dot or a space, a?.txt, a segment of 256 bytes, a name with a right-to-left override; a UTF-8 name with an accented letter is accepted; a file whose entry mode is 0755 is written without execute permission
```
