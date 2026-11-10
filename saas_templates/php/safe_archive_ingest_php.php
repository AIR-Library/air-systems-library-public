<?php
/**
 * Safe archive ingest (docs/specs/safe_archive_ingest.md).
 *
 * What it does: reads a user's uploaded .zip itself (END, CENTRAL and LOCAL records; no zip library chooses a
 * name), refuses anything unsafe (paths that leave the target, links and devices, encrypted or unknown
 * compression, bad or duplicate names, sizes over the limits, a compression ratio over the cap, lying headers),
 * and extract_archive unpacks it into a NEW directory: every file is written into a staging directory first
 * (inflate capped at usize + 1 bytes, CRC checked, exclusive create, mode 0644) and the staging directory is
 * renamed into place only when every file was written. Otherwise nothing is left.
 *
 * Inputs/outputs: see each function; a refusal is a returned {error, status, entry_index}, never an
 * exception. Numbers in the archive are unsigned and held in PHP's 64-bit integers.
 *
 * Why: Phase D wave 1, owner request 2026-11-10 (spec ids ARCHIVE-01..14).
 * Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files (creates target_dir and its staging directory under the caller's storage root; removes the
 * staging directory on any refusal), the CSPRNG (staging suffix). No database, no network, no money.
 */

declare(strict_types=1);

namespace SafeArchiveIngest;

use Throwable;

/**
 * The default limits. Out: the limits array. Why: LIMITS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: nothing.
 */
function default_limits(): array
{
    return [
        'max_archive_bytes' => 20971520, 'max_entries' => 1000, 'max_file_bytes' => 26214400,
        'max_total_bytes' => 104857600, 'max_ratio' => 100,
        'allowed_extensions' => ['txt', 'md', 'csv', 'json', 'pdf', 'png', 'jpg', 'jpeg', 'gif'],
    ];
}

/**
 * A refusal. In: error code, HTTP status, entry index (-1 for archive-wide checks). Out: the array.
 * Why: CONVENTIONS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function refuse(string $error, int $status, int $index = -1): array
{
    return ['error' => $error, 'status' => $status, 'entry_index' => $index];
}

/** u16 little-endian at $o. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
function u16(string $b, int $o): int
{
    return unpack('v', $b, $o)[1];
}

/** u32 little-endian (unsigned, in a 64-bit int) at $o. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
function u32(string $b, int $o): int
{
    return unpack('V', $b, $o)[1];
}

/**
 * ASCII lower case (A-Z only). In: text. Out: text. Why: C5, C9, C10. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function ascii_lower(string $s): string
{
    return strtr($s, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz');
}

/**
 * EXTENSION of a file name: its last part's text after the last ".", ASCII lower case; "" when the part has
 * no "." or its only "." is the first character. In: name. Out: extension. Why: C9. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function extension(string $name): string
{
    $slash = strrpos($name, '/');
    $part = $slash === false ? $name : substr($name, $slash + 1);
    $dot = strrpos($part, '.');
    return ($dot === false || $dot === 0) ? '' : ascii_lower(substr($part, $dot + 1));
}

/**
 * C4: true when the name is unsafe (empty, not strict UTF-8, a control byte, 0x7F or a back-slash, absolute,
 * a drive letter, or an empty, "." or ".." part after one trailing "/" is removed). In: name. Out: bool.
 * Why: ARCHIVE-02 (zip slip). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function unsafe_path(string $name): bool
{
    if ($name === '' || preg_match('//u', $name) !== 1 || preg_match('/[\x00-\x1F\x7F\\\\]/', $name) === 1) {
        return true;
    }
    if ($name[0] === '/' || preg_match('/^[A-Za-z]:/', $name) === 1) {
        return true;
    }
    $trimmed = substr($name, -1) === '/' ? substr($name, 0, -1) : $name;
    foreach (explode('/', $trimmed) as $part) {
        if ($part === '' || $part === '.' || $part === '..') {
            return true;
        }
    }
    return false;
}

/**
 * C5: true for a name that does not unpack everywhere (too long, invisible or bidi characters, a part over
 * 255 bytes, a Windows-forbidden character, a trailing dot or space, or a Windows reserved name).
 * In: a name that passed C4. Out: bool. Why: ARCHIVE-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: nothing.
 */
function bad_name(string $name): bool
{
    if (strlen($name) > 1024
        || preg_match('/[\x{80}-\x{9F}\x{61C}\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{2066}-\x{2069}\x{FEFF}]/u', $name) === 1) {
        return true;
    }
    $trimmed = substr($name, -1) === '/' ? substr($name, 0, -1) : $name;
    $reserved = ['con', 'prn', 'aux', 'nul', 'conin$', 'conout$'];
    for ($d = 0; $d <= 9; $d++) {
        $reserved[] = "com$d";
        $reserved[] = "lpt$d";
    }
    foreach (["\u{B9}", "\u{B2}", "\u{B3}"] as $sup) {
        $reserved[] = 'com' . $sup;
        $reserved[] = 'lpt' . $sup;
    }
    foreach (explode('/', $trimmed) as $part) {
        if (strlen($part) > 255 || strpbrk($part, ':*?"<>|') !== false) {
            return true;
        }
        $last = substr($part, -1);
        if ($last === '.' || $last === ' ') {
            return true;
        }
        $dot = strpos($part, '.');
        $stem = rtrim(ascii_lower($dot === false ? $part : substr($part, 0, $dot)), ' ');
        if (in_array($stem, $reserved, true)) {
            return true;
        }
    }
    return false;
}

/**
 * Checks A, B and C. In: archive bytes, limits (merged over the defaults). Out: a refusal, or
 * {ok: true, entries, total_bytes, files: [{path, size}], _entries: parsed records} (the last key is
 * internal and removed by the public functions). Reads no file data.
 * Why: ARCHIVE-02..12, ARCHIVE-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function check_archive(string $b, array $limits): array
{
    $L = $limits + default_limits();
    $len = strlen($b);
    // A. The container
    if ($len === 0) {
        return refuse('empty_upload', 400);
    }
    if ($len > $L['max_archive_bytes']) {
        return refuse('archive_too_large', 413);
    }
    if (strncmp($b, "PK\x03\x04", 4) !== 0) {
        return refuse('not_a_zip', 400);
    }
    $i = -1;
    for ($p = $len - 22; $p >= max(0, $len - 65557); $p--) {
        if (substr_compare($b, "PK\x05\x06", $p, 4) === 0 && $p + 22 + u16($b, $p + 20) === $len) {
            $i = $p;
            break;
        }
    }
    if ($i < 0) {
        return refuse('not_a_zip', 400);
    }
    $disk = u16($b, $i + 4);
    $cdDisk = u16($b, $i + 6);
    $here = u16($b, $i + 8);
    $entries = u16($b, $i + 10);
    $cdSize = u32($b, $i + 12);
    $cdOffset = u32($b, $i + 16);
    if ($disk !== 0 || $cdDisk !== 0 || $here !== $entries || $entries === 0xFFFF || $cdSize === 0xFFFFFFFF
        || $cdOffset === 0xFFFFFFFF || ($i >= 20 && substr_compare($b, "PK\x06\x07", $i - 20, 4) === 0)) {
        return refuse('unsupported_zip', 400);
    }
    if ($cdOffset + $cdSize !== $i) {
        return refuse('not_a_zip', 400);
    }
    if ($entries === 0) {
        return refuse('empty_archive', 400);
    }
    if ($entries > $L['max_entries']) {
        return refuse('too_many_entries', 413);
    }
    // B. The central directory
    $recs = [];
    $pos = $cdOffset;
    for ($n = 0; $n < $entries; $n++) {
        if ($pos + 46 > $i || substr_compare($b, "PK\x01\x02", $pos, 4) !== 0) {
            return refuse('not_a_zip', 400);
        }
        $nameLen = u16($b, $pos + 28);
        $extraLen = u16($b, $pos + 30);
        $commentLen = u16($b, $pos + 32);
        $end = $pos + 46 + $nameLen + $extraLen + $commentLen;
        if ($end > $i) {
            return refuse('not_a_zip', 400);
        }
        $recs[] = [
            'made_by' => u16($b, $pos + 4), 'flags' => u16($b, $pos + 8), 'method' => u16($b, $pos + 10),
            'crc' => u32($b, $pos + 16), 'csize' => u32($b, $pos + 20), 'usize' => u32($b, $pos + 24),
            'disk_start' => u16($b, $pos + 34), 'external' => u32($b, $pos + 38), 'local_offset' => u32($b, $pos + 42),
            'name' => substr($b, $pos + 46, $nameLen), 'extra' => substr($b, $pos + 46 + $nameLen, $extraLen),
        ];
        $pos = $end;
    }
    if ($pos !== $i) {
        return refuse('not_a_zip', 400);
    }
    // C. Each entry
    $allowed = $L['allowed_extensions'];
    $fileKeys = [];
    $dirKeys = [];
    $sum = 0;
    $files = [];
    foreach ($recs as $k => &$r) {
        $name = $r['name'];
        if ($r['csize'] === 0xFFFFFFFF || $r['usize'] === 0xFFFFFFFF || $r['local_offset'] === 0xFFFFFFFF || $r['disk_start'] !== 0) {
            return refuse('unsupported_zip', 400, $k);
        }
        if (($r['flags'] & 0x2041) !== 0) {
            return refuse('encrypted_entry', 400, $k);
        }
        if ($r['method'] !== 0 && $r['method'] !== 8) {
            return refuse('unsupported_compression', 400, $k);
        }
        if (unsafe_path($name)) {
            return refuse('unsafe_path', 400, $k);
        }
        if (bad_name($name)) {
            return refuse('bad_name', 400, $k);
        }
        $extraVerdict = check_extra($r['extra'], $name);
        if ($extraVerdict !== null) {
            return refuse($extraVerdict, 400, $k);
        }
        $type = ($r['external'] >> 16) & 0xF000;
        if ($type !== 0 && $type !== 0x8000 && $type !== 0x4000) {
            return refuse('special_file', 400, $k);
        }
        $isDir = substr($name, -1) === '/';
        $r['is_dir'] = $isDir;
        if (($isDir && $r['usize'] !== 0) || (!$isDir && $r['method'] === 0 && $r['csize'] !== $r['usize'])) {
            return refuse('size_mismatch', 400, $k);
        }
        if (!$isDir && !in_array(extension($name), $allowed, true)) {
            return refuse('extension_not_allowed', 400, $k);
        }
        $key = ascii_lower($isDir ? substr($name, 0, -1) : $name);
        $dup = isset($fileKeys[$key]) || (!$isDir && isset($dirKeys[$key]));
        for ($s = strpos($key, '/'); !$dup && $s !== false; $s = strpos($key, '/', $s + 1)) {
            $dup = isset($fileKeys[substr($key, 0, $s)]);
        }
        if ($dup) {
            return refuse('duplicate_name', 400, $k);
        }
        if ($isDir) {
            $dirKeys[$key] = true;
        } else {
            $fileKeys[$key] = true;
        }
        for ($s = strpos($key, '/'); $s !== false; $s = strpos($key, '/', $s + 1)) {
            $dirKeys[substr($key, 0, $s)] = true;
        }
        if ($r['usize'] > $L['max_file_bytes']) {
            return refuse('entry_too_large', 413, $k);
        }
        $sum += $r['usize'];
        if ($sum > $L['max_total_bytes']) {
            return refuse('total_too_large', 413, $k);
        }
        if (!$isDir) {
            $files[] = ['path' => $name, 'size' => $r['usize']];
        }
    }
    unset($r);
    if ($files === []) {
        return refuse('empty_archive', 400);
    }
    if ($sum > $L['max_ratio'] * $len) {
        return refuse('compression_ratio_exceeded', 413);
    }
    // C15. The local records
    foreach ($recs as $k => &$r) {
        $lo = $r['local_offset'];
        if ($lo + 30 > $cdOffset || substr_compare($b, "PK\x03\x04", $lo, 4) !== 0) {
            return refuse('not_a_zip', 400, $k);
        }
        $lNameLen = u16($b, $lo + 26);
        $lExtraLen = u16($b, $lo + 28);
        $dataStart = $lo + 30 + $lNameLen + $lExtraLen;
        if ($dataStart + $r['csize'] > $cdOffset) {
            return refuse('not_a_zip', 400, $k);
        }
        $lFlags = u16($b, $lo + 6);
        if (substr($b, $lo + 30, $lNameLen) !== $r['name'] || $lFlags !== $r['flags'] || u16($b, $lo + 8) !== $r['method']) {
            return refuse('header_mismatch', 400, $k);
        }
        if (($lFlags & 0x0008) === 0 && (u32($b, $lo + 14) !== $r['crc'] || u32($b, $lo + 18) !== $r['csize'] || u32($b, $lo + 22) !== $r['usize'])) {
            return refuse('header_mismatch', 400, $k);
        }
        $r['data_start'] = $dataStart;
    }
    unset($r);
    return ['ok' => true, 'entries' => $entries, 'total_bytes' => $sum, 'files' => $files, '_entries' => $recs];
}

/**
 * C6: the extra field. First its structure (a block that runs past the field, 1-3 bytes left over, a 0x7075
 * block under 5 bytes -> "not_a_zip"), then each Unicode Path block of version 1 must name the entry's own
 * name byte for byte ("header_mismatch"). In: extra bytes, entry name. Out: null when fine, else the error.
 * Why: ARCHIVE-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function check_extra(string $extra, string $name): ?string
{
    $n = strlen($extra);
    $blocks = [];
    $p = 0;
    while ($p < $n) {
        if ($n - $p < 4) {
            return 'not_a_zip';
        }
        $id = u16($extra, $p);
        $size = u16($extra, $p + 2);
        if ($p + 4 + $size > $n || ($id === 0x7075 && $size < 5)) {
            return 'not_a_zip';
        }
        $blocks[] = [$id, substr($extra, $p + 4, $size)];
        $p += 4 + $size;
    }
    foreach ($blocks as [$id, $data]) {
        if ($id === 0x7075 && ord($data[0]) === 1 && substr($data, 5) !== $name) {
            return 'header_mismatch';
        }
    }
    return null;
}

/**
 * inspect_archive: checks A, B and C; reads no file data and writes nothing.
 * In: archive bytes, limits (any subset; the rest are defaults). Out: {ok: true, entries, total_bytes,
 * files: [{path, size}]} or a refusal. Why: ARCHIVE-02..12, 14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: nothing.
 */
function inspect_archive(string $bytes, array $limits = []): array
{
    $r = check_archive($bytes, $limits);
    unset($r['_entries']);
    return $r;
}

/**
 * Inflate a raw DEFLATE stream, feeding at most 4096 input bytes at a time and stopping once more than
 * $cap bytes came out. In: compressed bytes, cap (usize + 1). Out: the bytes, or null when the inflater
 * reported invalid data. Why: D3 (the inflate cap stops a bomb). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: nothing.
 */
function inflate_capped(string $data, int $cap): ?string
{
    $ctx = @inflate_init(ZLIB_ENCODING_RAW);
    if ($ctx === false) {
        return null;
    }
    $out = '';
    $n = strlen($data);
    for ($p = 0; $p < $n; $p += 4096) {
        $chunk = @inflate_add($ctx, substr($data, $p, 4096), ZLIB_SYNC_FLUSH);
        if ($chunk === false) {
            return null;
        }
        $out .= $chunk;
        if (strlen($out) >= $cap) {
            break;
        }
        if (inflate_get_status($ctx) === ZLIB_STREAM_END) {
            break;
        }
    }
    return $out;
}

/**
 * Remove a directory tree without following links. In: path. Out: none (best effort).
 * Why: D2-D4 remove STAGING on any refusal. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files.
 */
function remove_tree(string $path): void
{
    if (is_link($path) || is_file($path)) {
        @unlink($path);
        return;
    }
    if (!is_dir($path)) {
        return;
    }
    foreach (scandir($path) ?: [] as $f) {
        if ($f !== '.' && $f !== '..') {
            remove_tree($path . '/' . $f);
        }
    }
    @rmdir($path);
}

/**
 * Textual path normalisation ("." and ".." resolved, repeated "/" folded). In: path. Out: path.
 * Why: D3's containment check. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function normalise(string $path): string
{
    $out = [];
    foreach (explode('/', $path) as $part) {
        if ($part === '' || $part === '.') {
            continue;
        }
        if ($part === '..') {
            array_pop($out);
        } else {
            $out[] = $part;
        }
    }
    return ($path !== '' && $path[0] === '/' ? '/' : '') . implode('/', $out);
}

/**
 * Create a directory and its parents with mode 0755 (umask ignored). In: path. Out: true when it exists.
 * Why: D3. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files.
 */
function make_dirs(string $path): bool
{
    if (is_dir($path) && !is_link($path)) {
        return true;
    }
    $parent = dirname($path);
    if (!make_dirs($parent)) {
        return false;
    }
    if (!@mkdir($path, 0755) && !(is_dir($path) && !is_link($path))) {
        return false;
    }
    return @chmod($path, 0755);
}

/**
 * extract_archive: checks A, B, C, then D. target_dir must not exist; its parent must.
 * In: archive bytes, target_dir (from the server, never from the upload), limits.
 * Out: {ok: true, entries, total_bytes, files: [{path, size, sha256}]} or a refusal; target_dir exists only
 * when every file was written. Why: ARCHIVE-01, ARCHIVE-07, ARCHIVE-13, ARCHIVE-14. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files (target_dir, its staging directory), the CSPRNG.
 */
function extract_archive(string $bytes, string $targetDir, array $limits = []): array
{
    $c = check_archive($bytes, $limits);
    if (($c['ok'] ?? false) !== true) {
        return $c;
    }
    $target = rtrim($targetDir, '/');
    clearstatcache();
    if (file_exists($target) || is_link($target)) {
        return refuse('target_exists', 409);
    }
    $staging = $target . '.partial-' . bin2hex(random_bytes(8));
    if (!@mkdir($staging, 0700) || !@chmod($staging, 0700)) {
        return refuse('target_unwritable', 500);
    }
    try {
        $out = [];
        $base = normalise($staging) . '/';
        foreach ($c['_entries'] as $k => $r) {
            $name = $r['is_dir'] ? substr($r['name'], 0, -1) : $r['name'];
            $dest = $staging . '/' . $name;
            if (strncmp(normalise($dest), $base, strlen($base)) !== 0) {
                remove_tree($staging);
                return refuse('unsafe_path', 400, $k);
            }
            if ($r['is_dir']) {
                if (!make_dirs($dest)) {
                    throw new \RuntimeException('io');
                }
                continue;
            }
            $raw = substr($bytes, $r['data_start'], $r['csize']);
            $data = $r['method'] === 8 ? inflate_capped($raw, $r['usize'] + 1) : $raw;
            if ($data === null || strlen($data) !== $r['usize'] || crc32($data) !== $r['crc']) {
                remove_tree($staging);
                return refuse('corrupt_entry', 400, $k);
            }
            if (!make_dirs(dirname($dest))) {
                throw new \RuntimeException('io');
            }
            $fh = @fopen($dest, 'xb');
            if ($fh === false) {
                if (file_exists($dest) || is_link($dest)) {
                    remove_tree($staging);
                    return refuse('duplicate_name', 400, $k);
                }
                throw new \RuntimeException('io');
            }
            $ok = fwrite($fh, $data) === strlen($data);
            $ok = fclose($fh) && $ok;
            if (!$ok || !@chmod($dest, 0644)) {
                throw new \RuntimeException('io');
            }
            $out[] = ['path' => $r['name'], 'size' => $r['usize'], 'sha256' => hash('sha256', $data)];
        }
        if (!@rename($staging, $target)) {
            throw new \RuntimeException('io');
        }
    } catch (Throwable $e) {
        remove_tree($staging);
        return refuse('target_unwritable', 500);
    }
    return ['ok' => true, 'entries' => $c['entries'], 'total_bytes' => $c['total_bytes'], 'files' => $out];
}
