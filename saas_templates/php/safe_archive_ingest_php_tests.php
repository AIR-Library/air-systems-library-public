<?php
/**
 * Safe archive ingest tests (docs/specs/safe_archive_ingest.md, ARCHIVE-01..14).
 *
 * Self-running script. Archives are made with the spec's TEST ARCHIVE BUILDER (build_zip, no compressor);
 * extraction goes into a fresh temporary directory per test, removed at the end. Exits 1 on any failure.
 *
 * Why: Phase D wave 1, owner request 2026-11-10. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files under a temporary directory only (created and removed); no database, network or money.
 */

declare(strict_types=1);

require_once __DIR__ . '/safe_archive_ingest_php.php';

use function SafeArchiveIngest\extract_archive;
use function SafeArchiveIngest\inspect_archive;
use function SafeArchiveIngest\remove_tree;

$GLOBALS['FAILS'] = 0;

/**
 * Assert identity. In: expected, actual, label. Out: none. Why: test helper. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: stdout.
 */
function eq($expected, $actual, string $msg): void
{
    if ($expected !== $actual) {
        $GLOBALS['FAILS']++;
        echo "  FAIL $msg\n    expected: " . var_export($expected, true) . "\n    actual:   " . var_export($actual, true) . "\n";
    }
}

/**
 * The spec's TEST ARCHIVE BUILDER. In: entries [{name, data, method, usize, crc, flags, external, creator,
 * extra, local_name}], comment. Out: zip bytes. Why: every ARCHIVE test. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function build_zip(array $entries, string $comment = ''): string
{
    $local = '';
    $central = '';
    foreach ($entries as $e) {
        $e += ['data' => '', 'method' => 0, 'flags' => 0, 'external' => 0, 'creator' => 0, 'extra' => ''];
        $e += ['usize' => strlen($e['data']), 'crc' => crc32($e['data']), 'local_name' => $e['name']];
        $offset = strlen($local);
        $local .= "PK\x03\x04" . pack('vvvvvVVVvv', 20, $e['flags'], $e['method'], 0, 0x0021, $e['crc'], strlen($e['data']), $e['usize'], strlen($e['local_name']), 0)
            . $e['local_name'] . $e['data'];
        $central .= "PK\x01\x02" . pack('vvvvvvVVVvvvvvVV', $e['creator'] * 256 + 20, 20, $e['flags'], $e['method'], 0, 0x0021, $e['crc'], strlen($e['data']), $e['usize'],
                strlen($e['name']), strlen($e['extra']), 0, 0, 0, $e['external'], $offset) . $e['name'] . $e['extra'];
    }
    return $local . $central . "PK\x05\x06" . pack('vvvvVVv', 0, 0, count($entries), count($entries), strlen($central), strlen($local), strlen($comment)) . $comment;
}

/** The BASIC archive. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
function basic(string $comment = ''): string
{
    return build_zip([
        ['name' => 'docs/', 'external' => 0x41ED0000, 'creator' => 3],
        ['name' => 'docs/readme.txt', 'data' => "hello\n"],
        ['name' => 'data.csv', 'data' => "a,b\n1,2\n", 'external' => 0x81ED0000, 'creator' => 3],
    ], $comment);
}

/** Z, the raw DEFLATE stream of 2000 zero bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function Z(): string
{
    return hex2bin('63601805a360148c8251300a46c1500700');
}

/**
 * A fresh, empty temporary parent directory. Out: its path (registered for removal at exit).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files (a temporary directory).
 */
function tmp_parent(): string
{
    $d = sys_get_temp_dir() . '/archive_test_' . bin2hex(random_bytes(6));
    mkdir($d, 0700);
    $GLOBALS['TMP'][] = $d;
    return $d;
}

/** The names in a directory. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files (read). */
function listing(string $dir): array
{
    return array_values(array_diff(scandir($dir), ['.', '..']));
}

/**
 * Assert a refusal from both inspect and extract, and that extraction left nothing.
 * In: archive, expected [error, status, entry_index], label, limits. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: files (a temporary directory).
 */
function refused(string $zip, array $want, string $msg, array $limits = []): void
{
    $w = ['error' => $want[0], 'status' => $want[1], 'entry_index' => $want[2]];
    $parent = tmp_parent();
    $r = extract_archive($zip, $parent . '/target', $limits);
    eq($w, $r, "$msg (extract)");
    eq([], listing($parent), "$msg leaves nothing");
    if (!in_array($want[0], ['corrupt_entry'], true)) {
        eq($w, inspect_archive($zip, $limits), "$msg (inspect)");
    }
}

/** Extract into a fresh target. Out: [result, target]. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files. */
function extract_new(string $zip, array $limits = []): array
{
    $t = tmp_parent() . '/target';
    return [extract_archive($zip, $t, $limits), $t];
}

// ARCHIVE-01
/** ARCHIVE-01: BASIC byte for byte, then extracted. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files. */
function test_archive01_basic(): void
{
    $hex = '504b03041400000000000000210000000000000000000000000005000000646f63732f504b0304140000000000000021'
        . '0020303a3606000000060000000f000000646f63732f726561646d652e74787468656c6c6f0a504b0304140000000000'
        . '000021007b07970a080000000800000008000000646174612e637376612c620a312c320a504b01021403140000000000'
        . '00002100000000000000000000000000050000000000000000000000ed4100000000646f63732f504b01021400140000'
        . '0000000000210020303a3606000000060000000f0000000000000000000000000023000000646f63732f726561646d65'
        . '2e747874504b01021403140000000000000021007b07970a0800000008000000080000000000000000000000ed815600'
        . '0000646174612e637376504b05060000000003000300a6000000840000000000';
    eq(320, strlen(basic()), '320 bytes');
    eq($hex, bin2hex(basic()), 'BASIC byte for byte');
    [$r, $t] = extract_new(basic());
    eq(['ok' => true, 'entries' => 3, 'total_bytes' => 14, 'files' => [
        ['path' => 'docs/readme.txt', 'size' => 6, 'sha256' => '5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03'],
        ['path' => 'data.csv', 'size' => 8, 'sha256' => '492d5ea496056f1a6a6592241032fab764c321596317930b4fa0e1e8bc3b7470'],
    ]], $r, 'result');
    eq(true, is_dir("$t/docs"), 'docs is a directory');
    eq(["hello\n", "a,b\n1,2\n"], [file_get_contents("$t/docs/readme.txt"), file_get_contents("$t/data.csv")], 'file bytes');
    eq(0644, fileperms("$t/data.csv") & 0777, 'data.csv 0644 although its entry says 0755');
    eq(0700, fileperms($t) & 0777, 'target keeps 0700');
    eq(['ok' => true, 'entries' => 3, 'total_bytes' => 14, 'files' => [['path' => 'docs/readme.txt', 'size' => 6], ['path' => 'data.csv', 'size' => 8]]], inspect_archive(basic()), 'inspect');
}

// ARCHIVE-02
/** ARCHIVE-02: zip slip and malformed names are unsafe_path with the entry's index. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_archive02_zip_slip(): void
{
    $names = ['../evil.txt', 'a/../../evil.txt', '/etc/passwd.txt', 'C:/x.txt', 'a\\b.txt', 'a//b.txt', './a.txt',
        "a\x00b.txt", "a\x01b.txt", "a\x7Fb.txt", '', hex2bin('61c0af622e747874'), hex2bin('61eda0802e747874'),
        hex2bin('61f49080802e747874'), hex2bin('61e2822e747874')];
    foreach ($names as $i => $name) {
        refused(build_zip([['name' => 'ok.txt', 'data' => 'x'], ['name' => $name, 'data' => 'y']]), ['unsafe_path', 400, 1], "name $i");
    }
}

// ARCHIVE-03
/** ARCHIVE-03: links and FIFOs are special_file whatever the creator. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_archive03_special_files(): void
{
    foreach ([0, 3, 19] as $creator) {
        refused(build_zip([['name' => 'link.txt', 'data' => '/etc/passwd', 'external' => 0xA1FF0000, 'creator' => $creator]]), ['special_file', 400, 0], "link creator $creator");
    }
    refused(build_zip([['name' => 'fifo.txt', 'external' => 0x11A40000, 'creator' => 3]]), ['special_file', 400, 0], 'fifo');
    eq(true, extract_new(build_zip([['name' => 'r.txt', 'data' => 'x', 'external' => 0x81A40000, 'creator' => 3]]))[0]['ok'] ?? false, 'regular accepted');
}

// ARCHIVE-04
/** ARCHIVE-04: entry count and archive size limits, exact limits accepted. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_archive04_count_and_size(): void
{
    $zip = build_zip([['name' => 'a.txt', 'data' => 'x'], ['name' => 'b.txt', 'data' => 'x'], ['name' => 'c.txt', 'data' => 'x']]);
    eq(283, strlen($zip), '283 bytes');
    eq(true, extract_new($zip, ['max_entries' => 3, 'max_archive_bytes' => 283])[0]['ok'] ?? false, 'exactly at the limits');
    refused($zip, ['too_many_entries', 413, -1], 'max_entries 2', ['max_entries' => 2]);
    refused($zip, ['archive_too_large', 413, -1], 'max_archive_bytes 282', ['max_archive_bytes' => 282]);
}

// ARCHIVE-05
/** ARCHIVE-05: total and per-file limits; an unsigned 0x80000000. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_archive05_declared_sizes(): void
{
    $zip = build_zip([['name' => 'a.txt', 'data' => '12345'], ['name' => 'b.txt', 'data' => '67890']]);
    eq(204, strlen($zip), '204 bytes');
    eq(true, extract_new($zip, ['max_total_bytes' => 10, 'max_file_bytes' => 5])[0]['ok'] ?? false, 'exactly at the limits');
    refused($zip, ['total_too_large', 413, 1], 'max_total_bytes 9', ['max_total_bytes' => 9]);
    refused($zip, ['entry_too_large', 413, 0], 'max_file_bytes 4', ['max_file_bytes' => 4]);
    $big = build_zip([['name' => 'a.txt', 'data' => Z(), 'method' => 8, 'usize' => 0x80000000, 'crc' => 0]]);
    refused($big, ['entry_too_large', 413, 0], 'unsigned 0x80000000');
    refused($big, ['compression_ratio_exceeded', 413, -1], 'unsigned, large limits', ['max_file_bytes' => 4294967296, 'max_total_bytes' => 4294967296]);
}

// ARCHIVE-06
/** ARCHIVE-06: the ZEROS ratio vector. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files. */
function test_archive06_ratio(): void
{
    $zeros = build_zip([['name' => 'zeros.txt', 'data' => Z(), 'method' => 8, 'usize' => 2000, 'crc' => 0x02C9F444]]);
    eq(133, strlen($zeros), '133 bytes');
    eq(0x02C9F444, crc32(str_repeat("\0", 2000)), 'CRC of 2000 zeros');
    refused($zeros, ['compression_ratio_exceeded', 413, -1], 'max_ratio 15', ['max_ratio' => 15]);
    [$r, $t] = extract_new($zeros, ['max_ratio' => 16]);
    eq(true, $r['ok'] ?? false, 'max_ratio 16 extracts');
    eq(str_repeat("\0", 2000), file_get_contents("$t/zeros.txt"), '2000 zero bytes');
}

// ARCHIVE-07
/** ARCHIVE-07: lying headers are corrupt_entry or size_mismatch, leaving no file. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_archive07_lying_headers(): void
{
    $z = ['name' => 'zeros.txt', 'data' => Z(), 'method' => 8, 'usize' => 2000, 'crc' => 0x02C9F444];
    eq(0xE38A6876, crc32(str_repeat("\0", 10)), 'CRC of 10 zeros');
    $corrupt = [
        'declares 10' => ['usize' => 10, 'crc' => 0xE38A6876] + $z,
        'declares 3000' => ['usize' => 3000] + $z,
        'missing last 4 bytes' => ['data' => substr(Z(), 0, -4)] + $z,
        'wrong crc deflated' => ['crc' => 1] + $z,
        'wrong crc stored' => ['name' => 'a.txt', 'data' => '12345', 'crc' => 0],
        'invalid data' => ['name' => 'zeros.txt', 'data' => "\xFF\xFF\xFF\xFF", 'method' => 8, 'usize' => 4, 'crc' => 0],
        'overruns then invalid' => ['data' => hex2bin('62601805a360148c8251300a46c1500700000000ffff07'), 'usize' => 10, 'crc' => 0xE38A6876] + $z,
    ];
    foreach ($corrupt as $name => $e) {
        refused(build_zip([$e]), ['corrupt_entry', 400, 0], $name);
    }
    refused(build_zip([['name' => 'a.txt', 'data' => '12345', 'usize' => 4]]), ['size_mismatch', 400, 0], 'stored sizes differ');
}

// ARCHIVE-08
/** ARCHIVE-08: the extension allow-list. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files. */
function test_archive08_extensions(): void
{
    foreach (['run.exe', 'a.txt.sh', 'README', '.env', 'inner.zip'] as $name) {
        refused(build_zip([['name' => $name, 'data' => 'x']]), ['extension_not_allowed', 400, 0], $name);
    }
    foreach (['A.TXT', 'x.Json'] as $name) {
        eq(true, extract_new(build_zip([['name' => $name, 'data' => 'x']]))[0]['ok'] ?? false, "$name accepted");
    }
    foreach (['README', 'a.sh'] as $name) {
        eq(true, extract_new(build_zip([['name' => $name, 'data' => 'x']]), ['allowed_extensions' => ['', 'sh']])[0]['ok'] ?? false, "$name accepted with ['', 'sh']");
    }
}

// ARCHIVE-09
/** ARCHIVE-09: duplicate names, case-folded, file/dir clashes in either order. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_archive09_duplicates(): void
{
    $pairs = [['a.txt', 'a.txt'], ['A.txt', 'a.txt'], ['d.txt/', 'd.txt'], ['d.txt', 'd.txt/'], ['d.txt', 'd.txt/e.txt'], ['d.txt/e.txt', 'd.txt']];
    foreach ($pairs as [$first, $second]) {
        refused(build_zip([['name' => $first, 'data' => substr($first, -1) === '/' ? '' : 'x'], ['name' => $second, 'data' => substr($second, -1) === '/' ? '' : 'y']]),
            ['duplicate_name', 400, 1], "$first then $second");
    }
    eq(true, extract_new(build_zip([['name' => 'd/'], ['name' => 'd/'], ['name' => 'd/x.txt', 'data' => 'x']]))[0]['ok'] ?? false, 'same directory twice');
}

// ARCHIVE-10
/** ARCHIVE-10: the container checks. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files. */
function test_archive10_container(): void
{
    $b = basic();
    $n = strlen($b);
    $set16 = static function (string $s, int $at, int $v): string {
        return substr($s, 0, $at) . pack('v', $v) . substr($s, $at + 2);
    };
    $set32 = static function (string $s, int $at, int $v): string {
        return substr($s, 0, $at) . pack('V', $v) . substr($s, $at + 4);
    };
    refused('', ['empty_upload', 400, -1], 'empty input');
    refused('this is not a zip file at all', ['not_a_zip', 400, -1], 'text');
    refused(substr($b, 0, -10), ['not_a_zip', 400, -1], 'truncated');
    refused($set16($set16($b, $n - 14, 4), $n - 12, 4), ['not_a_zip', 400, -1], 'count disagrees with the directory');
    refused($b . "\x00", ['not_a_zip', 400, -1], 'byte after the end record');
    refused($set32($set32($b, $n - 10, 300), $n - 6, 0xFFFFFFFE), ['not_a_zip', 400, -1], '32-bit sum wraps');
    refused($set16($b, $n - 18, 1), ['unsupported_zip', 400, -1], 'disk number');
    refused($set16($set16($b, $n - 14, 0xFFFF), $n - 12, 0xFFFF), ['unsupported_zip', 400, -1], 'zip64 counts');
    $withLocator = substr($b, 0, $n - 22) . "PK\x06\x07" . str_repeat("\x00", 16) . substr($b, $n - 22);
    refused($withLocator, ['unsupported_zip', 400, -1], 'zip64 locator before the end record');
    refused(hex2bin('504b0304504b0506000000000000000000000000040000001000504b0607787878787878787878787878'), ['empty_archive', 400, -1], '42 bytes, short input');
    refused(build_zip([['name' => 'docs/']]), ['empty_archive', 400, -1], 'only a directory');
    eq(true, extract_new(basic(str_repeat('c', 40)))[0]['ok'] ?? false, 'archive comment accepted');
}

// ARCHIVE-11
/** ARCHIVE-11: encryption flags, compression methods, data descriptor. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_archive11_flags_and_methods(): void
{
    refused(build_zip([['name' => 'a.txt', 'data' => '12345', 'flags' => 1]]), ['encrypted_entry', 400, 0], 'bit 0');
    refused(build_zip([['name' => 'a.txt', 'data' => '12345', 'flags' => 0x40]]), ['encrypted_entry', 400, 0], 'bit 6');
    refused(build_zip([['name' => 'a.txt', 'data' => '12345', 'flags' => 0x2000]]), ['encrypted_entry', 400, 0], 'bit 13');
    refused(build_zip([['name' => 'a.txt', 'data' => '12345', 'method' => 12]]), ['unsupported_compression', 400, 0], 'method 12');
    [$r, $t] = extract_new(build_zip([['name' => 'a.txt', 'data' => '12345', 'flags' => 8]]));
    eq(true, $r['ok'] ?? false, 'flag bit 3 accepted');
    eq('12345', @file_get_contents("$t/a.txt"), 'data descriptor entry written');
}

// ARCHIVE-12
/** ARCHIVE-12: local/central mismatch and the Unicode Path extra field. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_archive12_header_mismatch(): void
{
    refused(build_zip([['name' => 'first.txt', 'data' => 'x'], ['name' => 'ok.txt', 'data' => 'x', 'local_name' => 'no.txt']]), ['header_mismatch', 400, 1], 'local name differs');
    $evil = "\x75\x70" . pack('v', 16) . "\x01" . pack('V', crc32('ok.txt')) . '../evil.txt';
    eq('75701000012a0419052e2e2f6576696c2e747874', bin2hex($evil), 'extra vector');
    refused(build_zip([['name' => 'ok.txt', 'data' => 'x', 'extra' => $evil]]), ['header_mismatch', 400, 0], 'unicode path ../evil.txt');
    $same = "\x75\x70" . pack('v', 11) . "\x01" . pack('V', crc32('ok.txt')) . 'ok.txt';
    eq(true, extract_new(build_zip([['name' => 'ok.txt', 'data' => 'x', 'extra' => $same]]))[0]['ok'] ?? false, 'unicode path naming itself accepted');
    refused(build_zip([['name' => 'ok.txt', 'data' => 'x', 'extra' => hex2bin('0a0032006162')]]), ['not_a_zip', 400, 0], 'extra overruns');
}

// ARCHIVE-13
/** ARCHIVE-13: all or nothing; existing target; missing parent. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files. */
function test_archive13_all_or_nothing(): void
{
    $zip = build_zip([['name' => 'good.txt', 'data' => 'fine'], ['name' => 'bad.txt', 'data' => '12345', 'crc' => 0]]);
    $parent = tmp_parent();
    eq(['error' => 'corrupt_entry', 'status' => 400, 'entry_index' => 1], extract_archive($zip, "$parent/target"), 'second entry corrupt');
    eq([false, []], [file_exists("$parent/target"), listing($parent)], 'no target and no staging left');
    $parent = tmp_parent();
    mkdir("$parent/target");
    file_put_contents("$parent/target/keep.txt", 'mine');
    eq(['error' => 'target_exists', 'status' => 409, 'entry_index' => -1], extract_archive(basic(), "$parent/target"), 'existing target');
    eq(['mine', ['keep.txt']], [file_get_contents("$parent/target/keep.txt"), listing("$parent/target")], 'content kept');
    symlink("$parent/nowhere", "$parent/dangling");
    eq(['error' => 'target_exists', 'status' => 409, 'entry_index' => -1], extract_archive(basic(), "$parent/dangling"), 'dangling link is a target that exists');
    eq(['error' => 'target_unwritable', 'status' => 500, 'entry_index' => -1], extract_archive(basic(), "$parent/missing/target"), 'parent missing');
    eq(['dangling', 'target'], listing($parent), 'nothing else written');
}

// ARCHIVE-13
/**
 * ARCHIVE-13, D3 I/O failure: the target's parent sits deep enough that the first entry fits but the second
 * entry's full path is longer than PHP_MAXPATHLEN (its name passes every check of C: 4 parts of 200 bytes), so
 * writing it fails with an I/O error. The answer is 500 target_unwritable naming entry_index 1, the entry being
 * written, and nothing is left behind.
 * In: none. Out: assertions. Why: spec CONVENTIONS (D3 names the entry); review finding 4525101297.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: files under a temporary directory.
 */
function test_archive13_d3_io_failure_names_the_entry(): void
{
    $parent = tmp_parent();
    while (strlen($parent) < PHP_MAXPATHLEN - 600) {
        $parent .= '/' . str_repeat('p', 200);
        eq(true, mkdir($parent, 0700), 'deep parent created');
    }
    $long = implode('/', array_fill(0, 4, str_repeat('d', 200))) . '/f.txt';
    $zip = build_zip([['name' => 'first.txt', 'data' => 'ok'], ['name' => $long, 'data' => 'x']]);
    eq(['error' => 'target_unwritable', 'status' => 500, 'entry_index' => 1], extract_archive($zip, "$parent/target"), 'D3 I/O failure names entry 1');
    eq([false, []], [file_exists("$parent/target"), listing($parent)], 'no target and no staging left');
}

// ARCHIVE-14
/** ARCHIVE-14: names that do not unpack everywhere; execute bits dropped. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_archive14_bad_names(): void
{
    $bad = ['CON.txt', 'com1.txt', 'COM0.txt', 'LPT0.txt', "COM\u{b9}.txt", 'CONIN$.txt', 'CONOUT$.txt', 'a.', 'a ', 'a?.txt',
        str_repeat('x', 252) . '.txt', "a\u{202E}b.txt", 'nul .txt', 'dir/aux.md'];
    foreach ($bad as $name) {
        refused(build_zip([['name' => $name, 'data' => 'x']]), ['bad_name', 400, 0], 'bad name ' . bin2hex($name));
    }
    eq(256, strlen(str_repeat('x', 252) . '.txt'), '256-byte segment');
    foreach ([str_repeat('x', 251) . '.txt', "caf\u{e9}.txt", 'COM10.txt', 'conin.txt'] as $name) {
        eq(true, extract_new(build_zip([['name' => $name, 'data' => 'x']]))[0]['ok'] ?? false, 'accepted ' . bin2hex($name));
    }
    [$r, $t] = extract_new(build_zip([['name' => 'run.txt', 'data' => 'x', 'external' => 0x81ED0000, 'creator' => 3]]));
    eq(true, $r['ok'] ?? false, 'mode 0755 entry extracted');
    eq(0644, fileperms("$t/run.txt") & 0777, 'written without execute permission');
}

$GLOBALS['TMP'] = [];
$tests = array_filter(get_defined_functions()['user'], static fn(string $f): bool => str_starts_with($f, 'test_'));
foreach ($tests as $t) {
    $before = $GLOBALS['FAILS'];
    try {
        $t();
    } catch (Throwable $e) {
        $GLOBALS['FAILS']++;
        echo "  EXCEPTION in $t: " . get_class($e) . ' ' . $e->getMessage() . "\n";
    }
    echo ($GLOBALS['FAILS'] === $before ? 'PASS ' : 'FAIL ') . $t . "\n";
}
foreach ($GLOBALS['TMP'] as $d) {
    remove_tree($d);
}
echo $GLOBALS['FAILS'] === 0 ? "All tests passed\n" : "{$GLOBALS['FAILS']} assertion(s) failed\n";
exit($GLOBALS['FAILS'] === 0 ? 0 : 1);
