<?php

require_once __DIR__ . '/file_uploads_php.php';

$failed = 0;

function err(callable $fn, string $expected_code, int $expected_status): void {
    global $failed;
    try {
        $fn();
        echo "FAIL: Expected $expected_code/$expected_status but no exception thrown\n";
        $failed++;
    } catch (FileUploadError $e) {
        if ($e->error_code !== $expected_code || $e->status !== $expected_status) {
            echo "FAIL: Expected $expected_code/$expected_status, got {$e->error_code}/{$e->status}\n";
            $failed++;
        } else {
            echo "PASS: $expected_code/$expected_status\n";
        }
    } catch (Throwable $e) {
        echo "FAIL: Unexpected exception: " . get_class($e) . ": " . $e->getMessage() . "\n";
        $failed++;
    }
}

function assert_true(bool $cond, string $msg): void {
    global $failed;
    if (!$cond) {
        echo "FAIL: $msg\n";
        $failed++;
    } else {
        echo "PASS: $msg\n";
    }
}

function assert_eq(mixed $a, mixed $b, string $msg): void {
    global $failed;
    if ($a !== $b) {
        echo "FAIL: $msg (expected " . var_export($b, true) . ", got " . var_export($a, true) . ")\n";
        $failed++;
    } else {
        echo "PASS: $msg\n";
    }
}

function make_svc(array $overrides = []): FileUploads {
    global $state, $tmpdir;
    $store = new InMemoryFileStore();
    $options = [
        'storage_dir' => $tmpdir,
        'signing_key' => 'test-signing-key-not-a-secret-0000',
        'is_member' => function(string $u, string $o) use (&$state) {
            return in_array([$u, $o], $state['members'], true);
        },
        'now' => function() use (&$state) {
            return $state['clock'];
        },
        'random_bytes' => fn(int $n) => random_bytes($n),
        'max_file_size' => 10485760,
        'allowed_extensions' => ['pdf', 'png', 'jpg', 'jpeg', 'gif', 'txt', 'csv', 'docx', 'xlsx'],
    ];
    foreach ($overrides as $k => $v) {
        $options[$k] = $v;
    }
    return new FileUploads($store, $options);
}

function fresh_tmpdir(): string {
    $dir = sys_get_temp_dir() . '/fu_test_' . bin2hex(random_bytes(8));
    @mkdir($dir, 0700, true);
    return $dir;
}

function cleanup_tmpdir(string $dir): void {
    @array_map('unlink', glob($dir . '/*'));
    @rmdir($dir);
}

function list_files(string $dir): array {
    return array_values(array_diff(scandir($dir), ['.', '..']));
}

$PNG = hex2bin('89504e470d0a1a0a0000000d49484452000000010000000108000000003a7e9b550000000a4944415478da6360000000020001e527defc0000000049454e44ae426082');
$EXE = "MZ" . str_repeat("\x00", 62);
$GIF89a = "GIF89a" . str_repeat("\x00", 100);
$PNG_SHA256 = 'a4d4c009619311d9b83904acfd62fe3b7f918c312522bbcc6ad51cdec4fd1edf';

// UPLOAD-01
function test_exe_rejected_by_extension_and_magic_bytes(): void {
    global $state, $tmpdir, $PNG, $EXE;
    $tmpdir = fresh_tmpdir();
    $state = ['clock' => 1000, 'members' => [['alice', 'org1'], ['carol', 'org1'], ['bob', 'org2']]];

    $svc = make_svc();
    err(fn() => $svc->upload('alice', 'org1', 'setup.exe', $EXE, 'application/octet-stream'), 'EXTENSION_NOT_ALLOWED', 415);
    assert_true(empty(list_files($tmpdir)), 'storage dir empty after exe rejection');

    err(fn() => $svc->upload('alice', 'org1', 'setup.png', $EXE, 'image/png'), 'CONTENT_MISMATCH', 415);
    assert_true(empty(list_files($tmpdir)), 'storage dir empty after exe-as-png rejection');

    cleanup_tmpdir($tmpdir);
}

// UPLOAD-02
function test_real_png_stored_under_generated_name(): void {
    global $state, $tmpdir, $PNG;
    $tmpdir = fresh_tmpdir();
    $state = ['clock' => 1000, 'members' => [['alice', 'org1'], ['carol', 'org1'], ['bob', 'org2']]];

    $svc = make_svc();
    $r = $svc->upload('alice', 'org1', 'photo.png', $PNG, 'image/png');
    assert_true(preg_match('/^[0-9a-f]{32}$/', $r->file_id), 'file_id is 32 lowercase hex');

    assert_eq(list_files($tmpdir), [$r->file_id], 'dir contains only the generated file_id');

    $content = file_get_contents($tmpdir . '/' . $r->file_id);
    assert_eq($content, $PNG, 'stored bytes match uploaded PNG');

    $info = $svc->get_file('alice', $r->file_id);
    assert_eq($info->original_name, 'photo.png', 'original_name preserved');
    assert_eq($info->extension, 'png', 'extension is png');
    assert_eq($info->mime_type, 'image/png', 'mime_type is image/png');
    assert_eq($info->size_bytes, 67, 'size_bytes is 67');
    assert_eq($info->sha256, $PNG_SHA256, 'sha256 matches');
    assert_eq($info->created_at, 1000, 'created_at is 1000');
    assert_eq($info->owner_user_id, 'alice', 'owner_user_id is alice');

    cleanup_tmpdir($tmpdir);
}

// UPLOAD-03
function test_path_traversal_name_stored_safely(): void {
    global $state, $tmpdir, $PNG;
    $tmpdir = fresh_tmpdir();
    $state = ['clock' => 1000, 'members' => [['alice', 'org1'], ['carol', 'org1'], ['bob', 'org2']]];

    $svc = make_svc();
    $r1 = $svc->upload('alice', 'org1', '../../etc/passwd.png', $PNG, 'image/png');
    $info1 = $svc->get_file('alice', $r1->file_id);
    assert_eq($info1->original_name, 'passwd.png', 'original_name sanitized from ../../etc/passwd.png');

    assert_eq(list_files($tmpdir), [$r1->file_id], 'dir contains only generated name');

    $r2 = $svc->upload('alice', 'org1', '..\\..\\evil.png', $PNG, 'image/png');
    $info2 = $svc->get_file('alice', $r2->file_id);
    assert_eq($info2->original_name, 'evil.png', 'original_name sanitized from ..\\..\\evil.png');

    cleanup_tmpdir($tmpdir);
}

// UPLOAD-04
function test_file_over_size_limit_rejected(): void {
    global $state, $tmpdir, $PNG;
    $tmpdir = fresh_tmpdir();
    $state = ['clock' => 1000, 'members' => [['alice', 'org1'], ['carol', 'org1'], ['bob', 'org2']]];

    $svc = make_svc(['max_file_size' => 100]);
    $big101 = $PNG . str_repeat("\x00", 34);
    err(fn() => $svc->upload('alice', 'org1', 'big.png', $big101, 'image/png'), 'FILE_TOO_LARGE', 413);

    $exact100 = $PNG . str_repeat("\x00", 33);
    $r = $svc->upload('alice', 'org1', 'ok.png', $exact100, 'image/png');
    assert_true(preg_match('/^[0-9a-f]{32}$/', $r->file_id), 'exact 100 bytes accepted');

    $svc2 = make_svc();
    $big_default = $PNG . str_repeat("\x00", 10485761 - 67);
    err(fn() => $svc2->upload('alice', 'org1', 'big.png', $big_default, 'image/png'), 'FILE_TOO_LARGE', 413);

    cleanup_tmpdir($tmpdir);
}

// UPLOAD-05
function test_non_member_cannot_upload_or_download(): void {
    global $state, $tmpdir, $PNG;
    $tmpdir = fresh_tmpdir();
    $state = ['clock' => 1000, 'members' => [['alice', 'org1'], ['carol', 'org1'], ['bob', 'org2']]];

    $svc = make_svc();
    err(fn() => $svc->upload('bob', 'org1', 'photo.png', $PNG, 'image/png'), 'FORBIDDEN', 403);
    assert_true(empty(list_files($tmpdir)), 'storage dir empty after non-member upload');

    $r = $svc->upload('alice', 'org1', 'photo.png', $PNG, 'image/png');
    $link = $svc->create_download_link('alice', $r->file_id);

    err(fn() => $svc->create_download_link('bob', $r->file_id), 'FORBIDDEN', 403);
    err(fn() => $svc->download('bob', $link->token), 'FORBIDDEN', 403);

    $dl = $svc->download('alice', $link->token);
    assert_eq($dl->status, 200, 'download status 200');
    assert_eq($dl->content_type, 'image/png', 'content_type image/png');
    assert_eq($dl->body, $PNG, 'body matches PNG');

    cleanup_tmpdir($tmpdir);
}

// UPLOAD-06
function test_expired_and_tampered_links_rejected(): void {
    global $state, $tmpdir, $PNG;
    $tmpdir = fresh_tmpdir();
    $state = ['clock' => 1000, 'members' => [['alice', 'org1'], ['carol', 'org1'], ['bob', 'org2']]];

    $svc = make_svc();
    $r = $svc->upload('alice', 'org1', 'photo.png', $PNG, 'image/png');
    $link = $svc->create_download_link('alice', $r->file_id, 300);
    assert_eq($link->expires_at, 1300, 'expires_at is 1300');
    assert_true(str_starts_with($link->token, $r->file_id . '.1300.'), 'token middle is 1300');

    $state['clock'] = 1299;
    $dl = $svc->download('alice', $link->token);
    assert_eq($dl->status, 200, 'download works at 1299');

    $state['clock'] = 1300;
    err(fn() => $svc->download('alice', $link->token), 'LINK_EXPIRED', 410);

    $state['clock'] = 1000;
    $tampered = substr($link->token, 0, -1) . ($link->token[-1] === '0' ? '1' : '0');
    err(fn() => $svc->download('alice', $tampered), 'INVALID_LINK', 400);

    $parts = explode('.', $link->token);
    $extended = $parts[0] . '.9300.' . $parts[2];
    err(fn() => $svc->download('alice', $extended), 'INVALID_LINK', 400);

    cleanup_tmpdir($tmpdir);
}

// UPLOAD-07
function test_deleted_file_cannot_be_linked_or_downloaded(): void {
    global $state, $tmpdir, $PNG;
    $tmpdir = fresh_tmpdir();
    $state = ['clock' => 1000, 'members' => [['alice', 'org1'], ['carol', 'org1'], ['bob', 'org2']]];

    $svc = make_svc();
    $r = $svc->upload('alice', 'org1', 'photo.png', $PNG, 'image/png');
    $link = $svc->create_download_link('alice', $r->file_id);

    $svc->delete_file('alice', $r->file_id);

    err(fn() => $svc->create_download_link('alice', $r->file_id), 'NOT_FOUND', 404);
    err(fn() => $svc->download('alice', $link->token), 'NOT_FOUND', 404);
    err(fn() => $svc->get_file('alice', $r->file_id), 'NOT_FOUND', 404);
    err(fn() => $svc->delete_file('alice', $r->file_id), 'NOT_FOUND', 404);

    assert_eq(count(list_files($tmpdir)), 1, 'file bytes remain on disk after delete');

    cleanup_tmpdir($tmpdir);
}

function test_link_known_answer(): void {
    global $state, $tmpdir, $PNG;
    $tmpdir = fresh_tmpdir();
    $state = ['clock' => 1000, 'members' => [['alice', 'org1'], ['carol', 'org1'], ['bob', 'org2']]];

    $svc = make_svc(['random_bytes' => fn(int $n) => str_repeat("\x11", $n)]);
    $r = $svc->upload('alice', 'org1', 'photo.png', $PNG, 'image/png');
    assert_eq($r->file_id, str_repeat('11', 16), 'file_id is 11x16');

    $link = $svc->create_download_link('alice', $r->file_id, 300);
    $expected_token = '11111111111111111111111111111111.1300.d68893eb2822ef8782448b006c20860031c8063a53d980d852c39adcfdefadf2';
    assert_eq($link->token, $expected_token, 'token matches known answer');

    $dl = $svc->download('alice', $link->token);
    assert_eq($dl->body, $PNG, 'download returns PNG');

    err(fn() => $svc->upload('alice', 'org1', 'photo2.png', $PNG, 'image/png'), 'STORAGE_ERROR', 500);

    $dl2 = $svc->download('alice', $link->token);
    assert_eq($dl2->body, $PNG, 'first file still downloads after collision');

    cleanup_tmpdir($tmpdir);
}

function test_malformed_tokens_are_invalid_link(): void {
    global $state, $tmpdir, $PNG;
    $tmpdir = fresh_tmpdir();
    $state = ['clock' => 1000, 'members' => [['alice', 'org1'], ['carol', 'org1'], ['bob', 'org2']]];

    $svc = make_svc();
    $r = $svc->upload('alice', 'org1', 'photo.png', $PNG, 'image/png');
    $link = $svc->create_download_link('alice', $r->file_id, 300);

    $bad_tokens = [
        '', 'abc', 'a.b', 'a.b.c.d',
        strtoupper($r->file_id) . '.1300.' . substr($link->token, -64),
        $r->file_id . '.1300.' . strtoupper(substr($link->token, -64)),
        $r->file_id . '.13x0.' . substr($link->token, -64),
        $r->file_id . '.+1300.' . substr($link->token, -64),
        $r->file_id . '. 1300.' . substr($link->token, -64),
        $r->file_id . '.-1300.' . substr($link->token, -64),
        $r->file_id . '.13000000000000.' . substr($link->token, -64),
        $r->file_id . '.1300.' . substr($link->token, -64, 63),
        $r->file_id . '.1300.' . substr($link->token, -64) . "\n",
        substr($link->token, 0, -1) . 'é',
    ];

    foreach ($bad_tokens as $t) {
        err(fn() => $svc->download('alice', $t), 'INVALID_LINK', 400);
    }

    $dl = $svc->download('alice', $link->token);
    assert_eq($dl->status, 200, 'original token still works after malformed attempts');

    cleanup_tmpdir($tmpdir);
}

function test_error_precedence(): void {
    global $state, $tmpdir, $PNG, $EXE;
    $tmpdir = fresh_tmpdir();
    $state = ['clock' => 1000, 'members' => [['alice', 'org1'], ['carol', 'org1'], ['bob', 'org2']]];

    $svc = make_svc();
    err(fn() => $svc->upload('bob', 'org1', 'setup.exe', $EXE, 'application/octet-stream'), 'FORBIDDEN', 403);

    $svc2 = make_svc(['max_file_size' => 100]);
    $big_exe = $EXE . str_repeat("\x00", 38);
    err(fn() => $svc2->upload('alice', 'org1', 'big.exe', $big_exe, 'application/octet-stream'), 'EXTENSION_NOT_ALLOWED', 415);

    $big_png = $EXE . str_repeat("\x00", 38);
    err(fn() => $svc2->upload('alice', 'org1', 'big.png', $big_png, 'image/png'), 'FILE_TOO_LARGE', 413);

    $svc3 = make_svc();
    $r = $svc3->upload('alice', 'org1', 'photo.png', $PNG, 'image/png');
    $link = $svc3->create_download_link('alice', $r->file_id, 300);
    $state['clock'] = 5000;
    $tampered = substr($link->token, 0, -1) . ($link->token[-1] === '0' ? '1' : '0');
    err(fn() => $svc3->download('alice', $tampered), 'INVALID_LINK', 400);

    err(fn() => $svc3->create_download_link('alice', $r->file_id, 0), 'INVALID_TTL', 400);
    err(fn() => $svc3->create_download_link('alice', $r->file_id, -1), 'INVALID_TTL', 400);
    err(fn() => $svc3->create_download_link('alice', $r->file_id, 86401), 'INVALID_TTL', 400);
    $link_ok = $svc3->create_download_link('alice', $r->file_id, 86400);
    assert_true($link_ok !== null, 'ttl 86400 accepted');

    err(fn() => $svc3->create_download_link('alice', '../x'), 'NOT_FOUND', 404);
    err(fn() => $svc3->create_download_link('alice', str_repeat('00', 16)), 'NOT_FOUND', 404);

    cleanup_tmpdir($tmpdir);
}

function test_membership_rechecked_and_delete_owner_only(): void {
    global $state, $tmpdir, $PNG;
    $tmpdir = fresh_tmpdir();
    $state = ['clock' => 1000, 'members' => [['alice', 'org1'], ['carol', 'org1'], ['bob', 'org2']]];

    $svc = make_svc();
    $r = $svc->upload('alice', 'org1', 'photo.png', $PNG, 'image/png');
    $link = $svc->create_download_link('alice', $r->file_id, 300);

    $state['members'] = [['carol', 'org1'], ['bob', 'org2']];
    err(fn() => $svc->download('alice', $link->token), 'FORBIDDEN', 403);
    err(fn() => $svc->get_file('alice', $r->file_id), 'FORBIDDEN', 403);

    $state['members'] = [['alice', 'org1'], ['carol', 'org1'], ['bob', 'org2']];
    $dl = $svc->download('alice', $link->token);
    assert_eq($dl->status, 200, 'download works after membership restored');

    err(fn() => $svc->delete_file('carol', $r->file_id), 'FORBIDDEN', 403);
    err(fn() => $svc->delete_file('bob', $r->file_id), 'FORBIDDEN', 403);

    $svc->delete_file('alice', $r->file_id);
    err(fn() => $svc->delete_file('alice', $r->file_id), 'NOT_FOUND', 404);

    cleanup_tmpdir($tmpdir);
}

function test_filename_and_content_edges(): void {
    global $state, $tmpdir, $PNG, $GIF89a;
    $tmpdir = fresh_tmpdir();
    $state = ['clock' => 1000, 'members' => [['alice', 'org1'], ['carol', 'org1'], ['bob', 'org2']]];

    $svc = make_svc();

    $r = $svc->upload('alice', 'org1', 'PHOTO.PNG', $PNG, 'image/png');
    assert_eq($svc->get_file('alice', $r->file_id)->extension, 'png', 'uppercase extension accepted');

    $r = $svc->upload('alice', 'org1', 'ANIM.GIF', $GIF89a, 'image/gif');
    assert_eq($svc->get_file('alice', $r->file_id)->extension, 'gif', 'gif89a accepted');

    $r = $svc->upload('alice', 'org1', '.png', $PNG, 'image/png');
    assert_eq($svc->get_file('alice', $r->file_id)->extension, 'png', 'leading dot extension accepted');

    $r = $svc->upload('alice', 'org1', "evil.php\x00.png", $PNG, 'image/png');
    assert_eq($svc->get_file('alice', $r->file_id)->original_name, 'evil.php.png', 'null byte stripped from display name');

    err(fn() => $svc->upload('alice', 'org1', 'photo.png.exe', $PNG, 'image/png'), 'EXTENSION_NOT_ALLOWED', 415);
    err(fn() => $svc->upload('alice', 'org1', 'noext', $PNG, 'image/png'), 'EXTENSION_NOT_ALLOWED', 415);

    err(fn() => $svc->upload('alice', 'org1', '', $PNG, 'image/png'), 'INVALID_FILENAME', 400);
    err(fn() => $svc->upload('alice', 'org1', '..', $PNG, 'image/png'), 'INVALID_FILENAME', 400);
    err(fn() => $svc->upload('alice', 'org1', 'uploads/', $PNG, 'image/png'), 'INVALID_FILENAME', 400);

    $name255 = str_repeat('a', 251) . '.png';
    $r = $svc->upload('alice', 'org1', $name255, $PNG, 'image/png');
    assert_true(preg_match('/^[0-9a-f]{32}$/', $r->file_id), '255 byte name accepted');

    $name256 = str_repeat('a', 252) . '.png';
    err(fn() => $svc->upload('alice', 'org1', $name256, $PNG, 'image/png'), 'FILENAME_TOO_LONG', 400);

    $name_unicode = str_repeat('é', 126) . '.png';
    err(fn() => $svc->upload('alice', 'org1', $name_unicode, $PNG, 'image/png'), 'FILENAME_TOO_LONG', 400);

    $truncated_png = "\x89\x50\x4e";
    err(fn() => $svc->upload('alice', 'org1', 'tiny.png', $truncated_png, 'image/png'), 'CONTENT_MISMATCH', 415);

    $empty_png = '';
    err(fn() => $svc->upload('alice', 'org1', 'empty.png', $empty_png, 'image/png'), 'CONTENT_MISMATCH', 415);

    $txt_nul = "a\x00b";
    err(fn() => $svc->upload('alice', 'org1', 'a.txt', $txt_nul, 'text/plain'), 'CONTENT_MISMATCH', 415);

    $r = $svc->upload('alice', 'org1', 'hello.txt', 'hello', 'text/plain');
    $dl = $svc->download('alice', $svc->create_download_link('alice', $r->file_id)->token);
    assert_eq($dl->content_type, 'text/plain', 'txt content_type');
    assert_eq($dl->body, 'hello', 'txt body');

    cleanup_tmpdir($tmpdir);
}

function test_store_contract_and_config(): void {
    global $state, $tmpdir;
    $tmpdir = fresh_tmpdir();
    $state = ['clock' => 1000, 'members' => [['alice', 'org1'], ['carol', 'org1'], ['bob', 'org2']]];

    $store = new InMemoryFileStore();
    $rec = new FileRecord('abcdef', 'org1', 'alice', 'abcdef', 'test.png', 'png', 'image/png', 10, 'sha', 1000, null);
    assert_true($store->insert_file($rec), 'insert first returns true');
    assert_false($store->insert_file($rec), 'insert duplicate returns false');
    $found = $store->find_file('abcdef');
    assert_true($found !== null, 'find returns record');
    assert_eq($found->id, 'abcdef', 'found id matches');
    assert_eq($found->original_name, 'test.png', 'found original_name matches');
    $unknown = $store->find_file('xyz');
    assert_true($unknown === null, 'find unknown returns null');
    assert_true($store->mark_deleted('abcdef', 2000), 'mark_deleted first returns true');
    assert_false($store->mark_deleted('abcdef', 2001), 'mark_deleted second returns false');
    $deleted = $store->find_file('abcdef');
    assert_true($deleted !== null && $deleted->deleted_at === 2000, 'deleted_at set to 2000');

    $svc = make_svc(['storage_dir' => '']);
    err(fn() => $svc, 'INVALID_CONFIG', 500);

    $svc = make_svc(['storage_dir' => sys_get_temp_dir() . '/public/files']);
    err(fn() => $svc, 'INVALID_CONFIG', 500);

    $svc = make_svc(['signing_key' => str_repeat('x', 31)]);
    err(fn() => $svc, 'INVALID_CONFIG', 500);

    $svc = make_svc(['allowed_extensions' => ['svg']]);
    err(fn() => $svc, 'INVALID_CONFIG', 500);

    $svc = make_svc(['max_file_size' => 0]);
    err(fn() => $svc, 'INVALID_CONFIG', 500);

    cleanup_tmpdir($tmpdir);
}

function assert_false(bool $cond, string $msg): void {
    global $failed;
    if ($cond) {
        echo "FAIL: $msg\n";
        $failed++;
    } else {
        echo "PASS: $msg\n";
    }
}

exit($failed > 0 ? 1 : 0);
?>