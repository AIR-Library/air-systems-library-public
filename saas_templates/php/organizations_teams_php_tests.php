<?php
declare(strict_types=1);

require_once __DIR__ . '/organizations_teams_php.php';

use Aoi\Orgs\{OrganizationsTeams, InMemoryStore, OrgError};

$failed = 0;
$passed = 0;

function assert_ok(bool $cond, string $msg): void
{
    global $failed, $passed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    } else {
        $passed++;
        echo "PASS: $msg\n";
    }
}

function assert_error(callable $fn, string $expected_code, int $expected_status, string $msg): void
{
    global $failed, $passed;
    try {
        $fn();
        $failed++;
        echo "FAIL: $msg (expected $expected_code, got no exception)\n";
    } catch (OrgError $e) {
        if ($e->error_code === $expected_code && $e->status === $expected_status) {
            $passed++;
            echo "PASS: $msg\n";
        } else {
            $failed++;
            echo "FAIL: $msg (expected $expected_code/$expected_status, got {$e->error_code}/{$e->status})\n";
        }
    } catch (\Throwable $e) {
        $failed++;
        echo "FAIL: $msg (unexpected exception: " . get_class($e) . ": " . $e->getMessage() . ")\n";
    }
}

function make_service(array $options = []): OrganizationsTeams
{
    return new OrganizationsTeams(new InMemoryStore(), $options);
}

function user(string $id, string $email): array
{
    return ['id' => $id, 'email' => $email];
}

// T1
// ORG-01
function test_non_member_cannot_read_members_of_another_org(): void
{
    $svc = make_service();
    $owner = user('u-owner', 'owner@example.com');
    $outsider = user('u-out', 'out@example.com');
    $alpha = $svc->create_org($owner, 'Alpha');
    $beta = $svc->create_org($outsider, 'Beta');

    $ops = [
        fn() => $svc->list_members($outsider, $alpha['id']),
        fn() => $svc->get_org($outsider, $alpha['id']),
        fn() => $svc->invite($outsider, $alpha['id'], 'x@example.com', 'member'),
        fn() => $svc->change_role($outsider, $alpha['id'], $owner['id'], 'admin'),
        fn() => $svc->remove_member($outsider, $alpha['id'], $owner['id']),
        fn() => $svc->leave_org($outsider, $alpha['id']),
    ];
    foreach ($ops as $op) {
        assert_error($op, 'ORG_NOT_FOUND', 404, 'outsider on Alpha -> ORG_NOT_FOUND');
    }

    $fake_id = 'ffffffffffffffffffffffffffffffff';
    $ops2 = [
        fn() => $svc->list_members($outsider, $fake_id),
        fn() => $svc->get_org($outsider, $fake_id),
        fn() => $svc->invite($outsider, $fake_id, 'x@example.com', 'member'),
        fn() => $svc->change_role($outsider, $fake_id, $owner['id'], 'admin'),
        fn() => $svc->remove_member($outsider, $fake_id, $owner['id']),
        fn() => $svc->leave_org($outsider, $fake_id),
    ];
    foreach ($ops2 as $op) {
        assert_error($op, 'ORG_NOT_FOUND', 404, 'outsider on fake -> ORG_NOT_FOUND');
    }

    $org = $svc->get_org($outsider, $beta['id']);
    assert_ok($org['id'] === $beta['id'], 'outsider get_org own org works');

    assert_error(fn() => $svc->list_members(user('', ''), $alpha['id']), 'UNAUTHENTICATED', 401, 'empty id -> UNAUTHENTICATED');
    assert_error(fn() => $svc->create_org(user('', ''), 'Gamma'), 'UNAUTHENTICATED', 401, 'create_org empty id -> UNAUTHENTICATED');
}

// T2
// ORG-02
function test_member_cannot_invite_admin_can(): void
{
    $svc = make_service();
    $owner = user('u-owner', 'owner@example.com');
    $org = $svc->create_org($owner, 'Test');

    $member_user = user('u-member', 'member@example.com');
    $admin_user = user('u-admin', 'admin@example.com');
    $svc->invite($owner, $org['id'], $member_user['email'], 'member');
    $svc->accept_invitation($member_user, $svc->invite($owner, $org['id'], $member_user['email'], 'member'));
    $svc->invite($owner, $org['id'], $admin_user['email'], 'admin');
    $svc->accept_invitation($admin_user, $svc->invite($owner, $org['id'], $admin_user['email'], 'admin'));

    assert_error(fn() => $svc->invite($member_user, $org['id'], 'new@example.com', 'member'), 'FORBIDDEN', 403, 'member invite -> FORBIDDEN');

    $token = $svc->invite($admin_user, $org['id'], 'new@example.com', 'member');
    assert_ok(strlen($token) === 64 && ctype_xdigit($token) && strtolower($token) === $token, 'admin invite returns 64 lowercase hex');
    $new_user = user('u-new', 'new@example.com');
    $mem = $svc->accept_invitation($new_user, $token);
    assert_ok($mem['role'] === 'member', 'accepted member role');

    assert_error(fn() => $svc->invite($admin_user, $org['id'], 'another@example.com', 'owner'), 'FORBIDDEN', 403, 'admin invite owner -> FORBIDDEN');
}

// T3
// ORG-03
function test_admin_cannot_remove_owner_and_last_owner_cannot_leave(): void
{
    $svc = make_service();
    $owner = user('u-owner', 'owner@example.com');
    $org = $svc->create_org($owner, 'Test');

    $admin_user = user('u-admin', 'admin@example.com');
    $member_user = user('u-member', 'member@example.com');
    $svc->invite($owner, $org['id'], $admin_user['email'], 'admin');
    $svc->accept_invitation($admin_user, $svc->invite($owner, $org['id'], $admin_user['email'], 'admin'));
    $svc->invite($owner, $org['id'], $member_user['email'], 'member');
    $svc->accept_invitation($member_user, $svc->invite($owner, $org['id'], $member_user['email'], 'member'));

    assert_error(fn() => $svc->remove_member($admin_user, $org['id'], $owner['id']), 'FORBIDDEN', 403, 'admin remove owner -> FORBIDDEN');
    assert_error(fn() => $svc->change_role($admin_user, $org['id'], $owner['id'], 'member'), 'FORBIDDEN', 403, 'admin demote owner -> FORBIDDEN');
    assert_error(fn() => $svc->change_role($admin_user, $org['id'], $member_user['id'], 'owner'), 'FORBIDDEN', 403, 'admin promote member to owner -> FORBIDDEN');

    $svc->remove_member($admin_user, $org['id'], $member_user['id']);
    $members = $svc->list_members($owner, $org['id']);
    assert_ok(count($members) === 2, 'member removed, 2 left');

    assert_error(fn() => $svc->leave_org($owner, $org['id']), 'LAST_OWNER', 409, 'owner leave -> LAST_OWNER');
    assert_error(fn() => $svc->change_role($owner, $org['id'], $owner['id'], 'admin'), 'LAST_OWNER', 409, 'owner demote self -> LAST_OWNER');
    assert_error(fn() => $svc->remove_member($owner, $org['id'], $owner['id']), 'LAST_OWNER', 409, 'owner remove self -> LAST_OWNER');

    $members = $svc->list_members($owner, $org['id']);
    assert_ok(count($members) === 2 && $members[0]['role'] === 'owner', 'owner still there');
}

// T4
// ORG-04
function test_invitation_works_once_second_use_fails(): void
{
    $svc = make_service();
    $owner = user('u-owner', 'owner@example.com');
    $org = $svc->create_org($owner, 'Test');

    $x_user = user('u-x', 'x@example.com');
    $token = $svc->invite($owner, $org['id'], $x_user['email'], 'member');
    $mem = $svc->accept_invitation($x_user, $token);
    assert_ok($mem['org_id'] === $org['id'] && $mem['user_id'] === 'u-x' && $mem['role'] === 'member', 'first accept ok');

    assert_error(fn() => $svc->accept_invitation($x_user, $token), 'INVITATION_USED', 410, 'second accept -> INVITATION_USED');

    $token2 = $svc->invite($owner, $org['id'], $x_user['email'], 'member');
    assert_error(fn() => $svc->accept_invitation($x_user, $token2), 'ALREADY_MEMBER', 409, 'third accept -> ALREADY_MEMBER');
}

// T5
// ORG-05
function test_expired_invitation_fails(): void
{
    $t = 1700000000;
    $clock = function () use (&$t): int { return $t; };
    $svc = make_service(['clock' => $clock]);
    $owner = user('u-owner', 'owner@example.com');
    $org = $svc->create_org($owner, 'Test');

    $x_user = user('u-x', 'x@example.com');
    $token = $svc->invite($owner, $org['id'], $x_user['email'], 'member');
    $t += 691200;
    assert_error(fn() => $svc->accept_invitation($x_user, $token), 'INVITATION_EXPIRED', 410, 'expired -> INVITATION_EXPIRED');

    $members = $svc->list_members($owner, $org['id']);
    assert_ok(count($members) === 1, 'list_members still 1 row');
}

// T6
// ORG-05
function test_accept_with_different_email_fails(): void
{
    $svc = make_service();
    $owner = user('u-owner', 'owner@example.com');
    $org = $svc->create_org($owner, 'Test');

    $token = $svc->invite($owner, $org['id'], '  X@Example.COM ', 'member');
    $z_user = user('u-z', 'z@example.com');
    assert_error(fn() => $svc->accept_invitation($z_user, $token), 'EMAIL_MISMATCH', 403, 'different email -> EMAIL_MISMATCH');

    $x_user = user('u-x', 'x@example.com');
    $mem = $svc->accept_invitation($x_user, $token);
    assert_ok($mem['role'] === 'member', 'correct email works after mismatch');
}

// T7
// ORG-06
function test_raw_token_not_stored_in_database(): void
{
    $k = 0;
    $counter = function (int $n) use (&$k): string {
        $k++;
        return str_repeat(chr($k % 256), $n);
    };
    $svc = make_service(['random_bytes' => $counter]);
    $owner = user('u-owner', 'owner@example.com');
    $org = $svc->create_org($owner, 'Test');
    assert_ok($org['id'] === str_repeat('01', 16), 'org id = 01x16');

    $token = $svc->invite($owner, $org['id'], 'x@example.com', 'member');
    assert_ok($token === str_repeat('02', 32), 'token = 02x32');

    $k = 0;
    $store = new InMemoryStore();
    $svc2 = new OrganizationsTeams($store, ['random_bytes' => $counter]);
    $org2 = $svc2->create_org($owner, 'Test');
    $token2 = $svc2->invite($owner, $org2['id'], 'x@example.com', 'member');
    $dump = $store->debug_dump();
    assert_ok(strpos($dump, $token2) === false, 'raw token not in dump');
    $expected_hash = '749f1a97ff6cd00ea46ccb3a47bb123283fe56c8fa324bea295d928f558161df';
    assert_ok(strpos($dump, $expected_hash) !== false, 'token hash in dump');
}

// E1
function test_expiry_boundary_is_exact(): void
{
    $t = 1700000000;
    $clock = function () use (&$t): int { return $t; };
    $svc = make_service(['clock' => $clock]);
    $owner = user('u-owner', 'owner@example.com');
    $org = $svc->create_org($owner, 'Test');

    $x_user = user('u-x', 'x@example.com');
    $y_user = user('u-y', 'y@example.com');
    $token1 = $svc->invite($owner, $org['id'], $x_user['email'], 'member');
    $token2 = $svc->invite($owner, $org['id'], $y_user['email'], 'member');

    $t += 604799;
    $mem = $svc->accept_invitation($x_user, $token1);
    assert_ok($mem['role'] === 'member', 'first accept ok at T0+604799');

    $t += 1; // now T0+604800
    assert_error(fn() => $svc->accept_invitation($y_user, $token2), 'INVITATION_EXPIRED', 410, 'second accept expired at T0+604800');
}

// E2
function test_change_role_and_remove_on_non_member_are_not_found(): void
{
    $svc = make_service();
    $owner = user('u-owner', 'owner@example.com');
    $org = $svc->create_org($owner, 'Test');

    assert_error(fn() => $svc->change_role($owner, $org['id'], 'u-ghost', 'admin'), 'MEMBER_NOT_FOUND', 404, 'change_role non-member -> MEMBER_NOT_FOUND');
    assert_error(fn() => $svc->remove_member($owner, $org['id'], 'u-ghost'), 'MEMBER_NOT_FOUND', 404, 'remove_member non-member -> MEMBER_NOT_FOUND');
    assert_error(fn() => $svc->change_role($owner, $org['id'], 'u-ghost', 'superuser'), 'INVALID_ROLE', 400, 'change_role invalid role -> INVALID_ROLE');
    assert_error(fn() => $svc->invite($owner, $org['id'], 'new@example.com', 'Owner'), 'INVALID_ROLE', 400, 'invite Owner role -> INVALID_ROLE');

    $members = $svc->list_members($owner, $org['id']);
    assert_ok(count($members) === 1, 'list_members still 1 row');
}

// E3
function test_second_owner_can_leave_then_last_owner_cannot(): void
{
    $svc = make_service();
    $owner = user('u-owner', 'owner@example.com');
    $org = $svc->create_org($owner, 'Test');

    $o2_user = user('u-o2', 'o2@example.com');
    $token = $svc->invite($owner, $org['id'], $o2_user['email'], 'owner');
    $svc->accept_invitation($o2_user, $token);

    assert_ok($svc->change_role($owner, $org['id'], $o2_user['id'], 'admin')['role'] === 'admin', 'change to admin ok');
    assert_ok($svc->change_role($owner, $org['id'], $o2_user['id'], 'owner')['role'] === 'owner', 'change back to owner ok');

    $svc->leave_org($owner, $org['id']);
    assert_error(fn() => $svc->get_org($owner, $org['id']), 'ORG_NOT_FOUND', 404, 'owner left -> org not found for owner');

    assert_error(fn() => $svc->leave_org($o2_user, $org['id']), 'LAST_OWNER', 409, 'last owner leave -> LAST_OWNER');
}

// E4
function test_malformed_tokens_are_not_found(): void
{
    $svc = make_service();
    $owner = user('u-owner', 'owner@example.com');
    $org = $svc->create_org($owner, 'Test');
    $x_user = user('u-x', 'x@example.com');
    $token = $svc->invite($owner, $org['id'], $x_user['email'], 'member');

    $malformed = [
        '',
        'abc',
        str_repeat('0', 63),
        str_repeat('0', 65),
        str_repeat('g', 64),
        strtoupper($token),
        $token . "\n",
    ];
    foreach ($malformed as $s) {
        assert_error(fn() => $svc->accept_invitation($x_user, $s), 'INVITATION_NOT_FOUND', 404, "malformed token '$s' -> NOT_FOUND");
    }
    assert_ok($svc->accept_invitation($x_user, $token)['role'] === 'member', 'valid token works');
}

// E5
function test_slug_is_deterministic_and_collision_gets_suffix(): void
{
    $k = 0;
    $counter = function (int $n) use (&$k): string {
        $k++;
        return str_repeat(chr($k % 256), $n);
    };
    $svc = make_service(['random_bytes' => $counter]);
    $owner = user('u-owner', 'owner@example.com');

    $org1 = $svc->create_org($owner, '  Café Bar!! ');
    assert_ok($org1['name'] === 'Café Bar!!' && $org1['slug'] === 'caf-bar' && $org1['id'] === str_repeat('01', 16), 'first org');

    $org2 = $svc->create_org($owner, '  Café Bar!! ');
    assert_ok($org2['name'] === 'Café Bar!!' && $org2['slug'] === 'caf-bar-03030303' && $org2['id'] === str_repeat('02', 16), 'second org');

    assert_error(fn() => $svc->create_org($owner, '   '), 'INVALID_NAME', 400, 'whitespace only -> INVALID_NAME');
    assert_error(fn() => $svc->create_org($owner, str_repeat('a', 201)), 'INVALID_NAME', 400, '201 chars -> INVALID_NAME');
    $ok = $svc->create_org($owner, str_repeat('a', 200));
    assert_ok(strlen($ok['name']) === 200 && $ok['slug'] === str_repeat('a', 200), '200 chars ok');
    $org3 = $svc->create_org($owner, '!!!');
    assert_ok($org3['name'] === '!!!' && $org3['slug'] === 'org', '!!! -> org');
}

// E6
function test_invitation_revoked_when_inviter_loses_rights(): void
{
    $svc = make_service();
    $owner = user('u-owner', 'owner@example.com');
    $org = $svc->create_org($owner, 'Test');

    $admin_user = user('u-admin', 'admin@example.com');
    $svc->invite($owner, $org['id'], $admin_user['email'], 'admin');
    $svc->accept_invitation($admin_user, $svc->invite($owner, $org['id'], $admin_user['email'], 'admin'));

    $x_user = user('u-x', 'x@example.com');
    $token = $svc->invite($admin_user, $org['id'], $x_user['email'], 'member');

    $svc->remove_member($owner, $org['id'], $admin_user['id']);
    assert_error(fn() => $svc->accept_invitation($x_user, $token), 'INVITATION_REVOKED', 410, 'invitation revoked -> INVITATION_REVOKED');

    $members = $svc->list_members($owner, $org['id']);
    assert_ok(count($members) === 1, 'x not listed');
}

exit($failed > 0 ? 1 : 0);