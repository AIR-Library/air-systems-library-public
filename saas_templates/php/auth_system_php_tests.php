<?php
// Tests updated with the fix 2026-10-08: the token secret comes from AUTH_JWT_SECRET (it was hard-coded), MFA codes are really
//   checked (any code was accepted), and sign-up/login limits live in the database (static arrays
//   reset on every request).
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; session c6ee9a72 (2026-11-03).
// Touches: the database, the AUTH_JWT_SECRET environment variable.
declare(strict_types=1);
require_once 'auth_system_php.php';
putenv('AUTH_JWT_SECRET=' . bin2hex(random_bytes(32)));
// In-memory database, captured e-mails and a fake OAuth provider; no network, no auth.db file (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
Database::set(new PDO('sqlite::memory:'));
$GLOBALS['sent_mail'] = [];
$GLOBALS['oauth_profiles'] = [];
AuthSystem::configure(
    null,
    function (string $to, string $subject, string $body): void { $GLOBALS['sent_mail'][] = [$to, $subject, $body]; },
    function (string $provider, string $code): array {
        if (!isset($GLOBALS['oauth_profiles'][$provider . ':' . $code])) { throw new RuntimeException('bad code'); }
        return $GLOBALS['oauth_profiles'][$provider . ':' . $code];
    }
);

class TestRunner {
    private int $passed = 0;
    private int $failed = 0;
    public function assertEqual($a, $b, $msg=''): void {
        if ($a === $b) {
            $this->passed++;
            echo "PASS: $msg\n";
        } else {
            $this->failed++;
            echo "FAIL: $msg\n";
            echo "  Expected: ".var_export($b,true)."\n";
            echo "  Got: ".var_export($a,true)."\n";
        }
    }
    public function run(): void {
        $this->testSignupHappyPath();
        $this->testSignupDuplicateEmail();
        $this->testSignupWeakPassword();
        $this->testSignupIPRateLimit();
        $this->testVerifyEmailHappyPath();
        $this->testVerifyEmailExpiredCode();
        $this->testLoginHappyPathNoMFA();
        $this->testLoginWithMFAEnabled();
        $this->testLoginInvalidPassword();
        $this->testOauthCallbackNewUser();
        $this->testOauthCallbackExistingUser();
        $this->testMfaChallengeHappyPath();
        $this->testMfaChallengeWrongCode();
        $this->testTokenRefreshHappyPath();
        $this->testTokenRefreshBannedUser();
        $this->testPasswordChecksRunInOrder();
        $this->testOauthUnverifiedEmailRejected();
        echo "\nPassed: {$this->passed}, Failed: {$this->failed}\n";
        // A failed assertion must fail the run; it used to exit 0 whatever happened (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
        exit($this->failed > 0 ? 1 : 0);
    }
    private function resetDB(): void {
        $db = Database::get();
        $db->exec('DELETE FROM users');
        $db->exec('DELETE FROM auth_attempts');
        $db->exec('DELETE FROM sessions');
        $db->exec('DELETE FROM audit_log');
        $db->exec('DELETE FROM verification_codes');
        $db->exec('DELETE FROM oauth_accounts');
        $GLOBALS['sent_mail'] = [];
        $GLOBALS['oauth_profiles'] = [];
    }
    // AUTH-01
    private function testSignupHappyPath(): void {
        $this->resetDB();
        $res = AuthSystem::signup('user@example.com','StrongPassword123456','John Doe');
        $this->assertEqual($res['status_code'],200,'signup happy path status');
        $this->assertEqual($res['body']['status'],'pending_verification','signup happy path status text');
        $row = Database::get()->query("SELECT u.status, vc.code FROM users u JOIN verification_codes vc ON vc.user_id = u.id WHERE u.email = 'user@example.com'")->fetch(PDO::FETCH_ASSOC);
        $this->assertEqual($row['status'],'unverified','signup creates an unverified user');
        // "email sent": exactly one e-mail, to the new address, carrying the stored code.
        $this->assertEqual(count($GLOBALS['sent_mail']),1,'signup sends one e-mail');
        $this->assertEqual($GLOBALS['sent_mail'][0][0],'user@example.com','e-mail goes to the new address');
        $this->assertEqual(str_contains($GLOBALS['sent_mail'][0][2], $row['code']),true,'e-mail carries the verification code');
    }
    // AUTH-02
    private function testSignupDuplicateEmail(): void {
        $this->resetDB();
        AuthSystem::signup('dup@example.com','StrongPassword123456','John');
        $res = AuthSystem::signup('dup@example.com','StrongPassword123456','John');
        $this->assertEqual($res['status_code'],409,'duplicate email status');
        $this->assertEqual($res['body']['error'],'email_already_exists','duplicate email error code');
    }
    // AUTH-03
    private function testSignupWeakPassword(): void {
        $this->resetDB();
        $res = AuthSystem::signup('weak@example.com','short','Jane');
        $this->assertEqual($res['status_code'],400,'weak password status');
        $this->assertEqual($res['body']['error'],'password_rejected','weak password error');
        // AUTH-03 as amended: the reason is part of the contract (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
        $this->assertEqual($res['body']['reason'],'too_short','weak password reason');
        $this->assertEqual(Database::get()->query('SELECT COUNT(*) FROM users')->fetchColumn(),0,'no user created for a weak password');
    }
    /**
     * AUTH-03 order: too_short, too_long, blocklisted, first failure wins; a password equal to the name or
     * email is blocklisted; a long password that merely contains the name is accepted; no composition rules.
     * Why: amended AUTH-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory database.
     */
    // AUTH-03
    private function testPasswordChecksRunInOrder(): void {
        $this->resetDB();
        $cases = [
            ['password123', 'too_short'],
            [str_repeat('a', 65), 'too_long'],
            ['Jane Q Longname Public', 'blocklisted'],
            ['order@example.com', 'blocklisted'],
        ];
        foreach ($cases as [$pwd, $reason]) {
            $res = AuthSystem::signup('order@example.com', $pwd, 'Jane Q Longname Public');
            $this->assertEqual([$res['status_code'], $res['body']['error'] ?? null, $res['body']['reason'] ?? null], [400, 'password_rejected', $reason], "password '$pwd' -> $reason");
        }
        $this->assertEqual(AuthSystem::passwordRejection('correcthorsebatterystaple', 'a@b.c', 'Jane'), null, 'all-lowercase long password accepted (no composition rules)');
        $this->assertEqual(AuthSystem::passwordRejection('jane likes long passphrases', 'a@b.c', 'Jane'), null, 'containing the name is not equal to it');
        $this->assertEqual(AuthSystem::passwordRejection('a perfectly fine passphrase', 'a@b.c', ''), null, 'an empty name does not reject everything');
    }
    // AUTH-04
    private function testSignupIPRateLimit(): void {
        $this->resetDB();
        for ($i=0;$i<5;$i++) {
            AuthSystem::signup("ip{$i}@example.com",'StrongPassword123456','Name');
        }
        $res = AuthSystem::signup('ip6@example.com','StrongPassword123456','Name');
        $this->assertEqual($res['status_code'],429,'IP rate limit status');
        $this->assertEqual($res['body']['error'],'too_many_signups_from_ip','IP rate limit error');
    }
    // AUTH-05
    private function testVerifyEmailHappyPath(): void {
        $this->resetDB();
        $signup = AuthSystem::signup('verify@example.com','StrongPassword123456','Name');
        $db = Database::get();
        $stmt = $db->prepare('SELECT code FROM verification_codes WHERE type=\'email\'');
        $stmt->execute();
        $code = $stmt->fetchColumn();
        $res = AuthSystem::verify_email('verify@example.com',$code);
        $this->assertEqual($res['status_code'],200,'verify email status');
        $this->assertEqual($res['body']['status'],'verified','verify email status text');
        $this->assertEqual($db->query("SELECT status FROM users WHERE email='verify@example.com'")->fetchColumn(),'verified','user status is verified');
    }
    // AUTH-06
    private function testVerifyEmailExpiredCode(): void {
        $this->resetDB();
        $signup = AuthSystem::signup('expire@example.com','StrongPassword123456','Name');
        $db = Database::get();
        $stmt = $db->prepare('SELECT id, code FROM verification_codes WHERE type=\'email\'');
        $stmt->execute();
        [$id, $code] = $stmt->fetch(PDO::FETCH_NUM);
        // Expire it
        $stmt = $db->prepare('UPDATE verification_codes SET expires_at=? WHERE id=?');
        $stmt->execute([gmdate('c', time()-10),$id]);
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the test sent a wrong code ('dummy') and expected code_invalid, so it never
        // tested expiry; AUTH-06 sends the real, expired code and expects code_expired.
        $res = AuthSystem::verify_email('expire@example.com',$code);
        $this->assertEqual($res['status_code'],400,'expired code status');
        $this->assertEqual($res['body']['error'],'code_expired','expired code error');
        $res = AuthSystem::verify_email('expire@example.com','dummy');
        $this->assertEqual($res['body']['error'],'code_invalid','wrong code error');
        $this->assertEqual($db->query("SELECT email_verified_at FROM users WHERE email='expire@example.com'")->fetchColumn(),null,'user still unverified');
    }
    // AUTH-07
    private function testLoginHappyPathNoMFA(): void {
        $this->resetDB();
        AuthSystem::signup('login@example.com','StrongPassword123456','Name');
        $db = Database::get();
        $stmt = $db->prepare('SELECT id FROM users');
        $stmt->execute();
        $userId = $stmt->fetchColumn();
        // Verify email
        $stmt = $db->prepare('UPDATE users SET email_verified_at=? WHERE id=?');
        $stmt->execute([AuthSystem::now(),$userId]);
        $res = AuthSystem::login('login@example.com','StrongPassword123456','device1','127.0.0.1');
        $this->assertEqual($res['status_code'],200,'login status');
        $this->assertEqual($res['body']['status'],'authenticated','login status text');
    }
    // AUTH-08
    private function testLoginWithMFAEnabled(): void {
        $this->resetDB();
        AuthSystem::signup('mfa@example.com','StrongPassword123456','Name');
        $db = Database::get();
        $stmt = $db->prepare('SELECT id FROM users');
        $stmt->execute();
        $userId = $stmt->fetchColumn();
        // Verify email
        $stmt = $db->prepare('UPDATE users SET email_verified_at=?,mfa_enabled=1,mfa_secret=? WHERE id=?');
        $secret = 'JBSWY3DPEHPK3PXP'; // base32
        $stmt->execute([AuthSystem::now(),$secret,$userId]);
        $res = AuthSystem::login('mfa@example.com','StrongPassword123456','device1','127.0.0.1');
        $this->assertEqual($res['status_code'],202,'mfa required status');
        $this->assertEqual($res['body']['status'],'mfa_required','mfa required text');
    }
    // AUTH-09
    private function testLoginInvalidPassword(): void {
        $this->resetDB();
        AuthSystem::signup('badpass@example.com','StrongPassword123456','Name');
        $db = Database::get();
        $stmt = $db->prepare('SELECT id FROM users');
        $stmt->execute();
        $userId = $stmt->fetchColumn();
        $stmt = $db->prepare('UPDATE users SET email_verified_at=? WHERE id=?');
        $stmt->execute([AuthSystem::now(),$userId]);
        $res = AuthSystem::login('badpass@example.com','WrongPassword','device1','127.0.0.1');
        $this->assertEqual($res['status_code'],401,'invalid password status');
        $this->assertEqual($res['body']['error'],'invalid_credentials','invalid password error');
    }
    // AUTH-10
    private function testOauthCallbackNewUser(): void {
        $this->resetDB();
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the code is exchanged with the (fake) provider; it used to be read as the
        // e-mail itself, so the test passed an e-mail where the provider's code goes.
        $GLOBALS['oauth_profiles']['google:code-new'] = ['id' => 'g-111', 'email' => 'newuser@example.com', 'email_verified' => true];
        $res = AuthSystem::oauth_callback('google','code-new','state123');
        $this->assertEqual($res['status_code'],200,'oauth new user status');
        $this->assertEqual($res['body']['status'],'authenticated','oauth new user status text');
        $db = Database::get();
        $user = $db->query("SELECT id, status FROM users WHERE email='newuser@example.com'")->fetch(PDO::FETCH_ASSOC);
        $this->assertEqual($user['status'],'verified','oauth new user is created verified');
        $link = $db->query("SELECT user_id, provider, provider_user_id FROM oauth_accounts")->fetchAll(PDO::FETCH_ASSOC);
        $this->assertEqual($link,[['user_id'=>$user['id'],'provider'=>'google','provider_user_id'=>'g-111']],'oauth account linked to the new user');
    }
    /**
     * oauth_callback refuses a provider profile whose e-mail is not verified and a code the provider rejects,
     * creating no user. Why: auth_system.md gate email_verified_by_provider. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the in-memory database.
     */
    private function testOauthUnverifiedEmailRejected(): void {
        $this->resetDB();
        $GLOBALS['oauth_profiles']['google:code-unv'] = ['id' => 'g-222', 'email' => 'victim@example.com', 'email_verified' => false];
        $res = AuthSystem::oauth_callback('google','code-unv','state123');
        $this->assertEqual([$res['status_code'],$res['body']['error']],[400,'email_not_verified'],'unverified provider e-mail rejected');
        $res = AuthSystem::oauth_callback('google','victim@example.com','state123');
        $this->assertEqual([$res['status_code'],$res['body']['error']],[401,'oauth_failed'],'an e-mail passed as the code is not trusted');
        $this->assertEqual(Database::get()->query('SELECT COUNT(*) FROM users')->fetchColumn(),0,'no user created');
    }
    // AUTH-11
    private function testOauthCallbackExistingUser(): void {
        $this->resetDB();
        AuthSystem::signup('exist@example.com','StrongPassword123456','Name');
        $db = Database::get();
        $stmt = $db->prepare('SELECT id FROM users');
        $stmt->execute();
        $userId = $stmt->fetchColumn();
        $stmt = $db->prepare('UPDATE users SET email_verified_at=? WHERE id=?');
        $stmt->execute([AuthSystem::now(),$userId]);
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the provider (fake) returns the e-mail; the code is no longer the e-mail.
        $GLOBALS['oauth_profiles']['google:code-exist'] = ['id' => 'g-333', 'email' => 'exist@example.com', 'email_verified' => true];
        $res = AuthSystem::oauth_callback('google','code-exist','state123');
        $this->assertEqual($res['status_code'],200,'oauth existing user status');
        $this->assertEqual($res['body']['status'],'authenticated','oauth existing user status text');
        $this->assertEqual($res['body']['user']['id'],(int)$userId,'oauth signs in the existing account');
        $this->assertEqual($db->query('SELECT COUNT(*) FROM users')->fetchColumn(),1,'no second user created');
        $this->assertEqual($db->query('SELECT user_id FROM oauth_accounts WHERE provider_user_id = \'g-333\'')->fetchColumn(),$userId,'oauth linked to the existing account');
    }
    // AUTH-12
    private function testMfaChallengeHappyPath(): void {
        $this->resetDB();
        AuthSystem::signup('mfa2@example.com','StrongPassword123456','Name');
        $db = Database::get();
        $stmt = $db->prepare('SELECT id FROM users');
        $stmt->execute();
        $userId = $stmt->fetchColumn();
        $stmt = $db->prepare('UPDATE users SET email_verified_at=?,mfa_enabled=1,mfa_secret=? WHERE id=?');
        $secret = 'JBSWY3DPEHPK3PXP';
        $stmt->execute([AuthSystem::now(),$secret,$userId]);
        // Create challenge
        $challenge_id = AuthSystem::randomString(32);
        $expires = gmdate('c', time()+300);
        $stmt = $db->prepare('INSERT INTO verification_codes (id,user_id,code,created_at,expires_at,type) VALUES (?,?,?,?,?,?)');
        $stmt->execute([$challenge_id,$userId,null,AuthSystem::now(),$expires,'mfa']);
        $code = AuthSystem::totp($secret);
        $res = AuthSystem::mfa_challenge($challenge_id,$code);
        $this->assertEqual($res['status_code'],200,'mfa challenge status');
        $this->assertEqual($res['body']['status'],'authenticated','mfa challenge status text');
    }
    // AUTH-13
    private function testMfaChallengeWrongCode(): void {
        $this->resetDB();
        AuthSystem::signup('mfa3@example.com','StrongPassword123456','Name');
        $db = Database::get();
        $stmt = $db->prepare('SELECT id FROM users');
        $stmt->execute();
        $userId = $stmt->fetchColumn();
        $stmt = $db->prepare('UPDATE users SET email_verified_at=?,mfa_enabled=1,mfa_secret=? WHERE id=?');
        $secret = 'JBSWY3DPEHPK3PXP';
        $stmt->execute([AuthSystem::now(),$secret,$userId]);
        $challenge_id = AuthSystem::randomString(32);
        $expires = gmdate('c', time()+300);
        $stmt = $db->prepare('INSERT INTO verification_codes (id,user_id,code,created_at,expires_at,type) VALUES (?,?,?,?,?,?)');
        $stmt->execute([$challenge_id,$userId,null,AuthSystem::now(),$expires,'mfa']);
        $res = AuthSystem::mfa_challenge($challenge_id,'000000');
        $this->assertEqual($res['status_code'],401,'mfa wrong code status');
        $this->assertEqual($res['body']['error'],'invalid_code','mfa wrong code error');
    }
    // AUTH-14
    private function testTokenRefreshHappyPath(): void {
        $this->resetDB();
        AuthSystem::signup('refresh@example.com','StrongPassword123456','Name');
        $db = Database::get();
        $stmt = $db->prepare('SELECT id FROM users');
        $stmt->execute();
        $userId = $stmt->fetchColumn();
        $stmt = $db->prepare('UPDATE users SET email_verified_at=? WHERE id=?');
        $stmt->execute([AuthSystem::now(),$userId]);
        $login = AuthSystem::login('refresh@example.com','StrongPassword123456','device1','127.0.0.1');
        $session_id = $login['body']['session_id'];
        $stmt = $db->prepare('SELECT refresh_token FROM sessions WHERE id=?');
        $stmt->execute([$session_id]);
        $refresh = $stmt->fetchColumn();
        $res = AuthSystem::token_refresh($refresh);
        $this->assertEqual($res['status_code'],200,'token refresh status');
        $this->assertEqual($res['body']['status'],'ok','token refresh status text');
    }
    // AUTH-15
    private function testTokenRefreshBannedUser(): void {
        $this->resetDB();
        AuthSystem::signup('ban@example.com','StrongPassword123456','Name');
        $db = Database::get();
        $stmt = $db->prepare('SELECT id FROM users');
        $stmt->execute();
        $userId = $stmt->fetchColumn();
        $stmt = $db->prepare('UPDATE users SET email_verified_at=?,status=\'banned\' WHERE id=?');
        $stmt->execute([AuthSystem::now(),$userId]);
        $login = AuthSystem::login('ban@example.com','StrongPassword123456','device1','127.0.0.1');
        $session_id = $login['body']['session_id'];
        $stmt = $db->prepare('SELECT refresh_token FROM sessions WHERE id=?');
        $stmt->execute([$session_id]);
        $refresh = $stmt->fetchColumn();
        $res = AuthSystem::token_refresh($refresh);
        $this->assertEqual($res['status_code'],403,'token refresh banned status');
        $this->assertEqual($res['body']['error'],'user_banned','token refresh banned error');
    }
}
$runner = new TestRunner();
$runner->run();
?>