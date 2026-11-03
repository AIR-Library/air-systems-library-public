<?php
// Tests updated with the fix 2026-10-08: the token secret comes from AUTH_JWT_SECRET (it was hard-coded), MFA codes are really
//   checked (any code was accepted), and sign-up/login limits live in the database (static arrays
//   reset on every request).
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; session c6ee9a72 (2026-11-03).
// Touches: the database, the AUTH_JWT_SECRET environment variable.
declare(strict_types=1);
require_once 'auth_system_php.php';
putenv('AUTH_JWT_SECRET=' . bin2hex(random_bytes(32)));

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
        echo "\nPassed: {$this->passed}, Failed: {$this->failed}\n";
    }
    private function resetDB(): void {
        $db = Database::get();
        $db->exec('DELETE FROM users');
        $db->exec('DELETE FROM auth_attempts');
        $db->exec('DELETE FROM sessions');
        $db->exec('DELETE FROM audit_log');
        $db->exec('DELETE FROM verification_codes');
    }
    private function testSignupHappyPath(): void {
        $this->resetDB();
        $res = AuthSystem::signup('user@example.com','StrongPassword123456','John Doe');
        $this->assertEqual($res['status_code'],200,'signup happy path status');
        $this->assertEqual($res['body']['status'],'pending_verification','signup happy path status text');
    }
    private function testSignupDuplicateEmail(): void {
        $this->resetDB();
        AuthSystem::signup('dup@example.com','StrongPassword123456','John');
        $res = AuthSystem::signup('dup@example.com','StrongPassword123456','John');
        $this->assertEqual($res['status_code'],409,'duplicate email status');
        $this->assertEqual($res['body']['error'],'email_already_exists','duplicate email error code');
    }
    private function testSignupWeakPassword(): void {
        $this->resetDB();
        $res = AuthSystem::signup('weak@example.com','short','Jane');
        $this->assertEqual($res['status_code'],400,'weak password status');
        $this->assertEqual($res['body']['error'],'password_rejected','weak password error');
    }
    private function testSignupIPRateLimit(): void {
        $this->resetDB();
        for ($i=0;$i<5;$i++) {
            AuthSystem::signup("ip{$i}@example.com",'StrongPassword123456','Name');
        }
        $res = AuthSystem::signup('ip6@example.com','StrongPassword123456','Name');
        $this->assertEqual($res['status_code'],429,'IP rate limit status');
        $this->assertEqual($res['body']['error'],'too_many_signups_from_ip','IP rate limit error');
    }
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
    }
    private function testVerifyEmailExpiredCode(): void {
        $this->resetDB();
        $signup = AuthSystem::signup('expire@example.com','StrongPassword123456','Name');
        $db = Database::get();
        $stmt = $db->prepare('SELECT id FROM verification_codes WHERE type=\'email\'');
        $stmt->execute();
        $id = $stmt->fetchColumn();
        // Expire it
        $stmt = $db->prepare('UPDATE verification_codes SET expires_at=? WHERE id=?');
        $stmt->execute([gmdate('c', time()-10),$id]);
        $res = AuthSystem::verify_email('expire@example.com','dummy');
        $this->assertEqual($res['status_code'],400,'expired code status');
        $this->assertEqual($res['body']['error'],'code_invalid','expired code error');
    }
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
    private function testOauthCallbackNewUser(): void {
        $this->resetDB();
        $res = AuthSystem::oauth_callback('google','newuser@example.com','state123');
        $this->assertEqual($res['status_code'],200,'oauth new user status');
        $this->assertEqual($res['body']['status'],'authenticated','oauth new user status text');
    }
    private function testOauthCallbackExistingUser(): void {
        $this->resetDB();
        AuthSystem::signup('exist@example.com','StrongPassword123456','Name');
        $db = Database::get();
        $stmt = $db->prepare('SELECT id FROM users');
        $stmt->execute();
        $userId = $stmt->fetchColumn();
        $stmt = $db->prepare('UPDATE users SET email_verified_at=? WHERE id=?');
        $stmt->execute([AuthSystem::now(),$userId]);
        $res = AuthSystem::oauth_callback('google','exist@example.com','state123');
        $this->assertEqual($res['status_code'],200,'oauth existing user status');
        $this->assertEqual($res['body']['status'],'authenticated','oauth existing user status text');
    }
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