<?php
// Tests updated with the fix 2026-10-08: the token secret comes from AUTH_JWT_SECRET (it was hard-coded), MFA codes are really
//   checked (any code was accepted), and sign-up/login limits live in the database (static arrays
//   reset on every request).
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; session c6ee9a72 (2026-11-03).
// Touches: the database, the AUTH_JWT_SECRET environment variable.
// Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.2, AUTH-16 and "Secrets at rest"): the database holds only
//   hashes of verification codes and refresh tokens, so the tests take the code from the e-mail and the refresh token
//   from login's response (they read both from the database); OAuth tests get a state from oauth_start() (any state
//   was accepted); MFA challenge rows name the column code_hash. Each changed test says so.
declare(strict_types=1);
require_once 'auth_system_php.php';
putenv('AUTH_JWT_SECRET=' . bin2hex(random_bytes(32)));
// Fixed 32+ byte HMAC key for stored secrets (spec d270fa3: tests pass a fixed test key). 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP.
const TEST_SECRET_KEY = 'test-secret-key-0123456789abcdef-auth';
putenv('AUTH_SECRET_KEY=' . TEST_SECRET_KEY);
/**
 * The value the module stores for a secret: lowercase hex HMAC-SHA256(TEST_SECRET_KEY, $value).
 * Input: the secret. Output: 64 hex characters. Why: spec d270fa3: keyed HMAC for stored secrets; the tests computed
 * a plain SHA-256 here until 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function storedHash(string $value): string { return hash_hmac('sha256', $value, TEST_SECRET_KEY); }
/**
 * Plain, unkeyed SHA-256 hex of a secret, which the module must no longer store. Input: the secret. Output: 64 hex
 * characters. Why: spec d270fa3: keyed HMAC for stored secrets (AUTH-16 asserts the stored value is not this).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function plainSha256(string $value): string { return hash('sha256', $value); }
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
        $this->testRefreshTokensAndCodesStoredOnlyAsHashes();
        $this->testEveryFlowThatCreatesASessionReturnsARefreshToken();
        $this->testOauthStateIsSingleUseAndExpires();
        $this->testServiceRefusesToStartWithoutSecretKey();
        $this->testFiveWrongVerificationCodesInvalidateTheCode();
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
        $db->exec('DELETE FROM oauth_states');
        $GLOBALS['sent_mail'] = [];
        $GLOBALS['oauth_profiles'] = [];
    }
    /**
     * The verification code from the last e-mail sent (the database keeps only its hash). Input: none. Output: the
     * code. Why: AUTH-16 (codes stored only as code_hash). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private function mailedCode(): string {
        $last = end($GLOBALS['sent_mail']);
        preg_match('/Your code: ([0-9a-f]+)/', (string)($last[2] ?? ''), $m);
        return $m[1] ?? '';
    }
    /**
     * A fresh OAuth state from oauth_start() for $provider. Why: the callback accepts only a state it issued
     * (Phase B.2). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory database (oauth_states).
     */
    private function oauthState(string $provider = 'google'): string {
        return AuthSystem::oauth_start($provider)['body']['state'];
    }
    /**
     * Sign up, mark the e-mail verified and return the user id. Why: shared set-up of the AUTH-16 tests.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory database.
     */
    private function verifiedUser(string $email): int {
        AuthSystem::signup($email,'StrongPassword123456','Name');
        $db = Database::get();
        $stmt = $db->prepare('SELECT id FROM users WHERE email=?');
        $stmt->execute([$email]);
        $userId = (int)$stmt->fetchColumn();
        $db->prepare('UPDATE users SET email_verified_at=? WHERE id=?')->execute([AuthSystem::now(),$userId]);
        return $userId;
    }
    // AUTH-01
    private function testSignupHappyPath(): void {
        $this->resetDB();
        $res = AuthSystem::signup('user@example.com','StrongPassword123456','John Doe');
        $this->assertEqual($res['status_code'],200,'signup happy path status');
        $this->assertEqual($res['body']['status'],'pending_verification','signup happy path status text');
        $row = Database::get()->query("SELECT u.status, vc.code_hash FROM users u JOIN verification_codes vc ON vc.user_id = u.id WHERE u.email = 'user@example.com'")->fetch(PDO::FETCH_ASSOC);
        $this->assertEqual($row['status'],'unverified','signup creates an unverified user');
        // "email sent": exactly one e-mail, to the new address, carrying the stored code. The database keeps only
        // the code's hash since 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2), so the mailed code is checked
        // against code_hash (the test read the plain code column). Since spec d270fa3 (2026-11-10,
        // session_012zDydZCZ4AChqhEZ4oVtaP) code_hash is the keyed HMAC, not a plain SHA-256.
        $this->assertEqual(count($GLOBALS['sent_mail']),1,'signup sends one e-mail');
        $this->assertEqual($GLOBALS['sent_mail'][0][0],'user@example.com','e-mail goes to the new address');
        $this->assertEqual(storedHash($this->mailedCode()),$row['code_hash'],'e-mail carries the verification code');
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
        // The code comes from the e-mail; the database keeps only its hash (Phase B.2, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
        $code = $this->mailedCode();
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
        // The code comes from the e-mail; the database keeps only its hash (Phase B.2, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
        $id = $db->query('SELECT id FROM verification_codes WHERE type=\'email\'')->fetchColumn();
        $code = $this->mailedCode();
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
        // The state comes from oauth_start() since 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2; 'state123' was accepted).
        $res = AuthSystem::oauth_callback('google','code-new',$this->oauthState());
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
        // Each callback gets a fresh state from oauth_start() (Phase B.2, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
        $res = AuthSystem::oauth_callback('google','code-unv',$this->oauthState());
        $this->assertEqual([$res['status_code'],$res['body']['error']],[400,'email_not_verified'],'unverified provider e-mail rejected');
        $res = AuthSystem::oauth_callback('google','victim@example.com',$this->oauthState());
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
        // The state comes from oauth_start() (Phase B.2, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
        $res = AuthSystem::oauth_callback('google','code-exist',$this->oauthState());
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
        // The column is code_hash since 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2); an MFA challenge stores none.
        $stmt = $db->prepare('INSERT INTO verification_codes (id,user_id,code_hash,created_at,expires_at,type) VALUES (?,?,?,?,?,?)');
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
        // The column is code_hash since 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2); an MFA challenge stores none.
        $stmt = $db->prepare('INSERT INTO verification_codes (id,user_id,code_hash,created_at,expires_at,type) VALUES (?,?,?,?,?,?)');
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
        // The refresh token comes from login's response; the database keeps only its hash (Phase B.2, AUTH-16,
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP; the test read sessions.refresh_token).
        $refresh = $login['body']['refresh_token'];
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
        // The refresh token comes from login's response (Phase B.2, AUTH-16, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
        $refresh = $login['body']['refresh_token'];
        $res = AuthSystem::token_refresh($refresh);
        $this->assertEqual($res['status_code'],403,'token refresh banned status');
        $this->assertEqual($res['body']['error'],'user_banned','token refresh banned error');
    }
    /**
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec d270fa3: keyed HMAC for stored secrets): each stored
     * value must equal HMAC-SHA256(TEST_SECRET_KEY, value) and must not equal its plain SHA-256.
     * AUTH-16: login returns a refresh_token that token_refresh accepts; the sessions table holds only its SHA-256
     * (no column holds the token), and the e-mail verification code is stored only as its hash. A token made of the
     * stored hash is refused. Input: the in-memory database. Output: assertions.
     * Why: auth_system.md AUTH-16 and "Secrets at rest" (Phase B.2). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the in-memory database.
     */
    // AUTH-16
    private function testRefreshTokensAndCodesStoredOnlyAsHashes(): void {
        $this->resetDB();
        $db = Database::get();
        AuthSystem::signup('hash@example.com','StrongPassword123456','Name');
        $code = $this->mailedCode();
        $this->assertEqual(strlen($code) >= 32, true, 'a verification code was mailed');
        $codes = json_encode($db->query('SELECT * FROM verification_codes')->fetchAll(PDO::FETCH_ASSOC));
        $this->assertEqual(str_contains($codes, $code), false, 'the code is not stored');
        $this->assertEqual($db->query("SELECT code_hash FROM verification_codes WHERE type='email'")->fetchColumn(), storedHash($code), 'code_hash = HMAC-SHA256(test key, code)');
        // spec d270fa3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): keyed, so not the code's plain SHA-256.
        $this->assertEqual($db->query("SELECT code_hash FROM verification_codes WHERE type='email'")->fetchColumn() !== plainSha256($code), true, 'code_hash is not the plain SHA-256 of the code');
        $this->assertEqual(AuthSystem::verify_email('hash@example.com', storedHash($code))['body']['error'] ?? null, 'code_invalid', 'the stored hash is not a usable code');
        $this->assertEqual(AuthSystem::verify_email('hash@example.com', $code)['status_code'], 200, 'the mailed code verifies');

        $login = AuthSystem::login('hash@example.com','StrongPassword123456','device1','127.0.0.1');
        $refresh = $login['body']['refresh_token'] ?? '';
        $this->assertEqual(preg_match('/^[0-9a-f]{64}$/', $refresh), 1, 'login returns a refresh_token');
        $columns = array_column($db->query('PRAGMA table_info(sessions)')->fetchAll(PDO::FETCH_ASSOC), 'name');
        $this->assertEqual(in_array('refresh_token', $columns, true), false, 'sessions has no refresh_token column');
        $sessions = $db->query('SELECT * FROM sessions')->fetchAll(PDO::FETCH_ASSOC);
        $this->assertEqual(str_contains(json_encode($sessions), $refresh), false, 'the token is not stored');
        $this->assertEqual($sessions[0]['refresh_token_hash'], storedHash($refresh), 'refresh_token_hash = HMAC-SHA256(test key, token)');
        $this->assertEqual($sessions[0]['refresh_token_hash'] !== plainSha256($refresh), true, 'refresh_token_hash is not the plain SHA-256 of the token');
        $res = AuthSystem::token_refresh($refresh);
        $this->assertEqual([$res['status_code'], $res['body']['status']], [200, 'ok'], 'token_refresh accepts the returned token');
        $this->assertEqual(AuthSystem::verify_access_token($res['body']['token'])['status_code'], 200, 'the new access token verifies');
        $this->assertEqual(AuthSystem::token_refresh($sessions[0]['refresh_token_hash'])['body']['error'] ?? null, 'invalid_token', 'the stored hash is not a usable token');
    }
    /**
     * AUTH-16: every flow that creates a session (login, MFA challenge, OAuth callback) returns a refresh_token that
     * token_refresh accepts, and each session row stores only its hash (its keyed HMAC since spec d270fa3, 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP). Input: the in-memory database and the fake
     * provider. Output: assertions. Why: auth_system.md login amendment (Phase B.2). 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory database.
     */
    // AUTH-16
    private function testEveryFlowThatCreatesASessionReturnsARefreshToken(): void {
        $this->resetDB();
        $db = Database::get();
        $userId = $this->verifiedUser('flows@example.com');
        $secret = 'JBSWY3DPEHPK3PXP';
        $db->prepare('UPDATE users SET mfa_enabled=1, mfa_secret=? WHERE id=?')->execute([$secret, $userId]);
        $challenge = AuthSystem::login('flows@example.com','StrongPassword123456','device1','127.0.0.1');
        $this->assertEqual($challenge['status_code'], 202, 'MFA user gets a challenge');
        $mfa = AuthSystem::mfa_challenge($challenge['body']['challenge_id'], AuthSystem::totp($secret));
        $GLOBALS['oauth_profiles']['github:code-flows'] = ['id' => 'gh-1', 'email' => 'flows@example.com', 'email_verified' => true];
        $oauth = AuthSystem::oauth_callback('github', 'code-flows', $this->oauthState('github'));
        foreach (['mfa_challenge' => $mfa, 'oauth_callback' => $oauth] as $flow => $res) {
            $this->assertEqual($res['status_code'], 200, "$flow authenticated");
            $token = $res['body']['refresh_token'] ?? '';
            $this->assertEqual((int)$db->query("SELECT COUNT(*) FROM sessions WHERE refresh_token_hash = '" . storedHash($token) . "'")->fetchColumn(), 1, "$flow stored the token's hash");
            $this->assertEqual(AuthSystem::token_refresh($token)['status_code'], 200, "$flow refresh_token accepted by token_refresh");
        }
        $this->assertEqual($mfa['body']['refresh_token'] !== $oauth['body']['refresh_token'], true, 'each session has its own token');
    }
    /**
     * OAuth state (auth_system.md "Secrets at rest", Phase B.2): oauth_start() issues a state stored only as its
     * SHA-256; the callback accepts it once, only for the provider it was issued for, and only within 10 minutes;
     * a made-up state is refused before the provider is asked; the provider's code is exchanged through the injected
     * client, never used as an identity. Input: the in-memory database, a settable clock and the fake provider.
     * Output: assertions. Why: AUTH-10/11 gate state_valid. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the in-memory database; the clock is restored afterwards. Changed 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP (spec d270fa3): the stored state is its HMAC-SHA256 under the test key.
     */
    // AUTH-10
    private function testOauthStateIsSingleUseAndExpires(): void {
        $this->resetDB();
        $db = Database::get();
        $GLOBALS['oauth_profiles']['google:code-s'] = ['id' => 'g-s', 'email' => 'state@example.com', 'email_verified' => true];
        $exchanges = 0;
        $GLOBALS['clock_now'] = 1_800_000_000;
        AuthSystem::configure(
            fn(): int => $GLOBALS['clock_now'],
            function (string $to, string $subject, string $body): void { $GLOBALS['sent_mail'][] = [$to, $subject, $body]; },
            function (string $provider, string $code) use (&$exchanges): array {
                $exchanges++;
                if (!isset($GLOBALS['oauth_profiles'][$provider . ':' . $code])) { throw new RuntimeException('bad code'); }
                return $GLOBALS['oauth_profiles'][$provider . ':' . $code];
            }
        );
        try {
            $start = AuthSystem::oauth_start('google');
            $state = $start['body']['state'];
            $this->assertEqual([$start['status_code'], $start['body']['expires_in'], strlen($state)], [200, 600, 64], 'oauth_start issues a 10-minute state');
            $this->assertEqual($db->query('SELECT state_hash FROM oauth_states')->fetchColumn(), storedHash($state), 'only the state hash is stored');
            $this->assertEqual(storedHash($state) !== plainSha256($state), true, 'the stored state hash is keyed, not a plain SHA-256');
            $bad = AuthSystem::oauth_callback('google', 'code-s', 'made-up-state');
            $this->assertEqual([$bad['status_code'], $bad['body']['error']], [400, 'invalid_state'], 'a state oauth_start never issued is refused');
            $this->assertEqual(AuthSystem::oauth_callback('github', 'code-s', $state)['body']['error'] ?? null, 'invalid_state', 'a state is bound to its provider');
            $this->assertEqual($exchanges, 0, 'no code exchange before the state is valid');

            $state = $this->oauthState();
            $ok = AuthSystem::oauth_callback('google', 'code-s', $state);
            $this->assertEqual([$ok['status_code'], $exchanges], [200, 1], 'a fresh state works once; the code is exchanged through the client');
            $again = AuthSystem::oauth_callback('google', 'code-s', $state);
            $this->assertEqual([$again['status_code'], $again['body']['error'], $exchanges], [400, 'invalid_state', 1], 'a used state is refused');

            $late = $this->oauthState();
            $GLOBALS['clock_now'] += 600;
            $this->assertEqual(AuthSystem::oauth_callback('google', 'code-s', $late)['body']['error'] ?? null, 'invalid_state', 'a state 10 minutes old is refused');
            $inTime = $this->oauthState();
            $GLOBALS['clock_now'] += 599;
            $this->assertEqual(AuthSystem::oauth_callback('google', 'code-s', $inTime)['status_code'], 200, 'a state under 10 minutes old works');
            $this->assertEqual((int)$db->query('SELECT COUNT(*) FROM users')->fetchColumn(), 1, 'one user, from the provider profile');
        } finally {
            AuthSystem::configure(
                null,
                function (string $to, string $subject, string $body): void { $GLOBALS['sent_mail'][] = [$to, $subject, $body]; },
                function (string $provider, string $code): array {
                    if (!isset($GLOBALS['oauth_profiles'][$provider . ':' . $code])) { throw new RuntimeException('bad code'); }
                    return $GLOBALS['oauth_profiles'][$provider . ':' . $code];
                }
            );
        }
    }
    /**
     * AUTH-16: the service refuses to start without a 32-byte key: configure() and secretHash() throw
     * RuntimeException when AUTH_SECRET_KEY is unset, empty or 31 bytes, and work again with the test key.
     * Input: the AUTH_SECRET_KEY environment variable. Output: assertions. Why: spec d270fa3: keyed HMAC for stored
     * secrets ("the service refuses to start without it"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the AUTH_SECRET_KEY environment variable (restored to the test key afterwards).
     */
    // AUTH-16
    private function testServiceRefusesToStartWithoutSecretKey(): void {
        try {
            foreach (['unset' => false, 'empty' => '', '31 bytes' => str_repeat('k', 31)] as $label => $value) {
                putenv($value === false ? 'AUTH_SECRET_KEY' : 'AUTH_SECRET_KEY=' . $value);
                foreach (['configure' => fn() => AuthSystem::configure(), 'secretHash' => fn() => AuthSystem::secretHash('123456')] as $call => $fn) {
                    $refused = false;
                    try { $fn(); } catch (RuntimeException $e) { $refused = str_contains($e->getMessage(), 'AUTH_SECRET_KEY'); }
                    $this->assertEqual($refused, true, "$call refuses with AUTH_SECRET_KEY $label");
                }
            }
        } finally {
            putenv('AUTH_SECRET_KEY=' . TEST_SECRET_KEY);
        }
        $this->assertEqual(AuthSystem::secretHash('123456'), storedHash('123456'), 'with a 32-byte key the stored hash is HMAC-SHA256(key, value)');
        $this->assertEqual(AuthSystem::secretHash('123456') !== plainSha256('123456'), true, 'and not the plain SHA-256');
    }
    /**
     * verify_email attempts (auth_system.md flow 2, Phase B.3): 5 wrong codes for one user invalidate that user's
     * current code, so the right code then gets 400 code_invalid and the user stays unverified; with 4 wrong codes
     * the right one, the 5th try, still verifies; another user's wrong codes never count against this one.
     * Input: none. Output: assertions. Why: the Phase B.3 ruling (a 6-digit code must not be guessable by
     * retrying). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory database.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.4 ruling af92d76): tagged AUTH-17, the id the
     * ruling gave this rule, and it now also shows that a newly sent code (a fresh row, stored as its HMAC as signup
     * stores one) verifies the user after the old code was invalidated. Nothing it asserted before changed.
     */
    // AUTH-17
    private function testFiveWrongVerificationCodesInvalidateTheCode(): void {
        $this->resetDB();
        $db = Database::get();
        AuthSystem::signup('guess@example.com','StrongPassword123456','Name');
        $code = $this->mailedCode();
        for ($i = 1; $i <= 5; $i++) {
            $res = AuthSystem::verify_email('guess@example.com', 'wrong' . $i);
            $this->assertEqual([$res['status_code'], $res['body']['error'] ?? null], [400, 'code_invalid'], "wrong code $i");
        }
        $res = AuthSystem::verify_email('guess@example.com', $code);
        $this->assertEqual([$res['status_code'], $res['body']['error'] ?? null], [400, 'code_invalid'], 'the right code after 5 wrong ones is refused');
        $this->assertEqual($db->query("SELECT email_verified_at FROM users WHERE email='guess@example.com'")->fetchColumn(), null, 'still unverified');
        $this->assertEqual((int)$db->query("SELECT COUNT(*) FROM verification_codes vc JOIN users u ON u.id = vc.user_id WHERE u.email='guess@example.com'")->fetchColumn(), 0, 'the code is gone');
        // AUTH-17 (Phase B.4, 2026-11-10): a newly sent code works again.
        $guessId = $db->query("SELECT id FROM users WHERE email='guess@example.com'")->fetchColumn();
        $stmt = $db->prepare('INSERT INTO verification_codes (id,user_id,code_hash,created_at,expires_at,type) VALUES (?,?,?,?,?,?)');
        $stmt->execute([AuthSystem::randomString(16), $guessId, storedHash('a1b2c3'), AuthSystem::now(), gmdate('c', time() + 3600), 'email']);
        $res = AuthSystem::verify_email('guess@example.com', 'a1b2c3');
        $this->assertEqual([$res['status_code'], $res['body']['status'] ?? null], [200, 'verified'], 'a newly sent code verifies');

        AuthSystem::signup('four@example.com','StrongPassword123456','Name');
        $four = $this->mailedCode();
        AuthSystem::signup('other@example.com','StrongPassword123456','Name');
        for ($i = 1; $i <= 3; $i++) {
            AuthSystem::verify_email('other@example.com', 'nope' . $i);
        }
        for ($i = 1; $i <= 4; $i++) {
            AuthSystem::verify_email('four@example.com', 'wrong' . $i);
        }
        $res = AuthSystem::verify_email('four@example.com', $four);
        $this->assertEqual([$res['status_code'], $res['body']['status'] ?? null], [200, 'verified'], 'the right code as the 5th try verifies');
    }
}
$runner = new TestRunner();
$runner->run();
?>