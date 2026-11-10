<?php
// Repaired 2026-10-08: the token secret comes from AUTH_JWT_SECRET (it was hard-coded), MFA codes are really
//   checked (any code was accepted), and sign-up/login limits live in the database (static arrays
//   reset on every request).
// Why: the suite failed on CI (it was listed in ci/baseline.json). Reviewed by Claude; session c6ee9a72 (2026-11-03).
// Touches: the database, the AUTH_JWT_SECRET environment variable.
// Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): password checks run too_short, too_long, blocklisted in
//   that order (AUTH-03); verify_email reports code_expired and compares codes in constant time (AUTH-06) and sets
//   status 'verified' (AUTH-05); the e-mail sender, OAuth profile fetcher, clock and database are injectable;
//   oauth_callback takes the e-mail only from the provider and links the account in oauth_accounts (AUTH-10/11).
declare(strict_types=1);

class Database {
    private static ?PDO $pdo = null;
    /**
     * Use the given connection for every later call (tests pass an in-memory SQLite connection) and create
     * the tables on it. Input: a PDO connection. Output: none.
     * Why: the common rules want tests on an in-memory store, not an auth.db file left in the working
     * directory. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (creates tables).
     */
    public static function set(PDO $pdo): void {
        self::$pdo = $pdo;
        self::$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        self::migrate();
    }
    public static function get(): PDO {
        if (!self::$pdo) {
            self::$pdo = new PDO('sqlite:auth.db');
            self::$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            self::migrate();
        }
        return self::$pdo;
    }
    private static function migrate(): void {
        $sql = <<<SQL
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    tier TEXT DEFAULT 'free',
    status TEXT DEFAULT 'unverified',
    email_verified_at TEXT,
    mfa_secret TEXT,
    mfa_enabled INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    refresh_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip TEXT,
    device_id TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS audit_log (
    timestamp TEXT NOT NULL,
    actor_id INTEGER,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id INTEGER,
    old_value TEXT,
    new_value TEXT
);
CREATE TABLE IF NOT EXISTS verification_codes (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    code TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    type TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS oauth_accounts (
    user_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(provider, provider_user_id),
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS auth_attempts (
    bucket TEXT NOT NULL,
    at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_bucket ON auth_attempts(bucket, at);
SQL;
        self::$pdo->exec($sql);
    }
}

class AuthSystem {
    /** @var ?Closure(): int injectable clock (unix seconds); null means time(). */
    private static ?Closure $clock = null;
    /** @var ?Closure(string $to, string $subject, string $body): void injectable e-mail sender. */
    private static ?Closure $mailer = null;
    /** @var ?Closure(string $provider, string $code): array injectable OAuth code exchange. */
    private static ?Closure $oauthProfile = null;

    /**
     * Inject the clock, the e-mail sender and the OAuth profile fetcher.
     *
     * Inputs: $clock fn(): int unix seconds (null = time()); $mailer fn(to, subject, body) (null = no e-mail
     * is sent); $oauthProfile fn(provider, code): {id, email, email_verified} that exchanges the code with the
     * provider (null = oauth_callback refuses with 503 oauth_not_configured). Output: none.
     * Why: no network in tests, a deterministic clock, and AUTH-01 ("email sent") / AUTH-10/11 need fakes.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing by itself.
     */
    public static function configure(?Closure $clock = null, ?Closure $mailer = null, ?Closure $oauthProfile = null): void {
        self::$clock = $clock;
        self::$mailer = $mailer;
        self::$oauthProfile = $oauthProfile;
    }
    /** Current unix time from the injected clock (time() when none). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    private static function t(): int { return self::$clock ? (self::$clock)() : time(); }
    /**
     * Counts attempts in a sliding window in the database and records this one. Returns how many
     * attempts (including this one) fall inside the window. 2026-10-08 fix: the original kept these
     * counters in static arrays, which PHP resets on every request, so no limit ever held in
     * production, and in tests they never reset, so later tests were blocked.
     */
    private static function attempt(string $bucket, int $windowSeconds, bool $record = true): int
    {
        $db = Database::get();
        $now = self::t();
        $db->prepare('DELETE FROM auth_attempts WHERE at < ?')->execute([$now - 86400]);
        if ($record) {
            $db->prepare('INSERT INTO auth_attempts (bucket, at) VALUES (?, ?)')->execute([$bucket, $now]);
        }
        $stmt = $db->prepare('SELECT COUNT(*) FROM auth_attempts WHERE bucket = ? AND at > ?');
        $stmt->execute([$bucket, $now - $windowSeconds]);
        return (int) $stmt->fetchColumn();
    }
    private static array $commonPasswords = [
        '123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111',
        '1234567', 'dragon', '123123', 'baseball', 'abc123', 'football', 'monkey',
        'letmein', 'shadow', 'master', '666666', 'qwertyuiop', '123321', 'mustang',
        '1234567890', 'michael', '654321', 'pussy', 'superman', '1qaz2wsx', '7777777',
        'fuckyou', '121212', '000000', 'qazwsx', '123qwe', 'killer', 'trustno1',
        'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster', 'soccer',
        'harley', 'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou', 'fuckme',
        '2000', 'charlie', 'robert', 'thomas', 'hockey', 'ranger', 'daniel', 'starwars',
        'klaster', '112233', 'george', 'asshole', 'computer', 'michelle', 'jessica',
        'pepper', '1111', 'zxcvbn', '555555', '11111111', '131313', 'freedom',
        '777777', 'passw0rd', 'fuck', '123123123', '123456789a', '123456a', '123456b',
        '123456c', '123456d', '123456e', '123456f', '123456g', '123456h', '123456i',
        '123456j', '123456k', '123456l', '123456m', '123456n', '123456o', '123456p',
        '123456q', '123456r', '123456s', '123456t', '123456u', '123456v', '123456w',
        '123456x', '123456y', '123456z'
    ];
    private const SERVICE_NAME = 'authsystem';
    /**
     * 2026-10-08 fix: was a hard-coded 'supersecretkey', which lets anyone forge access tokens. The
     * secret now comes from the AUTH_JWT_SECRET environment variable (at least 32 bytes) and the module
     * refuses to sign or verify without it.
     */
    private static function jwtSecret(): string
    {
        $secret = (string) getenv('AUTH_JWT_SECRET');
        if (strlen($secret) < 32) {
            throw new RuntimeException('AUTH_JWT_SECRET must be set to at least 32 random bytes');
        }
        return $secret;
    }
    private const JWT_ALG = 'HS256';
    private const ACCESS_TOKEN_EXPIRES = 900; // 15 minutes
    private const REFRESH_TOKEN_EXPIRES = 2592000; // 30 days

    // Utility
    public static function now(): string { return gmdate('c', self::t()); }
    public static function randomString(int $len): string { return bin2hex(random_bytes($len)); }
    /**
     * Send an e-mail through the injected sender (configure()). Inputs: address, subject, body. Output: none.
     * Why: AUTH-01 requires the verification e-mail to be sent; it was an empty placeholder. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: whatever the injected sender reaches (an e-mail service in production; a fake in tests).
     */
    private static function sendEmail(string $email, string $subject, string $body): void {
        if (self::$mailer !== null) {
            (self::$mailer)($email, $subject, $body);
        }
    }
    private static function logWhy(string $flow, array $points): void {
        // For brevity, omitted detailed logging
    }
    private static function auditLog(?int $actor, string $action, ?string $resourceType = null, ?int $resourceId = null, ?string $old = null, ?string $new = null): void {
        $db = Database::get();
        $stmt = $db->prepare('INSERT INTO audit_log (timestamp, actor_id, action, resource_type, resource_id, old_value, new_value) VALUES (?,?,?,?,?,?,?)');
        $stmt->execute([self::now(), $actor, $action, $resourceType, $resourceId, $old, $new]);
    }
    private static function hashPassword(string $pwd): string { return password_hash($pwd, PASSWORD_BCRYPT); }
    private static function verifyPassword(string $pwd, string $hash): bool { return password_verify($pwd, $hash); }
    private static function base32Decode(string $b32): string {
        $b32 = strtoupper($b32);
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $binary = '';
        for ($i = 0; $i < strlen($b32); $i++) {
            $index = strpos($alphabet, $b32[$i]);
            if ($index === false) continue;
            $binary .= str_pad(decbin($index), 5, '0', STR_PAD_LEFT);
        }
        $bytes = '';
        for ($i = 0; $i + 8 <= strlen($binary); $i += 8) {
            $bytes .= chr(bindec(substr($binary, $i, 8)));
        }
        return $bytes;
    }
    public static function totp(string $secret, ?int $time = null, int $step = 30, int $digits = 6): string {
        $time = $time ?? self::t();
        $counter = floor($time / $step);
        $key = self::base32Decode($secret);
        $counterBytes = pack('N*', 0) . pack('N*', $counter);
        $hash = hash_hmac('sha1', $counterBytes, $key, true);
        $offset = ord(substr($hash, -1)) & 0x0F;
        $code = (unpack('N', substr($hash, $offset, 4))[1] & 0x7FFFFFFF) % pow(10, $digits);
        return str_pad((string)$code, $digits, '0', STR_PAD_LEFT);
    }
    private static function jwtEncode(array $payload): string {
        $header = ['alg'=>self::JWT_ALG,'typ'=>'JWT'];
        $base64Url = function($data){ return rtrim(strtr(base64_encode($data), '+/', '-_'), '='); };
        $headerB64 = $base64Url(json_encode($header));
        $payloadB64 = $base64Url(json_encode($payload));
        $signature = hash_hmac('sha256', "$headerB64.$payloadB64", self::jwtSecret(), true);
        $signatureB64 = $base64Url($signature);
        return "$headerB64.$payloadB64.$signatureB64";
    }
    private static function jwtDecode(string $jwt): array {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) throw new Exception('invalid_token');
        [$headerB64, $payloadB64, $signatureB64] = $parts;
        $base64UrlDecode = function($data){ $pad = 4 - (strlen($data) % 4); if ($pad < 4) $data .= str_repeat('=', $pad); return base64_decode(strtr($data, '-_', '+/')); };
        $header = json_decode((string)$base64UrlDecode($headerB64), true);
        if (!is_array($header) || ($header['alg'] ?? null) !== self::JWT_ALG) throw new Exception('invalid_token');
        $expectedSig = hash_hmac('sha256', "$headerB64.$payloadB64", self::jwtSecret(), true);
        if (!hash_equals($expectedSig, base64_decode(strtr($signatureB64, '-_', '+/')))) throw new Exception('invalid_token');
        $payload = json_decode((string)$base64UrlDecode($payloadB64), true);
        if (!is_array($payload) || !isset($payload['user_id'], $payload['exp'])) throw new Exception('invalid_token');
        if (self::t() > $payload['exp']) throw new Exception('token_expired');
        return $payload;
    }

    /**
     * Check a password against the NIST SP 800-63B-4 rules of auth_system.md.
     *
     * Inputs: the password, the user's email and name. Output: null when accepted, else the rejection reason.
     * Checks run too_short (< 15 characters), too_long (> 64), blocklisted (bundled common list, or equal to
     * the email, the name or the service name, case-insensitive) and the first failure wins, so "password123"
     * is too_short. No composition rules. Why: AUTH-03 as amended; the name check matched any password that
     * merely contained the name, and an empty name rejected every password. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public static function passwordRejection(string $password, string $email, string $name): ?string {
        $len = mb_strlen($password, 'UTF-8');
        if ($len < 15) return 'too_short';
        if ($len > 64) return 'too_long';
        $lower = mb_strtolower($password, 'UTF-8');
        if (in_array($lower, self::$commonPasswords, true)) return 'blocklisted';
        foreach ([$email, $name, self::SERVICE_NAME] as $personal) {
            if ($personal !== '' && $lower === mb_strtolower($personal, 'UTF-8')) return 'blocklisted';
        }
        return null;
    }

    // 1. signup
    public static function signup(string $email, string $password, string $name): array {
        $db = Database::get();
        // Rate limit
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $now = self::t();
        if (self::attempt('signup:' . $ip, 86400, false) >= 5) {
            return ['status_code'=>429,'body'=>['error'=>'too_many_signups_from_ip','message'=>'Rate limit exceeded']];
        }
        // Email unique
        $stmt = $db->prepare('SELECT id FROM users WHERE email = ?');
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            return ['status_code'=>409,'body'=>['error'=>'email_already_exists','message'=>'Email already registered']];
        }
        // Password strength (AUTH-03): too_short, too_long, blocklisted; the first failure wins.
        $reason = self::passwordRejection($password, $email, $name);
        if ($reason !== null) {
            return ['status_code'=>400,'body'=>['error'=>'password_rejected','reason'=>$reason,'message'=>'Choose a different password']];
        }
        // Create user
        $hash = self::hashPassword($password);
        $stmt = $db->prepare('INSERT INTO users (email,password_hash,tier,status) VALUES (?,?,?,?)');
        $stmt->execute([$email,$hash,'free','unverified']);
        $userId = (int)$db->lastInsertId();
        // Verification code
        $code = self::randomString(16);
        $expires = gmdate('c', $now + 86400);
        $stmt = $db->prepare('INSERT INTO verification_codes (id,user_id,code,created_at,expires_at,type) VALUES (?,?,?,?,?,?)');
        $stmt->execute([self::randomString(32),$userId,$code,$now,$expires,'email']);
        // Send email
        self::sendEmail($email,'Verify your account',"Your code: $code");
        // Logs
        self::logWhy('signup',['email_unique','password_strength','rate_limit_ip_24h']);
        self::auditLog($userId,'user_created',null,$userId);
        self::attempt('signup:' . $ip, 86400);
        return ['status_code'=>200,'body'=>['success'=>true,'status'=>'pending_verification','email'=>$email,'message'=>'check email']];
    }

    /**
     * Verify a user's e-mail with the code sent at signup.
     *
     * Inputs: email, code. Output: 200 {status: "verified", user_id, message}, or 400 with error
     * code_invalid (no such user or no matching code), code_expired (the matching code is past expires_at)
     * or already_verified. Codes are compared in constant time (hash_equals), never in the SQL WHERE.
     * Why: AUTH-05/06; expiry was never checked and status stayed 'unverified'. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (users, verification_codes, audit_log).
     */
    public static function verify_email(string $email, string $code): array {
        $db = Database::get();
        $stmt = $db->prepare('SELECT id,email_verified_at FROM users WHERE email=?');
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$user) return ['status_code'=>400,'body'=>['error'=>'code_invalid','message'=>'Invalid code']];
        if ($user['email_verified_at']) return ['status_code'=>400,'body'=>['error'=>'already_verified','message'=>'Email already verified']];
        $stmt = $db->prepare('SELECT id,code,expires_at FROM verification_codes WHERE user_id=? AND type=\'email\' ORDER BY rowid');
        $stmt->execute([$user['id']]);
        $row = null;
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $vc) {
            if ($vc['code'] !== null && hash_equals((string)$vc['code'], $code)) { $row = $vc; }
        }
        if ($row === null) return ['status_code'=>400,'body'=>['error'=>'code_invalid','message'=>'Invalid code']];
        if (self::t() >= strtotime($row['expires_at'])) return ['status_code'=>400,'body'=>['error'=>'code_expired','message'=>'Code expired']];
        $row = ['id'=>$user['id'],'vc_id'=>$row['id']];
        $now = self::now();
        $stmt = $db->prepare('UPDATE users SET email_verified_at=?, status=\'verified\' WHERE id=?');
        $stmt->execute([$now,$row['id']]);
        $stmt = $db->prepare('DELETE FROM verification_codes WHERE id=?');
        $stmt->execute([$row['vc_id']]);
        self::logWhy('verify_email',['code_valid','user_unverified']);
        self::auditLog((int)$row['id'],'email_verified',null,(int)$row['id']);
        return ['status_code'=>200,'body'=>['success'=>true,'status'=>'verified','user_id'=> (int)$row['id'],'message'=>'ready to login']];
    }

    /**
     * Log in: verified user and correct password -> session + access token, or 202 mfa_required with a
     * challenge id; wrong password -> 401 invalid_credentials (429 after 5 failures in 15 min per ip/email).
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: times come from the injectable clock. Touches: the database.
     */
    // 3. login
    public static function login(string $email, string $password, string $device_id, string $ip): array {
        $db = Database::get();
        $stmt = $db->prepare('SELECT * FROM users WHERE email=?');
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$user || !$user['email_verified_at']) {
            return ['status_code'=>401,'body'=>['error'=>'invalid_credentials','message'=>'Invalid credentials']];
        }
        if (!self::verifyPassword($password,$user['password_hash'])) {
            // Rate limit
            $key = $ip.'|'.$email;
            $now = self::t();
            if (self::attempt('login:' . $key, 900) > 5) {
                return ['status_code'=>429,'body'=>['error'=>'too_many_attempts','message'=>'Rate limit exceeded']];
            }
            return ['status_code'=>401,'body'=>['error'=>'invalid_credentials','message'=>'Invalid credentials']];
        }
        if ($user['mfa_enabled']) {
            $challenge_id = self::randomString(32);
            $expires = gmdate('c', self::t()+300);
            $stmt = $db->prepare('INSERT INTO verification_codes (id,user_id,code,created_at,expires_at,type) VALUES (?,?,?,?,?,?)');
            $stmt->execute([$challenge_id,$user['id'],null,self::now(),$expires,'mfa']);
            self::logWhy('login',['user_exists','password_correct','mfa_gate']);
            self::auditLog((int)$user['id'],'mfa_challenge_created',null,(int)$user['id']);
            return ['status_code'=>202,'body'=>['success'=>true,'status'=>'mfa_required','challenge_id'=>$challenge_id]];
        }
        // Create session
        $session_id = self::randomString(32);
        $refresh_token = self::randomString(64);
        $expires_at = gmdate('c', self::t()+self::REFRESH_TOKEN_EXPIRES);
        $stmt = $db->prepare('INSERT INTO sessions (id,user_id,refresh_token,created_at,expires_at,ip,device_id) VALUES (?,?,?,?,?,?,?)');
        $stmt->execute([$session_id,$user['id'],$refresh_token,self::now(),$expires_at,$ip,$device_id]);
        $access_payload = ['user_id'=>$user['id'],'tier'=>$user['tier'],'exp'=>self::t()+self::ACCESS_TOKEN_EXPIRES];
        $token = self::jwtEncode($access_payload);
        self::logWhy('login',['user_exists','password_correct','mfa_gate']);
        self::auditLog((int)$user['id'],'session_created',null,(int)$user['id'],$ip,$device_id);
        return ['status_code'=>200,'body'=>['success'=>true,'status'=>'authenticated','session_id'=>$session_id,'token'=>$token,'expires_in'=>self::ACCESS_TOKEN_EXPIRES,'user'=>['id'=>$user['id'],'email'=>$user['email'],'tier'=>$user['tier']]]];
    }

    /**
     * Sign in (or sign up) with an OAuth provider.
     *
     * Inputs: provider, the authorization code, state. The caller has already matched state to the visitor's
     * session (state_valid); nothing in state or code is trusted as identity. The injected profile fetcher
     * exchanges the code with the provider and returns {id, email, email_verified}.
     * Output: 200 {status: "authenticated", session_id, token, user}; 400 email_not_verified when the provider
     * does not vouch for the address; 401 oauth_failed when the exchange fails; 503 oauth_not_configured
     * without a fetcher. A returning user is found by (provider, provider id) first, then by e-mail (Case B:
     * link to the existing account); otherwise a verified user is created and linked (Case A).
     * Why: AUTH-10/11; the e-mail was read straight from the client's code, so anyone could log in as anyone,
     * and no link was stored. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (users, oauth_accounts, sessions, audit_log); the provider via the fetcher.
     */
    public static function oauth_callback(string $provider, string $code, string $state): array {
        if (self::$oauthProfile === null) {
            return ['status_code'=>503,'body'=>['error'=>'oauth_not_configured','message'=>'OAuth is not configured']];
        }
        try {
            $profile = (self::$oauthProfile)($provider, $code);
        } catch (Throwable $e) {
            return ['status_code'=>401,'body'=>['error'=>'oauth_failed','message'=>'OAuth exchange failed']];
        }
        if (!is_array($profile) || empty($profile['email_verified']) || !isset($profile['email'], $profile['id'])) {
            return ['status_code'=>400,'body'=>['error'=>'email_not_verified','message'=>'The provider did not verify this e-mail']];
        }
        $email = (string)$profile['email'];
        $providerUserId = (string)$profile['id'];
        $db = Database::get();
        $db->beginTransaction();
        try {
            $stmt = $db->prepare('SELECT u.* FROM oauth_accounts oa JOIN users u ON u.id = oa.user_id WHERE oa.provider=? AND oa.provider_user_id=?');
            $stmt->execute([$provider, $providerUserId]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$user) {
                $stmt = $db->prepare('SELECT * FROM users WHERE email=?');
                $stmt->execute([$email]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
            }
            $newUser = !$user;
            if ($newUser) {
                $stmt = $db->prepare('INSERT INTO users (email,tier,status,email_verified_at) VALUES (?,?,?,?)');
                $stmt->execute([$email,'free','verified',self::now()]);
                $user = ['id'=>(int)$db->lastInsertId(),'email'=>$email,'tier'=>'free','status'=>'verified'];
            }
            if (in_array($user['status'], ['suspended','banned'], true)) {
                $db->rollBack();
                return ['status_code'=>403,'body'=>['error'=>'user_banned','message'=>'User is banned or suspended']];
            }
            $db->prepare('INSERT OR IGNORE INTO oauth_accounts (user_id,provider,provider_user_id,created_at) VALUES (?,?,?,?)')
                ->execute([(int)$user['id'],$provider,$providerUserId,self::now()]);
            $session_id = self::randomString(32);
            $refresh_token = self::randomString(64);
            $expires_at = gmdate('c', self::t()+self::REFRESH_TOKEN_EXPIRES);
            $stmt = $db->prepare('INSERT INTO sessions (id,user_id,refresh_token,created_at,expires_at,ip,device_id) VALUES (?,?,?,?,?,?,?)');
            $stmt->execute([$session_id,(int)$user['id'],$refresh_token,self::now(),$expires_at,'0.0.0.0','']);
            $db->commit();
        } catch (Throwable $e) {
            if ($db->inTransaction()) $db->rollBack();
            throw $e;
        }
        $token = self::jwtEncode(['user_id'=>(int)$user['id'],'tier'=>$user['tier'],'exp'=>self::t()+self::ACCESS_TOKEN_EXPIRES]);
        self::logWhy('oauth_callback',['state_valid','email_verified']);
        self::auditLog((int)$user['id'],'oauth_login',$provider,(int)$user['id'],null,$newUser ? 'new_user' : 'linked');
        return ['status_code'=>200,'body'=>['success'=>true,'status'=>'authenticated','session_id'=>$session_id,'token'=>$token,'user'=>['id'=>(int)$user['id'],'email'=>$user['email'],'tier'=>$user['tier']]]];
    }

    /**
     * Complete an MFA challenge with a TOTP code (constant-time compare, one step of drift) -> session +
     * token; wrong code -> 401 invalid_code. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the injectable clock, and
     * the response's user carries the stored email and tier (they were null and 'free').
     * Touches: the database.
     */
    // 5. mfa_challenge
    public static function mfa_challenge(string $challenge_id, string $code): array {
        $db = Database::get();
        $stmt = $db->prepare('SELECT vc.user_id,vc.expires_at,u.mfa_secret,u.email,u.tier,u.status FROM verification_codes vc JOIN users u ON vc.user_id=u.id WHERE vc.id=? AND vc.type=\'mfa\'');
        $stmt->execute([$challenge_id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) return ['status_code'=>400,'body'=>['error'=>'invalid_challenge','message'=>'Challenge not found']];
        if (self::t() > strtotime($row['expires_at'])) return ['status_code'=>400,'body'=>['error'=>'challenge_expired','message'=>'Challenge expired']];
        // 2026-10-08 fix: was `if (!self::totp(...) === $code)`, which compares false with the code and
        // therefore accepted ANY code. Constant-time compare, current step plus one step of drift.
        $now = self::t();
        $ok = false;
        foreach ([$now - 30, $now, $now + 30] as $t) {
            $ok = $ok || hash_equals(self::totp((string) $row['mfa_secret'], $t), $code);
        }
        if (!$ok) {
            return ['status_code'=>401,'body'=>['error'=>'invalid_code','message'=>'Invalid MFA code']];
        }
        // Delete challenge
        $stmt = $db->prepare('DELETE FROM verification_codes WHERE id=?');
        $stmt->execute([$challenge_id]);
        // Create session
        $session_id = self::randomString(32);
        $refresh_token = self::randomString(64);
        $expires_at = gmdate('c', self::t()+self::REFRESH_TOKEN_EXPIRES);
        $stmt = $db->prepare('INSERT INTO sessions (id,user_id,refresh_token,created_at,expires_at,ip,device_id) VALUES (?,?,?,?,?,?,?)');
        $stmt->execute([$session_id,(int)$row['user_id'],$refresh_token,self::now(),$expires_at,'0.0.0.0','']);
        $access_payload = ['user_id'=>(int)$row['user_id'],'tier'=>$row['tier'],'exp'=>self::t()+self::ACCESS_TOKEN_EXPIRES];
        $token = self::jwtEncode($access_payload);
        self::logWhy('mfa_challenge',['challenge_valid','code_correct']);
        self::auditLog((int)$row['user_id'],'mfa_verified',null,(int)$row['user_id']);
        return ['status_code'=>200,'body'=>['success'=>true,'status'=>'authenticated','session_id'=>$session_id,'token'=>$token,'user'=>['id'=>(int)$row['user_id'],'email'=>$row['email'],'tier'=>$row['tier']]]];
    }

    /**
     * Issue a new access token for a valid, unexpired refresh token; a banned or suspended user gets 403
     * user_banned. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: times come from the injectable clock.
     * Touches: the database.
     */
    // 6. token_refresh
    public static function token_refresh(string $refresh_token): array {
        $db = Database::get();
        $stmt = $db->prepare('SELECT * FROM sessions WHERE refresh_token=?');
        $stmt->execute([$refresh_token]);
        $session = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$session) return ['status_code'=>400,'body'=>['error'=>'invalid_token','message'=>'Invalid refresh token']];
        if (self::t() > strtotime($session['expires_at'])) return ['status_code'=>400,'body'=>['error'=>'token_expired','message'=>'Refresh token expired']];
        $stmt = $db->prepare('SELECT * FROM users WHERE id=?');
        $stmt->execute([$session['user_id']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$user || in_array($user['status'],['suspended','banned'])) {
            return ['status_code'=>403,'body'=>['error'=>'user_banned','message'=>'User is banned or suspended']];
        }
        $access_payload = ['user_id'=>$user['id'],'tier'=>$user['tier'],'exp'=>self::t()+self::ACCESS_TOKEN_EXPIRES];
        $token = self::jwtEncode($access_payload);
        self::logWhy('token_refresh',['token_valid','user_active']);
        self::auditLog((int)$user['id'],'token_refreshed',null,(int)$user['id']);
        return ['status_code'=>200,'body'=>['success'=>true,'status'=>'ok','token'=>$token,'expires_in'=>self::ACCESS_TOKEN_EXPIRES]];
    }

    /**
     * Verify an access token: HS256 only (the header's alg must be HS256; the signature is recomputed with a
     * fixed algorithm and compared in constant time), not expired, user active. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP:
     * a malformed header or payload is invalid_token (it raised warnings), expiry uses the injectable clock.
     * Touches: the database (read).
     */
    // 7. verify_access_token
    public static function verify_access_token(string $token): array {
        try {
            $payload = self::jwtDecode($token);
        } catch (Exception $e) {
            $msg = $e->getMessage();
            if ($msg==='token_expired') return ['status_code'=>401,'body'=>['error'=>'token_expired','message'=>'Token expired']];
            return ['status_code'=>401,'body'=>['error'=>'invalid_token','message'=>'Invalid token']];
        }
        $db = Database::get();
        $stmt = $db->prepare('SELECT * FROM users WHERE id=?');
        $stmt->execute([$payload['user_id']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$user || in_array($user['status'],['suspended','banned'])) {
            return ['status_code'=>401,'body'=>['error'=>'user_banned','message'=>'User is banned or suspended']];
        }
        self::logWhy('verify_access_token',['signature_valid','not_expired','user_active']);
        return ['status_code'=>200,'body'=>['success'=>true,'status'=>'ok','user'=>['id'=>$user['id'],'email'=>$user['email'],'tier'=>$user['tier']]]];
    }
}