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
// Changed again 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.2, AUTH-16 and "Secrets at rest"): every flow that
//   creates a session (login, MFA, OAuth) returns its refresh_token, which token_refresh() takes; sessions store only
//   refresh_token_hash (HMAC-SHA256 since d270fa3), verification codes only code_hash, OAuth state only state_hash; OAuth state comes
//   from oauth_start(), is single-use and expires in 10 minutes; the callback exchanges the code through the
//   injected provider client and never uses the code as an identity. A database read hands out no usable credential.
// Changed again 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP, spec d270fa3: keyed HMAC for stored secrets): those hashes
//   are now HMAC-SHA256 under the AUTH_SECRET_KEY environment variable (at least 32 bytes; configure() refuses to start
//   without it), not a plain SHA-256. Touches also: the AUTH_SECRET_KEY environment variable.
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
    /**
     * Create the tables if missing. sessions keeps refresh_token_hash, verification_codes keeps code_hash and
     * oauth_states keeps state_hash: only HMAC-SHA256 hex (AUTH_SECRET_KEY, spec d270fa3) of each secret (Phase B.2, "Secrets at rest", 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP; the plain columns refresh_token and code are gone). An older database that
     * still has those columns needs a migration that drops them; CREATE TABLE IF NOT EXISTS leaves it as it is.
     * Input: none. Output: none. Touches: the database (DDL).
     * Phase B.3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): verification_codes has an attempts column (wrong
     * e-mail codes; 5 invalidate the code); an older database gets it through ALTER TABLE.
     */
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
    refresh_token_hash TEXT NOT NULL UNIQUE,
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
    code_hash TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    type TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
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
CREATE TABLE IF NOT EXISTS oauth_states (
    state_hash TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_attempts (
    bucket TEXT NOT NULL,
    at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_bucket ON auth_attempts(bucket, at);
SQL;
        self::$pdo->exec($sql);
        // [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.3: verification_codes.attempts counts wrong e-mail
        // codes (5 invalidate the code). A database made before it gets the column added here.
        try {
            self::$pdo->query('SELECT attempts FROM verification_codes LIMIT 0');
        } catch (PDOException $e) {
            self::$pdo->exec('ALTER TABLE verification_codes ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0');
        }
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
     * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] spec d270fa3: keyed HMAC for stored secrets: configure() is the
     * service's start, and it throws RuntimeException (changing nothing) unless AUTH_SECRET_KEY holds at least 32
     * bytes, so the service refuses to start without the key. Touches: the AUTH_SECRET_KEY environment variable (read).
     */
    public static function configure(?Closure $clock = null, ?Closure $mailer = null, ?Closure $oauthProfile = null): void {
        self::secretKey();
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
    /** OAuth state lifetime: 10 minutes (auth_system.md "Secrets at rest", Phase B.2, 2026-11-10). */
    public const OAUTH_STATE_EXPIRES = 600;

    /**
     * The HMAC key for stored secrets, read from the AUTH_SECRET_KEY environment variable the way jwtSecret() reads
     * AUTH_JWT_SECRET. Input: none. Output: the key (at least 32 bytes). Throws RuntimeException when it is unset or
     * shorter, so the service refuses to start (configure()) or to hash a secret without it.
     * Why: spec d270fa3: keyed HMAC for stored secrets. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the AUTH_SECRET_KEY environment variable (read only).
     */
    private static function secretKey(): string
    {
        $key = (string) getenv('AUTH_SECRET_KEY');
        if (strlen($key) < 32) {
            throw new RuntimeException('AUTH_SECRET_KEY must be set to at least 32 bytes');
        }
        return $key;
    }

    /**
     * Keyed hash of a secret, lowercase hex HMAC-SHA256(AUTH_SECRET_KEY, secret): the only form in which refresh
     * tokens, verification codes and OAuth state are stored. Input: the secret. Output: 64 lowercase hex characters.
     * Why: auth_system.md "Secrets at rest" (Phase B.2, AUTH-16); spec d270fa3: keyed HMAC for stored secrets (it was
     * a plain SHA-256 until 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the AUTH_SECRET_KEY environment variable (read only).
     */
    public static function secretHash(string $secret): string { return hash_hmac('sha256', $secret, self::secretKey()); }

    /**
     * Create a session row and return its id and refresh token. The refresh token is 32 random bytes as hex; only
     * its HMAC-SHA256 is stored (refresh_token_hash), so a database read hands out no usable token.
     * Inputs: user id, ip, device id. Output: {session_id, refresh_token}. Why: AUTH-16; login, MFA and OAuth each
     * wrote the plain token into sessions.refresh_token and none returned it. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (sessions).
     */
    private static function createSession(int $userId, string $ip, string $deviceId): array {
        $sessionId = self::randomString(32);
        $refreshToken = self::randomString(32);
        $expiresAt = gmdate('c', self::t() + self::REFRESH_TOKEN_EXPIRES);
        Database::get()->prepare('INSERT INTO sessions (id,user_id,refresh_token_hash,created_at,expires_at,ip,device_id) VALUES (?,?,?,?,?,?,?)')
            ->execute([$sessionId, $userId, self::secretHash($refreshToken), self::now(), $expiresAt, $ip, $deviceId]);
        return ['session_id' => $sessionId, 'refresh_token' => $refreshToken];
    }

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
        // Only the code's HMAC-SHA256 (spec d270fa3) is stored (Phase B.2, AUTH-16, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
        $stmt = $db->prepare('INSERT INTO verification_codes (id,user_id,code_hash,created_at,expires_at,type) VALUES (?,?,?,?,?,?)');
        $stmt->execute([self::randomString(32),$userId,self::secretHash($code),$now,$expires,'email']);
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
     * or already_verified. The code's HMAC-SHA256 is compared with the stored code_hash in constant time
     * (hash_equals), never in the SQL WHERE.
     * Why: AUTH-05/06; expiry was never checked and status stayed 'unverified'. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Codes are stored only as code_hash since the same day (Phase B.2, AUTH-16).
     * Phase B.3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, auth_system.md flow 2 "Attempts"): every wrong code
     * adds 1 to the attempts of the user's current e-mail codes, and a code with 5 wrong tries is deleted, so
     * further tries, even with the right code, get 400 code_invalid until a new code is sent.
     * Touches: the database (users, verification_codes, audit_log).
     */
    public static function verify_email(string $email, string $code): array {
        $db = Database::get();
        $stmt = $db->prepare('SELECT id,email_verified_at FROM users WHERE email=?');
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$user) return ['status_code'=>400,'body'=>['error'=>'code_invalid','message'=>'Invalid code']];
        if ($user['email_verified_at']) return ['status_code'=>400,'body'=>['error'=>'already_verified','message'=>'Email already verified']];
        $stmt = $db->prepare('SELECT id,code_hash,expires_at FROM verification_codes WHERE user_id=? AND type=\'email\' ORDER BY rowid');
        $stmt->execute([$user['id']]);
        $row = null;
        $given = self::secretHash($code);
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $vc) {
            if ($vc['code_hash'] !== null && hash_equals((string)$vc['code_hash'], $given)) { $row = $vc; }
        }
        if ($row === null) {
            // A wrong code counts against the user's current code; 5 wrong codes invalidate it (Phase B.3).
            $db->prepare('UPDATE verification_codes SET attempts = attempts + 1 WHERE user_id=? AND type=\'email\'')->execute([$user['id']]);
            $db->prepare('DELETE FROM verification_codes WHERE user_id=? AND type=\'email\' AND attempts >= 5')->execute([$user['id']]);
            return ['status_code'=>400,'body'=>['error'=>'code_invalid','message'=>'Invalid code']];
        }
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

    /** resend_verification: requests accepted per email per hour (AUTH-18). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    public const RESENDS_PER_HOUR = 3;
    /** Life of a resent verification code: 10 minutes (AUTH-18). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    public const RESEND_CODE_EXPIRES = 600;

    /**
     * Replace an unverified user's e-mail code and e-mail the new one (auth_system.md flow 2b).
     *
     * Input: the email. Output: 202 {success, status: "sent"}, or 429 {error: "too_many_requests"}. At most 3
     * requests per email per hour are accepted: the count and this request's row are one conditional INSERT into
     * auth_attempts (bucket "resend:<email>"), so concurrent requests cannot pass the limit, and a 4th within the
     * hour sends nothing. For an unverified user it deletes the user's e-mail codes, stores a new 6-digit code
     * (attempts 0, its HMAC-SHA256 under AUTH_SECRET_KEY, 10-minute expiry) and sends it through the injected mailer.
     * An unknown or already verified email gets the same 202 {success, status: "sent"} and nothing is sent, so the
     * answer never says whether an account exists; those requests count toward the limit too.
     * Why: AUTH-18 (commit 0eb5a4e): after 5 wrong codes (AUTH-17) nothing could issue a new code, so anyone who knew
     * an email could block its verification. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (auth_attempts, users read, verification_codes, audit_log), the injected mailer.
     */
    public static function resend_verification(string $email): array {
        $db = Database::get();
        $now = self::t();
        $bucket = 'resend:' . $email;
        $db->prepare('DELETE FROM auth_attempts WHERE at < ?')->execute([$now - 86400]);
        // Every number is bound as an integer: PDO binds execute()'s values as text, and SQLite orders any integer
        // before any text, so "COUNT(*) < '3'" would always hold.
        $stmt = $db->prepare('INSERT INTO auth_attempts (bucket, at) SELECT ?, ? WHERE (SELECT COUNT(*) FROM auth_attempts WHERE bucket = ? AND at > ?) < ?');
        $stmt->bindValue(1, $bucket, PDO::PARAM_STR);
        $stmt->bindValue(2, $now, PDO::PARAM_INT);
        $stmt->bindValue(3, $bucket, PDO::PARAM_STR);
        $stmt->bindValue(4, $now - 3600, PDO::PARAM_INT);
        $stmt->bindValue(5, self::RESENDS_PER_HOUR, PDO::PARAM_INT);
        $stmt->execute();
        if ($stmt->rowCount() !== 1) {
            self::logWhy('resend_verification', ['rate_limit_email_1h:failed']);
            return ['status_code'=>429,'body'=>['error'=>'too_many_requests','message'=>'Too many verification e-mails requested']];
        }
        $sent = ['status_code'=>202,'body'=>['success'=>true,'status'=>'sent']];
        $stmt = $db->prepare('SELECT id,email_verified_at FROM users WHERE email=?');
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$user || $user['email_verified_at']) {
            // Unknown or already verified: the same answer as a real resend, and no e-mail (no account enumeration).
            self::logWhy('resend_verification', ['rate_limit_email_1h', 'user_unverified:failed']);
            return $sent;
        }
        $userId = (int)$user['id'];
        $code = sprintf('%06d', random_int(0, 999999));
        $db->prepare('DELETE FROM verification_codes WHERE user_id=? AND type=\'email\'')->execute([$userId]);
        $db->prepare('INSERT INTO verification_codes (id,user_id,code_hash,created_at,expires_at,type,attempts) VALUES (?,?,?,?,?,?,0)')
            ->execute([self::randomString(32), $userId, self::secretHash($code), self::now(), gmdate('c', $now + self::RESEND_CODE_EXPIRES), 'email']);
        self::sendEmail($email, 'Verify your account', "Your code: $code");
        self::logWhy('resend_verification', ['rate_limit_email_1h', 'user_unverified']);
        self::auditLog($userId, 'verification_resent', 'user', $userId);
        return $sent;
    }

    /**
     * Log in: verified user and correct password -> 200 {status: "authenticated", session_id, token,
     * refresh_token, expires_in, user}, or 202 mfa_required with a challenge id; wrong password -> 401
     * invalid_credentials (429 after 5 failures in 15 min per ip/email).
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: times come from the injectable clock; the same day
     * (Phase B.2, AUTH-16) the response carries refresh_token and the session stores only its hash.
     * Touches: the database.
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
            $stmt = $db->prepare('INSERT INTO verification_codes (id,user_id,code_hash,created_at,expires_at,type) VALUES (?,?,?,?,?,?)');
            $stmt->execute([$challenge_id,$user['id'],null,self::now(),$expires,'mfa']);
            self::logWhy('login',['user_exists','password_correct','mfa_gate']);
            self::auditLog((int)$user['id'],'mfa_challenge_created',null,(int)$user['id']);
            return ['status_code'=>202,'body'=>['success'=>true,'status'=>'mfa_required','challenge_id'=>$challenge_id]];
        }
        // Create session (only the refresh token's hash is stored; the token goes to the client)
        $session = self::createSession((int)$user['id'], $ip, $device_id);
        $session_id = $session['session_id'];
        $access_payload = ['user_id'=>$user['id'],'tier'=>$user['tier'],'exp'=>self::t()+self::ACCESS_TOKEN_EXPIRES];
        $token = self::jwtEncode($access_payload);
        self::logWhy('login',['user_exists','password_correct','mfa_gate']);
        self::auditLog((int)$user['id'],'session_created',null,(int)$user['id'],$ip,$device_id);
        return ['status_code'=>200,'body'=>['success'=>true,'status'=>'authenticated','session_id'=>$session_id,'token'=>$token,'refresh_token'=>$session['refresh_token'],'expires_in'=>self::ACCESS_TOKEN_EXPIRES,'user'=>['id'=>$user['id'],'email'=>$user['email'],'tier'=>$user['tier']]]];
    }

    /**
     * Start an OAuth sign-in: make the state value the provider will send back.
     *
     * Input: the provider name. Output: 200 {success, state, expires_in: 600}. state is 32 random bytes as hex;
     * only its HMAC-SHA256 is stored (oauth_states), with the provider and an expiry 10 minutes ahead. The app keeps
     * state in the visitor's session (cookie) and sends it in the provider's authorize URL; oauth_callback()
     * accepts it once. Why: auth_system.md "Secrets at rest" (Phase B.2): OAuth state is single-use, expires in
     * 10 minutes and is stored only as its hash; the callback took any state. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (oauth_states).
     */
    public static function oauth_start(string $provider): array {
        $state = self::randomString(32);
        $now = self::t();
        $db = Database::get();
        $db->prepare('DELETE FROM oauth_states WHERE expires_at <= ?')->execute([$now]);
        $db->prepare('INSERT INTO oauth_states (state_hash,provider,created_at,expires_at) VALUES (?,?,?,?)')
            ->execute([self::secretHash($state), $provider, $now, $now + self::OAUTH_STATE_EXPIRES]);
        return ['status_code'=>200,'body'=>['success'=>true,'state'=>$state,'expires_in'=>self::OAUTH_STATE_EXPIRES]];
    }

    /**
     * Use up an OAuth state: true when its hash is stored for this provider and has not expired; the row is
     * deleted in the same statement, so a second use (or a concurrent one) finds nothing. Inputs: provider, state.
     * Output: bool. Why: single-use, 10-minute state (Phase B.2). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (oauth_states).
     */
    private static function consumeOauthState(string $provider, string $state): bool {
        if ($state === '') return false;
        $hash = self::secretHash($state);
        $stmt = Database::get()->prepare('DELETE FROM oauth_states WHERE state_hash=? AND provider=? AND expires_at > ?');
        $stmt->execute([$hash, $provider, self::t()]);
        return $stmt->rowCount() === 1;
    }

    /**
     * Sign in (or sign up) with an OAuth provider.
     *
     * Inputs: provider, the authorization code, state. state must be one oauth_start() issued for this provider,
     * unused and under 10 minutes old (else 400 invalid_state, before the provider is called); it is used up
     * whatever happens next. The app has matched state to the visitor's session cookie. Nothing in state or code
     * is trusted as identity: the injected provider client exchanges the code with the provider and returns
     * {id, email, email_verified}.
     * Output: 200 {status: "authenticated", session_id, token, refresh_token, expires_in, user}; 400
     * invalid_state; 400 email_not_verified when the provider does not vouch for the address; 401 oauth_failed
     * when the exchange fails; 503 oauth_not_configured without a provider client. A returning user is found by
     * (provider, provider id) first, then by e-mail (Case B: link to the existing account); otherwise a verified
     * user is created and linked (Case A).
     * Why: AUTH-10/11; the e-mail was read straight from the client's code, so anyone could log in as anyone,
     * and no link was stored. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. The state check and refresh_token are
     * the same day (Phase B.2, AUTH-16 and "Secrets at rest").
     * Touches: the database (oauth_states, users, oauth_accounts, sessions, audit_log); the provider via the client.
     */
    public static function oauth_callback(string $provider, string $code, string $state): array {
        if (self::$oauthProfile === null) {
            return ['status_code'=>503,'body'=>['error'=>'oauth_not_configured','message'=>'OAuth is not configured']];
        }
        if (!self::consumeOauthState($provider, $state)) {
            return ['status_code'=>400,'body'=>['error'=>'invalid_state','message'=>'Invalid or expired OAuth state']];
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
            $session = self::createSession((int)$user['id'], '0.0.0.0', '');
            $session_id = $session['session_id'];
            $db->commit();
        } catch (Throwable $e) {
            if ($db->inTransaction()) $db->rollBack();
            throw $e;
        }
        $token = self::jwtEncode(['user_id'=>(int)$user['id'],'tier'=>$user['tier'],'exp'=>self::t()+self::ACCESS_TOKEN_EXPIRES]);
        self::logWhy('oauth_callback',['state_valid','email_verified']);
        self::auditLog((int)$user['id'],'oauth_login',$provider,(int)$user['id'],null,$newUser ? 'new_user' : 'linked');
        return ['status_code'=>200,'body'=>['success'=>true,'status'=>'authenticated','session_id'=>$session_id,'token'=>$token,'refresh_token'=>$session['refresh_token'],'expires_in'=>self::ACCESS_TOKEN_EXPIRES,'user'=>['id'=>(int)$user['id'],'email'=>$user['email'],'tier'=>$user['tier']]]];
    }

    /**
     * Complete an MFA challenge with a TOTP code (constant-time compare, one step of drift) -> session +
     * token; wrong code -> 401 invalid_code. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the injectable clock, and
     * the response's user carries the stored email and tier (they were null and 'free'). The same day (Phase B.2,
     * AUTH-16) the response carries refresh_token and expires_in, and the session stores only the token's hash.
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
        // Create session (only the refresh token's hash is stored)
        $session = self::createSession((int)$row['user_id'], '0.0.0.0', '');
        $session_id = $session['session_id'];
        $access_payload = ['user_id'=>(int)$row['user_id'],'tier'=>$row['tier'],'exp'=>self::t()+self::ACCESS_TOKEN_EXPIRES];
        $token = self::jwtEncode($access_payload);
        self::logWhy('mfa_challenge',['challenge_valid','code_correct']);
        self::auditLog((int)$row['user_id'],'mfa_verified',null,(int)$row['user_id']);
        return ['status_code'=>200,'body'=>['success'=>true,'status'=>'authenticated','session_id'=>$session_id,'token'=>$token,'refresh_token'=>$session['refresh_token'],'expires_in'=>self::ACCESS_TOKEN_EXPIRES,'user'=>['id'=>(int)$row['user_id'],'email'=>$row['email'],'tier'=>$row['tier']]]];
    }

    /**
     * Issue a new access token for a valid, unexpired refresh token; a banned or suspended user gets 403
     * user_banned. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: times come from the injectable clock. The same
     * day (Phase B.2, AUTH-16) the session is found by the token's HMAC-SHA256 (refresh_token_hash) and the hashes are
     * compared in constant time; the plain token is no longer stored. Input: the refresh_token login, MFA or OAuth
     * returned. Output: 200 {status: "ok", token, expires_in}, 400 invalid_token | token_expired, 403 user_banned.
     * Touches: the database.
     */
    // 6. token_refresh
    public static function token_refresh(string $refresh_token): array {
        $db = Database::get();
        $given = self::secretHash($refresh_token);
        $stmt = $db->prepare('SELECT * FROM sessions WHERE refresh_token_hash=?');
        $stmt->execute([$given]);
        $session = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$session || !hash_equals((string)$session['refresh_token_hash'], $given)) return ['status_code'=>400,'body'=>['error'=>'invalid_token','message'=>'Invalid refresh token']];
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