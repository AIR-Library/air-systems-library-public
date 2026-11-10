<?php
/**
 * TOTP two-factor: authenticator codes and recovery codes (docs/specs/totp_two_factor.md).
 *
 * What it does: enrolls a user's authenticator app (sealed secret, otpauth URI), confirms it and hands out 8
 * one-time recovery codes (only their keyed hashes are stored), verifies 6-digit codes with one 30-second step
 * of drift each way, refuses any code twice (CLAIM), counts every try before looking at the code (TRY) and
 * locks after 5 failures in 900 seconds, and after 100 failures in a row asks for a recovery code.
 *
 * Inputs/outputs: see each function; a refusal is a returned {error, status[, retry_after]}, never an
 * exception. user_id is always the verified caller (the account that has just passed the first factor).
 *
 * Why: Phase D wave 1, owner request 2026-11-10 (spec ids TOTP-01..14).
 * Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the database (totp_enrollments, totp_recovery_codes, totp_failures through PDO), the CSPRNG.
 * No network, no files, no money. Never logs or returns a secret, a code, a recovery code or a key.
 */

declare(strict_types=1);

namespace TotpTwoFactor;

use PDO;
use RuntimeException;

const STEP = 30;
const DIGITS = 6;
const WINDOW = 1;
const LOCK_FAILURES = 5;
const LOCK_SECONDS = 900;
const HARD_LOCK_FAILURES = 100;
const RECOVERY_CODES = 8;
const RECOVERY_ALPHABET = '23456789abcdefghjkmnpqrstvwxyz';
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Raised by construction with a key of the wrong size ("invalid_key") and by base32_decode
 * ("invalid_base32"). The message is only the code: never a key or a secret.
 * Why: TOTP-02, TOTP-11 (fail closed). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
final class TotpError extends RuntimeException
{
    private string $errorCode;

    /**
     * In: the spec's error code. Out: the exception. Why: TOTP-02, TOTP-11. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public function __construct(string $errorCode)
    {
        parent::__construct($errorCode);
        $this->errorCode = $errorCode;
    }

    /**
     * In: nothing. Out: the spec's error code. Why: TOTP-02, TOTP-11. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public function getErrorCode(): string
    {
        return $this->errorCode;
    }
}

/**
 * base32_encode: RFC 4648 alphabet, upper case, no "=" padding. In: bytes. Out: text.
 * Why: TOTP-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function base32_encode(string $bytes): string
{
    $out = '';
    $buffer = 0;
    $bits = 0;
    $n = strlen($bytes);
    for ($i = 0; $i < $n; $i++) {
        $buffer = (($buffer << 8) | ord($bytes[$i])) & 0xFFFF;
        $bits += 8;
        while ($bits >= 5) {
            $bits -= 5;
            $out .= BASE32_ALPHABET[($buffer >> $bits) & 31];
        }
    }
    if ($bits > 0) {
        $out .= BASE32_ALPHABET[($buffer << (5 - $bits)) & 31];
    }
    return $out;
}

/**
 * base32_decode: drop ASCII spaces, "-" and "=", upper-case a-z, then decode 5 bits per character; leftover
 * bits are dropped. In: text. Out: bytes. Throws TotpError("invalid_base32") for any other character, nothing
 * left, or a length of 1, 3 or 6 modulo 8 (checked before decoding).
 * Why: TOTP-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function base32_decode(string $text): string
{
    $t = strtr(str_replace([' ', '-', '='], '', $text), 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    $n = strlen($t);
    if ($n === 0 || strspn($t, BASE32_ALPHABET) !== $n || in_array($n % 8, [1, 3, 6], true)) {
        throw new TotpError('invalid_base32');
    }
    $out = '';
    $buffer = 0;
    $bits = 0;
    for ($i = 0; $i < $n; $i++) {
        $buffer = (($buffer << 5) | strpos(BASE32_ALPHABET, $t[$i])) & 0xFFFF;
        $bits += 5;
        if ($bits >= 8) {
            $bits -= 8;
            $out .= chr(($buffer >> $bits) & 0xFF);
        }
    }
    return $out;
}

/**
 * hotp (RFC 4226): HMAC-SHA1 over the 8-byte big-endian counter, dynamic truncation, mod 10^digits.
 * In: key bytes, a 64-bit counter, digits. Out: the zero-padded code.
 * Why: TOTP-01 (a counter above 32 bits is not cut). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: nothing.
 */
function hotp(string $key, int $counter, int $digits = DIGITS): string
{
    $mac = hash_hmac('sha1', pack('J', $counter), $key, true);
    $o = ord($mac[19]) & 0x0F;
    $v = ((ord($mac[$o]) & 0x7F) << 24) | (ord($mac[$o + 1]) << 16) | (ord($mac[$o + 2]) << 8) | ord($mac[$o + 3]);
    return str_pad((string)($v % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
}

/**
 * totp_at (RFC 6238): hotp(base32_decode(secret), floor(unix_time / 30), digits).
 * In: base32 secret, unix time (64-bit), digits. Out: the code. Throws TotpError("invalid_base32").
 * Why: TOTP-01. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function totp_at(string $secretBase32, int $unixTime, int $digits = DIGITS): string
{
    return hotp(base32_decode($secretBase32), intdiv($unixTime, STEP), $digits);
}

/**
 * pct: every byte of the UTF-8 text not in [A-Za-z0-9._~-] becomes "%" + two upper-case hex digits.
 * In: text. Out: text. Why: TOTP-03 (exact otpauth URI). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: nothing.
 */
function pct(string $s): string
{
    $out = '';
    $n = strlen($s);
    for ($i = 0; $i < $n; $i++) {
        $c = $s[$i];
        $out .= (ctype_alnum($c) && ord($c) < 0x80) || $c === '.' || $c === '_' || $c === '~' || $c === '-'
            ? $c : sprintf('%%%02X', ord($c));
    }
    return $out;
}

/**
 * otpauth_uri: the Key URI an authenticator app reads. In: base32 secret, issuer, account label. Out: URI.
 * Why: TOTP-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function otpauth_uri(string $secret, string $issuer, string $accountLabel): string
{
    return 'otpauth://totp/' . pct($issuer . ':' . $accountLabel) . '?secret=' . $secret . '&issuer=' . pct($issuer)
        . '&algorithm=SHA1&digits=6&period=30';
}

/**
 * seal: "v1." + base64(nonce12 + ciphertext + tag16), AES-256-GCM with the aad text.
 * In: 32-byte key, 12-byte nonce, plaintext, aad. Out: sealed text. Why: TOTP-03, TOTP-11. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing (OpenSSL in memory).
 */
function seal(string $key32, string $nonce12, string $plaintext, string $aad): string
{
    $tag = '';
    $ct = openssl_encrypt($plaintext, 'aes-256-gcm', $key32, OPENSSL_RAW_DATA, $nonce12, $tag, $aad, 16);
    if ($ct === false || strlen($tag) !== 16) {
        throw new RuntimeException('seal_failed');
    }
    return 'v1.' . base64_encode($nonce12 . $ct . $tag);
}

/**
 * open: the plaintext, or null for a missing "v1." prefix, bad base64, fewer than 28 bytes, or a tag that does
 * not verify (wrong key, wrong aad, any changed byte). In: 32-byte key, sealed text, aad. Out: ?string.
 * Why: TOTP-10, TOTP-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function open(string $key32, string $sealed, string $aad): ?string
{
    if (strncmp($sealed, 'v1.', 3) !== 0) {
        return null;
    }
    $raw = base64_decode(substr($sealed, 3), true);
    if ($raw === false || strlen($raw) < 28) {
        return null;
    }
    $nonce = substr($raw, 0, 12);
    $tag = substr($raw, -16);
    $ct = substr($raw, 12, strlen($raw) - 28);
    $pt = openssl_decrypt($ct, 'aes-256-gcm', $key32, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
    return $pt === false ? null : $pt;
}

/**
 * The TOTP INPUT form of a code, or null: at most 64 characters, then ASCII spaces and "-" removed, exactly 6
 * characters 0-9. In: ?string. Out: ?string. Why: TOTP-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: nothing.
 */
function totp_input(?string $code): ?string
{
    if ($code === null || strlen($code) > 64) {
        return null;
    }
    $c = str_replace([' ', '-'], '', $code);
    return (strlen($c) === 6 && strspn($c, '0123456789') === 6) ? $c : null;
}

/**
 * The RECOVERY INPUT form of a code, or null: at most 64 characters, A-Z lower-cased, ASCII spaces and "-"
 * removed, exactly 12 symbols of the RECOVERY ALPHABET. In: ?string. Out: ?string.
 * Why: TOTP-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function recovery_input(?string $code): ?string
{
    if ($code === null || strlen($code) > 64) {
        return null;
    }
    $c = str_replace([' ', '-'], '', strtr($code, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'));
    return (strlen($c) === 12 && strspn($c, RECOVERY_ALPHABET) === 12) ? $c : null;
}

/**
 * The SQL store: one PDO connection shared by every call; every write the spec names is one statement.
 *
 * Inputs: a PDO connection (SQLite in the tests). Outputs: see each method.
 * Why: TOTP-03..14 (atomic TRY and CLAIM). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the database tables totp_enrollments, totp_recovery_codes, totp_failures.
 */
final class SqlTotpStore
{
    private PDO $db;

    /**
     * In: a PDO connection. Out: the store (error mode set to exceptions). Why: storage behind an interface.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the connection's settings.
     */
    public function __construct(PDO $db)
    {
        $this->db = $db;
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    /**
     * Create the three tables of the spec's SCHEMA if missing. In/out: none. Why: SCHEMA. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (DDL).
     */
    public function migrate(): void
    {
        $this->db->exec('CREATE TABLE IF NOT EXISTS totp_enrollments (user_id TEXT PRIMARY KEY, secret_enc TEXT NOT NULL,
            confirmed_at INT NULL, last_used_step INT NOT NULL DEFAULT 0, failed_since_success INT NOT NULL DEFAULT 0,
            created_at INT NOT NULL)');
        $this->db->exec('CREATE TABLE IF NOT EXISTS totp_recovery_codes (id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL, code_hash TEXT NOT NULL, created_at INT NOT NULL, used_at INT NULL,
            UNIQUE (user_id, code_hash))');
        $this->db->exec('CREATE TABLE IF NOT EXISTS totp_failures (id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL, at INT NOT NULL)');
    }

    /**
     * The user's enrollment row, or null. In: user_id. Out: ?array. Why: FLOWS. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
     */
    public function getEnrollment(string $userId): ?array
    {
        $st = $this->db->prepare('SELECT * FROM totp_enrollments WHERE user_id = ?');
        $st->execute([$userId]);
        $r = $st->fetch(PDO::FETCH_ASSOC);
        return $r === false ? null : $r;
    }

    /**
     * Write an unconfirmed row, replacing an unconfirmed one; a confirmed row is never replaced.
     * In: user_id, sealed secret, now. Out: true when a row was written. Why: enroll_start step 2. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (one upsert).
     */
    public function writeUnconfirmed(string $userId, string $secretEnc, int $now): bool
    {
        $st = $this->db->prepare('INSERT INTO totp_enrollments (user_id, secret_enc, confirmed_at, last_used_step,
            failed_since_success, created_at) VALUES (:u, :s, NULL, 0, 0, :now)
            ON CONFLICT(user_id) DO UPDATE SET secret_enc = excluded.secret_enc, confirmed_at = NULL,
            last_used_step = 0, failed_since_success = 0, created_at = excluded.created_at
            WHERE totp_enrollments.confirmed_at IS NULL');
        $st->execute([':u' => $userId, ':s' => $secretEnc, ':now' => $now]);
        return $st->rowCount() === 1;
    }

    /**
     * enroll_confirm step 7: confirm only the unconfirmed row whose secret_enc is the one that was opened.
     * In: user_id, now, step, secret_enc read. Out: true when one row changed. Why: TOTP-04. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (one conditional update).
     */
    public function confirm(string $userId, int $now, int $step, string $secretEncRead): bool
    {
        $st = $this->db->prepare('UPDATE totp_enrollments SET confirmed_at = :now, last_used_step = :step,
            failed_since_success = 0 WHERE user_id = :u AND confirmed_at IS NULL AND secret_enc = :secret_enc_read');
        $st->execute([':now' => $now, ':step' => $step, ':u' => $userId, ':secret_enc_read' => $secretEncRead]);
        return $st->rowCount() === 1;
    }

    /**
     * CLAIM(step): one conditional write; of two requests with the same code exactly one changes a row.
     * In: user_id, step. Out: true when one row changed. Why: TOTP-06. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (one conditional update).
     */
    public function claim(string $userId, int $step): bool
    {
        $st = $this->db->prepare('UPDATE totp_enrollments SET last_used_step = :step, failed_since_success = 0
            WHERE user_id = :u AND confirmed_at IS NOT NULL AND last_used_step < :step');
        $st->execute([':step' => $step, ':u' => $userId]);
        return $st->rowCount() === 1;
    }

    /**
     * TRY(user_id): count the try first, in one atomic conditional insert. In: user_id, now. Out: the slot
     * row's id, or null when the user is LOCKED. Why: TOTP-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (one conditional insert).
     */
    public function tryWrite(string $userId, int $now): ?int
    {
        $st = $this->db->prepare('INSERT INTO totp_failures (user_id, at) SELECT :u, :now
            WHERE (SELECT COUNT(*) FROM totp_failures WHERE user_id = :u2 AND at > :now2 - ' . LOCK_SECONDS . ') < ' . LOCK_FAILURES);
        $st->execute([':u' => $userId, ':now' => $now, ':u2' => $userId, ':now2' => $now]);
        return $st->rowCount() === 1 ? (int)$this->db->lastInsertId() : null;
    }

    /**
     * Delete this call's slot row, and only it. In: the slot id. Out: none. Why: every answer that is not a
     * FAILURE. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (one delete).
     */
    public function deleteSlot(int $slotId): void
    {
        $this->db->prepare('DELETE FROM totp_failures WHERE id = ?')->execute([$slotId]);
    }

    /**
     * FAILURE: the slot stays; failed_since_success + 1 in one statement. In: user_id. Out: none.
     * Why: TOTP-07, TOTP-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (one update).
     */
    public function addFailure(string $userId): void
    {
        $this->db->prepare('UPDATE totp_enrollments SET failed_since_success = failed_since_success + 1 WHERE user_id = :u')
            ->execute([':u' => $userId]);
    }

    /**
     * An ok answer by recovery code sets failed_since_success to 0. In: user_id. Out: none.
     * Why: TOTP-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (one update).
     */
    public function resetFailedSinceSuccess(string $userId): void
    {
        $this->db->prepare('UPDATE totp_enrollments SET failed_since_success = 0 WHERE user_id = :u')->execute([':u' => $userId]);
    }

    /**
     * The `at` of the 5th most recent failure inside the window, or null when the user is not LOCKED.
     * In: user_id, now. Out: ?int. Why: LOCKED, retry_after, status.locked_until. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
     */
    public function lockAnchor(string $userId, int $now): ?int
    {
        $st = $this->db->prepare('SELECT at FROM totp_failures WHERE user_id = :u AND at > :t ORDER BY at DESC, id DESC LIMIT 1 OFFSET ' . (LOCK_FAILURES - 1));
        $st->execute([':u' => $userId, ':t' => $now - LOCK_SECONDS]);
        $v = $st->fetchColumn();
        return $v === false ? null : (int)$v;
    }

    /**
     * Store recovery code hashes. In: user_id, hashes, now. Out: none. Why: TOTP-04. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (inserts).
     */
    public function insertRecoveryHashes(string $userId, array $hashes, int $now): void
    {
        $st = $this->db->prepare('INSERT INTO totp_recovery_codes (user_id, code_hash, created_at, used_at) VALUES (?, ?, ?, NULL)');
        foreach ($hashes as $h) {
            $st->execute([$userId, $h, $now]);
        }
    }

    /**
     * Use a recovery code once, in one conditional update. In: user_id, code_hash, now. Out: true when one row
     * changed. Why: TOTP-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (one update).
     */
    public function useRecoveryCode(string $userId, string $hash, int $now): bool
    {
        $st = $this->db->prepare('UPDATE totp_recovery_codes SET used_at = :now WHERE user_id = :u AND code_hash = :h AND used_at IS NULL');
        $st->execute([':now' => $now, ':u' => $userId, ':h' => $hash]);
        return $st->rowCount() === 1;
    }

    /**
     * Unused recovery codes of the user. In: user_id. Out: count. Why: recovery_codes_left. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
     */
    public function recoveryLeft(string $userId): int
    {
        $st = $this->db->prepare('SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = ? AND used_at IS NULL');
        $st->execute([$userId]);
        return (int)$st->fetchColumn();
    }

    /**
     * Delete the user's enrollment, recovery codes and failures. In: user_id. Out: none. Why: TOTP-12.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (deletes, in one transaction).
     */
    public function deleteUser(string $userId): void
    {
        $this->db->beginTransaction();
        try {
            foreach (['totp_enrollments', 'totp_recovery_codes', 'totp_failures'] as $t) {
                $this->db->prepare("DELETE FROM $t WHERE user_id = ?")->execute([$userId]);
            }
            $this->db->commit();
        } catch (\Throwable $e) {
            $this->db->rollBack();
            throw $e;
        }
    }

    /**
     * Rows of a table for a user (test and audit helper). In: table name (one of the three), user_id.
     * Out: rows. Why: TOTP-03/04/12 assert what is stored. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (read).
     */
    public function rows(string $table, string $userId): array
    {
        if (!in_array($table, ['totp_enrollments', 'totp_recovery_codes', 'totp_failures'], true)) {
            throw new RuntimeException('unknown_table');
        }
        $st = $this->db->prepare("SELECT * FROM $table WHERE user_id = ? ORDER BY rowid");
        $st->execute([$userId]);
        return $st->fetchAll(PDO::FETCH_ASSOC);
    }
}

/**
 * The service: enroll_start, enroll_confirm, verify, disable, status.
 *
 * Inputs: store, encryption_key (exactly 32 bytes), recovery_hash_key (>= 32 bytes), issuer, clock (returns
 * unix seconds), random_bytes(n) (defaults to the CSPRNG). Outputs: see each method.
 * Why: TOTP-03..14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database through the store.
 */
final class TotpService
{
    private SqlTotpStore $store;
    private string $encryptionKey;
    private string $recoveryHashKey;
    private string $issuer;
    /** @var callable(): int */
    private $clock;
    /** @var callable(int): string */
    private $randomBytes;

    /**
     * Build the service. Throws TotpError("invalid_key") for an encryption_key that is not 32 bytes or a
     * recovery_hash_key under 32 bytes (fail closed). In: see the class. Out: the service.
     * Why: TOTP-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public function __construct(SqlTotpStore $store, string $encryptionKey, string $recoveryHashKey, string $issuer,
                                ?callable $clock = null, ?callable $randomBytes = null)
    {
        if (strlen($encryptionKey) !== 32 || strlen($recoveryHashKey) < 32) {
            throw new TotpError('invalid_key');
        }
        $this->store = $store;
        $this->encryptionKey = $encryptionKey;
        $this->recoveryHashKey = $recoveryHashKey;
        $this->issuer = $issuer;
        $this->clock = $clock ?? static fn(): int => time();
        $this->randomBytes = $randomBytes ?? static fn(int $n): string => random_bytes($n);
    }

    /**
     * The injected time. Out: unix seconds. Why: CONVENTIONS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the clock.
     */
    private function now(): int
    {
        return (int)($this->clock)();
    }

    /**
     * Exactly n bytes from the injected source. In: n. Out: bytes. Why: CONFIGURATION. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the CSPRNG (or the test's queue).
     */
    private function rand(int $n): string
    {
        $b = ($this->randomBytes)($n);
        if (strlen($b) !== $n) {
            throw new RuntimeException('random_bytes_short');
        }
        return $b;
    }

    /**
     * generate_secret: base32_encode(random_bytes(20)), 32 characters. Out: text. Why: TOTP-02. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the CSPRNG.
     */
    public function generateSecret(): string
    {
        return base32_encode($this->rand(20));
    }

    /**
     * code_hash: lower-case hex HMAC-SHA256(recovery_hash_key, "recovery:" + user_id + ":" + RECOVERY INPUT).
     * In: user_id, the RECOVERY INPUT form. Out: hex. Why: TOTP-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: nothing.
     */
    public function codeHash(string $userId, string $recoveryInput): string
    {
        return hash_hmac('sha256', 'recovery:' . $userId . ':' . $recoveryInput, $this->recoveryHashKey);
    }

    /**
     * enroll_start: 409 already_enrolled for a confirmed row; otherwise a new secret, sealed under
     * "totp:" + user_id, replaces any unconfirmed row. In: user_id (verified caller), account label.
     * Out: {secret, otpauth_uri} or {error, status}. Why: TOTP-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database, the CSPRNG.
     */
    public function enrollStart(string $userId, string $accountLabel): array
    {
        $row = $this->store->getEnrollment($userId);
        if ($row !== null && $row['confirmed_at'] !== null) {
            return ['error' => 'already_enrolled', 'status' => 409];
        }
        $secret = $this->generateSecret();
        $nonce = $this->rand(12);
        if (!$this->store->writeUnconfirmed($userId, seal($this->encryptionKey, $nonce, $secret, 'totp:' . $userId), $this->now())) {
            return ['error' => 'already_enrolled', 'status' => 409];
        }
        return ['secret' => $secret, 'otpauth_uri' => otpauth_uri($secret, $this->issuer, $accountLabel)];
    }

    /**
     * enroll_confirm: steps 1-8 of the spec. In: user_id, code. Out: {recovery_codes: [8]} or a refusal.
     * Why: TOTP-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database, the CSPRNG.
     */
    public function enrollConfirm(string $userId, ?string $code): array
    {
        $row = $this->store->getEnrollment($userId);
        if ($row === null) {
            return ['error' => 'enrollment_not_started', 'status' => 409];
        }
        if ($row['confirmed_at'] !== null) {
            return ['error' => 'already_enrolled', 'status' => 409];
        }
        $now = $this->now();
        $slot = $this->store->tryWrite($userId, $now);
        if ($slot === null) {
            return $this->locked($userId, $now);
        }
        $input = totp_input($code);
        if ($input === null) {
            return $this->failure($userId);
        }
        $secret = open($this->encryptionKey, $row['secret_enc'], 'totp:' . $userId);
        if ($secret === null) {
            $this->store->deleteSlot($slot);
            return ['error' => 'secret_unreadable', 'status' => 503];
        }
        $step = $this->match($secret, $input, $now);
        if ($step === null) {
            return $this->failure($userId);
        }
        if (!$this->store->confirm($userId, $now, $step, $row['secret_enc'])) {
            $again = $this->store->getEnrollment($userId);
            if ($again !== null && $again['confirmed_at'] !== null) {
                $this->store->deleteSlot($slot);
                return ['error' => 'already_enrolled', 'status' => 409];
            }
            return $this->failure($userId);
        }
        $codes = $this->makeRecoveryCodes();
        $this->store->insertRecoveryHashes($userId, array_map(fn(string $c): string => $this->codeHash($userId, str_replace('-', '', $c)), $codes), $now);
        $this->store->deleteSlot($slot);
        return ['recovery_codes' => $codes];
    }

    /**
     * verify: steps 1-5 of the spec. In: user_id (verified caller), code (missing allowed).
     * Out: {ok: true, method, recovery_codes_left} or a refusal. Why: TOTP-05..10, TOTP-13, TOTP-14.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function verify(string $userId, ?string $code): array
    {
        $row = $this->store->getEnrollment($userId);
        if ($row === null || $row['confirmed_at'] === null) {
            return ['error' => 'not_enrolled', 'status' => 409];
        }
        $now = $this->now();
        $slot = $this->store->tryWrite($userId, $now);
        if ($slot === null) {
            return $this->locked($userId, $now);
        }
        $input = totp_input($code);
        if ($input !== null) {
            if ((int)$row['failed_since_success'] >= HARD_LOCK_FAILURES) {
                $this->store->deleteSlot($slot);
                return ['error' => 'recovery_required', 'status' => 429];
            }
            $secret = open($this->encryptionKey, $row['secret_enc'], 'totp:' . $userId);
            if ($secret === null) {
                $this->store->deleteSlot($slot);
                return ['error' => 'secret_unreadable', 'status' => 503];
            }
            $step = $this->match($secret, $input, $now);
            if ($step === null || $step <= (int)$row['last_used_step'] || !$this->store->claim($userId, $step)) {
                return $this->failure($userId);
            }
            $this->store->deleteSlot($slot);
            return ['ok' => true, 'method' => 'totp', 'recovery_codes_left' => $this->store->recoveryLeft($userId)];
        }
        $recovery = recovery_input($code);
        if ($recovery !== null && $this->store->useRecoveryCode($userId, $this->codeHash($userId, $recovery), $now)) {
            $this->store->resetFailedSinceSuccess($userId);
            $this->store->deleteSlot($slot);
            return ['ok' => true, 'method' => 'recovery_code', 'recovery_codes_left' => $this->store->recoveryLeft($userId)];
        }
        return $this->failure($userId);
    }

    /**
     * disable: verify's steps 1-5 with the same answers; on ok deletes the enrollment, recovery codes and
     * failures. In: user_id, code. Out: {disabled: true} or a refusal. Why: TOTP-12. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function disable(string $userId, ?string $code): array
    {
        $r = $this->verify($userId, $code);
        if (($r['ok'] ?? false) !== true) {
            return $r;
        }
        $this->store->deleteUser($userId);
        return ['disabled' => true];
    }

    /**
     * status: {enrolled, locked_until, recovery_required, recovery_codes_left}; reading changes nothing.
     * In: user_id. Out: the status. Why: auth_system's mfa_enabled_check. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
     */
    public function status(string $userId): array
    {
        $row = $this->store->getEnrollment($userId);
        $enrolled = $row !== null && $row['confirmed_at'] !== null;
        $anchor = $this->store->lockAnchor($userId, $this->now());
        return [
            'enrolled' => $enrolled,
            'locked_until' => $anchor === null ? null : $anchor + LOCK_SECONDS,
            'recovery_required' => $enrolled && (int)$row['failed_since_success'] >= HARD_LOCK_FAILURES,
            'recovery_codes_left' => $this->store->recoveryLeft($userId),
        ];
    }

    /**
     * MATCH: compare hotp(key, s + d) for d = -1, 0, +1 (skipping negative steps) with the input, all in
     * constant time and with no early exit; the largest equal step. In: base32 secret, TOTP input, now.
     * Out: ?int. Why: TOTP-05, TOTP-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private function match(string $secretBase32, string $input, int $now): ?int
    {
        try {
            $key = base32_decode($secretBase32);
        } catch (TotpError $e) {
            return null;
        }
        $s = intdiv($now, STEP);
        $found = null;
        for ($d = -WINDOW; $d <= WINDOW; $d++) {
            if ($s + $d < 0) {
                continue;
            }
            $equal = hash_equals(hotp($key, $s + $d), $input);
            if ($equal) {
                $found = $s + $d;
            }
        }
        return $found;
    }

    /**
     * FAILURE: the slot row stays as the failure; failed_since_success + 1. Out: 401 invalid_code.
     * In: user_id. Why: TOTP-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    private function failure(string $userId): array
    {
        $this->store->addFailure($userId);
        return ['error' => 'invalid_code', 'status' => 401];
    }

    /**
     * 429 locked with retry_after = (the 5th most recent failure's at) + 900 - now. In: user_id, now.
     * Out: the refusal. Why: TOTP-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
     */
    private function locked(string $userId, int $now): array
    {
        $anchor = $this->store->lockAnchor($userId, $now);
        return ['error' => 'locked', 'status' => 429, 'retry_after' => $anchor === null ? 1 : $anchor + LOCK_SECONDS - $now];
    }

    /**
     * 8 RECOVERY CODES: symbols drawn one byte at a time (random_bytes(1) each; b >= 240 drawn again; symbol =
     * alphabet[b mod 30]); a code equal to an earlier one of the set is dropped. Out: ["xxxx-xxxx-xxxx" x 8].
     * Why: TOTP-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the CSPRNG.
     */
    private function makeRecoveryCodes(): array
    {
        $codes = [];
        while (count($codes) < RECOVERY_CODES) {
            $raw = '';
            while (strlen($raw) < 12) {
                $b = ord($this->rand(1));
                if ($b >= 240) {
                    continue;
                }
                $raw .= RECOVERY_ALPHABET[$b % 30];
            }
            $code = substr($raw, 0, 4) . '-' . substr($raw, 4, 4) . '-' . substr($raw, 8, 4);
            if (!in_array($code, $codes, true)) {
                $codes[] = $code;
            }
        }
        return $codes;
    }
}
