<?php
/**
 * Passwordless sign-in with an emailed 6-digit code (docs/specs/passwordless_email_code_signin.md).
 *
 * What it does: start() sends a one-time 6-digit code (10 minutes, one per address, 5 tries) and answers the
 * same whether or not the address has an account; verify() counts the try first, compares in constant time,
 * uses the code up with one conditional delete, and finds or creates the account (revoking the credentials of
 * an existing row nobody had proven). Sends and tries are limited per address and per IP in clock-hour and
 * clock-day windows. The code, the address and the IP are stored only as HMAC-SHA256 under the server secret.
 *
 * Inputs/outputs: see each method; a refusal is a returned {error, status}, never an exception.
 *
 * Why: Phase D wave 1, owner request 2026-11-10 (spec ids EMAILCODE-01..14).
 * Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the database (accounts, email_codes, rate_windows through PDO), the CSPRNG, and email through the
 * injected sender (network in production). No money, no files. Never logs the code, the address or the secret.
 */

declare(strict_types=1);

namespace PasswordlessEmailCodeSignin;

use PDO;
use RuntimeException;
use Throwable;

const CODE_TTL = 600;
const CODE_ATTEMPTS = 5;
const START_PER_EMAIL_HOUR = 5;
const START_PER_EMAIL_DAY = 10;
const START_PER_IP_HOUR = 20;
const VERIFY_PER_IP_HOUR = 30;
const VERIFY_PER_EMAIL_HOUR = 10;

/**
 * Raised only by construction (not_configured: a secret under 32 bytes or no sender). The message is only
 * the code. Why: EMAILCODE-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
final class SigninError extends RuntimeException
{
    private string $errorCode;

    /** In: the spec's error code. Out: the exception. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    public function __construct(string $errorCode)
    {
        parent::__construct($errorCode);
        $this->errorCode = $errorCode;
    }

    /** Out: the spec's error code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    public function getErrorCode(): string
    {
        return $this->errorCode;
    }
}

/**
 * normalize_email: trim space, tab, CR, LF; map A-Z to a-z; 3 to 254 characters matching the whole pattern
 * [a-z0-9][a-z0-9._%+=-]*@[a-z0-9-]+(\.[a-z0-9-]+)+. In: ?string. Out: the address or null.
 * Why: EMAILCODE-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function normalize_email(?string $raw): ?string
{
    if ($raw === null) {
        return null;
    }
    $e = strtr(trim($raw, " \t\r\n"), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz');
    $n = strlen($e);
    if ($n < 3 || $n > 254 || preg_match('/^[a-z0-9][a-z0-9._%+=-]*@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/D', $e) !== 1) {
        return null;
    }
    return $e;
}

/**
 * The accounts store: auth_system's users table seen through three operations.
 * Why: "Do not keep two tables of people". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
 */
interface AccountStore
{
    /** The row {id, email, email_verified_at, status, created_at} for an address, or null. */
    public function findByEmail(string $email): ?array;

    /** Insert a verified active account unless a row with that email exists. */
    public function insertVerifiedIfAbsent(string $id, string $email, int $now): void;

    /** Set email_verified_at = now on a row where it is still null. */
    public function markVerified(string $id, int $now): void;
}

/**
 * SQL accounts store. In: PDO. Why: SCHEMA accounts. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the database table accounts.
 */
final class SqlAccountStore implements AccountStore
{
    private PDO $db;

    /** In: PDO. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: connection settings. */
    public function __construct(PDO $db)
    {
        $this->db = $db;
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    /** Create the accounts table if missing. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (DDL). */
    public function migrate(): void
    {
        $this->db->exec("CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE,
            email_verified_at INT NULL, status TEXT NOT NULL DEFAULT 'active', created_at INT NOT NULL)");
    }

    /** See AccountStore. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read). */
    public function findByEmail(string $email): ?array
    {
        $st = $this->db->prepare('SELECT * FROM accounts WHERE email = ?');
        $st->execute([$email]);
        $r = $st->fetch(PDO::FETCH_ASSOC);
        return $r === false ? null : $r;
    }

    /** See AccountStore; one insert that does nothing on a duplicate email. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database. */
    public function insertVerifiedIfAbsent(string $id, string $email, int $now): void
    {
        $this->db->prepare("INSERT INTO accounts (id, email, email_verified_at, status, created_at) VALUES (?, ?, ?, 'active', ?)
            ON CONFLICT (email) DO NOTHING")->execute([$id, $email, $now, $now]);
    }

    /** See AccountStore. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database. */
    public function markVerified(string $id, int $now): void
    {
        $this->db->prepare('UPDATE accounts SET email_verified_at = ? WHERE id = ? AND email_verified_at IS NULL')->execute([$now, $id]);
    }
}

/**
 * SQL store for email_codes and rate_windows. Every write the spec names is one statement, or one
 * transaction whose first statement is the write (so it holds the lock). Why: SCHEMA. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database tables email_codes and rate_windows.
 */
final class SqlCodeStore
{
    public PDO $db;

    /** In: PDO. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: connection settings. */
    public function __construct(PDO $db)
    {
        $this->db = $db;
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    /** Create both tables if missing. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (DDL). */
    public function migrate(): void
    {
        $this->db->exec('CREATE TABLE IF NOT EXISTS email_codes (email_hash TEXT PRIMARY KEY, code_hash TEXT NOT NULL,
            expires_at INT NOT NULL, attempts INT NOT NULL DEFAULT 0, created_at INT NOT NULL)');
        $this->db->exec('CREATE TABLE IF NOT EXISTS rate_windows (key TEXT, window_start INT, count INT NOT NULL,
            PRIMARY KEY (key, window_start))');
    }

    /**
     * BUMP: insert (key, window_start, 1) or add 1, and read the count after it, in one transaction that writes
     * first. In: key, window start. Out: the count. Why: EMAILCODE-08..10. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function bump(string $key, int $windowStart): int
    {
        $this->db->beginTransaction();
        try {
            $this->db->prepare('INSERT INTO rate_windows (key, window_start, count) VALUES (?, ?, 1)
                ON CONFLICT (key, window_start) DO UPDATE SET count = rate_windows.count + 1')->execute([$key, $windowStart]);
            $st = $this->db->prepare('SELECT count FROM rate_windows WHERE key = ? AND window_start = ?');
            $st->execute([$key, $windowStart]);
            $n = (int)$st->fetchColumn();
            $this->db->commit();
            return $n;
        } catch (Throwable $e) {
            $this->db->rollBack();
            throw $e;
        }
    }

    /**
     * Write the address's code row, replacing an earlier one. In: email_hash, code_hash, now. Out: none.
     * Why: start step 4. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function putCode(string $emailHash, string $codeHash, int $now): void
    {
        $this->db->prepare('INSERT INTO email_codes (email_hash, code_hash, expires_at, attempts, created_at) VALUES (?, ?, ?, 0, ?)
            ON CONFLICT (email_hash) DO UPDATE SET code_hash = excluded.code_hash, expires_at = excluded.expires_at,
            attempts = 0, created_at = excluded.created_at')->execute([$emailHash, $codeHash, $now + CODE_TTL, $now]);
    }

    /**
     * Remove only this code (a parallel start may have replaced it). In: email_hash, code_hash. Out: none.
     * Why: start step 5. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function deleteCode(string $emailHash, string $codeHash): bool
    {
        $st = $this->db->prepare('DELETE FROM email_codes WHERE email_hash = :h AND code_hash = :c');
        $st->execute([':h' => $emailHash, ':c' => $codeHash]);
        return $st->rowCount() === 1;
    }

    /**
     * COUNT THE TRY FIRST: the conditional UPDATE, then (in the same transaction, which the UPDATE locked) the
     * stored code_hash and the new attempts. In: email_hash, now. Out: [code_hash, attempts] or null when no
     * row changed. Why: verify step 4. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function countTry(string $emailHash, int $now): ?array
    {
        $this->db->beginTransaction();
        try {
            $st = $this->db->prepare('UPDATE email_codes SET attempts = attempts + 1
                WHERE email_hash = :h AND attempts < ' . CODE_ATTEMPTS . ' AND expires_at > :now');
            $st->execute([':h' => $emailHash, ':now' => $now]);
            $out = null;
            if ($st->rowCount() === 1) {
                $q = $this->db->prepare('SELECT code_hash, attempts FROM email_codes WHERE email_hash = ?');
                $q->execute([$emailHash]);
                $r = $q->fetch(PDO::FETCH_ASSOC);
                $out = [(string)$r['code_hash'], (int)$r['attempts']];
            }
            $this->db->commit();
            return $out;
        } catch (Throwable $e) {
            $this->db->rollBack();
            throw $e;
        }
    }

    /**
     * Delete the address's row when it is expired or used up. In: email_hash, now. Out: none.
     * Why: verify step 4. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function deleteDead(string $emailHash, int $now): void
    {
        $this->db->prepare('DELETE FROM email_codes WHERE email_hash = :h AND (attempts >= ' . CODE_ATTEMPTS . ' OR expires_at <= :now)')
            ->execute([':h' => $emailHash, ':now' => $now]);
    }
}

/**
 * The sign-in service: start and verify.
 *
 * Inputs: code store, account store, secret (>= 32 bytes), sender(to, code, expires_in) -> bool,
 * revoke_unproven(account_id), clock, random_bytes(n), generate_code(). Outputs: see each method.
 * Why: EMAILCODE-01..14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the database, the CSPRNG, the sender (email).
 */
final class EmailCodeSignin
{
    private SqlCodeStore $codes;
    private AccountStore $accounts;
    private string $secret;
    /** @var callable(string, string, int): bool */
    private $sender;
    /** @var callable(string): void */
    private $revokeUnproven;
    /** @var callable(): int */
    private $clock;
    /** @var callable(int): string */
    private $randomBytes;
    /** @var callable(): string */
    private $generateCode;

    /**
     * Build the service; a secret under 32 bytes or no sender fails with not_configured (fail closed).
     * In: see the class. Out: the service. Why: EMAILCODE-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: nothing.
     */
    public function __construct(SqlCodeStore $codes, AccountStore $accounts, string $secret, ?callable $sender,
                                ?callable $revokeUnproven = null, ?callable $clock = null, ?callable $randomBytes = null,
                                ?callable $generateCode = null)
    {
        if (strlen($secret) < 32 || $sender === null) {
            throw new SigninError('not_configured');
        }
        $this->codes = $codes;
        $this->accounts = $accounts;
        $this->secret = $secret;
        $this->sender = $sender;
        $this->revokeUnproven = $revokeUnproven ?? static function (string $id): void {
        };
        $this->clock = $clock ?? static fn(): int => time();
        $this->randomBytes = $randomBytes ?? static fn(int $n): string => random_bytes($n);
        $this->generateCode = $generateCode ?? fn(): string => $this->defaultCode();
    }

    /** The injected time. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the clock. */
    private function now(): int
    {
        return (int)($this->clock)();
    }

    /** hmac_hex(text). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    public function hmacHex(string $text): string
    {
        return hash_hmac('sha256', $text, $this->secret);
    }

    /** email_hash(email). Why: EMAILCODE-02. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    public function emailHash(string $email): string
    {
        return $this->hmacHex('email:' . $email);
    }

    /** code_hash(email, code). Why: EMAILCODE-02, EMAILCODE-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    public function codeHash(string $email, string $code): string
    {
        return $this->hmacHex('code:' . $this->emailHash($email) . ':' . $code);
    }

    /** ip_hash(ip): the first 32 characters. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    public function ipHash(string $ip): string
    {
        return substr($this->hmacHex('ip:' . $ip), 0, 32);
    }

    /** EK(email): the first 32 characters of email_hash. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    private function ek(string $email): string
    {
        return substr($this->emailHash($email), 0, 32);
    }

    /**
     * CODE: an unsigned big-endian u32 from random_bytes(4); n >= 4294000000 is drawn again; n mod 1000000 with
     * 6 digits. Out: the code. Why: EMAILCODE-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the CSPRNG.
     */
    public function defaultCode(): string
    {
        do {
            $b = ($this->randomBytes)(4);
            if (strlen($b) !== 4) {
                throw new RuntimeException('random_bytes_short');
            }
            $n = unpack('N', $b)[1];
        } while ($n >= 4294000000);
        return str_pad((string)($n % 1000000), 6, '0', STR_PAD_LEFT);
    }

    /**
     * BUMP(key, span): one atomic count in the clock window. In: key, 3600 or 86400. Out: the count after.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    private function bump(string $key, int $span): int
    {
        $now = $this->now();
        return $this->codes->bump($key, $now - ($now % $span));
    }

    /**
     * start: steps 1-6 of the spec; never reads accounts. In: email (missing allowed), ip (missing ->
     * "unknown"). Out: {status: 202, sent: true, expires_in: 600} or a refusal.
     * Why: EMAILCODE-01, 02, 06..09, 11, 12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database, the sender.
     */
    public function start(?string $email, ?string $ip): array
    {
        $e = normalize_email($email);
        if ($e === null) {
            return ['error' => 'invalid_email', 'status' => 422];
        }
        $ip = ($ip === null || $ip === '') ? 'unknown' : $ip;
        $limited = ['error' => 'too_many_requests', 'status' => 429];
        if ($this->bump('start-ip#' . $this->ipHash($ip), 3600) > START_PER_IP_HOUR) {
            return $limited;
        }
        $h = $this->bump('start-email#' . $this->ek($e), 3600);
        $d = $this->bump('start-email-day#' . $this->ek($e), 86400);
        if ($h > START_PER_EMAIL_HOUR || $d > START_PER_EMAIL_DAY) {
            return $limited;
        }
        $code = (string)($this->generateCode)();
        $emailHash = $this->emailHash($e);
        $codeHash = $this->codeHash($e, $code);
        $this->codes->putCode($emailHash, $codeHash, $this->now());
        try {
            $sent = ($this->sender)($e, $code, CODE_TTL) === true;
        } catch (Throwable $ex) {
            $sent = false;
        }
        if (!$sent) {
            $this->codes->deleteCode($emailHash, $codeHash);
            return ['error' => 'send_failed', 'status' => 503];
        }
        return ['status' => 202, 'sent' => true, 'expires_in' => CODE_TTL];
    }

    /**
     * verify: steps 1-9 of the spec. In: email, code (missing allowed), ip. Out: {status: 200, account_id,
     * email, new_account} or a refusal. Why: EMAILCODE-01, 03..07, 10, 11, 13, 14. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database, the revoke hook.
     */
    public function verify(?string $email, ?string $code, ?string $ip): array
    {
        $ip = ($ip === null || $ip === '') ? 'unknown' : $ip;
        $limited = ['error' => 'too_many_requests', 'status' => 429];
        $invalid = ['error' => 'invalid_code', 'status' => 400];
        if ($this->bump('verify-ip#' . $this->ipHash($ip), 3600) > VERIFY_PER_IP_HOUR) {
            return $limited;
        }
        $e = normalize_email($email);
        $c = $code === null ? '' : str_replace([' ', '-'], '', $code);
        if ($e === null || strlen($c) !== 6 || strspn($c, '0123456789') !== 6) {
            return $invalid;
        }
        if ($this->bump('verify-email#' . $this->ek($e), 3600) > VERIFY_PER_EMAIL_HOUR) {
            return $limited;
        }
        $now = $this->now();
        $h = $this->emailHash($e);
        $offered = $this->codeHash($e, $c);
        $try = $this->codes->countTry($h, $now);
        if ($try === null) {
            $this->codes->deleteDead($h, $now);
            hash_equals(str_repeat('0', 64), $offered);
            return $invalid;
        }
        [$stored, $attempts] = $try;
        if (!hash_equals($stored, $offered)) {
            if ($attempts >= CODE_ATTEMPTS) {
                $this->codes->deleteDead($h, $now);
            }
            return $invalid;
        }
        if (!$this->codes->deleteCode($h, $stored)) {
            return $invalid;
        }
        $id = bin2hex(($this->randomBytes)(16));
        $this->accounts->insertVerifiedIfAbsent($id, $e, $now);
        $row = $this->accounts->findByEmail($e);
        if ($row === null) {
            return ['error' => 'processing_failed', 'status' => 500];
        }
        $newAccount = $row['id'] === $id;
        if (!$newAccount && $row['email_verified_at'] === null) {
            try {
                ($this->revokeUnproven)((string)$row['id']);
            } catch (Throwable $ex) {
                return ['error' => 'processing_failed', 'status' => 500];
            }
            $this->accounts->markVerified((string)$row['id'], $now);
        }
        if ($row['status'] !== 'active') {
            return ['error' => 'account_unavailable', 'status' => 403];
        }
        return ['status' => 200, 'account_id' => (string)$row['id'], 'email' => $e, 'new_account' => $newAccount];
    }
}
