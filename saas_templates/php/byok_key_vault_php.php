<?php
/**
 * BYOK key vault: users' own provider API keys, sealed with AES-256-GCM envelope encryption
 * (docs/specs/byok_key_vault.md).
 *
 * What it does: save_key checks a user's key with its provider (at most 10 checks per user per clock hour,
 * counted first), seals it under a fresh data key (DEK) that is itself wrapped by a master key, and keeps only
 * the ciphertext, the wrapped DEK and a 4-character hint. use_key opens it for the same user only and records
 * every use; delete_key removes it; rewrap() moves rows to the active master key without touching ciphertext.
 *
 * Inputs/outputs: see each method; a refusal is a returned {error, status[, retry_after]}, never an
 * exception. user_id is always the verified caller.
 *
 * Why: Phase D wave 1, owner request 2026-11-10 (spec ids VAULT-01..14).
 * Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the database (provider_keys, provider_key_audit, provider_key_save_windows through PDO), the
 * CSPRNG, and the network through the injected provider client (one read-only check per save). No money,
 * no files. The key appears in full only in save_key's input and use_key's result.
 */

declare(strict_types=1);

namespace ByokKeyVault;

use PDO;
use RuntimeException;
use Throwable;

const SAVES_PER_HOUR = 10;

/**
 * Raised only by construction: invalid_master_key or invalid_provider_config (fail closed). The message is
 * only the code. Why: VAULT-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
final class VaultError extends RuntimeException
{
    private string $errorCode;

    /** In: the spec's error code. Out: the exception. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    public function __construct(string $errorCode)
    {
        parent::__construct($errorCode);
        $this->errorCode = $errorCode;
    }

    /** Out: the spec's error code. Why: VAULT-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    public function getErrorCode(): string
    {
        return $this->errorCode;
    }
}

/**
 * The provider check. The real one makes ONE read-only call that only a valid key passes (2xx or 429 = "ok";
 * 400, 401, 403 = "rejected"; anything else = "unreachable"). Tests pass a fake: no network.
 * Why: VAULT-01, VAULT-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the network (real client).
 */
interface ProviderClient
{
    /**
     * In: provider id, the trimmed key. Out: "ok" | "rejected" | "unreachable" (anything else is unreachable).
     * May throw: the vault answers 502 provider_unreachable.
     */
    public function check(string $provider, string $key);
}

/**
 * AES-256-GCM: nonce + ciphertext + 16-byte tag, base64 with padding. In: key, nonce, plaintext, aad.
 * Out: base64 text. Why: ENVELOPE. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function gcm_seal(string $key, string $nonce, string $plaintext, string $aad): string
{
    $tag = '';
    $ct = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, 16);
    if ($ct === false || strlen($tag) !== 16) {
        throw new RuntimeException('seal_failed');
    }
    return base64_encode($nonce . $ct . $tag);
}

/**
 * Open gcm_seal's output, or null for bad base64, fewer than 28 bytes, or a tag that fails (lengths checked
 * before slicing). In: key, base64 text, aad. Out: ?string. Why: VAULT-08. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function gcm_open(string $key, string $b64, string $aad): ?string
{
    $raw = base64_decode($b64, true);
    if ($raw === false || strlen($raw) < 28) {
        return null;
    }
    $pt = openssl_decrypt(substr($raw, 12, strlen($raw) - 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, -16), $aad);
    return $pt === false ? null : $pt;
}

/**
 * The SQL store. Every write the spec names is one statement or one transaction.
 *
 * Inputs: a PDO connection (SQLite in the tests). Outputs: see each method.
 * Why: VAULT-01..13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the database tables provider_keys, provider_key_audit, provider_key_save_windows.
 */
final class SqlVaultStore
{
    public PDO $db;

    /** In: PDO. Out: the store (exceptions on). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: connection settings. */
    public function __construct(PDO $db)
    {
        $this->db = $db;
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    /**
     * Create the spec's three tables if missing. Why: SCHEMA. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (DDL).
     */
    public function migrate(): void
    {
        $this->db->exec('CREATE TABLE IF NOT EXISTS provider_keys (user_id TEXT, provider TEXT, key_id TEXT NOT NULL,
            wrapped_dek TEXT NOT NULL, ciphertext TEXT NOT NULL, hint TEXT NOT NULL, created_at INT NOT NULL,
            last_used_at INT NULL, PRIMARY KEY (user_id, provider))');
        $this->db->exec('CREATE TABLE IF NOT EXISTS provider_key_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT,
            provider TEXT, action TEXT, purpose TEXT NULL, key_id TEXT, at INT)');
        $this->db->exec('CREATE TABLE IF NOT EXISTS provider_key_save_windows (user_id TEXT, window_start INT, count INT,
            PRIMARY KEY (user_id, window_start))');
    }

    /**
     * Count one provider check in the user's clock-hour window, in one conditional statement.
     * In: user_id, window start. Out: true when counted (the count was under 10). Why: VAULT-12.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (one upsert).
     */
    public function countCheck(string $userId, int $windowStart): bool
    {
        $st = $this->db->prepare('INSERT INTO provider_key_save_windows (user_id, window_start, count) VALUES (:u, :w, 1)
            ON CONFLICT (user_id, window_start) DO UPDATE SET count = provider_key_save_windows.count + 1
            WHERE provider_key_save_windows.count < ' . SAVES_PER_HOUR);
        $st->execute([':u' => $userId, ':w' => $windowStart]);
        return $st->rowCount() === 1;
    }

    /**
     * Replace the user's row for the provider and add the key_saved audit row, in ONE transaction.
     * In: the row's fields, now. Out: none; throws on failure (rolled back). Why: VAULT-01, VAULT-09.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function saveRow(string $userId, string $provider, string $keyId, string $wrapped, string $ciphertext, string $hint, int $now): void
    {
        $this->tx(function () use ($userId, $provider, $keyId, $wrapped, $ciphertext, $hint, $now): void {
            $this->db->prepare('INSERT INTO provider_keys (user_id, provider, key_id, wrapped_dek, ciphertext, hint, created_at, last_used_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT (user_id, provider) DO UPDATE SET key_id = excluded.key_id, wrapped_dek = excluded.wrapped_dek,
                ciphertext = excluded.ciphertext, hint = excluded.hint, created_at = excluded.created_at, last_used_at = NULL')
                ->execute([$userId, $provider, $keyId, $wrapped, $ciphertext, $hint, $now]);
            $this->audit($userId, $provider, 'key_saved', null, $keyId, $now);
        });
    }

    /**
     * The user's row for a provider, or null. In: user_id, provider. Out: ?array. Why: use_key.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
     */
    public function getRow(string $userId, string $provider): ?array
    {
        $st = $this->db->prepare('SELECT * FROM provider_keys WHERE user_id = ? AND provider = ?');
        $st->execute([$userId, $provider]);
        $r = $st->fetch(PDO::FETCH_ASSOC);
        return $r === false ? null : $r;
    }

    /**
     * The user's rows without secrets, sorted by provider (binary order). In: user_id. Out: rows.
     * Why: VAULT-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
     */
    public function listRows(string $userId): array
    {
        $st = $this->db->prepare('SELECT provider, hint, key_id, created_at, last_used_at FROM provider_keys WHERE user_id = ? ORDER BY provider COLLATE BINARY');
        $st->execute([$userId]);
        return array_map(static fn(array $r): array => [
            'provider' => $r['provider'], 'hint' => $r['hint'], 'key_id' => $r['key_id'],
            'created_at' => (int)$r['created_at'], 'last_used_at' => $r['last_used_at'] === null ? null : (int)$r['last_used_at'],
        ], $st->fetchAll(PDO::FETCH_ASSOC));
    }

    /**
     * last_used_at = now and the key_used audit row, in ONE transaction. In: user_id, provider, purpose,
     * key_id, now. Out: none; throws on failure (rolled back). Why: VAULT-06. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function recordUse(string $userId, string $provider, string $purpose, string $keyId, int $now): void
    {
        $this->tx(function () use ($userId, $provider, $purpose, $keyId, $now): void {
            $this->db->prepare('UPDATE provider_keys SET last_used_at = ? WHERE user_id = ? AND provider = ?')->execute([$now, $userId, $provider]);
            $this->audit($userId, $provider, 'key_used', $purpose, $keyId, $now);
        });
    }

    /**
     * Delete the row and add key_deleted, in one transaction; no row -> false and no audit row.
     * In: user_id, provider, now. Out: bool. Why: VAULT-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database.
     */
    public function deleteRow(string $userId, string $provider, int $now): bool
    {
        return $this->tx(function () use ($userId, $provider, $now): bool {
            $row = $this->getRow($userId, $provider);
            if ($row === null) {
                return false;
            }
            $st = $this->db->prepare('DELETE FROM provider_keys WHERE user_id = ? AND provider = ?');
            $st->execute([$userId, $provider]);
            if ($st->rowCount() !== 1) {
                return false;
            }
            $this->audit($userId, $provider, 'key_deleted', null, $row['key_id'], $now);
            return true;
        });
    }

    /**
     * Rows whose key_id is not the active one, in (user_id, provider) order. In: active key id. Out: rows.
     * Why: rewrap(). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
     */
    public function rowsNotUnder(string $activeKeyId): array
    {
        $st = $this->db->prepare('SELECT * FROM provider_keys WHERE key_id <> ? ORDER BY user_id COLLATE BINARY, provider COLLATE BINARY');
        $st->execute([$activeKeyId]);
        return $st->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * The rewrap write: only if the row still holds the wrapped_dek that was read; with it the key_rewrapped
     * audit row, in one transaction. In: user_id, provider, active key id, new wrapped DEK, the wrapped DEK
     * read, now. Out: true when one row changed. Why: VAULT-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database.
     */
    public function rewrapRow(string $userId, string $provider, string $active, string $newWrapped, string $wrappedRead, int $now): bool
    {
        return $this->tx(function () use ($userId, $provider, $active, $newWrapped, $wrappedRead, $now): bool {
            $st = $this->db->prepare('UPDATE provider_keys SET key_id = :active, wrapped_dek = :new_wrapped
                WHERE user_id = :u AND provider = :p AND wrapped_dek = :wrapped_dek_read');
            $st->execute([':active' => $active, ':new_wrapped' => $newWrapped, ':u' => $userId, ':p' => $provider, ':wrapped_dek_read' => $wrappedRead]);
            if ($st->rowCount() !== 1) {
                return false;
            }
            $this->audit($userId, $provider, 'key_rewrapped', null, $active, $now);
            return true;
        });
    }

    /**
     * The user's audit rows, oldest first. In: user_id. Out: [{at, action, provider, purpose, key_id}].
     * Why: list_audit. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
     */
    public function listAudit(string $userId): array
    {
        $st = $this->db->prepare('SELECT at, action, provider, purpose, key_id FROM provider_key_audit WHERE user_id = ? ORDER BY id');
        $st->execute([$userId]);
        return array_map(static fn(array $r): array => [
            'at' => (int)$r['at'], 'action' => $r['action'], 'provider' => $r['provider'], 'purpose' => $r['purpose'], 'key_id' => $r['key_id'],
        ], $st->fetchAll(PDO::FETCH_ASSOC));
    }

    /**
     * Insert one audit row. In: its fields. Out: none. Why: every use is recorded. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    private function audit(string $userId, string $provider, string $action, ?string $purpose, string $keyId, int $now): void
    {
        $this->db->prepare('INSERT INTO provider_key_audit (user_id, provider, action, purpose, key_id, at) VALUES (?, ?, ?, ?, ?, ?)')
            ->execute([$userId, $provider, $action, $purpose, $keyId, $now]);
    }

    /**
     * Run a callable in one transaction; roll back and re-throw on any error. In: callable. Out: its result.
     * Why: ONE transaction rules. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    private function tx(callable $fn)
    {
        $this->db->beginTransaction();
        try {
            $r = $fn();
            $this->db->commit();
            return $r;
        } catch (Throwable $e) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            throw $e;
        }
    }
}

/**
 * The vault: save_key, list_keys, use_key, delete_key, rewrap, list_audit.
 *
 * Inputs: store, master_keys {key_id: 32 bytes}, active_key_id, providers {id: {prefix, min_length,
 * max_length}}, provider client, clock, random_bytes(n). Outputs: see each method.
 * Why: VAULT-01..14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the database, the CSPRNG, the provider client (network in production).
 */
final class KeyVault
{
    private SqlVaultStore $store;
    private array $masterKeys;
    private string $activeKeyId;
    private array $providers;
    private ProviderClient $client;
    /** @var callable(): int */
    private $clock;
    /** @var callable(int): string */
    private $randomBytes;

    /**
     * Build the vault, failing closed: invalid_master_key for a master key that is not 32 bytes, a malformed
     * key_id or an active_key_id not in master_keys; invalid_provider_config for a malformed provider.
     * In: see the class. Out: the vault. Why: VAULT-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: nothing.
     */
    public function __construct(SqlVaultStore $store, array $masterKeys, string $activeKeyId, array $providers,
                                ProviderClient $client, ?callable $clock = null, ?callable $randomBytes = null)
    {
        foreach ($masterKeys as $id => $key) {
            if (!is_string($key) || strlen($key) !== 32 || preg_match('/^[A-Za-z0-9_-]{1,32}$/D', (string)$id) !== 1) {
                throw new VaultError('invalid_master_key');
            }
        }
        if (!array_key_exists($activeKeyId, $masterKeys)) {
            throw new VaultError('invalid_master_key');
        }
        foreach ($providers as $id => $p) {
            $prefix = $p['prefix'] ?? null;
            $min = $p['min_length'] ?? null;
            $max = $p['max_length'] ?? null;
            if (preg_match('/^[a-z0-9_]{1,32}$/D', (string)$id) !== 1 || !is_string($prefix) || !is_int($min) || !is_int($max)
                || $min < 20 || $min > $max || $max > 4096 || $min < strlen($prefix) + 16) {
                throw new VaultError('invalid_provider_config');
            }
        }
        $this->store = $store;
        $this->masterKeys = $masterKeys;
        $this->activeKeyId = $activeKeyId;
        $this->providers = $providers;
        $this->client = $client;
        $this->clock = $clock ?? static fn(): int => time();
        $this->randomBytes = $randomBytes ?? static fn(int $n): string => random_bytes($n);
    }

    /** The injected time. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the clock. */
    private function now(): int
    {
        return (int)($this->clock)();
    }

    /** Exactly n random bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the CSPRNG. */
    private function rand(int $n): string
    {
        $b = ($this->randomBytes)($n);
        if (!is_string($b) || strlen($b) !== $n) {
            throw new RuntimeException('random_bytes_short');
        }
        return $b;
    }

    /** aad of the data ciphertext. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    private static function dataAad(string $provider, string $userId): string
    {
        return 'byok:data:' . $provider . ':' . $userId;
    }

    /** aad of the wrapped DEK. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    private static function dekAad(string $keyId, string $provider, string $userId): string
    {
        return 'byok:dek:' . $keyId . ':' . $provider . ':' . $userId;
    }

    /**
     * save_key: steps 1-6 of the spec. In: user_id (verified caller), provider, key (missing allowed).
     * Out: {provider, hint, key_id, created_at} or a refusal. Why: VAULT-01..04, VAULT-09, VAULT-12.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database, the CSPRNG, the provider client.
     */
    public function saveKey(string $userId, string $provider, ?string $key): array
    {
        if (!isset($this->providers[$provider])) {
            return ['error' => 'unknown_provider', 'status' => 404];
        }
        if ($key === null) {
            return ['error' => 'invalid_key_format', 'status' => 400];
        }
        $cfg = $this->providers[$provider];
        $k = trim($key, " \t\r\n");
        $len = strlen($k);
        if (strncmp($k, $cfg['prefix'], strlen($cfg['prefix'])) !== 0 || $len < $cfg['min_length'] || $len > $cfg['max_length']
            || preg_match('/^[\x21-\x7E]*$/D', $k) !== 1) {
            return ['error' => 'invalid_key_format', 'status' => 400];
        }
        $now = $this->now();
        $w = $now - ($now % 3600);
        if (!$this->store->countCheck($userId, $w)) {
            return ['error' => 'rate_limited', 'status' => 429, 'retry_after' => $w + 3600 - $now];
        }
        try {
            $v = $this->client->check($provider, $k);
        } catch (Throwable $e) {
            $v = null;
        }
        if ($v === 'rejected') {
            return ['error' => 'key_rejected', 'status' => 400];
        }
        if ($v !== 'ok') {
            return ['error' => 'provider_unreachable', 'status' => 502];
        }
        $dek = $this->rand(32);
        $dataNonce = $this->rand(12);
        $wrapNonce = $this->rand(12);
        $keyId = $this->activeKeyId;
        $ciphertext = gcm_seal($dek, $dataNonce, $k, self::dataAad($provider, $userId));
        $wrapped = gcm_seal($this->masterKeys[$keyId], $wrapNonce, $dek, self::dekAad($keyId, $provider, $userId));
        $hint = substr($k, -4);
        try {
            $this->store->saveRow($userId, $provider, $keyId, $wrapped, $ciphertext, $hint, $now);
        } catch (Throwable $e) {
            return ['error' => 'storage_failed', 'status' => 500];
        }
        return ['provider' => $provider, 'hint' => $hint, 'key_id' => $keyId, 'created_at' => $now];
    }

    /**
     * list_keys: [{provider, hint, key_id, created_at, last_used_at}] sorted by provider; no secret.
     * In: user_id. Out: list. Why: VAULT-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function listKeys(string $userId): array
    {
        return $this->store->listRows($userId);
    }

    /**
     * use_key (SERVER-SIDE ONLY): steps 1-5 of the spec. In: user_id, provider, purpose. Out: {key} or a
     * refusal; no key unless last_used_at and the key_used audit row were written together.
     * Why: VAULT-06..08, VAULT-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function useKey(string $userId, string $provider, ?string $purpose): array
    {
        if ($purpose === null || preg_match('/^[A-Za-z0-9_.:-]{1,100}$/D', $purpose) !== 1) {
            return ['error' => 'invalid_purpose', 'status' => 400];
        }
        $row = $this->store->getRow($userId, $provider);
        if ($row === null) {
            return ['error' => 'key_not_found', 'status' => 404];
        }
        $keyId = (string)$row['key_id'];
        if (!array_key_exists($keyId, $this->masterKeys)) {
            return ['error' => 'key_unavailable', 'status' => 503];
        }
        $dek = gcm_open($this->masterKeys[$keyId], (string)$row['wrapped_dek'], self::dekAad($keyId, $provider, $userId));
        $key = ($dek !== null && strlen($dek) === 32) ? gcm_open($dek, (string)$row['ciphertext'], self::dataAad($provider, $userId)) : null;
        if ($key === null) {
            return ['error' => 'key_unreadable', 'status' => 500];
        }
        try {
            $this->store->recordUse($userId, $provider, $purpose, $keyId, $this->now());
        } catch (Throwable $e) {
            return ['error' => 'storage_failed', 'status' => 500];
        }
        return ['key' => $key];
    }

    /**
     * delete_key: {deleted: true} with a key_deleted audit row, or {deleted: false} when there was no row.
     * In: user_id, provider. Out: the answer. Why: VAULT-07, VAULT-13. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function deleteKey(string $userId, string $provider): array
    {
        try {
            return ['deleted' => $this->store->deleteRow($userId, $provider, $this->now())];
        } catch (Throwable $e) {
            return ['error' => 'storage_failed', 'status' => 500];
        }
    }

    /**
     * rewrap (OPERATOR ONLY): re-wrap every DEK not under the active master key, never touching ciphertext;
     * a row changed meanwhile is left alone and counted in neither number. Out: {rewrapped, failed}.
     * Why: VAULT-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database, the CSPRNG.
     */
    public function rewrap(): array
    {
        $rewrapped = 0;
        $failed = 0;
        foreach ($this->store->rowsNotUnder($this->activeKeyId) as $row) {
            $userId = (string)$row['user_id'];
            $provider = (string)$row['provider'];
            $oldId = (string)$row['key_id'];
            $dek = array_key_exists($oldId, $this->masterKeys)
                ? gcm_open($this->masterKeys[$oldId], (string)$row['wrapped_dek'], self::dekAad($oldId, $provider, $userId)) : null;
            if ($dek === null || strlen($dek) !== 32) {
                $failed++;
                continue;
            }
            $new = gcm_seal($this->masterKeys[$this->activeKeyId], $this->rand(12), $dek, self::dekAad($this->activeKeyId, $provider, $userId));
            if ($this->store->rewrapRow($userId, $provider, $this->activeKeyId, $new, (string)$row['wrapped_dek'], $this->now())) {
                $rewrapped++;
            }
        }
        return ['rewrapped' => $rewrapped, 'failed' => $failed];
    }

    /**
     * list_audit: the user's audit rows, oldest first. In: user_id. Out: [{at, action, provider, purpose,
     * key_id}]. Why: every use is recorded. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function listAudit(string $userId): array
    {
        return $this->store->listAudit($userId);
    }
}
