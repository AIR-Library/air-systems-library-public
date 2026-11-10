<?php

declare(strict_types=1);

namespace TrialAbusePrevention;

use PDO;
use PDOException;
use DateTime;
use DateTimeImmutable;
use DateTimeInterface;
use InvalidArgumentException;
use RuntimeException;

/**
 * Trial Abuse Prevention module.
 *
 * Implements the 6-gate abuse detection pipeline (email trial history, payment
 * method history, IP signup rate limit, device fingerprint, trial payment
 * timing, chargeback history) with a shared why-chain audit log.
 *
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (TRIAL-09/10/11/14/15 as amended): the device gate counts OTHER
 * users (null-safe) and decides FAIL >= 5, PASS < 2, PASS for the user's own device, else CHALLENGE; the
 * device row is written after the decision and only for PASS/CHALLENGE, and signup runs the gate before
 * recording (recording first made a device farm always pass). Payment timing judges the payment being added
 * now: days_after_trial = floor((now - (created_at + trial_days)) / 1 day); PASS < 5, FAIL >= 90 with no
 * earlier payment, else CHALLENGE; trial_days is configuration (default 14).
 * Touches: the database (all tables below). No network.
 */
final class TrialAbusePrevention
{
    public const DECISION_PASS = 'PASS';
    public const DECISION_CHALLENGE = 'CHALLENGE';
    public const DECISION_FAIL = 'FAIL';

    private const STATUS_COMPLETED = 'completed';
    private const STATUS_CHARGEBACKED = 'chargebacked';

    private const IP_LIMIT_PASS = 5;
    private const IP_LIMIT_CHALLENGE = 10;
    private const IP_WINDOW_HOURS = 24;
    private const IP_RETRY_AFTER_SECONDS = 86400;

    private const DEVICE_LIMIT_CHALLENGE = 2;
    private const DEVICE_LIMIT_FAIL = 5;

    private const CHARGEBACK_LIMIT_CHALLENGE = 1;
    private const CHARGEBACK_LIMIT_FAIL = 2;

    private const PAYMENT_LIMIT_CHALLENGE = 2;
    private const PAYMENT_LIMIT_FAIL = 3;

    private const EMAIL_LIMIT_CHALLENGE = 1;
    private const EMAIL_LIMIT_FAIL = 2;

    private const LATE_PAYMENT_GRACE_DAYS = 5;
    private const READD_BLOCK_DAYS = 90;

    private const CHALLENGE_CAPTCHA = 'captcha';
    private const CHALLENGE_EMAIL_CONFIRM = 'email_confirm';

    private const GATE_EMAIL_TRIAL_HISTORY = 'email_trial_history';
    private const GATE_PAYMENT_METHOD_HISTORY = 'payment_method_history';
    private const GATE_IP_SIGNUP_RATE_LIMIT = 'ip_signup_rate_limit';
    private const GATE_DEVICE_FINGERPRINT = 'device_fingerprint';
    private const GATE_TRIAL_PAYMENT_TIMING = 'trial_payment_timing';
    private const GATE_CHARGEBACK_HISTORY = 'chargeback_history';

    private PDO $db;
    private ?string $nowOverride;
    private int $trialDays;

    /**
     * Inputs: $db (shared connection), $nowOverride (fixed "now" for tests and replays; null = the system
     * clock, UTC), $trialDays (trial length for new signups; configuration, default 14).
     * Why: trial_days is configurable (amended TRIAL-10/11/15). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: nothing until a method is called.
     */
    public function __construct(PDO $db, ?string $nowOverride = null, int $trialDays = 14)
    {
        if ($trialDays < 0) {
            throw new InvalidArgumentException('trial_days must not be negative');
        }
        $this->db = $db;
        $this->nowOverride = $nowOverride;
        $this->trialDays = $trialDays;
    }

    /**
     * Execute the DDL for the abuse-prevention tables. Idempotent.
     */
    public static function migrate(PDO $db): void
    {
        $db->exec(
            'CREATE TABLE IF NOT EXISTS trial_abuse_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                email TEXT NOT NULL,
                stripe_payment_method_id TEXT,
                ip TEXT,
                device_fingerprint TEXT,
                signup_date TEXT NOT NULL,
                trial_started_at TEXT NOT NULL,
                payment_added_date TEXT,
                subscription_status TEXT NOT NULL DEFAULT "trialing",
                chargeback_count INTEGER NOT NULL DEFAULT 0,
                refund_count INTEGER NOT NULL DEFAULT 0,
                gate_flags TEXT,
                alert_reason TEXT,
                created_at TEXT NOT NULL
            )'
        );

        $db->exec(
            'CREATE TABLE IF NOT EXISTS device_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                device_hash TEXT NOT NULL,
                user_agent TEXT,
                screen_resolution TEXT,
                timezone TEXT,
                created_at TEXT NOT NULL
            )'
        );

        $db->exec(
            'CREATE TABLE IF NOT EXISTS gate_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                gate_name TEXT NOT NULL,
                decision TEXT NOT NULL,
                rule_inputs TEXT,
                rule_outputs TEXT,
                created_at TEXT NOT NULL
            )'
        );

        $db->exec(
            'CREATE TABLE IF NOT EXISTS signups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                email TEXT,
                ip TEXT NOT NULL,
                created_at TEXT NOT NULL
            )'
        );

        $db->exec(
            'CREATE TABLE IF NOT EXISTS stripe_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer TEXT NOT NULL,
                type TEXT NOT NULL,
                created_at TEXT NOT NULL
            )'
        );

        $db->exec(
            'CREATE TABLE IF NOT EXISTS refunds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )'
        );

        $db->exec(
            'CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                abuse_flags TEXT,
                stripe_customer_id TEXT,
                trial_days INTEGER NOT NULL DEFAULT 14,
                created_at TEXT NOT NULL
            )'
        );

        $db->exec(
            'CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                stripe_payment_method_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT "active",
                created_at TEXT NOT NULL
            )'
        );
    }

    /**
     * Gate 1: email trial history.
     */
    public function checkEmailTrialHistory(string $email): GateResult
    {
        $stmt = $this->db->prepare(
            'SELECT COUNT(*) FROM trial_abuse_ledger
             WHERE email = :email AND subscription_status IN (:s1, :s2)'
        );
        $stmt->execute([
            'email' => $email,
            's1' => self::STATUS_COMPLETED,
            's2' => self::STATUS_CHARGEBACKED,
        ]);
        $priorCount = (int) $stmt->fetchColumn();

        if ($priorCount >= self::EMAIL_LIMIT_FAIL) {
            $decision = self::DECISION_FAIL;
        } elseif ($priorCount >= self::EMAIL_LIMIT_CHALLENGE) {
            $decision = self::DECISION_CHALLENGE;
        } else {
            $decision = self::DECISION_PASS;
        }

        $this->logGate(
            self::GATE_EMAIL_TRIAL_HISTORY,
            null,
            $decision,
            ['email' => $email, 'prior_count' => $priorCount],
            ['decision' => $decision]
        );

        return new GateResult(
            self::GATE_EMAIL_TRIAL_HISTORY,
            $decision,
            ['email' => $email, 'prior_count' => $priorCount],
            ['decision' => $decision]
        );
    }

    /**
     * Gate 2: payment method history.
     */
    public function checkPaymentMethodHistory(string $stripePaymentMethodId): GateResult
    {
        $stmt = $this->db->prepare(
            'SELECT COUNT(*) FROM trial_abuse_ledger
             WHERE stripe_payment_method_id = :pmid AND subscription_status IN (:s1, :s2)'
        );
        $stmt->execute([
            'pmid' => $stripePaymentMethodId,
            's1' => self::STATUS_COMPLETED,
            's2' => self::STATUS_CHARGEBACKED,
        ]);
        $priorCount = (int) $stmt->fetchColumn();

        if ($priorCount >= self::PAYMENT_LIMIT_FAIL) {
            $decision = self::DECISION_FAIL;
        } elseif ($priorCount >= self::PAYMENT_LIMIT_CHALLENGE) {
            $decision = self::DECISION_CHALLENGE;
        } else {
            $decision = self::DECISION_PASS;
        }

        $this->logGate(
            self::GATE_PAYMENT_METHOD_HISTORY,
            null,
            $decision,
            ['payment_id' => $stripePaymentMethodId, 'prior_count' => $priorCount],
            ['decision' => $decision]
        );

        return new GateResult(
            self::GATE_PAYMENT_METHOD_HISTORY,
            $decision,
            ['payment_id' => $stripePaymentMethodId, 'prior_count' => $priorCount],
            ['decision' => $decision]
        );
    }

    /**
     * Gate 3: IP signup rate limit.
     */
    public function checkIpSignupRateLimit(string $ip): GateResult
    {
        $cutoff = $this->now()->modify('-' . self::IP_WINDOW_HOURS . ' hours')->format('Y-m-d H:i:s');
        $stmt = $this->db->prepare(
            'SELECT COUNT(*) FROM signups WHERE ip = :ip AND created_at > :cutoff'
        );
        $stmt->execute(['ip' => $ip, 'cutoff' => $cutoff]);
        $count = (int) $stmt->fetchColumn();

        if ($count >= self::IP_LIMIT_CHALLENGE) {
            $decision = self::DECISION_FAIL;
        } elseif ($count >= self::IP_LIMIT_PASS) {
            $decision = self::DECISION_CHALLENGE;
        } else {
            $decision = self::DECISION_PASS;
        }

        $this->logGate(
            self::GATE_IP_SIGNUP_RATE_LIMIT,
            null,
            $decision,
            ['ip' => $ip, 'count' => $count, 'limit' => self::IP_LIMIT_CHALLENGE],
            ['decision' => $decision]
        );

        return new GateResult(
            self::GATE_IP_SIGNUP_RATE_LIMIT,
            $decision,
            ['ip' => $ip, 'count' => $count, 'limit' => self::IP_LIMIT_CHALLENGE],
            ['decision' => $decision]
        );
    }

    /**
     * Gate 4: device fingerprint (amended TRIAL-09/14).
     *
     * Inputs: the device {user_agent, screen_resolution, timezone, browser_language} and the user it is
     * being checked for (null before the user exists, e.g. at signup). Output: GateResult with
     * matching_users = the number of OTHER users with this device hash (null-safe: with no user every user
     * counts). Decision, in this order: FAIL if count >= 5; PASS if count < 2; PASS if this user already has
     * a row for this device; CHALLENGE otherwise. This method writes NO device row; callers record the device
     * after the decision and only for PASS/CHALLENGE (checkAndRecordDevice, signup).
     * Why: the old gate counted the user themself, let a known device pass even at 5+ users, and the old
     * CHALLENGE range overlapped FAIL at exactly 5. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (reads; one gate_decisions row).
     */
    public function checkDeviceFingerprint(array $device, ?string $userId = null): GateResult
    {
        $deviceHash = self::computeDeviceHash($device);

        $stmt = $this->db->prepare(
            'SELECT COUNT(DISTINCT user_id) FROM device_fingerprints
             WHERE device_hash = :hash AND (:uid1 IS NULL OR user_id != :uid2)'
        );
        $stmt->execute(['hash' => $deviceHash, 'uid1' => $userId, 'uid2' => $userId]);
        $matchingUsers = (int) $stmt->fetchColumn();

        $knownDevice = false;
        if ($userId !== null) {
            $known = $this->db->prepare(
                'SELECT COUNT(*) FROM device_fingerprints WHERE user_id = :uid AND device_hash = :hash'
            );
            $known->execute(['uid' => $userId, 'hash' => $deviceHash]);
            $knownDevice = (int) $known->fetchColumn() > 0;
        }

        if ($matchingUsers >= self::DEVICE_LIMIT_FAIL) {
            $decision = self::DECISION_FAIL;
        } elseif ($matchingUsers < self::DEVICE_LIMIT_CHALLENGE) {
            $decision = self::DECISION_PASS;
        } elseif ($knownDevice) {
            $decision = self::DECISION_PASS;
        } else {
            $decision = self::DECISION_CHALLENGE;
        }

        $inputs = ['device_hash' => $deviceHash, 'matching_users' => $matchingUsers, 'known_device' => $knownDevice];
        $this->logGate(self::GATE_DEVICE_FINGERPRINT, $userId, $decision, $inputs, ['decision' => $decision]);

        return new GateResult(self::GATE_DEVICE_FINGERPRINT, $decision, $inputs, ['decision' => $decision]);
    }

    /**
     * Run the device gate for an existing user and then, only for PASS or CHALLENGE, record the device
     * (once per user and device). A FAIL records nothing. Output: the GateResult.
     * Why: amended TRIAL-14 ("a FAIL records no device row"; the row is written after the decision).
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function checkAndRecordDevice(array $device, string $userId): GateResult
    {
        $result = $this->checkDeviceFingerprint($device, $userId);
        if (!$result->isFail() && !$result->ruleInputs['known_device']) {
            $this->recordDeviceFingerprint($userId, $device, $result->ruleInputs['device_hash']);
        }
        return $result;
    }

    /**
     * Gate 5: trial payment timing (amended TRIAL-10/11/15), judged when a payment method is being added,
     * so the payment date is now.
     *
     * Input: the user id. Output: GateResult with days_after_trial = floor((now - trial_end) / 1 day), where
     * trial_end = user.created_at + user.trial_days (negative while the trial runs; floor rounds toward
     * negative infinity) and earlier_payment = the ledger already has a payment_added_date for the user.
     * Decision: PASS if days_after_trial < 5; FAIL if days_after_trial >= 90 and no earlier payment;
     * CHALLENGE otherwise. Throws InvalidArgumentException for an unknown user.
     * Why: the old rule compared days since signup and a stored payment date in ways the spec dropped.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (reads; one gate_decisions row).
     */
    public function checkTrialPaymentTiming(string $userId): GateResult
    {
        $user = $this->fetchUser($userId);
        if ($user === null) {
            throw new InvalidArgumentException("User not found: {$userId}");
        }

        $trialDays = (int) $user['trial_days'];
        $trialEnd = (new DateTimeImmutable($user['created_at']))->getTimestamp() + $trialDays * 86400;
        $now = $this->now()->getTimestamp();
        $daysAfterTrial = (int) floor(($now - $trialEnd) / 86400);

        $earlierPayment = false;
        $stmt = $this->db->prepare('SELECT COUNT(*) FROM trial_abuse_ledger WHERE user_id = :uid AND payment_added_date IS NOT NULL');
        $stmt->execute(['uid' => $userId]);
        $earlierPayment = (int) $stmt->fetchColumn() > 0;

        if ($daysAfterTrial < self::LATE_PAYMENT_GRACE_DAYS) {
            $decision = self::DECISION_PASS;
        } elseif ($daysAfterTrial >= self::READD_BLOCK_DAYS && !$earlierPayment) {
            $decision = self::DECISION_FAIL;
        } else {
            $decision = self::DECISION_CHALLENGE;
        }

        $inputs = ['trial_duration' => $trialDays, 'payment_delay' => $daysAfterTrial, 'days_after_trial' => $daysAfterTrial, 'earlier_payment' => $earlierPayment];
        $this->logGate(self::GATE_TRIAL_PAYMENT_TIMING, $userId, $decision, $inputs, ['decision' => $decision]);

        return new GateResult(self::GATE_TRIAL_PAYMENT_TIMING, $decision, $inputs, ['decision' => $decision]);
    }

    /**
     * Gate 6: chargeback history.
     */
    public function checkChargebackHistory(string $userId): GateResult
    {
        $user = $this->fetchUser($userId);
        if ($user === null) {
            throw new InvalidArgumentException("User not found: {$userId}");
        }

        $stripeCustomerId = $user['stripe_customer_id'] ?? null;
        $stripeCount = 0;
        if ($stripeCustomerId !== null) {
            $stmt = $this->db->prepare(
                "SELECT COUNT(*) FROM stripe_events WHERE customer = :cust AND type LIKE '%chargeback%'"
            );
            $stmt->execute(['cust' => $stripeCustomerId]);
            $stripeCount = (int) $stmt->fetchColumn();
        }

        $refundStmt = $this->db->prepare(
            "SELECT COUNT(*) FROM refunds WHERE user_id = :uid AND status = 'chargebacked'"
        );
        $refundStmt->execute(['uid' => $userId]);
        $refundCount = (int) $refundStmt->fetchColumn();

        $totalChargebacks = $stripeCount + $refundCount;

        if ($totalChargebacks >= self::CHARGEBACK_LIMIT_FAIL) {
            $decision = self::DECISION_FAIL;
        } elseif ($totalChargebacks >= self::CHARGEBACK_LIMIT_CHALLENGE) {
            $decision = self::DECISION_CHALLENGE;
        } else {
            $decision = self::DECISION_PASS;
        }

        $this->logGate(
            self::GATE_CHARGEBACK_HISTORY,
            $userId,
            $decision,
            ['chargebacks' => $totalChargebacks, 'stripe' => $stripeCount, 'refunds' => $refundCount],
            ['decision' => $decision]
        );

        return new GateResult(
            self::GATE_CHARGEBACK_HISTORY,
            $decision,
            ['chargebacks' => $totalChargebacks, 'stripe' => $stripeCount, 'refunds' => $refundCount],
            ['decision' => $decision]
        );
    }

    /**
     * Run the signup flow: email + IP gates (+ the device gate when a device is given), create user, apply
     * flags, record the device (PASS/CHALLENGE only), log ledger.
     *
     * Inputs: email, password, the caller's IP (from the server, not the body), the device or []. Output:
     * {status, body}: 409 email_has_trial_history, 429 too_many_signups_from_ip, 403 device_suspected_fraud
     * (no user and no device row are created), or 200 with challenge 'captcha' / 'email_confirm'.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the device gate now runs BEFORE the device is recorded (it used to
     * record first and never check), and new users get the configured trial_days.
     * Touches: the database.
     *
     * @return array{status: int, body: array<string, mixed>}
     */
    public function signup(string $email, string $password, string $ip, array $device = []): array
    {
        $emailGate = $this->checkEmailTrialHistory($email);
        $ipGate = $this->checkIpSignupRateLimit($ip);
        $deviceGate = $device !== [] ? $this->checkDeviceFingerprint($device, null) : null;

        if ($emailGate->decision === self::DECISION_FAIL) {
            return [
                'status' => 409,
                'body' => [
                    'error' => 'email_has_trial_history',
                    'message' => 'This email has prior trial history and cannot sign up again.',
                    'code' => 409,
                ],
            ];
        }

        if ($ipGate->decision === self::DECISION_FAIL) {
            return [
                'status' => 429,
                'body' => [
                    'error' => 'too_many_signups_from_ip',
                    'message' => 'Too many signups from this IP address.',
                    'code' => 429,
                    'retry_after' => self::IP_RETRY_AFTER_SECONDS,
                ],
            ];
        }

        if ($deviceGate !== null && $deviceGate->isFail()) {
            return [
                'status' => 403,
                'body' => [
                    'error' => 'device_suspected_fraud',
                    'message' => 'This device is linked to too many accounts.',
                    'code' => 403,
                ],
            ];
        }

        $userId = $this->generateId('usr');
        $now = $this->now()->format('Y-m-d H:i:s');
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        $stmt = $this->db->prepare(
            'INSERT INTO users (id, email, password_hash, abuse_flags, stripe_customer_id, trial_days, created_at)
             VALUES (:id, :email, :hash, :flags, :cust, :days, :created)'
        );
        $stmt->execute([
            'id' => $userId,
            'email' => $email,
            'hash' => $passwordHash,
            'flags' => null,
            'cust' => null,
            'days' => $this->trialDays,
            'created' => $now,
        ]);

        $signupStmt = $this->db->prepare(
            'INSERT INTO signups (user_id, email, ip, created_at) VALUES (:uid, :email, :ip, :created)'
        );
        $signupStmt->execute([
            'uid' => $userId,
            'email' => $email,
            'ip' => $ip,
            'created' => $now,
        ]);

        $abuseFlags = [];
        if ($emailGate->decision === self::DECISION_CHALLENGE) {
            $abuseFlags[] = 'email_trial_attempt_2+';
        }
        if ($ipGate->decision === self::DECISION_CHALLENGE) {
            $abuseFlags[] = 'ip_rate_limited';
        }

        $gateFlags = [
            'email' => $emailGate->decision,
            'ip' => $ipGate->decision,
        ];

        // The device row is written after the gate's decision, and only for PASS or CHALLENGE (a FAIL
        // returned above).
        $deviceHash = $deviceGate?->ruleInputs['device_hash'];
        if ($deviceGate !== null) {
            $gateFlags['device'] = $deviceGate->decision;
            $this->recordDeviceFingerprint($userId, $device, $deviceHash);
            if ($deviceGate->isChallenge()) {
                $abuseFlags[] = 'new_device_challenge';
            }
        }

        $ledgerStmt = $this->db->prepare(
            'INSERT INTO trial_abuse_ledger
             (user_id, email, stripe_payment_method_id, ip, device_fingerprint, signup_date,
              trial_started_at, payment_added_date, subscription_status, chargeback_count,
              refund_count, gate_flags, alert_reason, created_at)
             VALUES (:uid, :email, :pmid, :ip, :device, :signup, :trial, :payment, :status,
              :cb, :rf, :flags, :alert, :created)'
        );
        $ledgerStmt->execute([
            'uid' => $userId,
            'email' => $email,
            'pmid' => null,
            'ip' => $ip,
            'device' => $deviceHash,
            'signup' => $now,
            'trial' => $now,
            'payment' => null,
            'status' => 'trialing',
            'cb' => 0,
            'rf' => 0,
            'flags' => json_encode($gateFlags),
            'alert' => null,
            'created' => $now,
        ]);

        if ($abuseFlags !== []) {
            $this->updateUserFlags($userId, $abuseFlags);
        }

        $body = [
            'success' => true,
            'user_id' => $userId,
            'email' => $email,
            'verification_email_sent' => true,
        ];

        if ($deviceGate !== null && $deviceGate->isChallenge()) {
            $body['challenge'] = self::CHALLENGE_EMAIL_CONFIRM;
            $body['message'] = 'New device login detected. Please confirm your email.';
        }
        if ($ipGate->decision === self::DECISION_CHALLENGE) {
            $body['challenge'] = self::CHALLENGE_CAPTCHA;
            $body['message'] = 'Please complete CAPTCHA verification.';
        }

        return ['status' => 200, 'body' => $body];
    }

    /**
     * Run the payment flow: payment + timing + chargeback gates, create subscription.
     *
     * @return array{status: int, body: array<string, mixed>}
     */
    public function subscriptionCreated(string $userId, string $stripePaymentMethodId): array
    {
        $paymentGate = $this->checkPaymentMethodHistory($stripePaymentMethodId);
        $timingGate = $this->checkTrialPaymentTiming($userId);
        $chargebackGate = $this->checkChargebackHistory($userId);

        if ($paymentGate->decision === self::DECISION_FAIL) {
            return [
                'status' => 403,
                'body' => [
                    'error' => 'payment_method_used_for_multiple_trials',
                    'message' => 'This payment method has been used for multiple trials.',
                    'code' => 403,
                ],
            ];
        }

        if ($timingGate->decision === self::DECISION_FAIL) {
            return [
                'status' => 403,
                'body' => [
                    'error' => 'trial_ended_no_payment_cannot_retry',
                    'message' => 'Trial ended without payment; cannot re-add payment method.',
                    'code' => 403,
                ],
            ];
        }

        if ($chargebackGate->decision === self::DECISION_FAIL) {
            return [
                'status' => 403,
                'body' => [
                    'error' => 'chargeback_history_requires_prepayment',
                    'message' => 'Chargeback history requires prepayment.',
                    'code' => 403,
                ],
            ];
        }

        $now = $this->now()->format('Y-m-d H:i:s');

        $subStmt = $this->db->prepare(
            'INSERT INTO subscriptions (user_id, stripe_payment_method_id, status, created_at)
             VALUES (:uid, :pmid, :status, :created)'
        );
        $subStmt->execute([
            'uid' => $userId,
            'pmid' => $stripePaymentMethodId,
            'status' => 'active',
            'created' => $now,
        ]);

        $ledger = $this->fetchLedgerByUser($userId);
        if ($ledger !== null) {
            $gateFlags = json_decode($ledger['gate_flags'] ?? '{}', true) ?: [];
            $gateFlags['payment'] = $paymentGate->decision;
            $gateFlags['timing'] = $timingGate->decision;
            $gateFlags['chargeback'] = $chargebackGate->decision;

            $updateStmt = $this->db->prepare(
                'UPDATE trial_abuse_ledger
                 SET payment_added_date = :payment, stripe_payment_method_id = :pmid,
                     subscription_status = :status, gate_flags = :flags
                 WHERE user_id = :uid'
            );
            $updateStmt->execute([
                'payment' => $now,
                'pmid' => $stripePaymentMethodId,
                'status' => 'completed',
                'flags' => json_encode($gateFlags),
                'uid' => $userId,
            ]);
        }

        $abuseFlags = [];
        if ($paymentGate->decision === self::DECISION_CHALLENGE) {
            $abuseFlags[] = 'payment_reuse_2x';
        }
        if ($timingGate->decision === self::DECISION_CHALLENGE) {
            $abuseFlags[] = 'late_payment_entry';
        }
        if ($chargebackGate->decision === self::DECISION_CHALLENGE) {
            $abuseFlags[] = 'chargeback_1x';
        }

        if ($abuseFlags !== []) {
            $this->updateUserFlags($userId, $abuseFlags);
        }

        $body = [
            'success' => true,
            'user_id' => $userId,
            'subscription_status' => 'active',
            'stripe_payment_method_id' => $stripePaymentMethodId,
        ];

        $challenges = [];
        if ($paymentGate->decision === self::DECISION_CHALLENGE) {
            $challenges[] = self::CHALLENGE_EMAIL_CONFIRM;
        }
        if ($timingGate->decision === self::DECISION_CHALLENGE) {
            $challenges[] = self::CHALLENGE_EMAIL_CONFIRM;
        }
        if ($chargebackGate->decision === self::DECISION_CHALLENGE) {
            $challenges[] = self::CHALLENGE_EMAIL_CONFIRM;
        }

        if ($challenges !== []) {
            $body['challenge'] = self::CHALLENGE_EMAIL_CONFIRM;
            $body['message'] = 'New device login detected. Please confirm your email.';
        }

        return ['status' => 200, 'body' => $body];
    }

    /**
     * Record a device fingerprint for a user.
     */
    public function recordDeviceFingerprint(string $userId, array $device, ?string $deviceHash = null): void
    {
        $hash = $deviceHash ?? self::computeDeviceHash($device);
        $now = $this->now()->format('Y-m-d H:i:s');

        $stmt = $this->db->prepare(
            'INSERT INTO device_fingerprints (user_id, device_hash, user_agent, screen_resolution, timezone, created_at)
             VALUES (:uid, :hash, :ua, :res, :tz, :created)'
        );
        $stmt->execute([
            'uid' => $userId,
            'hash' => $hash,
            'ua' => $device['user_agent'] ?? null,
            'res' => $device['screen_resolution'] ?? null,
            'tz' => $device['timezone'] ?? null,
            'created' => $now,
        ]);
    }

    /**
     * Compute a deterministic SHA-256 hash of a device fingerprint.
     */
    public static function computeDeviceHash(array $device): string
    {
        $canonical = [
            'user_agent' => $device['user_agent'] ?? '',
            'screen_resolution' => $device['screen_resolution'] ?? '',
            'timezone' => $device['timezone'] ?? '',
            'browser_language' => $device['browser_language'] ?? '',
        ];
        ksort($canonical);
        return hash('sha256', json_encode($canonical));
    }

    /**
     * Log a gate decision to the gate_decisions table.
     */
    public function logGate(
        string $gateName,
        ?string $userId,
        string $decision,
        array $ruleInputs,
        array $ruleOutputs
    ): void {
        $now = $this->now()->format('Y-m-d H:i:s');
        $stmt = $this->db->prepare(
            'INSERT INTO gate_decisions (user_id, gate_name, decision, rule_inputs, rule_outputs, created_at)
             VALUES (:uid, :gate, :decision, :inputs, :outputs, :created)'
        );
        $stmt->execute([
            'uid' => $userId,
            'gate' => $gateName,
            'decision' => $decision,
            'inputs' => json_encode($ruleInputs),
            'outputs' => json_encode($ruleOutputs),
            'created' => $now,
        ]);
    }

    /**
     * Fetch a user row by id.
     *
     * @return array<string, mixed>|null
     */
    public function fetchUser(string $userId): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM users WHERE id = :id');
        $stmt->execute(['id' => $userId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row === false ? null : $row;
    }

    /**
     * Fetch the abuse ledger row for a user.
     *
     * @return array<string, mixed>|null
     */
    public function fetchLedgerByUser(string $userId): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM trial_abuse_ledger WHERE user_id = :uid ORDER BY created_at DESC LIMIT 1');
        $stmt->execute(['uid' => $userId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row === false ? null : $row;
    }

    /**
     * Append abuse flags to a user's flag list.
     *
     * @param string[] $flags
     */
    public function updateUserFlags(string $userId, array $flags): void
    {
        $user = $this->fetchUser($userId);
        if ($user === null) {
            throw new InvalidArgumentException("User not found: {$userId}");
        }

        $existing = $user['abuse_flags'] !== null
            ? json_decode($user['abuse_flags'], true)
            : [];
        if (!is_array($existing)) {
            $existing = [];
        }

        $merged = array_values(array_unique(array_merge($existing, $flags)));

        $stmt = $this->db->prepare('UPDATE users SET abuse_flags = :flags WHERE id = :id');
        $stmt->execute(['flags' => json_encode($merged), 'id' => $userId]);
    }

    /**
     * Seed a user directly (used by tests and external integrations).
     *
     * @param array<string, mixed> $overrides
     */
    public function createUser(string $userId, string $email, string $password, array $overrides = []): void
    {
        $now = $this->now()->format('Y-m-d H:i:s');
        $stmt = $this->db->prepare(
            'INSERT INTO users (id, email, password_hash, abuse_flags, stripe_customer_id, trial_days, created_at)
             VALUES (:id, :email, :hash, :flags, :cust, :days, :created)'
        );
        $stmt->execute([
            'id' => $userId,
            'email' => $email,
            'hash' => password_hash($password, PASSWORD_DEFAULT),
            'flags' => $overrides['abuse_flags'] ?? null,
            'cust' => $overrides['stripe_customer_id'] ?? null,
            'days' => $overrides['trial_days'] ?? 14,
            'created' => $overrides['created_at'] ?? $now,
        ]);
    }

    /**
     * Seed a ledger row directly (used by tests).
     *
     * @param array<string, mixed> $overrides
     */
    public function createLedgerEntry(string $userId, string $email, array $overrides = []): void
    {
        $now = $this->now()->format('Y-m-d H:i:s');
        $stmt = $this->db->prepare(
            'INSERT INTO trial_abuse_ledger
             (user_id, email, stripe_payment_method_id, ip, device_fingerprint, signup_date,
              trial_started_at, payment_added_date, subscription_status, chargeback_count,
              refund_count, gate_flags, alert_reason, created_at)
             VALUES (:uid, :email, :pmid, :ip, :device, :signup, :trial, :payment, :status,
              :cb, :rf, :flags, :alert, :created)'
        );
        $stmt->execute([
            'uid' => $userId,
            'email' => $email,
            'pmid' => $overrides['stripe_payment_method_id'] ?? null,
            'ip' => $overrides['ip'] ?? null,
            'device' => $overrides['device_fingerprint'] ?? null,
            'signup' => $overrides['signup_date'] ?? $now,
            'trial' => $overrides['trial_started_at'] ?? $now,
            'payment' => $overrides['payment_added_date'] ?? null,
            'status' => $overrides['subscription_status'] ?? 'trialing',
            'cb' => $overrides['chargeback_count'] ?? 0,
            'rf' => $overrides['refund_count'] ?? 0,
            'flags' => isset($overrides['gate_flags']) ? json_encode($overrides['gate_flags']) : null,
            'alert' => $overrides['alert_reason'] ?? null,
            'created' => $overrides['created_at'] ?? $now,
        ]);
    }

    /**
     * Seed a signup row (used by tests).
     */
    public function createSignup(string $userId, string $email, string $ip, ?string $createdAt = null): void
    {
        $now = $createdAt ?? $this->now()->format('Y-m-d H:i:s');
        $stmt = $this->db->prepare(
            'INSERT INTO signups (user_id, email, ip, created_at) VALUES (:uid, :email, :ip, :created)'
        );
        $stmt->execute(['uid' => $userId, 'email' => $email, 'ip' => $ip, 'created' => $now]);
    }

    /**
     * Seed a stripe event (used by tests).
     */
    public function createStripeEvent(string $customer, string $type, ?string $createdAt = null): void
    {
        $now = $createdAt ?? $this->now()->format('Y-m-d H:i:s');
        $stmt = $this->db->prepare(
            'INSERT INTO stripe_events (customer, type, created_at) VALUES (:cust, :type, :created)'
        );
        $stmt->execute(['cust' => $customer, 'type' => $type, 'created' => $now]);
    }

    /**
     * Seed a refund row (used by tests).
     */
    public function createRefund(string $userId, string $status, ?string $createdAt = null): void
    {
        $now = $createdAt ?? $this->now()->format('Y-m-d H:i:s');
        $stmt = $this->db->prepare(
            'INSERT INTO refunds (user_id, status, created_at) VALUES (:uid, :status, :created)'
        );
        $stmt->execute(['uid' => $userId, 'status' => $status, 'created' => $now]);
    }

    private function now(): DateTimeImmutable
    {
        if ($this->nowOverride !== null) {
            return new DateTimeImmutable($this->nowOverride);
        }
        return new DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }

    private function generateId(string $prefix): string
    {
        return $prefix . '_' . bin2hex(random_bytes(12));
    }
}

/**
 * Immutable result of a single gate evaluation.
 */
final class GateResult
{
    public function __construct(
        public readonly string $gate,
        public readonly string $decision,
        public readonly array $ruleInputs,
        public readonly array $ruleOutputs
    ) {
    }

    public function isPass(): bool
    {
        return $this->decision === TrialAbusePrevention::DECISION_PASS;
    }

    public function isChallenge(): bool
    {
        return $this->decision === TrialAbusePrevention::DECISION_CHALLENGE;
    }

    public function isFail(): bool
    {
        return $this->decision === TrialAbusePrevention::DECISION_FAIL;
    }
}