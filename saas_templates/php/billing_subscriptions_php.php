<?php
/**
 * Billing & Subscriptions (template #4): Stripe subscriptions, plan changes, a refund queue and
 * a signature-verified, idempotent Stripe webhook handler, on PDO (SQLite or any PDO driver).
 *
 * Inputs/outputs: static methods take plain values and return arrays shaped
 * {success: true, ...} or {error: "code", message: "..."}; handleStripeWebhook() takes the raw
 * body and request headers and returns {received: true} or an error.
 *
 * Why (repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP): the suite failed with
 * "Failed opening required 'vendor/autoload.php'": both files required a vendor folder next to
 * the suite, while the runner (like any composer project) loads the autoloader itself. Behind
 * that: the file ran BillingSystem::init() when it was included (a side effect that throws without
 * environment variables), PRICE_IDS was private though callers need it, Stripe could not be
 * replaced by a test double (the Stripe client's services are magic properties), an event was
 * marked processed before it was processed (a crash lost it for good), a second event for the same
 * invoice hit a primary-key error, an unknown price wrote tier "unknown", old_tier came from
 * Stripe's plan nickname instead of our record, and several partial refunds could add up to more
 * than the invoice.
 *
 * Touches: the database (subscriptions, invoices, refunds, events, audit_logs) and, through
 * StripeSdkGateway, the Stripe API over the network, which moves real money. Refunds are only
 * queued (status 'queued'); nothing here executes a refund.
 */

declare(strict_types=1);

use Stripe\Exception\SignatureVerificationException;
use Stripe\StripeClient;
use Stripe\Webhook;

/**
 * The Stripe calls billing needs, so the system can run against a test double or an in-memory
 * fake with no network.
 *
 * Why: StripeClient exposes services as magic properties, which cannot be mocked; tests need a
 * seam. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the network (Stripe) in
 * the real implementation.
 */
interface StripeGateway
{
    /**
     * Create a subscription.
     *
     * @param array $params {customer: string, items: list<{price: string}>}
     * @return object With at least id and current_period_end (unix seconds).
     *
     * Why: the StripeGateway seam (Stripe services are magic properties that cannot be mocked). 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the network (Stripe API) and real money in StripeSdkGateway.
     */
    public function createSubscription(array $params): object;

    /**
     * Change a subscription's price.
     *
     * @param string $subscriptionId Stripe subscription id.
     * @param array  $params         {items: list<{price: string}>}
     * @return object With at least id and current_period_end; proration_details optional.
     *
     * Why: the StripeGateway seam; the SDK version replaces the current item instead of adding a second one. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the network (Stripe API) and real money in StripeSdkGateway.
     */
    public function updateSubscription(string $subscriptionId, array $params): object;
}

/**
 * StripeGateway over the official stripe-php client.
 *
 * Why: the production side of the seam above. 2026-11-10, session
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches the network (api.stripe.com) and real money.
 */
final class StripeSdkGateway implements StripeGateway
{
    /**
     * @param StripeClient $client A client built with the secret key (STRIPE_SECRET_KEY).
     *
     * Why: the StripeGateway seam. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing (stores the client).
     */
    public function __construct(private StripeClient $client)
    {
    }

    /**
     * Calls subscriptions->create with $params unchanged.
     *
     * Why: the StripeGateway seam (Stripe services are magic properties that cannot be mocked). 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the network (Stripe API) and real money in StripeSdkGateway.
     */
    public function createSubscription(array $params): object
    {
        return $this->client->subscriptions->create($params);
    }

    /**
     * Calls subscriptions->update. Stripe adds a second item when an item has no id, so an
     * item given only as {price} replaces the subscription's current first item, with
     * prorations created.
     *
     * Why: the StripeGateway seam; the SDK version replaces the current item instead of adding a second one. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the network (Stripe API) and real money in StripeSdkGateway.
     */
    public function updateSubscription(string $subscriptionId, array $params): object
    {
        if (isset($params['items'][0]) && !isset($params['items'][0]['id'])) {
            $current = $this->client->subscriptions->retrieve($subscriptionId);
            $params['items'][0]['id'] = $current->items->data[0]->id;
            $params['proration_behavior'] = $params['proration_behavior'] ?? 'create_prorations';
        }
        return $this->client->subscriptions->update($subscriptionId, $params);
    }
}

/**
 * The billing system (static facade, one configured instance per process).
 *
 * Why: see the file header. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the database and Stripe.
 */
class BillingSystem
{
    /** Stripe price id per tier. Replace these placeholders with your account's price ids. */
    public const PRICE_IDS = [
        'solo' => 'price_1UIxxxxxx',
        'team' => 'price_1UIyyyyyy',
        'enterprise' => 'price_1UIzzzzzz',
    ];

    /** Stripe access; tests assign a test double here after init(). */
    public static ?StripeGateway $stripe = null;

    private static ?PDO $pdo = null;
    private static ?string $webhookSecret = null;

    /** Database schema (SQLite DDL). */
    public const SCHEMA = <<<SQL
CREATE TABLE IF NOT EXISTS subscriptions (
    stripe_subscription_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    tier TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    cancelled_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_subscriptions_customer ON subscriptions (customer_id);
CREATE TABLE IF NOT EXISTS invoices (
    stripe_invoice_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    status TEXT NOT NULL,
    paid_at TEXT
);
CREATE TABLE IF NOT EXISTS refunds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    invoice_id TEXT NOT NULL,
    amount INTEGER NOT NULL CHECK (amount > 0),
    status TEXT NOT NULL,
    reason TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL,
    executed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_refunds_invoice ON refunds (invoice_id);
CREATE TABLE IF NOT EXISTS events (
    stripe_event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    processed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    data TEXT,
    created_at TEXT NOT NULL
)
SQL;

    /**
     * Configure the system and create the tables. Call once at start-up (it no longer runs when
     * the file is included).
     *
     * @param PDO|null           $pdo           Connection; default: DB_DSN, DB_USER, DB_PASS.
     * @param StripeGateway|null $stripe        Stripe access; default: StripeSdkGateway with
     *                                          STRIPE_SECRET_KEY when that is set.
     * @param string|null        $webhookSecret Default: STRIPE_WEBHOOK_SECRET.
     * @throws RuntimeException when no connection is given and DB_DSN is not set.
     *
     * Why: init used to run on include and to require the Stripe key even where only the
     * database is used. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the
     * database (CREATE TABLE) and reads environment variables; no network.
     */
    public static function init(?PDO $pdo = null, ?StripeGateway $stripe = null, ?string $webhookSecret = null): void
    {
        if ($pdo === null) {
            $dsn = getenv('DB_DSN');
            if (!$dsn) {
                throw new RuntimeException('DB_DSN not set');
            }
            $pdo = new PDO($dsn, getenv('DB_USER') ?: null, getenv('DB_PASS') ?: null);
        }
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $pdo->exec(self::SCHEMA);
        self::$pdo = $pdo;

        if ($stripe === null) {
            $key = getenv('STRIPE_SECRET_KEY');
            $stripe = $key ? new StripeSdkGateway(new StripeClient($key)) : null;
        }
        self::$stripe = $stripe;

        $secret = $webhookSecret ?? getenv('STRIPE_WEBHOOK_SECRET');
        self::$webhookSecret = ($secret === false || $secret === '') ? null : $secret;
    }

    /**
     * The configured connection.
     *
     * @throws RuntimeException before init().
     *
     * Why: callers (and tests) read billing records through the same connection.
     * 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
     */
    public static function pdo(): PDO
    {
        if (self::$pdo === null) {
            throw new RuntimeException('BillingSystem::init() has not been called');
        }
        return self::$pdo;
    }

    /**
     * Create a subscription in Stripe and record it (flow 1).
     *
     * @param string $customerId Stripe customer id.
     * @param string $tier       solo | team | enterprise.
     * @return array {success, subscription_id, tier, status: 'active', next_billing_date} or
     *               {error: invalid_tier | stripe_not_configured | stripe_error, message}
     *
     * Why: validates the tier before any Stripe call; Stripe sits behind StripeGateway.
     * 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches Stripe (creates a paid
     * subscription), the database and the audit log.
     */
    public static function createSubscription(string $customerId, string $tier): array
    {
        if (!isset(self::PRICE_IDS[$tier])) {
            return ['error' => 'invalid_tier', 'message' => 'Unknown tier'];
        }
        if (self::$stripe === null) {
            return ['error' => 'stripe_not_configured', 'message' => 'Stripe is not configured'];
        }
        try {
            $subscription = self::$stripe->createSubscription([
                'customer' => $customerId,
                'items' => [['price' => self::PRICE_IDS[$tier]]],
            ]);
        } catch (Throwable) {
            return ['error' => 'stripe_error', 'message' => 'The payment provider rejected the request'];
        }

        $now = self::now();
        self::pdo()->prepare(
            'INSERT INTO subscriptions (stripe_subscription_id, customer_id, tier, status, created_at, updated_at)
             VALUES (:id, :customer_id, :tier, :status, :created_at, :updated_at)'
        )->execute([
            ':id' => $subscription->id,
            ':customer_id' => $customerId,
            ':tier' => $tier,
            ':status' => 'active',
            ':created_at' => $now,
            ':updated_at' => $now,
        ]);
        self::auditLog('subscription_created', [
            'customer_id' => $customerId,
            'tier' => $tier,
            'stripe_sub_id' => $subscription->id,
        ]);

        return [
            'success' => true,
            'subscription_id' => $subscription->id,
            'tier' => $tier,
            'status' => 'active',
            'next_billing_date' => self::fromUnix($subscription->current_period_end ?? null),
        ];
    }

    /**
     * Move a subscription to another tier (flow 2).
     *
     * @param string $subscriptionId Stripe subscription id (must be in our records).
     * @param string $newTier        solo | team | enterprise.
     * @return array {success, subscription_id, old_tier, new_tier, effective_date, proration_credit}
     *               or {error: invalid_tier | subscription_not_found | stripe_not_configured | stripe_error, message}
     *
     * Why: old_tier now comes from our record (it was Stripe's plan nickname of the *new* plan).
     * 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches Stripe (changes what the
     * customer pays), the database and the audit log.
     */
    public static function changePlan(string $subscriptionId, string $newTier): array
    {
        if (!isset(self::PRICE_IDS[$newTier])) {
            return ['error' => 'invalid_tier', 'message' => 'Unknown tier'];
        }
        $current = self::findSubscription($subscriptionId);
        if ($current === null) {
            return ['error' => 'subscription_not_found', 'message' => 'Subscription does not exist'];
        }
        if (self::$stripe === null) {
            return ['error' => 'stripe_not_configured', 'message' => 'Stripe is not configured'];
        }
        try {
            $subscription = self::$stripe->updateSubscription($subscriptionId, [
                'items' => [['price' => self::PRICE_IDS[$newTier]]],
            ]);
        } catch (Throwable) {
            return ['error' => 'stripe_error', 'message' => 'The payment provider rejected the request'];
        }

        self::pdo()->prepare(
            'UPDATE subscriptions SET tier = :tier, updated_at = :updated_at WHERE stripe_subscription_id = :id'
        )->execute([':tier' => $newTier, ':updated_at' => self::now(), ':id' => $subscriptionId]);

        // Proration lines Stripe reports (amounts in cents; negative amounts are credits)
        $prorationCredit = 0;
        foreach ((array) ($subscription->proration_details ?? []) as $detail) {
            $amount = is_array($detail) ? ($detail['amount'] ?? 0) : ($detail->amount ?? 0);
            $prorationCredit += (int) $amount;
        }

        self::auditLog('plan_changed', [
            'subscription_id' => $subscriptionId,
            'old_tier' => $current['tier'],
            'new_tier' => $newTier,
            'proration_credits' => $prorationCredit,
        ]);

        return [
            'success' => true,
            'subscription_id' => $subscriptionId,
            'old_tier' => $current['tier'],
            'new_tier' => $newTier,
            'effective_date' => self::fromUnix($subscription->current_period_end ?? null),
            'proration_credit' => $prorationCredit,
        ];
    }

    /**
     * Queue a refund for later review/execution (flow 3); it is never executed here.
     *
     * @param string $invoiceId Stripe invoice id.
     * @param int    $amount    Cents, > 0; with earlier queued/executed refunds it may not
     *                          exceed the invoice amount.
     * @param string $reason    Why the refund is given.
     * @param string $createdBy Who queued it (taken from your authenticated admin, not the client).
     * @return array {success, refund_id, status: 'queued', amount, reason} or
     *               {error: invalid_amount | invoice_not_found | invoice_not_succeeded | refund_exceeds_invoice, message}
     *
     * Why: earlier refunds now count toward the limit, inside one transaction.
     * 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database and the audit
     * log; no money moves.
     */
    public static function queueRefund(string $invoiceId, int $amount, string $reason, string $createdBy): array
    {
        if ($amount <= 0) {
            return ['error' => 'invalid_amount', 'message' => 'Refund amount must be positive'];
        }
        $pdo = self::pdo();
        $pdo->beginTransaction();
        try {
            $stmt = $pdo->prepare('SELECT amount, status FROM invoices WHERE stripe_invoice_id = :id');
            $stmt->execute([':id' => $invoiceId]);
            $invoice = $stmt->fetch();
            if ($invoice === false) {
                $pdo->rollBack();
                return ['error' => 'invoice_not_found', 'message' => 'Invoice does not exist'];
            }
            if ($invoice['status'] !== 'succeeded') {
                $pdo->rollBack();
                return ['error' => 'invoice_not_succeeded', 'message' => 'Invoice has not been paid'];
            }
            $sum = $pdo->prepare("SELECT COALESCE(SUM(amount), 0) FROM refunds WHERE invoice_id = :id AND status IN ('queued', 'executed')");
            $sum->execute([':id' => $invoiceId]);
            if ($amount + (int) $sum->fetchColumn() > (int) $invoice['amount']) {
                $pdo->rollBack();
                return ['error' => 'refund_exceeds_invoice', 'message' => 'Refund amount exceeds invoice'];
            }

            $pdo->prepare(
                'INSERT INTO refunds (invoice_id, amount, status, reason, created_by, created_at)
                 VALUES (:invoice_id, :amount, :status, :reason, :created_by, :created_at)'
            )->execute([
                ':invoice_id' => $invoiceId,
                ':amount' => $amount,
                ':status' => 'queued',
                ':reason' => $reason,
                ':created_by' => $createdBy,
                ':created_at' => self::now(),
            ]);
            $refundId = (int) $pdo->lastInsertId();
            self::auditLog('refund_queued', ['invoice_id' => $invoiceId, 'amount' => $amount, 'reason' => $reason]);
            $pdo->commit();
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }

        return ['success' => true, 'refund_id' => $refundId, 'status' => 'queued', 'amount' => $amount, 'reason' => $reason];
    }

    /**
     * Handle a Stripe webhook (flow 4): verify the Stripe-Signature header (HMAC-SHA256,
     * constant-time compare, 5-minute tolerance, by stripe-php), then process the event once.
     * The event id is recorded in the same transaction as its effects, so a duplicate is
     * skipped and a crash leaves the event unrecorded for Stripe to resend.
     *
     * @param string $rawBody The request body exactly as received.
     * @param array  $headers Request headers (any letter case).
     * @return array {received: true, duplicate?: true} or
     *               {error: missing_webhook_secret | missing_signature | invalid_signature | invalid_event | processing_failed, message}
     *               (answer invalid_signature with HTTP 403, processing_failed with 500)
     *
     * Why: see the file header (event recorded before processing; duplicate invoice rows).
     * 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database and the audit
     * log; never logs the secret or the signature.
     */
    public static function handleStripeWebhook(string $rawBody, array $headers): array
    {
        if (self::$webhookSecret === null) {
            return ['error' => 'missing_webhook_secret', 'message' => 'Webhook secret not configured'];
        }
        $sigHeader = null;
        foreach ($headers as $name => $value) {
            if (strtolower((string) $name) === 'stripe-signature') {
                $sigHeader = is_array($value) ? ($value[0] ?? null) : $value;
            }
        }
        if (!is_string($sigHeader) || $sigHeader === '') {
            return ['error' => 'missing_signature', 'message' => 'Missing Stripe signature header'];
        }

        try {
            $event = Webhook::constructEvent($rawBody, $sigHeader, self::$webhookSecret);
        } catch (SignatureVerificationException) {
            return ['error' => 'invalid_signature', 'message' => 'Signature verification failed'];
        } catch (Throwable) {
            return ['error' => 'invalid_event', 'message' => 'Malformed event'];
        }
        if (!is_string($event->id ?? null) || !is_string($event->type ?? null)) {
            return ['error' => 'invalid_event', 'message' => 'Malformed event'];
        }

        $pdo = self::pdo();
        $pdo->beginTransaction();
        try {
            $record = $pdo->prepare(
                'INSERT INTO events (stripe_event_id, event_type, processed_at) VALUES (:id, :type, :at)
                 ON CONFLICT (stripe_event_id) DO NOTHING'
            );
            $record->execute([':id' => $event->id, ':type' => $event->type, ':at' => self::now()]);
            if ($record->rowCount() === 0) {
                $pdo->commit();
                return ['received' => true, 'duplicate' => true];
            }
            self::applyEvent($event->type, $event->data->object);
            $pdo->commit();
        } catch (Throwable) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            return ['error' => 'processing_failed', 'message' => 'Event could not be processed'];
        }

        return ['received' => true];
    }

    /**
     * Apply one verified event's effect (inside handleStripeWebhook's transaction).
     *
     * Why: split out of the webhook handler; an unknown price no longer writes tier "unknown",
     * and payment_failed uses the invoice's own subscription. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database and the audit log.
     */
    private static function applyEvent(string $type, object $object): void
    {
        $pdo = self::pdo();
        switch ($type) {
            case 'invoice.payment_succeeded':
                $amount = (int) ($object->amount_paid ?? $object->amount ?? 0);
                $pdo->prepare(
                    "INSERT INTO invoices (stripe_invoice_id, customer_id, amount, status, paid_at)
                     VALUES (:id, :customer_id, :amount, 'succeeded', :paid_at)
                     ON CONFLICT (stripe_invoice_id) DO UPDATE SET status = 'succeeded', amount = excluded.amount, paid_at = excluded.paid_at"
                )->execute([
                    ':id' => (string) $object->id,
                    ':customer_id' => (string) $object->customer,
                    ':amount' => $amount,
                    ':paid_at' => self::fromUnix($object->created ?? null) ?? self::now(),
                ]);
                self::auditLog('payment_succeeded', ['customer_id' => $object->customer, 'invoice_id' => $object->id, 'amount' => $amount]);
                break;

            case 'invoice.payment_failed':
                $now = self::now();
                if (isset($object->subscription) && is_string($object->subscription)) {
                    $pdo->prepare(
                        "UPDATE subscriptions SET status = 'past_due', updated_at = :now
                         WHERE stripe_subscription_id = :id AND status != 'past_due'"
                    )->execute([':now' => $now, ':id' => $object->subscription]);
                } else {
                    $pdo->prepare(
                        "UPDATE subscriptions SET status = 'past_due', updated_at = :now
                         WHERE customer_id = :customer AND status = 'active'"
                    )->execute([':now' => $now, ':customer' => (string) $object->customer]);
                }
                self::auditLog('payment_failed', [
                    'customer_id' => $object->customer,
                    'invoice_id' => $object->id,
                    'reason' => $object->last_finalization_error->message ?? $object->failure_reason ?? 'unknown',
                ]);
                break;

            case 'customer.subscription.updated':
                $existing = self::findSubscription((string) $object->id);
                $price = $object->items->data[0]->price ?? null;
                $tier = null;
                if ($price !== null) {
                    $lookup = $price->lookup_key ?? null;
                    $tier = (is_string($lookup) && isset(self::PRICE_IDS[$lookup]))
                        ? $lookup
                        : (array_search($price->id ?? null, self::PRICE_IDS, true) ?: null);
                }
                $pdo->prepare(
                    'UPDATE subscriptions SET tier = COALESCE(:tier, tier), status = :status, updated_at = :now
                     WHERE stripe_subscription_id = :id'
                )->execute([
                    ':tier' => $tier,
                    ':status' => (string) $object->status,
                    ':now' => self::now(),
                    ':id' => (string) $object->id,
                ]);
                self::auditLog('subscription_updated', [
                    'customer_id' => $object->customer,
                    'old_tier' => $existing['tier'] ?? null,
                    'new_tier' => $tier ?? ($existing['tier'] ?? null),
                ]);
                break;

            case 'customer.subscription.deleted':
                $now = self::now();
                $pdo->prepare(
                    "UPDATE subscriptions SET status = 'cancelled', cancelled_at = :now, updated_at = :now2
                     WHERE stripe_subscription_id = :id"
                )->execute([':now' => $now, ':now2' => $now, ':id' => (string) $object->id]);
                self::auditLog('subscription_cancelled', ['customer_id' => $object->customer]);
                break;
        }
    }

    /**
     * Our record of a subscription, or null.
     *
     * Why: changePlan and the update event need the current tier. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (read).
     */
    private static function findSubscription(string $subscriptionId): ?array
    {
        $stmt = self::pdo()->prepare('SELECT * FROM subscriptions WHERE stripe_subscription_id = :id');
        $stmt->execute([':id' => $subscriptionId]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /**
     * Append an audit_logs row (action plus JSON data; never secrets).
     *
     * Why: the spec logs every billing action. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
     */
    private static function auditLog(string $action, array $data): void
    {
        self::pdo()->prepare('INSERT INTO audit_logs (action, data, created_at) VALUES (:action, :data, :created_at)')
            ->execute([':action' => $action, ':data' => json_encode($data, JSON_UNESCAPED_SLASHES), ':created_at' => self::now()]);
    }

    /**
     * Now as UTC ISO 8601.
     *
     * Why: the spec's timestamp format. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches nothing.
     */
    private static function now(): string
    {
        return (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format(DateTimeInterface::ATOM);
    }

    /**
     * Unix seconds to UTC ISO 8601, or null when absent.
     *
     * Why: Stripe sends unix times. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches nothing.
     */
    private static function fromUnix(mixed $seconds): ?string
    {
        if (!is_int($seconds) && !(is_string($seconds) && ctype_digit($seconds))) {
            return null;
        }
        return (new DateTimeImmutable('@' . $seconds))->setTimezone(new DateTimeZone('UTC'))->format(DateTimeInterface::ATOM);
    }
}
