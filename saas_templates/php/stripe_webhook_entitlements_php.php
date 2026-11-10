<?php
/**
 * Stripe webhook -> entitlements (docs/specs/stripe_webhook_entitlements.md).
 *
 * What it does: receives Stripe's webhook, proves it came from Stripe (Stripe-Signature, HMAC-SHA256, 300 s
 * tolerance) BEFORE parsing, applies every event exactly once (CLAIM on the event id) and in order (event
 * created time, then rank created < updated < deleted; a tie of one kind is settled by asking Stripe), and keeps
 * one answer per user: what they are entitled to right now. The webhook is the only writer of that answer.
 *
 * Inputs/outputs: see each method; every answer is a returned array with its HTTP `status`, never an
 * exception. get_entitlement's `status` is the subscription's status in Stripe's spelling.
 *
 * Why: Phase D wave 1, owner request 2026-11-10 (spec ids STRIPEWH-01..14).
 * Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the database (stripe_events, entitlement_subscriptions through PDO) and, through the injected Stripe
 * client, the network (retrieve a subscription). Decides paid access (money). Never logs the secret, the
 * signature header or the payload.
 */

declare(strict_types=1);

namespace StripeWebhookEntitlements;

use PDO;
use stdClass;
use Throwable;

const TOLERANCE = 300;

/**
 * The Stripe API the system needs. retrieveSubscription returns the subscription object (stdClass from
 * json_decode, or an array that is converted), or throws. Tests pass a fake: no network.
 * Why: STRIPEWH-09, STRIPEWH-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the network (real client).
 */
interface StripeClient
{
    /** In: a subscription id. Out: the subscription object. Throws on any failure. */
    public function retrieveSubscription(string $subscriptionId);
}

/**
 * sign_payload: "t=" + timestamp + ",v1=" + lower-case hex HMAC-SHA256(the whole secret text, timestamp + "."
 * + payload). In: raw payload, secret, timestamp. Out: the header. Why: STRIPEWH-01. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function sign_payload(string $payload, string $secret, int $timestamp): string
{
    return 't=' . $timestamp . ',v1=' . hash_hmac('sha256', $timestamp . '.' . $payload, $secret);
}

/**
 * verify_signature: steps 1-5 of the spec. In: raw payload, header (missing allowed), secret, now.
 * Out: {ok: true, timestamp} or {error, status}. Every candidate is compared in constant time with no early
 * exit. Why: STRIPEWH-02..05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function verify_signature(string $payload, ?string $header, string $secret, int $now): array
{
    if (strlen($secret) < 16) {
        return ['error' => 'webhook_not_configured', 'status' => 503];
    }
    if ($header === null || $header === '') {
        return ['error' => 'missing_signature', 'status' => 400];
    }
    $bad = ['error' => 'invalid_signature', 'status' => 400];
    if (strlen($header) > 4096) {
        return $bad;
    }
    $t = [];
    $candidates = [];
    foreach (explode(',', $header) as $element) {
        $element = trim($element, ' ');
        $eq = strpos($element, '=');
        if ($eq === false) {
            continue;
        }
        $name = substr($element, 0, $eq);
        $value = substr($element, $eq + 1);
        if ($name === 't') {
            $t[] = $value;
        } elseif ($name === 'v1' && preg_match('/^[0-9a-f]{64}$/D', $value) === 1) {
            $candidates[] = $value;
        }
    }
    if (count($t) !== 1 || preg_match('/^[0-9]{1,12}$/D', $t[0]) !== 1 || $candidates === []) {
        return $bad;
    }
    $expected = hash_hmac('sha256', $t[0] . '.' . $payload, $secret);
    $match = false;
    foreach ($candidates as $c) {
        $match = hash_equals($expected, $c) || $match;
    }
    if (!$match) {
        return $bad;
    }
    $ts = (int)$t[0];
    if (abs($now - $ts) > TOLERANCE) {
        return ['error' => 'timestamp_out_of_tolerance', 'status' => 400];
    }
    return ['ok' => true, 'timestamp' => $ts];
}

/**
 * TIME: a JSON number (never bool, text or null) whose value is a whole number from 0 to 99999999999.
 * In: a decoded JSON value. Out: the int, or null. Why: STRIPEWH-06, STRIPEWH-11. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function as_time($v): ?int
{
    if (is_int($v)) {
        return ($v >= 0 && $v <= 99999999999) ? $v : null;
    }
    if (is_float($v) && is_finite($v) && $v === floor($v) && $v >= 0 && $v <= 99999999999) {
        return (int)$v;
    }
    return null;
}

/**
 * A property of a decoded JSON object, or null. In: value, key. Out: the property or null.
 * Why: reading untrusted event objects safely. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function prop($o, string $k)
{
    return ($o instanceof stdClass && property_exists($o, $k)) ? $o->$k : null;
}

/**
 * The SQL store. Why: SCHEMA. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the database tables stripe_events and entitlement_subscriptions.
 */
final class SqlEntitlementStore
{
    public PDO $db;

    /** In: PDO. Out: the store (exceptions on). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: connection settings. */
    public function __construct(PDO $db)
    {
        $this->db = $db;
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    /** Create the spec's two tables if missing. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (DDL). */
    public function migrate(): void
    {
        $this->db->exec('CREATE TABLE IF NOT EXISTS stripe_events (event_id TEXT PRIMARY KEY, type TEXT, created INT, received_at INT, result TEXT)');
        $this->db->exec('CREATE TABLE IF NOT EXISTS entitlement_subscriptions (stripe_subscription_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL, stripe_customer_id TEXT, price_id TEXT, plan TEXT NULL, status TEXT,
            current_period_end INT NOT NULL, cancel_at_period_end BOOL, event_at INT, event_rank INT, updated_at INT)');
    }

    /**
     * CLAIM: insert the event row; false when the id is already there (an insert that fails on the key).
     * In: event id, type, created, now. Out: bool. Why: STRIPEWH-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database.
     */
    public function claimEvent(string $id, string $type, int $created, int $now): bool
    {
        $st = $this->db->prepare('INSERT INTO stripe_events (event_id, type, created, received_at, result) VALUES (?, ?, ?, ?, NULL)
            ON CONFLICT (event_id) DO NOTHING');
        $st->execute([$id, $type, $created, $now]);
        return $st->rowCount() === 1;
    }

    /** Store an event's result. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database. */
    public function setResult(string $id, string $result): void
    {
        $this->db->prepare('UPDATE stripe_events SET result = ? WHERE event_id = ?')->execute([$result, $id]);
    }

    /** An event row or null (test and audit helper). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read). */
    public function getEvent(string $id): ?array
    {
        $st = $this->db->prepare('SELECT * FROM stripe_events WHERE event_id = ?');
        $st->execute([$id]);
        $r = $st->fetch(PDO::FETCH_ASSOC);
        return $r === false ? null : $r;
    }

    /** A subscription row or null. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read). */
    public function getRow(string $subId): ?array
    {
        $st = $this->db->prepare('SELECT * FROM entitlement_subscriptions WHERE stripe_subscription_id = ?');
        $st->execute([$subId]);
        $r = $st->fetch(PDO::FETCH_ASSOC);
        return $r === false ? null : $r;
    }

    /** The distinct user ids of rows with this customer id. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read). */
    public function usersForCustomer(string $customerId): array
    {
        $st = $this->db->prepare('SELECT DISTINCT user_id FROM entitlement_subscriptions WHERE stripe_customer_id = ?');
        $st->execute([$customerId]);
        return $st->fetchAll(PDO::FETCH_COLUMN);
    }

    /** The user's rows. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read). */
    public function rowsForUser(string $userId): array
    {
        $st = $this->db->prepare('SELECT * FROM entitlement_subscriptions WHERE user_id = ?');
        $st->execute([$userId]);
        return $st->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Write (insert or replace) a subscription row. In: the row's fields. Out: none.
     * Why: SUBSCRIPTION rule g. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    public function writeRow(array $r): void
    {
        $this->db->prepare('INSERT INTO entitlement_subscriptions (stripe_subscription_id, user_id, stripe_customer_id, price_id,
            plan, status, current_period_end, cancel_at_period_end, event_at, event_rank, updated_at)
            VALUES (:id, :u, :c, :p, :plan, :s, :cpe, :cape, :ea, :er, :ua)
            ON CONFLICT (stripe_subscription_id) DO UPDATE SET user_id = excluded.user_id, stripe_customer_id = excluded.stripe_customer_id,
            price_id = excluded.price_id, plan = excluded.plan, status = excluded.status, current_period_end = excluded.current_period_end,
            cancel_at_period_end = excluded.cancel_at_period_end, event_at = excluded.event_at, event_rank = excluded.event_rank,
            updated_at = excluded.updated_at')
            ->execute([':id' => $r['id'], ':u' => $r['user_id'], ':c' => $r['customer'], ':p' => $r['price_id'], ':plan' => $r['plan'],
                ':s' => $r['status'], ':cpe' => $r['current_period_end'], ':cape' => $r['cancel_at_period_end'] ? 1 : 0,
                ':ea' => $r['event_at'], ':er' => $r['event_rank'], ':ua' => $r['updated_at']]);
    }
}

/**
 * The webhook handler and the entitlement answer.
 *
 * Inputs: store, webhook_secret, price_plans {price_id: plan}, Stripe client, user_exists(user_id), clock,
 * period_grace_seconds. Outputs: see each method.
 * Why: STRIPEWH-01..14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: the database, the Stripe client (network in production), paid access (money).
 */
final class EntitlementWebhook
{
    private SqlEntitlementStore $store;
    private string $secret;
    private array $pricePlans;
    private StripeClient $client;
    /** @var callable(string): bool */
    private $userExists;
    /** @var callable(): int */
    private $clock;
    private int $grace;

    /**
     * In: see the class (clock defaults to time(), grace to 0). Out: the handler.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public function __construct(SqlEntitlementStore $store, string $webhookSecret, array $pricePlans, StripeClient $client,
                                callable $userExists, ?callable $clock = null, int $periodGraceSeconds = 0)
    {
        $this->store = $store;
        $this->secret = $webhookSecret;
        $this->pricePlans = $pricePlans;
        $this->client = $client;
        $this->userExists = $userExists;
        $this->clock = $clock ?? static fn(): int => time();
        $this->grace = $periodGraceSeconds;
    }

    /** The injected time. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the clock. */
    private function now(): int
    {
        return (int)($this->clock)();
    }

    /**
     * handle_webhook: verify, parse, CLAIM, APPLY, all of 7-9 in one transaction.
     * In: raw payload, Stripe-Signature header (missing allowed). Out: {status: 200, received: true, result}
     * or {error, status}. Why: STRIPEWH-01..14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database, the Stripe client.
     */
    public function handleWebhook(string $payload, ?string $header): array
    {
        $now = $this->now();
        $v = verify_signature($payload, $header, $this->secret, $now);
        if (($v['ok'] ?? false) !== true) {
            return $v;
        }
        $event = $this->parse($payload);
        if ($event === null) {
            return ['error' => 'invalid_payload', 'status' => 400];
        }
        $db = $this->store->db;
        try {
            $db->beginTransaction();
            if (!$this->store->claimEvent($event->id, $event->type, as_time($event->created), $now)) {
                $db->rollBack();
                return ['status' => 200, 'received' => true, 'result' => 'duplicate'];
            }
            $result = $this->apply($event, $now);
            $this->store->setResult($event->id, $result);
            $db->commit();
            return ['status' => 200, 'received' => true, 'result' => $result];
        } catch (Throwable $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            return ['error' => 'processing_failed', 'status' => 500];
        }
    }

    /**
     * get_entitlement: rules a, b, c of the spec, computed from the clock at every call.
     * In: user_id. Out: {entitled, plan, status, current_period_end, cancel_at_period_end}.
     * Why: STRIPEWH-07, STRIPEWH-10, STRIPEWH-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (read).
     */
    public function getEntitlement(string $userId): array
    {
        $rows = $this->store->rowsForUser($userId);
        if ($rows === []) {
            return ['entitled' => false, 'plan' => null, 'status' => 'none', 'current_period_end' => null, 'cancel_at_period_end' => false];
        }
        $now = $this->now();
        $entitling = array_values(array_filter($rows, fn(array $r): bool => $r['plan'] !== null
            && in_array($r['status'], ['active', 'trialing'], true) && (int)$r['current_period_end'] + $this->grace > $now));
        if ($entitling !== []) {
            usort($entitling, static fn(array $a, array $b): int => [(int)$b['current_period_end'], (int)$b['event_at']] <=> [(int)$a['current_period_end'], (int)$a['event_at']]
                ?: strcmp((string)$b['stripe_subscription_id'], (string)$a['stripe_subscription_id']));
            return self::answer($entitling[0], true);
        }
        usort($rows, static fn(array $a, array $b): int => (int)$b['event_at'] <=> (int)$a['event_at']
            ?: strcmp((string)$b['stripe_subscription_id'], (string)$a['stripe_subscription_id']));
        return self::answer($rows[0], false);
    }

    /** One row as the entitlement answer. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    private static function answer(array $r, bool $entitled): array
    {
        return ['entitled' => $entitled, 'plan' => $entitled ? $r['plan'] : null, 'status' => $r['status'],
            'current_period_end' => (int)$r['current_period_end'], 'cancel_at_period_end' => (bool)(int)$r['cancel_at_period_end']];
    }

    /**
     * Step 6: parse the verified payload; null for anything that is not a valid event (invalid UTF-8, a BOM,
     * a parser error, a missing or malformed id, type, created or data.object). Out: ?stdClass.
     * Why: STRIPEWH-06. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private function parse(string $payload): ?stdClass
    {
        if (preg_match('//u', $payload) !== 1 || strncmp($payload, "\xEF\xBB\xBF", 3) === 0) {
            return null;
        }
        try {
            $e = json_decode($payload, false, 512, JSON_THROW_ON_ERROR);
        } catch (Throwable $ex) {
            return null;
        }
        if (!$e instanceof stdClass) {
            return null;
        }
        $id = prop($e, 'id');
        $type = prop($e, 'type');
        if (!is_string($id) || preg_match('/^evt_[A-Za-z0-9_]{1,200}$/D', $id) !== 1
            || !is_string($type) || preg_match('/^[\x20-\x7E]{1,100}$/D', $type) !== 1
            || as_time(prop($e, 'created')) === null || !(prop(prop($e, 'data'), 'object') instanceof stdClass)) {
            return null;
        }
        return $e;
    }

    /**
     * APPLY(event) by type. In: the verified event, now. Out: "applied" | "stale" | "ignored". Throws when the
     * Stripe client or the store fails (handleWebhook answers 500). Why: STRIPEWH-07..14. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database, the Stripe client.
     */
    private function apply(stdClass $event, int $now): string
    {
        $obj = $event->data->object;
        $created = as_time($event->created);
        $ranks = ['customer.subscription.created' => 0, 'customer.subscription.updated' => 1, 'customer.subscription.deleted' => 2];
        if (isset($ranks[$event->type])) {
            return $this->subscription($obj, prop(prop($obj, 'metadata'), 'user_id'), $ranks[$event->type], $created, $now, false);
        }
        if ($event->type !== 'checkout.session.completed') {
            return 'ignored';
        }
        $subId = prop($obj, 'subscription');
        if (prop($obj, 'mode') !== 'subscription' || !self::validSubId($subId)) {
            return 'ignored';
        }
        $row = $this->store->getRow($subId);
        if ($row !== null && [(int)$row['event_at'], (int)$row['event_rank']] > [$created, 1]) {
            return 'stale';
        }
        $sub = self::toObject($this->client->retrieveSubscription($subId));
        $ref = prop($obj, 'client_reference_id');
        $hint = (is_string($ref) && $ref !== '') ? $ref : prop(prop($obj, 'metadata'), 'user_id');
        return $this->subscription($sub, $hint, 1, $created, $now, true);
    }

    /** True for sub_[A-Za-z0-9_]{1,200}. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    private static function validSubId($id): bool
    {
        return is_string($id) && preg_match('/^sub_[A-Za-z0-9_]{1,200}$/D', $id) === 1;
    }

    /**
     * A client answer as a JSON object (stdClass); arrays are converted through JSON. Throws when it is not
     * an object. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static function toObject($sub): stdClass
    {
        if (is_array($sub)) {
            $sub = json_decode(json_encode($sub, JSON_THROW_ON_ERROR), false, 512, JSON_THROW_ON_ERROR);
        }
        if (!$sub instanceof stdClass) {
            throw new \RuntimeException('bad_subscription_object');
        }
        return $sub;
    }

    /** items.data[0].price.id when it is a text, else null. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    private static function priceId(stdClass $sub): ?string
    {
        $data = prop(prop($sub, 'items'), 'data');
        $p = is_array($data) && isset($data[0]) ? prop(prop($data[0], 'price'), 'id') : null;
        return is_string($p) ? $p : null;
    }

    /**
     * Rule b's price and plan for an existing row. In: the event's price id, the row. Out: [price_id, plan].
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private function pricePlan(?string $priceId, array $row): array
    {
        if ($priceId !== null && array_key_exists($priceId, $this->pricePlans)) {
            return [$priceId, $this->pricePlans[$priceId]];
        }
        if ($priceId === null || $priceId === $row['price_id']) {
            return [$row['price_id'], $row['plan']];
        }
        return [$priceId, null];
    }

    /**
     * SUBSCRIPTION(sub, hint, rank): rules a-g of the spec. In: subscription object, user hint, rank, the
     * event's created, now, whether the object was just fetched. Out: "applied" | "stale" | "ignored".
     * A tie of (created, rank) for rank 0 or 1 fetches the subscription from Stripe (unless just fetched) and
     * continues with that object; rule b's price and plan are then read from the fetched object.
     * Why: STRIPEWH-07, 09, 11, 12, 14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database, the Stripe client.
     */
    private function subscription(stdClass $sub, $hint, int $rank, int $eventAt, int $now, bool $fetched): string
    {
        $subId = prop($sub, 'id');
        if (!self::validSubId($subId)) {
            return 'ignored';
        }
        $row = $this->store->getRow($subId);
        $priceId = self::priceId($sub);
        if ($row === null) {
            if ($priceId === null || !array_key_exists($priceId, $this->pricePlans)) {
                return 'ignored';
            }
            $price = [$priceId, $this->pricePlans[$priceId]];
        } else {
            $price = $this->pricePlan($priceId, $row);
        }
        $customer = prop($sub, 'customer');
        if ($row !== null) {
            $userId = (string)$row['user_id'];
        } elseif (is_string($hint) && $hint !== '' && ($this->userExists)($hint) === true) {
            $userId = $hint;
        } else {
            $users = is_string($customer) ? $this->store->usersForCustomer($customer) : [];
            if (count($users) !== 1) {
                return 'ignored';
            }
            $userId = (string)$users[0];
        }
        if ($row !== null) {
            $stored = [(int)$row['event_at'], (int)$row['event_rank']];
            if ([$eventAt, $rank] < $stored) {
                return 'stale';
            }
            if ($rank <= 1 && [$eventAt, $rank] === $stored && !$fetched) {
                $sub = self::toObject($this->client->retrieveSubscription($subId));
                $price = $this->pricePlan(self::priceId($sub), $row);
                $customer = prop($sub, 'customer');
            }
        }
        $cpe = as_time(prop($sub, 'current_period_end'));
        if ($cpe === null) {
            $data = prop(prop($sub, 'items'), 'data');
            foreach (is_array($data) ? $data : [] as $item) {
                $t = as_time(prop($item, 'current_period_end'));
                if ($t !== null && ($cpe === null || $t > $cpe)) {
                    $cpe = $t;
                }
            }
        }
        if ($cpe === null) {
            $cpe = $row === null ? 0 : (int)$row['current_period_end'];
        }
        if ($rank === 2) {
            $status = 'canceled';
        } else {
            $s = prop($sub, 'status');
            if (!is_string($s) || preg_match('/^[a-z_]{1,32}$/D', $s) !== 1) {
                return 'ignored';
            }
            $status = $s;
        }
        $this->store->writeRow([
            'id' => $subId, 'user_id' => $userId, 'customer' => is_string($customer) ? $customer : null,
            'price_id' => $price[0], 'plan' => $price[1], 'status' => $status, 'current_period_end' => $cpe,
            'cancel_at_period_end' => prop($sub, 'cancel_at_period_end') === true, 'event_at' => $eventAt,
            'event_rank' => $rank, 'updated_at' => $now,
        ]);
        return 'applied';
    }
}
