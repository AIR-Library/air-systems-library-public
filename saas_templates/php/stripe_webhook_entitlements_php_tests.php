<?php
/**
 * Stripe webhook -> entitlements tests (docs/specs/stripe_webhook_entitlements.md, STRIPEWH-01..14).
 *
 * Self-running script on an in-memory SQLite store, a fake Stripe client (no network) and an injected clock.
 * Every body is signed with sign_payload at run time. Exits 1 on any failure.
 *
 * Why: Phase D wave 1, owner request 2026-11-10. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory and in-memory SQLite only.
 */

declare(strict_types=1);

require_once __DIR__ . '/stripe_webhook_entitlements_php.php';

use StripeWebhookEntitlements\EntitlementWebhook;
use StripeWebhookEntitlements\SqlEntitlementStore;
use StripeWebhookEntitlements\StripeClient;
use function StripeWebhookEntitlements\sign_payload;

$GLOBALS['FAILS'] = 0;

/**
 * Assert identity. In: expected, actual, label. Out: none. Why: test helper. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: stdout.
 */
function eq($expected, $actual, string $msg): void
{
    if ($expected !== $actual) {
        $GLOBALS['FAILS']++;
        echo "  FAIL $msg\n    expected: " . var_export($expected, true) . "\n    actual:   " . var_export($actual, true) . "\n";
    }
}

/** The spec's secret, from two pieces. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
function secret(): string
{
    return 'whsec_' . 'test_secret_for_vectors';
}

const BODY = '{"id":"evt_test_0001","type":"customer.subscription.updated","created":1700000000,'
    . '"data":{"object":{"id":"sub_test_0001","customer":"cus_test_0001","status":"active",'
    . '"current_period_end":1702592000,"cancel_at_period_end":false,'
    . '"metadata":{"user_id":"user_1"},"items":{"data":[{"price":{"id":"price_pro_monthly"}}]}}}}';
const NOW = 1_700_000_000;

/**
 * Fake Stripe client: answers from a map, or throws; records each call.
 * Why: no network in tests. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
final class FakeStripe implements StripeClient
{
    public array $subs = [];
    public array $calls = [];
    public bool $fail = false;

    /** In: id. Out: the mapped object. Throws when $fail. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    public function retrieveSubscription(string $subscriptionId)
    {
        $this->calls[] = $subscriptionId;
        if ($this->fail) {
            throw new RuntimeException('stripe down');
        }
        return $this->subs[$subscriptionId];
    }
}

/** Mutable clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
final class Clock
{
    public int $now = NOW;
}

/**
 * A fresh world. In: secret, grace, price plans. Out: [handler, store, stripe, clock].
 * Users user_1, user_2 and user_3 exist. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
 */
function world(?string $secret = null, int $grace = 0, ?array $plans = null, ?SqlEntitlementStore $store = null, ?Clock $clock = null, ?FakeStripe $stripe = null): array
{
    if ($store === null) {
        $store = new SqlEntitlementStore(new PDO('sqlite::memory:'));
        $store->migrate();
    }
    $stripe ??= new FakeStripe();
    $clock ??= new Clock();
    $h = new EntitlementWebhook($store, $secret ?? secret(), $plans ?? ['price_pro_monthly' => 'pro', 'price_team' => 'team'], $stripe,
        static fn(string $u): bool => in_array($u, ['user_1', 'user_2', 'user_3'], true), static fn(): int => $clock->now, $grace);
    return [$h, $store, $stripe, $clock];
}

/**
 * A subscription object. In: overrides. Out: array. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function sub(array $o = []): array
{
    return $o + ['id' => 'sub_a', 'customer' => 'cus_a', 'status' => 'active', 'current_period_end' => NOW + 1000,
        'cancel_at_period_end' => false, 'metadata' => ['user_id' => 'user_1'], 'items' => ['data' => [['price' => ['id' => 'price_pro_monthly']]]]];
}

/**
 * An event body. In: id, type, created, data.object. Out: JSON text. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function ev(string $id, string $type, int $created, array $object): string
{
    return json_encode(['id' => $id, 'type' => $type, 'created' => $created, 'data' => ['object' => $object]], JSON_UNESCAPED_SLASHES);
}

/**
 * Sign and deliver a body at the clock's time. Out: the answer. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: in-memory SQLite.
 */
function send(EntitlementWebhook $h, Clock $c, string $body): array
{
    return $h->handleWebhook($body, sign_payload($body, secret(), $c->now));
}

/** Row counts of both tables. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite (read). */
function counts(SqlEntitlementStore $s): array
{
    return [(int)$s->db->query('SELECT COUNT(*) FROM stripe_events')->fetchColumn(), (int)$s->db->query('SELECT COUNT(*) FROM entitlement_subscriptions')->fetchColumn()];
}

const APPLIED = ['status' => 200, 'received' => true, 'result' => 'applied'];
const STALE = ['status' => 200, 'received' => true, 'result' => 'stale'];
const IGNORED = ['status' => 200, 'received' => true, 'result' => 'ignored'];
const NONE = ['entitled' => false, 'plan' => null, 'status' => 'none', 'current_period_end' => null, 'cancel_at_period_end' => false];
const BADSIG = ['error' => 'invalid_signature', 'status' => 400];

// STRIPEWH-01
/** STRIPEWH-01: the signature vector and the applied event. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_stripewh01_vector(): void
{
    eq(317, strlen(BODY), 'body length');
    eq('f2e8a2d52e46e4642dde0390c9def15047ff2178a8d33a9928698aca132cbe88', hash('sha256', BODY), 'body sha256');
    $header = sign_payload(BODY, secret(), NOW);
    eq('t=1700000000,v1=5bca2d8b83d83f9a52f3b25714245817b15ae87b9e73abcca2c7a514977a8ae5', $header, 'header');
    [$h] = world();
    eq(APPLIED, $h->handleWebhook(BODY, $header), 'applied');
    eq(['entitled' => true, 'plan' => 'pro', 'status' => 'active', 'current_period_end' => 1702592000, 'cancel_at_period_end' => false], $h->getEntitlement('user_1'), 'entitlement');
}

// STRIPEWH-02
/** STRIPEWH-02: every bad signature is 400 invalid_signature with nothing stored. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_stripewh02_bad_signatures(): void
{
    $good = sign_payload(BODY, secret(), NOW);
    $v1 = substr($good, strlen('t=1700000000,v1='));
    $changed = BODY;
    $changed[100] = $changed[100] === 'a' ? 'b' : 'a';
    $cases = [
        'another secret' => [BODY, sign_payload(BODY, 'whsec_' . 'another_secret_value', NOW)],
        'changed body byte' => [$changed, $good],
        'changed t' => [BODY, 't=1700000001,v1=' . $v1],
        'no v1' => [BODY, 't=1700000000'],
        'v1 upper case' => [BODY, 't=1700000000,v1=' . strtoupper($v1)],
        'v1 63 chars' => [BODY, 't=1700000000,v1=' . substr($v1, 0, 63)],
        'only v0' => [BODY, 't=1700000000,v0=' . $v1],
        'two t' => [BODY, 't=1700000000,t=1700000000,v1=' . $v1],
        'over 4096 bytes' => [BODY, $good . ',x=' . str_repeat('a', 4100)],
    ];
    foreach ($cases as $name => [$body, $header]) {
        [$h, $s] = world();
        eq(BADSIG, $h->handleWebhook($body, $header), $name);
        eq([0, 0], counts($s), "$name stores nothing");
    }
}

// STRIPEWH-03
/** STRIPEWH-03: missing header; unconfigured secret. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_stripewh03_missing_and_unconfigured(): void
{
    [$h, $s] = world();
    eq(['error' => 'missing_signature', 'status' => 400], $h->handleWebhook(BODY, null), 'missing');
    eq(['error' => 'missing_signature', 'status' => 400], $h->handleWebhook(BODY, ''), 'empty');
    $short = 'whsec_' . 'short1234';
    eq(15, strlen($short), '15-byte secret');
    [$h2, $s2] = world($short);
    foreach ([sign_payload(BODY, $short, NOW), sign_payload(BODY, secret(), NOW), '', null, 'garbage'] as $i => $header) {
        eq(['error' => 'webhook_not_configured', 'status' => 503], $h2->handleWebhook(BODY, $header), "unconfigured $i");
    }
    eq([0, 0], counts($s2), 'nothing stored');
}

// STRIPEWH-04
/** STRIPEWH-04: the tolerance vectors, each on a fresh store. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_stripewh04_tolerance(): void
{
    $header = sign_payload(BODY, secret(), NOW);
    $late = ['error' => 'timestamp_out_of_tolerance', 'status' => 400];
    foreach ([1700000300 => APPLIED, 1700000301 => $late, 1699999700 => APPLIED, 1699999699 => $late] as $now => $want) {
        [$h, , , $c] = world();
        $c->now = $now;
        eq($want, $h->handleWebhook(BODY, $header), "now $now");
    }
}

// STRIPEWH-05
/** STRIPEWH-05: two v1 values, the second right, with v0 and spaces. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_stripewh05_multiple_v1(): void
{
    $v1 = substr(sign_payload(BODY, secret(), NOW), strlen('t=1700000000,v1='));
    [$h] = world();
    eq(APPLIED, $h->handleWebhook(BODY, 't=1700000000, v1=' . str_repeat('0', 64) . ', v0=' . $v1 . ', v1=' . $v1), 'second v1 right');
}

// STRIPEWH-06
/**
 * STRIPEWH-06: signed bodies that are not valid events are 400 invalid_payload and not recorded; the TIME
 * rule for created. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
 */
function test_stripewh06_invalid_payloads(): void
{
    $obj = '{"object":{"id":"sub_x"}}';
    $bad = [
        'not json' => 'not json',
        'not an object' => '[1,2,3]',
        'no evt_ id' => '{"id":"ev_1","type":"x.y","created":1700000000,"data":' . $obj . '}',
        'no id' => '{"type":"x.y","created":1700000000,"data":' . $obj . '}',
        'no type' => '{"id":"evt_1","created":1700000000,"data":' . $obj . '}',
        'no created' => '{"id":"evt_1","type":"x.y","data":' . $obj . '}',
        'no data.object' => '{"id":"evt_1","type":"x.y","created":1700000000,"data":{}}',
        'data.object array' => '{"id":"evt_1","type":"x.y","created":1700000000,"data":{"object":[]}}',
        'created true' => '{"id":"evt_1","type":"x.y","created":true,"data":' . $obj . '}',
        'created text' => '{"id":"evt_1","type":"x.y","created":"1700000000","data":' . $obj . '}',
        'created .5' => '{"id":"evt_1","type":"x.y","created":1700000000.5,"data":' . $obj . '}',
        'created -1' => '{"id":"evt_1","type":"x.y","created":-1,"data":' . $obj . '}',
        'created 1e11' => '{"id":"evt_1","type":"x.y","created":100000000000,"data":' . $obj . '}',
        'created 1e400' => '{"id":"evt_1","type":"x.y","created":1e400,"data":' . $obj . '}',
        'BOM' => "\xEF\xBB\xBF" . '{"id":"evt_1","type":"x.y","created":1700000000,"data":' . $obj . '}',
    ];
    foreach ($bad as $name => $body) {
        [$h, $s] = world();
        eq(['error' => 'invalid_payload', 'status' => 400], send($h, new Clock(), $body), $name);
        eq([0, 0], counts($s), "$name not recorded");
    }
    [$h, $s] = world();
    $body = '{"id":"evt_float","type":"customer.subscription.created","created":1700000000.0,"data":{"object":' . json_encode(sub(), JSON_UNESCAPED_SLASHES) . '}}';
    eq(APPLIED, send($h, new Clock(), $body), 'created 1700000000.0 accepted');
    eq('1700000000', (string)$s->getEvent('evt_float')['created'], 'created stored as a whole number');
}

// STRIPEWH-06
/**
 * STRIPEWH-06 (spec db20a03, Phase B.4): a correctly signed, otherwise valid body holding "x": 1e400 (a non-finite
 * number outside any TIME field), at the top level or inside data.object, is 400 invalid_payload and no event is
 * recorded; the same body without it is applied. In: none. Out: assertions. Why: STRIPEWH-06 as amended by
 * db20a03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
 */
function test_stripewh06_non_finite_number_anywhere(): void
{
    $good = ev('evt_inf', 'customer.subscription.created', NOW, sub());
    $bodies = [
        'top level' => '{"x":1e400,' . substr($good, 1),
        'in data.object' => str_replace('"object":{', '"object":{"x":1e400,', $good),
    ];
    eq(true, $bodies['in data.object'] !== $good, 'the nested body differs');
    foreach ($bodies as $name => $body) {
        [$h, $s] = world();
        eq(['error' => 'invalid_payload', 'status' => 400], send($h, new Clock(), $body), "1e400 $name");
        eq([0, 0], counts($s), "1e400 $name not recorded");
    }
    [$h] = world();
    eq(APPLIED, send($h, new Clock(), $good), 'the same body without it is applied');
}

// STRIPEWH-07
/** STRIPEWH-07: a created event grants; none before; other users unchanged. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_stripewh07_created_grants(): void
{
    [$h, , , $c] = world();
    send($h, $c, ev('evt_other', 'customer.subscription.created', NOW - 10, sub(['id' => 'sub_other', 'customer' => 'cus_o', 'metadata' => ['user_id' => 'user_2'], 'items' => ['data' => [['price' => ['id' => 'price_team']]]]])));
    $other = $h->getEntitlement('user_2');
    eq(NONE, $h->getEntitlement('user_1'), 'none before');
    eq(APPLIED, send($h, $c, ev('evt_1', 'customer.subscription.created', NOW, sub(['cancel_at_period_end' => true]))), 'applied');
    eq(['entitled' => true, 'plan' => 'pro', 'status' => 'active', 'current_period_end' => NOW + 1000, 'cancel_at_period_end' => true], $h->getEntitlement('user_1'), 'entitled');
    eq($other, $h->getEntitlement('user_2'), 'other user unchanged');
    eq(['entitled' => true, 'plan' => 'team', 'status' => 'active', 'current_period_end' => NOW + 1000, 'cancel_at_period_end' => false], $other, 'other user answer');
}

// STRIPEWH-08
/** STRIPEWH-08: the same event twice is duplicate; row unchanged. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_stripewh08_duplicate(): void
{
    [$h, $s, , $c] = world();
    $body = ev('evt_dup', 'customer.subscription.created', NOW, sub());
    eq(APPLIED, send($h, $c, $body), 'first');
    $row = $s->getRow('sub_a');
    $c->now += 5;
    eq(['status' => 200, 'received' => true, 'result' => 'duplicate'], send($h, $c, $body), 'second');
    eq($row, $s->getRow('sub_a'), 'row unchanged');
}

// STRIPEWH-09
/**
 * STRIPEWH-09: stale older events, rank order at equal times, and a same-rank tie fetched from Stripe.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite, the fake client.
 */
function test_stripewh09_ordering(): void
{
    [$h, $s, $stripe, $c] = world();
    eq(APPLIED, send($h, $c, ev('evt_200', 'customer.subscription.updated', 200, sub(['status' => 'active']))), 'created 200');
    $row = $s->getRow('sub_a');
    eq(STALE, send($h, $c, ev('evt_100', 'customer.subscription.updated', 100, sub(['status' => 'past_due']))), 'created 100 stale');
    eq($row, $s->getRow('sub_a'), 'unchanged');
    eq(STALE, send($h, $c, ev('evt_c200', 'customer.subscription.created', 200, sub(['status' => 'incomplete']))), 'created-type at equal time');
    eq('active', $s->getRow('sub_a')['status'], 'updated kept');
    eq(APPLIED, send($h, $c, ev('evt_d200', 'customer.subscription.deleted', 200, sub(['status' => 'active']))), 'deleted at equal time');
    eq(['canceled', 2], [$s->getRow('sub_a')['status'], (int)$s->getRow('sub_a')['event_rank']], 'deleted overwrote');
    eq([], $stripe->calls, 'no fetch so far');

    send($h, $c, ev('evt_b1', 'customer.subscription.updated', 400, sub(['id' => 'sub_b', 'status' => 'active'])));
    $stripe->subs['sub_b'] = sub(['id' => 'sub_b', 'status' => 'trialing', 'current_period_end' => NOW + 5000, 'cancel_at_period_end' => true]);
    eq(APPLIED, send($h, $c, ev('evt_b2', 'customer.subscription.updated', 400, sub(['id' => 'sub_b', 'status' => 'past_due']))), 'tie applied');
    eq(['sub_b'], $stripe->calls, 'fetched once by id');
    $r = $s->getRow('sub_b');
    eq(['trialing', NOW + 5000, 1], [$r['status'], (int)$r['current_period_end'], (int)$r['cancel_at_period_end']], 'row has the fetched state');
}

// STRIPEWH-10
/** STRIPEWH-10: non-payment ends access at once; the period end and the grace. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function test_stripewh10_entitlement_end(): void
{
    foreach (['past_due', 'unpaid', 'canceled'] as $i => $status) {
        [$h, , , $c] = world();
        send($h, $c, ev('evt_a', 'customer.subscription.created', 100, sub()));
        eq(true, $h->getEntitlement('user_1')['entitled'], "$status before");
        send($h, $c, ev('evt_b', 'customer.subscription.updated', 200, sub(['status' => $status])));
        eq(['entitled' => false, 'plan' => null, 'status' => $status, 'current_period_end' => NOW + 1000, 'cancel_at_period_end' => false], $h->getEntitlement('user_1'), $status);
    }
    [$h, , , $c] = world();
    send($h, $c, ev('evt_a', 'customer.subscription.created', 100, sub(['current_period_end' => NOW + 1])));
    eq(true, $h->getEntitlement('user_1')['entitled'], 'one second after now: entitled');
    $c->now = NOW + 1;
    eq(['entitled' => false, 'plan' => null, 'status' => 'active', 'current_period_end' => NOW + 1, 'cancel_at_period_end' => false], $h->getEntitlement('user_1'), 'equal to now: not entitled');
    [$g, , , $gc] = world(null, 60);
    send($g, $gc, ev('evt_a', 'customer.subscription.created', 100, sub(['current_period_end' => NOW + 1])));
    $gc->now = NOW + 60;
    eq(true, $g->getEntitlement('user_1')['entitled'], 'grace: 59 s after the end');
    $gc->now = NOW + 61;
    eq(false, $g->getEntitlement('user_1')['entitled'], 'grace: 60 s after the end');
}

// STRIPEWH-11
/** STRIPEWH-11: the period end's sources. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite. */
function test_stripewh11_period_end(): void
{
    [$h, $s, , $c] = world();
    send($h, $c, ev('evt_1', 'customer.subscription.created', 100, sub(['current_period_end' => NOW + 100, 'items' => ['data' => [['price' => ['id' => 'price_pro_monthly'], 'current_period_end' => NOW + 999]]]])));
    eq(NOW + 100, (int)$s->getRow('sub_a')['current_period_end'], 'top level wins');
    $o = sub(['items' => ['data' => [['price' => ['id' => 'price_pro_monthly'], 'current_period_end' => NOW + 300], ['price' => ['id' => 'price_x'], 'current_period_end' => NOW + 700], ['current_period_end' => 'soon']]]]);
    unset($o['current_period_end']);
    send($h, $c, ev('evt_2', 'customer.subscription.updated', 200, $o));
    eq(NOW + 700, (int)$s->getRow('sub_a')['current_period_end'], 'largest item');
    $o = sub();
    unset($o['current_period_end']);
    $o['items'] = ['data' => [['price' => ['id' => 'price_pro_monthly']]]];
    eq(APPLIED, send($h, $c, ev('evt_3', 'customer.subscription.updated', 300, $o)), 'neither applied');
    eq(NOW + 700, (int)$s->getRow('sub_a')['current_period_end'], 'stored period end kept');
}

// STRIPEWH-12
/**
 * STRIPEWH-12: the ignored cases are recorded with no change; a deleted event for a price that left
 * price_plans applies; moving to an unknown price applies and ends the entitlement. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
 */
function test_stripewh12_ignored_and_price_changes(): void
{
    [$h, $s, , $c] = world();
    $ignored = [
        'evt_unknown_price' => ev('evt_unknown_price', 'customer.subscription.created', 100, sub(['items' => ['data' => [['price' => ['id' => 'price_free']]]]])),
        'evt_no_user' => ev('evt_no_user', 'customer.subscription.created', 100, sub(['metadata' => ['user_id' => 'ghost'], 'customer' => 'cus_new'])),
        'evt_other_type' => ev('evt_other_type', 'invoice.paid', 100, ['id' => 'in_1']),
        'evt_bad_sub' => ev('evt_bad_sub', 'customer.subscription.created', 100, sub(['id' => 'sub-bad id'])),
    ];
    foreach ($ignored as $id => $body) {
        eq(IGNORED, send($h, $c, $body), $id);
        eq('ignored', $s->getEvent($id)['result'] ?? null, "$id recorded");
    }
    eq(0, counts($s)[1], 'no subscription row');
    eq(NONE, $h->getEntitlement('user_1'), 'no entitlement');

    send($h, $c, ev('evt_old', 'customer.subscription.created', 100, sub(['id' => 'sub_old', 'items' => ['data' => [['price' => ['id' => 'price_team']]]]])));
    [$h2] = world(null, 0, ['price_pro_monthly' => 'pro'], $s, $c);
    eq(APPLIED, send($h2, $c, ev('evt_old_del', 'customer.subscription.deleted', 200, sub(['id' => 'sub_old', 'items' => ['data' => [['price' => ['id' => 'price_team']]]]]))), 'deleted with a retired price');
    eq(['canceled', 'team'], [$s->getRow('sub_old')['status'], $s->getRow('sub_old')['plan']], 'retired price keeps its plan');

    send($h2, $c, ev('evt_m1', 'customer.subscription.created', 300, sub(['id' => 'sub_m', 'metadata' => ['user_id' => 'user_3']])));
    eq(true, $h2->getEntitlement('user_3')['entitled'], 'user_3 entitled');
    eq(APPLIED, send($h2, $c, ev('evt_m2', 'customer.subscription.updated', 400, sub(['id' => 'sub_m', 'metadata' => ['user_id' => 'user_3'], 'items' => ['data' => [['price' => ['id' => 'price_unknown']]]]]))), 'moved to an unknown price');
    eq(['price_unknown', null], [$s->getRow('sub_m')['price_id'], $s->getRow('sub_m')['plan']], 'plan null');
    eq(['entitled' => false, 'plan' => null, 'status' => 'active', 'current_period_end' => NOW + 1000, 'cancel_at_period_end' => false], $h2->getEntitlement('user_3'), 'no longer entitled');
}

// STRIPEWH-13
/**
 * STRIPEWH-13: checkout.session.completed fetches the subscription; a client error is 500 with the event not
 * recorded, and the redelivery applies. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
 */
function test_stripewh13_checkout(): void
{
    [$h, $s, $stripe, $c] = world();
    $session = ['id' => 'cs_1', 'mode' => 'subscription', 'subscription' => 'sub_chk', 'client_reference_id' => 'user_2', 'metadata' => ['user_id' => 'user_3']];
    $o = sub(['id' => 'sub_chk', 'customer' => 'cus_chk']);
    unset($o['metadata']);
    $stripe->subs['sub_chk'] = $o;
    $body = ev('evt_chk', 'checkout.session.completed', 500, $session);
    $stripe->fail = true;
    eq(['error' => 'processing_failed', 'status' => 500], send($h, $c, $body), 'client raises');
    eq([null, 0], [$s->getEvent('evt_chk'), counts($s)[1]], 'not recorded, nothing written');
    $stripe->fail = false;
    eq(APPLIED, send($h, $c, $body), 'redelivered');
    eq(['sub_chk', 'sub_chk'], $stripe->calls, 'fetched by the session subscription id');
    eq('user_2', $s->getRow('sub_chk')['user_id'], 'user is client_reference_id');
    eq(true, $h->getEntitlement('user_2')['entitled'], 'entitled');
    eq('applied', $s->getEvent('evt_chk')['result'], 'recorded');
    eq(IGNORED, send($h, $c, ev('evt_pay', 'checkout.session.completed', 600, ['mode' => 'payment', 'subscription' => 'sub_chk'])), 'payment mode ignored');
}

// STRIPEWH-14
/**
 * STRIPEWH-14: two subscriptions per user; user found through the stored row or the customer id; a
 * subscription never moves to another user. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite.
 */
function test_stripewh14_users_and_subscriptions(): void
{
    [$h, $s, , $c] = world();
    send($h, $c, ev('evt_1', 'customer.subscription.created', 100, sub(['id' => 'sub_one', 'current_period_end' => NOW + 2000])));
    $o = sub(['id' => 'sub_two', 'current_period_end' => NOW + 1000, 'items' => ['data' => [['price' => ['id' => 'price_team']]]]]);
    unset($o['metadata']);
    eq(APPLIED, send($h, $c, ev('evt_2', 'customer.subscription.created', 110, $o)), 'second subscription found by customer id');
    eq('user_1', $s->getRow('sub_two')['user_id'], 'customer id user');
    eq('pro', $h->getEntitlement('user_1')['plan'], 'greatest period end wins');
    $end = sub(['id' => 'sub_one']);
    unset($end['metadata']);
    eq(APPLIED, send($h, $c, ev('evt_3', 'customer.subscription.deleted', 200, $end)), 'end one, user from stored row');
    eq(['entitled' => true, 'plan' => 'team', 'status' => 'active', 'current_period_end' => NOW + 1000, 'cancel_at_period_end' => false], $h->getEntitlement('user_1'), 'the other still entitles');
    eq(APPLIED, send($h, $c, ev('evt_4', 'customer.subscription.updated', 300, sub(['id' => 'sub_two', 'metadata' => ['user_id' => 'user_2'], 'items' => ['data' => [['price' => ['id' => 'price_team']]]]]))), 'event naming another user');
    eq('user_1', $s->getRow('sub_two')['user_id'], 'never moves');
    eq(NONE, $h->getEntitlement('user_2'), 'user_2 gets nothing');
}

$tests = array_filter(get_defined_functions()['user'], static fn(string $f): bool => str_starts_with($f, 'test_'));
foreach ($tests as $t) {
    $before = $GLOBALS['FAILS'];
    try {
        $t();
    } catch (Throwable $e) {
        $GLOBALS['FAILS']++;
        echo "  EXCEPTION in $t: " . get_class($e) . ' ' . $e->getMessage() . "\n";
    }
    echo ($GLOBALS['FAILS'] === $before ? 'PASS ' : 'FAIL ') . $t . "\n";
}
echo $GLOBALS['FAILS'] === 0 ? "All tests passed\n" : "{$GLOBALS['FAILS']} assertion(s) failed\n";
exit($GLOBALS['FAILS'] === 0 ? 0 : 1);
