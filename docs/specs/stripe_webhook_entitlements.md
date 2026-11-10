# Stripe Webhook Entitlements (Verified Events to Plan Access)

Reference contract for `saas_templates/<lang>/stripe_webhook_entitlements_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# STRIPEWH-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `STRIPEWH-01` | sign_payload with the spec's secret, timestamp and body gives the spec's header; handle_webhook with that header at now = 1700000000 answers 200 applied, and get_entitlement("user_1") is the spec's answer |
| `STRIPEWH-02` | 400 invalid_signature, with nothing stored, for: another secret; one changed byte of the body; a changed t; no v1 element; a v1 that is not 64 lower-case hex characters; only a v0 element; two t elements |
| `STRIPEWH-03` | a missing or empty header is 400 missing_signature; a webhook_secret under 16 bytes is 503 webhook_not_configured for every call, whatever its signature |
| `STRIPEWH-04` | tolerance: a correctly signed event whose t is 300 seconds old is accepted, 301 seconds old is 400 timestamp_out_of_tolerance, and 301 seconds in the future is refused the same way |
| `STRIPEWH-05` | a header with two v1 values is accepted when either is right (the second, in the test), also with a v0 element and spaces after the commas |
| `STRIPEWH-06` | a correctly signed body that is not JSON, is not an object, has no evt_ id, no type, no whole-number created or no data.object is 400 invalid_payload, and its id is not recorded; created given as true, as "1700000000", as 1700000000.5, as -1 or as 100000000000 is invalid_payload, and created 1700000000.0 is accepted |
| `STRIPEWH-07` | customer.subscription.created with status active, a known price and metadata.user_id gives {entitled: true, plan, status: "active", current_period_end, cancel_at_period_end}; before that event the user's answer is the "none" answer, and the event leaves another user's answer as it was |
| `STRIPEWH-08` | the same event id delivered twice: the second answer is 200 duplicate and the subscription row is unchanged |
| `STRIPEWH-09` | out of order: after an event created at 200, an event for the same subscription created at 100 is 200 stale and changes nothing; at an equal created time a created-type event does not overwrite an updated one, and a deleted one overwrites both; a second updated event with the same created as the stored one makes the system fetch the subscription through the injected client, and the row ends with the fetched state |
| `STRIPEWH-10` | the entitlement ends at once when the status becomes past_due, unpaid or canceled, and for an active status when current_period_end <= now (equal to now: not entitled; one second after now: entitled); with period_grace_seconds 60 it lasts 60 seconds longer |
| `STRIPEWH-11` | the period end is the top-level current_period_end, else the largest items.data[].current_period_end; an event with neither keeps the stored period end |
| `STRIPEWH-12` | 200 ignored, with no entitlement change, for: a new subscription whose price is not in price_plans; a user that does not exist; an event type the system does not handle; a malformed subscription id; each of these event ids is still recorded; a deleted event for a stored subscription is applied even when its price has left price_plans; an updated event that moves a stored subscription to a price that is not in price_plans is applied, and the user is no longer entitled |
| `STRIPEWH-13` | checkout.session.completed: the subscription is fetched through the injected client by the session's subscription id and the user is client_reference_id; when the client raises, the answer is 500 processing_failed, the event id is NOT recorded, and the same event delivered again is applied |
| `STRIPEWH-14` | one user with two subscriptions: ending one leaves the entitlement the other gives; an event without metadata finds its user through the stored subscription or the customer id; an event naming another user never moves a subscription |

## Contract

```text
Source: Stripe's documented webhook signature scheme (the Stripe-Signature header, "t=<timestamp>,v1=<hex
HMAC-SHA256>") and its event and subscription objects. The entitlement rules come from two production billing
implementations and their tests.

PURPOSE:
  Receive Stripe's webhook, prove it came from Stripe, apply every event exactly once and in the right order,
  and keep one answer per user: what they are entitled to right now. The webhook is the ONLY writer of that
  answer, so no request from a browser can grant a plan.

SCHEMA:
  stripe_events (event_id TEXT PRIMARY KEY, type TEXT, created INT, received_at INT, result TEXT)
  entitlement_subscriptions (stripe_subscription_id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
                 stripe_customer_id TEXT, price_id TEXT, plan TEXT NULL, status TEXT,
                 current_period_end INT NOT NULL, cancel_at_period_end BOOL, event_at INT, event_rank INT,
                 updated_at INT)
  ("a row" below is a row of entitlement_subscriptions. The table has its own name so that it never collides
  with the subscriptions table of billing_subscriptions.)

CONVENTIONS:
  - Names are snake_case here; each language spells them its own way (handleWebhook, HandleWebhook).
  - Every answer is a RETURNED value with its `status` (the HTTP status the route serves), never an
    unhandled exception.
  - now = the injected clock, whole seconds since the Unix epoch.
  - payload = the RAW request body: the exact bytes received, never parsed and written out again.
  - Texts are ordered and compared byte by byte (ordinal), never by locale: C# StringComparer.Ordinal, SQL
    COLLATE "C" or BINARY.
  - "Missing" is the language's own absent value where the parameter can carry one (None, null, undefined, nil
    pointer, Option::None); otherwise the empty text. The injected Stripe client "raises" by the language's
    error path: an exception, a Go error, a Rust Err.
  - get_entitlement is not an HTTP answer: its `status` is the subscription's status, in Stripe's spelling.

CONFIGURATION (injected):
  webhook_secret            the endpoint's signing secret
  price_plans               {price_id: plan}, for example {"price_pro_monthly": "pro"}
  stripe_client             retrieve_subscription(subscription_id) -> a subscription object, or raises.
                            Tests pass a fake: no network.
  user_exists(user_id)      the application's account lookup -> true | false
  period_grace_seconds      default 0. Added to current_period_end when entitlement is decided, for a product
                            that will not turn a paying customer away in the seconds between the end of a
                            period and the renewal event.
  clock; TOLERANCE = 300 seconds

ENDPOINTS / FUNCTIONS (the checks run in the order written; the first that fails answers):
  sign_payload(payload, secret, timestamp) -> "t=" + timestamp + ",v1=" + hex
      hex = lower-case hex of HMAC-SHA256(key = the UTF-8 of secret, message = the decimal digits of timestamp
      + "." + payload). For tests and for clients that call this endpoint in a test environment.
      The WHOLE secret text, "whsec_" included, is the key. Do not base64-decode it as the webhooks system
      does with its own secrets.
  verify_signature(payload, header, secret, now) -> {ok: true, timestamp}
      1. secret is shorter than 16 bytes                    -> 503 {error: "webhook_not_configured"}
      2. header is missing or empty                         -> 400 {error: "missing_signature"}
      3. header is longer than 4096 bytes                   -> 400 {error: "invalid_signature"}
         Split it at ","; trim ASCII spaces from each element; split each at its first "="; an element with no
         "=" is ignored. There is exactly ONE element named t and its value is 1 to 12 digits 0-9
                                                    otherwise -> 400 {error: "invalid_signature"}
         candidates = the values of the elements named v1 that are exactly 64 characters of [0-9a-f]; other
         names (v0, ...) are ignored.           no candidate -> 400 {error: "invalid_signature"}
      4. expected = hex of HMAC-SHA256(secret, the t value as written + "." + payload). Compare expected with
         EVERY candidate in constant time, without stopping at the first hit.
                                                  none equal -> 400 {error: "invalid_signature"}
      5. the absolute value of (now - t) is over 300        -> 400 {error: "timestamp_out_of_tolerance"}
  handle_webhook(payload, header) -> {status: 200, received: true, result}
      result: "applied" | "duplicate" | "stale" | "ignored"
      1-5. verify_signature(payload, header, webhook_secret, now); its refusal is the answer.
      6. Only now parse the payload as JSON. It must be valid UTF-8 with no byte-order mark, and the parse must
         succeed: anything the parser raises, a depth limit included, is this step's refusal. It must be an
         object with: id, a text matching evt_[A-Za-z0-9_]{1,200} (the whole text); type, a text of 1 to 100
         characters, each U+0020 to U+007E; created, a TIME; data.object, an object.
                                                    otherwise -> 400 {error: "invalid_payload"}
         TIME (the one number rule of this spec; current_period_end uses it too): a JSON number, never true,
         false, a text or null, whose value is a whole number from 0 to 99999999999. 1700000000.0 and 1.7e9
         count, because parsers do not tell them from 1700000000. 1700000000.5, -1, 1e400 and 100000000000 do
         not. Read it as the language's number and test: it is finite, it equals its floor, it is in range.
         (Python: the type is int or float and not bool.)
         A body holding any number that is not finite in the language's double (1e400 anywhere, not only in a
         TIME field) is 400 invalid_payload as a whole: some parsers refuse it while parsing, so every language
         refuses it. Amended 2026-11-10 (Phase B.4, found by the Rust implementer).
      7. CLAIM: insert stripe_events (event_id, type, created, received_at = now). The id is already there
                                                            -> {status: 200, received: true, result: "duplicate"}
      8. result = APPLY(event). Store it in the event's row -> {status: 200, received: true, result}
      9. Any error raised while applying (the Stripe client, the store): undo step 7 and every change of this
         call                                               -> 500 {error: "processing_failed"}
         Stripe then sends the event again, and that delivery is applied. Steps 7-9 are one transaction.
  get_entitlement(user_id) -> {entitled, plan, status, current_period_end, cancel_at_period_end}
      ENTITLING(row): row.plan is not null AND row.status is "active" or "trialing" AND
      row.current_period_end + period_grace_seconds > now.
      a. Among the user's ENTITLING rows take the greatest current_period_end, then the greatest event_at, then
         the greatest stripe_subscription_id -> {entitled: true, plan, status, current_period_end,
         cancel_at_period_end} of that row.
      b. No ENTITLING row but some row: the greatest event_at, then the greatest stripe_subscription_id
         -> {entitled: false, plan: null, status, current_period_end, cancel_at_period_end} of that row.
      c. No row -> {entitled: false, plan: null, status: "none", current_period_end: null,
         cancel_at_period_end: false}.
      Computed from the clock at every call, never cached past a period end.

APPLY(event), by event.type:
  "customer.subscription.created"   -> SUBSCRIPTION(data.object, hint = object.metadata.user_id, rank 0)
  "customer.subscription.updated"   -> SUBSCRIPTION(data.object, hint = object.metadata.user_id, rank 1)
  "customer.subscription.deleted"   -> SUBSCRIPTION(data.object, hint = object.metadata.user_id, rank 2);
                                       the stored status is "canceled" whatever the object says
  "checkout.session.completed"      -> session = data.object. session.mode is not "subscription", or
                                       session.subscription is not a valid subscription id -> "ignored".
                                       A row for that id exists and (row.event_at, row.event_rank) is greater
                                       than (event.created, 1) -> "stale", without calling Stripe.
                                       sub = stripe_client.retrieve_subscription(session.subscription)
                                       -> SUBSCRIPTION(sub, hint = session.client_reference_id, or else
                                       session.metadata.user_id, rank 1)
                                       client_reference_id is trusted only for Checkout Sessions YOUR SERVER
                                       created: on a Payment Link the buyer sets it in the URL.
  any other type                    -> "ignored"

SUBSCRIPTION(sub, hint, rank), with event_at = event.created:
  a. sub.id does not match sub_[A-Za-z0-9_]{1,200} (the whole text)        -> "ignored"
  b. row = the stored row for sub.id, if any. price_id = sub.items.data[0].price.id.
     No row, and price_id is missing or not in price_plans                  -> "ignored"
     (an unknown price never creates a row, so it never grants.)
     A row exists; the event still applies, so the subscription's end always arrives. Its price and plan:
       price_id is in price_plans                     -> price_id, plan = price_plans[price_id]
       price_id is missing, or equals the row's price_id
                                                      -> the row keeps its price_id and plan (a price that
                                                         was taken off sale still serves those who bought it)
       price_id is another price, not in price_plans  -> price_id = that price, plan = null
     A row whose plan is null entitles nobody, whatever its status.
  c. USER: row.user_id when there is a row (a subscription never moves to another user); else hint, when it
     is a non-empty text and user_exists(hint); else the user_id of the stored rows with the same
     stripe_customer_id as sub.customer, when there is at least one and they all name the same user; else
                                                                            -> "ignored"
  d. a row exists and (event_at, rank) is less than (row.event_at, row.event_rank), comparing event_at first
                                                                            -> "stale"
     a row exists, rank is 0 or 1, and (event_at, rank) EQUALS (row.event_at, row.event_rank): two events of
     one second and one kind, and nothing in them says which is newer. Do not guess from arrival order:
     sub = stripe_client.retrieve_subscription(sub.id), what Stripe holds now, and continue with that object:
     rule b (price_id and plan) is applied again to the fetched object, so the row ends with Stripe's current
     price and plan. (Ruled 2026-11-10 after the Python, TypeScript and PHP implementers read it that way.)
     If the client raises, step 9 answers 500 and Stripe sends the event again.
     (Rank 2 needs no fetch: the status is "canceled" either way. checkout.session.completed has just
     fetched the subscription: it does not fetch a second time.)
  e. current_period_end = sub.current_period_end when it is a TIME; else the largest
     items.data[].current_period_end that is a TIME; else the stored row's value (0 for a new row)
  f. status = "canceled" for rank 2, else sub.status when it is a text of 1 to 32 characters, each one of
     [a-z_]; else                                                           -> "ignored"
  g. Write the row: user_id, stripe_customer_id = sub.customer, price_id and plan as rule b says, status,
     current_period_end, cancel_at_period_end = (sub.cancel_at_period_end is true), event_at, event_rank =
     rank, updated_at = now                                                 -> "applied"

IMPLEMENTATION -- RULES:
  - Verify BEFORE parsing: nothing in the body is trusted, or even decoded, until step 4 has passed.
  - Stripe's `created` has one-second resolution, so the rank orders events of the same second: created <
    updated < deleted. Two events with the same created AND rank cannot be ordered, so the second one makes
    the system ask Stripe.
  - Stripe sends events more than once and in any order, and retries any answer that is not 2xx. So duplicate,
    stale and ignored are 200; only a bad signature, a bad body or a failure that a retry can fix is not.
  - Non-payment ends access at once: only "active" and "trialing" entitle, and only until current_period_end
    (plus period_grace_seconds, 0 unless configured). A row with no known period end (0) entitles nobody.
  - Relation to billing_subscriptions: that system creates and changes subscriptions by calling Stripe; this
    one decides access from Stripe's events. Give Stripe ONE webhook route. Where both systems are installed
    the route calls this system's handle_webhook, and billing_subscriptions' webhook flow is not used for
    access. The tables here are stripe_events and entitlement_subscriptions, so they never collide with that
    system's events and subscriptions tables. Both answer a bad signature with 400 {error:
    "invalid_signature"}.
  - Statuses are stored exactly as Stripe spells them: "active", "trialing", "past_due", "unpaid",
    "incomplete", "incomplete_expired", "paused" and "canceled" (one l, where billing_subscriptions writes
    'cancelled'). Never translate or re-spell a status.
  - Newer Stripe API versions keep current_period_end on the subscription ITEMS; older ones on the subscription.
    Rule e reads both and never overwrites a known period end with nothing.
  - The user comes from data inside the signed event (metadata the server set at checkout) or from stored rows,
    never from a request parameter. No function of this system takes a plan, a status or a period end from a
    caller.
  - Never log the secret, the signature header or the payload. Logs may carry the event id, the type and the result.
  - SQL is parameterized; the CLAIM is an insert that fails on a duplicate key, not a read followed by a write.

PRIMITIVES (standard library unless a package is named):
  HMAC-SHA256      Python hmac + hashlib | JavaScript, TypeScript node:crypto createHmac | Java javax.crypto.Mac
                   "HmacSHA256" | C# System.Security.Cryptography.HMACSHA256 | PHP hash_hmac | Go crypto/hmac +
                   crypto/sha256 | Rust hmac + sha2 crates (on the runner's list)
  constant time    Python hmac.compare_digest | Node crypto.timingSafeEqual | Java MessageDigest.isEqual | C#
                   CryptographicOperations.FixedTimeEquals | PHP hash_equals | Go hmac.Equal | Rust: an XOR
                   fold over the two 64-character strings
  JSON             the standard library's parser (Java: Jackson or Gson, Rust: serde_json; both on the runner's
                   list). The Stripe SDK is not needed and not used.

TEST VECTORS (every language asserts these):
  secret    = "whsec_" + "test_secret_for_vectors"
  timestamp = 1700000000
  body      = the 317 bytes below, joined with nothing between the four lines (SHA-256 of the body:
              f2e8a2d52e46e4642dde0390c9def15047ff2178a8d33a9928698aca132cbe88)
      {"id":"evt_test_0001","type":"customer.subscription.updated","created":1700000000,
      "data":{"object":{"id":"sub_test_0001","customer":"cus_test_0001","status":"active",
      "current_period_end":1702592000,"cancel_at_period_end":false,
      "metadata":{"user_id":"user_1"},"items":{"data":[{"price":{"id":"price_pro_monthly"}}]}}}}
  sign_payload(body, secret, 1700000000) =
      "t=1700000000,v1=5bca2d8b83d83f9a52f3b25714245817b15ae87b9e73abcca2c7a514977a8ae5"
  With price_plans = {"price_pro_monthly": "pro"}, user_exists("user_1") = true and now = 1700000000:
      handle_webhook(body, that header) -> {status: 200, received: true, result: "applied"}
      get_entitlement("user_1") -> {entitled: true, plan: "pro", status: "active",
                                    current_period_end: 1702592000, cancel_at_period_end: false}
  With a fresh store each time: now = 1700000300 -> 200 applied; now = 1700000301 -> 400
      timestamp_out_of_tolerance; now = 1699999700 -> 200 applied; now = 1699999699 -> 400
      timestamp_out_of_tolerance.
  Other tests build their own bodies (change id, type, created, status, the price or the metadata) and sign
  them with sign_payload.

TESTS:
  - **STRIPEWH-01** sign_payload with the spec's secret, timestamp and body gives the spec's header; handle_webhook with that header at now = 1700000000 answers 200 applied, and get_entitlement("user_1") is the spec's answer
  - **STRIPEWH-02** 400 invalid_signature, with nothing stored, for: another secret; one changed byte of the body; a changed t; no v1 element; a v1 that is not 64 lower-case hex characters; only a v0 element; two t elements
  - **STRIPEWH-03** a missing or empty header is 400 missing_signature; a webhook_secret under 16 bytes is 503 webhook_not_configured for every call, whatever its signature
  - **STRIPEWH-04** tolerance: a correctly signed event whose t is 300 seconds old is accepted, 301 seconds old is 400 timestamp_out_of_tolerance, and 301 seconds in the future is refused the same way
  - **STRIPEWH-05** a header with two v1 values is accepted when either is right (the second, in the test), also with a v0 element and spaces after the commas
  - **STRIPEWH-06** a correctly signed body that is not JSON, is not an object, has no evt_ id, no type, no whole-number created or no data.object is 400 invalid_payload, and its id is not recorded; created given as true, as "1700000000", as 1700000000.5, as -1 or as 100000000000 is invalid_payload, and created 1700000000.0 is accepted
  - **STRIPEWH-07** customer.subscription.created with status active, a known price and metadata.user_id gives {entitled: true, plan, status: "active", current_period_end, cancel_at_period_end}; before that event the user's answer is the "none" answer, and the event leaves another user's answer as it was
  - **STRIPEWH-08** the same event id delivered twice: the second answer is 200 duplicate and the subscription row is unchanged
  - **STRIPEWH-09** out of order: after an event created at 200, an event for the same subscription created at 100 is 200 stale and changes nothing; at an equal created time a created-type event does not overwrite an updated one, and a deleted one overwrites both; a second updated event with the same created as the stored one makes the system fetch the subscription through the injected client, and the row ends with the fetched state
  - **STRIPEWH-10** the entitlement ends at once when the status becomes past_due, unpaid or canceled, and for an active status when current_period_end <= now (equal to now: not entitled; one second after now: entitled); with period_grace_seconds 60 it lasts 60 seconds longer
  - **STRIPEWH-11** the period end is the top-level current_period_end, else the largest items.data[].current_period_end; an event with neither keeps the stored period end
  - **STRIPEWH-12** 200 ignored, with no entitlement change, for: a new subscription whose price is not in price_plans; a user that does not exist; an event type the system does not handle; a malformed subscription id; each of these event ids is still recorded; a deleted event for a stored subscription is applied even when its price has left price_plans; an updated event that moves a stored subscription to a price that is not in price_plans is applied, and the user is no longer entitled
  - **STRIPEWH-13** checkout.session.completed: the subscription is fetched through the injected client by the session's subscription id and the user is client_reference_id; when the client raises, the answer is 500 processing_failed, the event id is NOT recorded, and the same event delivered again is applied
  - **STRIPEWH-14** one user with two subscriptions: ending one leaves the entitlement the other gives; an event without metadata finds its user through the stored subscription or the customer id; an event naming another user never moves a subscription
```
