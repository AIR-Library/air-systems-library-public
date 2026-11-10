import { test } from "node:test";
import assert from "node:assert";
import {
  handle,
  is_required,
  purge_expired,
  _test_store,
  IdempotencyService,
  OperationFailed,
} from "./idempotency_keys_typescript.ts";

type OpResult = { status: number; body: any };

function makeOp(counter: { count: number }, succeed = true, delay = 0) {
  return () => {
    if (delay > 0) {
      return new Promise<OpResult>((resolve, reject) => {
        setTimeout(() => {
          if (succeed) {
            counter.count++;
            resolve({ status: 200, body: { msg: "ok", count: counter.count } });
          } else {
            reject(new Error("operation failed"));
          }
        }, delay);
      });
    } else {
      if (!succeed) throw new Error("operation failed");
      counter.count++;
      return { status: 200, body: { msg: "ok", count: counter.count } };
    }
  };
}

/* Helper to parse problem+json body */
function parseProblem(body: string) {
  return JSON.parse(body);
}

/* 1. first call runs the operation once */
// IDEM-01
test("first call runs operation once", async () => {
  const counter = { count: 0 };
  const resp = await handle(
    "userA",
    "key-1",
    "POST",
    "/test",
    "payload",
    makeOp(counter)
  );
  assert.strictEqual(counter.count, 1);
  assert.strictEqual(resp.status, 200);
  assert.strictEqual(resp.content_type, "application/json");
  const parsed = JSON.parse(resp.body);
  assert.strictEqual(parsed.msg, "ok");
});

/* 2. second identical call returns stored response */
// IDEM-02
test("second identical call returns stored response", async () => {
  const counter = { count: 0 };
  const op = makeOp(counter);
  const first = await handle("userB", "key-2", "POST", "/test", "payload", op);
  const second = await handle("userB", "key-2", "POST", "/test", "payload", op);
  assert.strictEqual(counter.count, 1);
  assert.deepStrictEqual(first.body, second.body);
});

/* 3. same key, different body -> 422 */
// IDEM-03
test("same key, different body yields 422", async () => {
  const counter = { count: 0 };
  const op = makeOp(counter);
  await handle("userC", "key-3", "POST", "/test", "payload1", op);
  const resp = await handle(
    "userC",
    "key-3",
    "POST",
    "/test",
    "different",
    op
  );
  assert.strictEqual(resp.status, 422);
  assert.strictEqual(resp.content_type, "application/problem+json");
  const prob = parseProblem(resp.body);
  assert.strictEqual(prob.title, "Payload Mismatch");
});

/* 4. same key while first is in progress -> 409 */
// IDEM-04
test("concurrent request while in progress yields 409", async () => {
  const counter = { count: 0 };
  const op = makeOp(counter, true, 100); // 100ms delay
  const firstPromise = handle(
    "userD",
    "key-4",
    "POST",
    "/test",
    "payload",
    op
  );
  // fire second request immediately
  const secondResp = await handle(
    "userD",
    "key-4",
    "POST",
    "/test",
    "payload",
    op
  );
  const second = secondResp;
  assert.strictEqual(second.status, 409);
  assert.strictEqual(second.content_type, "application/problem+json");
  const prob = parseProblem(second.body);
  assert.strictEqual(prob.title, "Request In Progress");
  await firstPromise; // ensure cleanup
});

/* 5. required operation with no key -> 400 */
// IDEM-05
test("missing key on required operation yields 400", async () => {
  const counter = { count: 0 };
  const resp = await handle(
    "userE",
    undefined,
    "POST",
    "/test",
    "payload",
    makeOp(counter)
  );
  assert.strictEqual(resp.status, 400);
  assert.strictEqual(resp.content_type, "application/problem+json");
  const prob = parseProblem(resp.body);
  assert.strictEqual(prob.title, "Missing Idempotency-Key");
});

/* 6. same key under different scopes runs twice */
// IDEM-06
test("same key under different scopes are independent", async () => {
  const counter = { count: 0 };
  const op = makeOp(counter);
  await handle("scope1", "shared-key", "POST", "/test", "payload", op);
  await handle("scope2", "shared-key", "POST", "/test", "payload", op);
  assert.strictEqual(counter.count, 2);
});

/* 7. expired key runs operation again */
// IDEM-07
test("expired key allows re‑execution", async () => {
  const counter = { count: 0 };
  const op = makeOp(counter);
  await handle("userF", "key-5", "POST", "/test", "payload", op);
  // force expiration
  const rec = _test_store.get("userF", "key-5");
  assert.ok(rec);
  rec.expires_at = new Date(Date.now() - 1000);
  purge_expired();
  await handle("userF", "key-5", "POST", "/test", "payload", op);
  assert.strictEqual(counter.count, 2);
});

/* 8. operation that throws frees the key */
// IDEM-08
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the operation now raises OperationFailed. The IDEM-08/10 amendment
// says only OperationFailed (a definite "did nothing") frees the key; any other error leaves it 'uncertain'
// (see the IDEM-10 test below), so a plain Error here would no longer let the retry run.
test("failed operation frees the key for retry", async () => {
  const counter = { count: 0 };
  const failingOp = () => {
    throw new OperationFailed("card declined");
  };
  try {
    await handle("userG", "key-6", "POST", "/test", "payload", failingOp);
    assert.fail("should have thrown");
  } catch (e) {
    assert.ok(e instanceof OperationFailed);
  }
  // retry with a successful op
  const successOp = makeOp(counter);
  const resp = await handle("userG", "key-6", "POST", "/test", "payload", successOp);
  assert.strictEqual(counter.count, 1);
  assert.strictEqual(resp.status, 200);
});

/* 9. error responses have correct content type and fields */
// IDEM-09
test("error responses conform to problem+json spec", async () => {
  const counter = { count: 0 };
  const op = makeOp(counter);
  // 400 case
  const r400 = await handle("userH", undefined, "POST", "/test", "p", op);
  assert.strictEqual(r400.content_type, "application/problem+json");
  const p400 = parseProblem(r400.body);
  assert.ok(p400.type);
  assert.ok(p400.title);
  assert.ok(p400.detail);
  // 422 case
  await handle("userH", "k7", "POST", "/test", "a", op);
  const r422 = await handle("userH", "k7", "POST", "/test", "b", op);
  assert.strictEqual(r422.content_type, "application/problem+json");
  const p422 = parseProblem(r422.body);
  assert.ok(p422.type);
  assert.ok(p422.title);
  assert.ok(p422.detail);
  // 409 case (use delayed op)
  const delayedOp = makeOp(counter, true, 100);
  const p1 = handle("userI", "k8", "POST", "/test", "c", delayedOp);
  const r409 = await handle("userI", "k8", "POST", "/test", "c", delayedOp);
  assert.strictEqual(r409.status, 409);
  assert.strictEqual(r409.content_type, "application/problem+json");
  const p409 = parseProblem(r409.body);
  assert.ok(p409.type);
  assert.ok(p409.title);
  assert.ok(p409.detail);
  await p1; // cleanup
});

/** A clock the test moves by hand. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function fixedClock(start = Date.parse("2026-06-15T10:00:00Z")) {
  const clock = { t: start, now: () => new Date(clock.t) };
  return clock;
}

const DAY = 24 * 60 * 60 * 1000;

/**
 * IDEM-07: on an injected clock, a completed key 24 h old runs the operation again, while an in_progress key past
 * expires_at (a crashed process) is uncertain: 409 outcome_unknown, the operation does not run, and purge_expired
 * keeps it. In: a fresh service and a hand-moved clock. Out: assertions only. Why: IDEM-07 amendment.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// IDEM-07
test("expired completed key runs again; in_progress past expires_at is outcome_unknown", async () => {
  const clock = fixedClock();
  const svc = new IdempotencyService(undefined, clock.now);
  const counter = { count: 0 };
  await svc.handle("u", "done", "POST", "/charge", "{}", makeOp(counter));
  clock.t += DAY;
  const again = await svc.handle("u", "done", "POST", "/charge", "{}", makeOp(counter));
  assert.strictEqual(again.status, 200);
  assert.strictEqual(counter.count, 2);

  // An in_progress record whose process died: its operation never finishes.
  const never = svc.handle("u", "stuck", "POST", "/charge", "{}", () => new Promise<OpResult>(() => {}));
  void never;
  clock.t += DAY;
  svc.purge_expired();
  const ran = { count: 0 };
  const r = await svc.handle("u", "stuck", "POST", "/charge", "{}", makeOp(ran));
  assert.strictEqual(r.status, 409);
  assert.strictEqual(r.content_type, "application/problem+json");
  assert.strictEqual(parseProblem(r.body).type, "outcome_unknown");
  assert.strictEqual(ran.count, 0);
  assert.deepStrictEqual(svc.list_uncertain(10).map((x) => x.idem_key), ["stuck"]);
});

/**
 * IDEM-10: any error other than OperationFailed leaves the key 'uncertain': the retry gets 409 outcome_unknown
 * and the operation count stays at 1; release() frees it and the next retry runs. release() on a key that is not
 * uncertain is false and changes nothing. In: a fresh service. Out: assertions only. Why: IDEM-10 amendment (a
 * timeout after the provider was called must never charge twice). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
// IDEM-10
test("a non-OperationFailed error leaves the key uncertain until release()", async () => {
  const svc = new IdempotencyService(undefined, fixedClock().now);
  const counter = { count: 0 };
  const timesOut = () => {
    counter.count++;
    throw new Error("socket timeout after provider call");
  };
  await assert.rejects(svc.handle("u", "k", "POST", "/charge", "{}", timesOut), /socket timeout/);
  const retry = await svc.handle("u", "k", "POST", "/charge", "{}", timesOut);
  assert.strictEqual(retry.status, 409);
  const prob = parseProblem(retry.body);
  assert.strictEqual(prob.type, "outcome_unknown");
  assert.ok(prob.title && prob.detail);
  assert.strictEqual(counter.count, 1);
  // a different body is still 422 first
  assert.strictEqual((await svc.handle("u", "k", "POST", "/charge", "{\"x\":1}", timesOut)).status, 422);

  assert.strictEqual(svc.release("other-scope", "k"), false);
  assert.strictEqual(svc.release("u", "k"), true);
  assert.strictEqual(svc.release("u", "k"), false);
  const ok = await svc.handle("u", "k", "POST", "/charge", "{}", makeOp(counter));
  assert.strictEqual(ok.status, 200);
  assert.strictEqual(counter.count, 2);
  assert.strictEqual(svc.release("u", "k"), false, "a completed key is not released");
});

/**
 * IDEM-11: resolve() on an uncertain key stores the given response; a retry returns it without running the
 * operation; a second resolve() or a release() then returns false. The resolved record expires 24 h later.
 * In: a fresh service on a fixed clock. Out: assertions only. Why: IDEM-11 amendment.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
 */
// IDEM-11
test("resolve() stores the reconciled outcome once", async () => {
  const clock = fixedClock();
  const svc = new IdempotencyService(undefined, clock.now);
  const counter = { count: 0 };
  await assert.rejects(
    svc.handle("u", "r", "POST", "/charge", "{}", () => { throw new Error("connection reset"); }),
    /connection reset/,
  );
  assert.strictEqual(svc.resolve("u", "r", 201, { charge: "ch_1" }), true);
  const retry = await svc.handle("u", "r", "POST", "/charge", "{}", makeOp(counter));
  assert.strictEqual(retry.status, 201);
  assert.strictEqual(retry.content_type, "application/json");
  assert.deepStrictEqual(JSON.parse(retry.body), { charge: "ch_1" });
  assert.strictEqual(counter.count, 0);
  assert.strictEqual(svc.resolve("u", "r", 500, { other: true }), false);
  assert.strictEqual(svc.release("u", "r"), false);
  assert.deepStrictEqual(svc.list_uncertain(10), []);
  const rec = (svc.store as any).get("u", "r");
  assert.strictEqual(rec.expires_at.getTime(), clock.t + DAY);
});
