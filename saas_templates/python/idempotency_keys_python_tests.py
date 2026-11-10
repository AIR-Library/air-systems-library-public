import json
import sqlite3
import threading
import pytest
from idempotency_keys_python import (
    IdempotencyService, IdempotencyOptions, InMemoryStore, SqlStore,
    IdempotencyError, IdempotencyRecord, Store, compute_fingerprint, OperationFailed
)

T0 = 1700000000

class FakeClock:
    def __init__(self, t=T0):
        self.t = t
    def __call__(self):
        return self.t

def make_service(store=None, clock=None, ttl=86400, methods=("POST", "PATCH")):
    if store is None:
        store = InMemoryStore()
    if clock is None:
        clock = FakeClock()
    opts = IdempotencyOptions(clock=clock, ttl_seconds=ttl, required_methods=methods)
    return IdempotencyService(store, opts), store, clock

def make_op():
    state = {"count": 0}
    def op():
        state["count"] += 1
        return {"status": 201, "body": json.dumps({"n": state["count"]})}
    return op, state

def both_stores():
    """Yield a fresh InMemoryStore, then a fresh SqlStore on an in-memory SQLite database (usable from threads).
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only."""
    yield InMemoryStore()
    yield SqlStore(sqlite3.connect(":memory:", check_same_thread=False))


def problem_type(result):
    """The last path segment of a problem response's type, e.g. "outcome_unknown". 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    assert result["content_type"] == "application/problem+json"
    body = json.loads(result["body"])
    assert set(body) == {"type", "title", "detail"}
    return body["type"].rsplit("/", 1)[-1]


def run_all_stores(test_fn):
    def wrapper():
        # InMemoryStore
        test_fn(InMemoryStore, FakeClock)
        # SqlStore
        conn = sqlite3.connect(":memory:")
        store = SqlStore(conn)
        test_fn(store, FakeClock)
    return wrapper

# IDEM-01
def test_first_call_runs_operation_once():
    for StoreCls in [InMemoryStore, SqlStore]:
        if StoreCls == SqlStore:
            conn = sqlite3.connect(":memory:")
            store = SqlStore(conn)
        else:
            store = StoreCls()
        clock = FakeClock()
        svc, _, _ = make_service(store, clock)
        op, state = make_op()
        result = svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)
        assert result["status"] == 201
        assert result["content_type"] == "application/json"
        assert json.loads(result["body"]) == {"n": 1}
        assert state["count"] == 1

# IDEM-02
def test_identical_retry_replays_stored_response():
    for StoreCls in [InMemoryStore, SqlStore]:
        if StoreCls == SqlStore:
            conn = sqlite3.connect(":memory:")
            store = SqlStore(conn)
        else:
            store = StoreCls()
        clock = FakeClock()
        svc, _, _ = make_service(store, clock)
        op, state = make_op()
        r1 = svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)
        r2 = svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)
        assert r1 == r2
        assert json.loads(r2["body"]) == {"n": 1}
        assert state["count"] == 1

# IDEM-03
def test_same_key_different_body_is_422():
    for StoreCls in [InMemoryStore, SqlStore]:
        if StoreCls == SqlStore:
            conn = sqlite3.connect(":memory:")
            store = SqlStore(conn)
        else:
            store = StoreCls()
        clock = FakeClock()
        svc, _, _ = make_service(store, clock)
        op, state = make_op()
        svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)
        result = svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":200}', op)
        assert result["status"] == 422
        assert result["content_type"] == "application/problem+json"
        assert json.loads(result["body"]) == {
            "type": "https://developer.example.com/problems/idempotency-key-reused",
            "title": "Idempotency-Key is already used",
            "detail": "This Idempotency-Key was already used with a different request payload."
        }
        assert state["count"] == 1

# IDEM-04
def test_same_key_while_in_progress_is_409():
    for StoreCls in [InMemoryStore, SqlStore]:
        if StoreCls == SqlStore:
            conn = sqlite3.connect(":memory:")
            store = SqlStore(conn)
        else:
            store = StoreCls()
        clock = FakeClock()
        svc, _, _ = make_service(store, clock)
        op2_ran = {"count": 0}
        def op():
            op2_ran["count"] += 1
            inner_svc, _, _ = make_service(store, clock)
            inner_result = inner_svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', lambda: {"status": 200, "body": '{"x":1}'})
            assert inner_result["status"] == 409
            assert inner_result["content_type"] == "application/problem+json"
            assert json.loads(inner_result["body"]) == {
                "type": "https://developer.example.com/problems/idempotency-request-outstanding",
                "title": "A request is outstanding for this Idempotency-Key",
                "detail": "A request with the same Idempotency-Key is still being processed. Retry later."
            }
            return {"status": 201, "body": '{"n":1}'}
        result = svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)
        assert result["status"] == 201
        assert json.loads(result["body"]) == {"n": 1}
        assert op2_ran["count"] == 1

# IDEM-05
def test_required_method_without_key_is_400():
    for StoreCls in [InMemoryStore, SqlStore]:
        if StoreCls == SqlStore:
            conn = sqlite3.connect(":memory:")
            store = SqlStore(conn)
        else:
            store = StoreCls()
        clock = FakeClock()
        svc, _, _ = make_service(store, clock)
        op, state = make_op()
        r1 = svc.handle("client-a", None, "POST", "/charges", '{"amount":100}', op)
        assert r1["status"] == 400
        assert r1["content_type"] == "application/problem+json"
        assert json.loads(r1["body"]) == {
            "type": "https://developer.example.com/problems/idempotency-key-missing",
            "title": "Idempotency-Key is missing",
            "detail": "This operation requires an Idempotency-Key request header."
        }
        r2 = svc.handle("client-a", "", "POST", "/charges", '{"amount":100}', op)
        assert r2["status"] == 400
        assert state["count"] == 0

# IDEM-06
def test_same_key_in_two_scopes_runs_twice():
    for StoreCls in [InMemoryStore, SqlStore]:
        if StoreCls == SqlStore:
            conn = sqlite3.connect(":memory:")
            store = SqlStore(conn)
        else:
            store = StoreCls()
        clock = FakeClock()
        svc, _, _ = make_service(store, clock)
        op, state = make_op()
        r1 = svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)
        r2 = svc.handle("client-b", "key-1", "POST", "/charges", '{"amount":100}', op)
        assert r1["status"] == 201
        assert r2["status"] == 201
        assert json.loads(r1["body"]) == {"n": 1}
        assert json.loads(r2["body"]) == {"n": 2}
        assert state["count"] == 2

# IDEM-07
def test_expired_key_runs_operation_again():
    for StoreCls in [InMemoryStore, SqlStore]:
        if StoreCls == SqlStore:
            conn = sqlite3.connect(":memory:")
            store = SqlStore(conn)
        else:
            store = StoreCls()
        clock = FakeClock()
        svc, _, _ = make_service(store, clock)
        op, state = make_op()
        svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)
        clock.t = T0 + 86400
        result = svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)
        assert result["status"] == 201
        assert json.loads(result["body"]) == {"n": 2}
        assert state["count"] == 2


# IDEM-07
def test_in_progress_record_past_expires_at_is_uncertain():
    """An in_progress record past expires_at (a killed process) gets 409 outcome_unknown and never runs again,
    is listed for reconciliation, survives purge_expired, and is freed only by release().
    In: both stores, a record claimed and never finished. Out: assertions. Why: IDEM-07 as amended 2026-11-10.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only."""
    for store in both_stores():
        clock = FakeClock()
        svc, _, _ = make_service(store, clock)
        assert store.try_claim(IdempotencyRecord("client-a", "key-1", compute_fingerprint("POST", "/charges", '{"amount":100}'),
                                                 "in_progress", None, None, T0, T0 + 86400), T0)
        op, state = make_op()
        assert svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)["status"] == 409
        assert problem_type(svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)) == "idempotency-request-outstanding"
        assert svc.list_uncertain() == []
        clock.t = T0 + 86400
        result = svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)
        assert result["status"] == 409 and problem_type(result) == "outcome_unknown"
        assert state["count"] == 0
        assert svc.purge_expired() == 0
        assert svc.list_uncertain() == [{"scope": "client-a", "idem_key": "key-1", "created_at": T0}]
        assert svc.release("client-a", "key-1") is True
        assert svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)["status"] == 201
        assert state["count"] == 1


# IDEM-08
# [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] The operation now raises OperationFailed: under the amended spec only
# a definite failure frees the key; a plain Exception leaves it 'uncertain' (see the IDEM-10 test).
def test_raising_operation_frees_the_key():
    """An operation that raises OperationFailed frees the key; a retry runs once and is then replayed.
    In: the test fixtures. Out: assertions. Why: IDEM-08. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: raises OperationFailed (a plain Exception now leaves the key uncertain).
    Touches: memory and in-memory SQLite."""
    for StoreCls in [InMemoryStore, SqlStore]:
        if StoreCls == SqlStore:
            conn = sqlite3.connect(":memory:")
            store = SqlStore(conn)
        else:
            store = StoreCls()
        clock = FakeClock()
        svc, _, _ = make_service(store, clock)
        boom = OperationFailed("card declined")
        def failing_op():
            raise boom
        with pytest.raises(Exception) as exc_info:
            svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', failing_op)
        assert exc_info.value is boom
        op2, state = make_op()
        result = svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op2)
        assert result["status"] == 201
        assert json.loads(result["body"]) == {"n": 1}
        assert state["count"] == 1
        result3 = svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op2)
        assert result3["status"] == 201
        assert json.loads(result3["body"]) == {"n": 1}
        assert state["count"] == 1

# IDEM-10
def test_other_error_leaves_key_uncertain_until_release():
    """An operation that raises anything but OperationFailed leaves the key 'uncertain': the error is re-raised, a
    retry gets 409 outcome_unknown without running, purge keeps it, and after release() a retry runs.
    In: both stores. Out: assertions. Why: IDEM-10 (spec amended 2026-11-10).
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only."""
    for store in both_stores():
        clock = FakeClock()
        svc, _, _ = make_service(store, clock)
        calls = {"n": 0}

        def timeout_op():
            calls["n"] += 1
            raise TimeoutError("provider timed out after the charge was sent")

        with pytest.raises(TimeoutError):
            svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', timeout_op)
        for _ in range(2):
            result = svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', timeout_op)
            assert result["status"] == 409
            assert problem_type(result) == "outcome_unknown"
        assert calls["n"] == 1
        # a different body is still 422 (fingerprint check comes first)
        assert svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":5}', timeout_op)["status"] == 422
        clock.t = T0 + 10 * 86400
        assert svc.purge_expired() == 0
        assert svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', timeout_op)["status"] == 409
        assert svc.list_uncertain() == [{"scope": "client-a", "idem_key": "key-1", "created_at": T0}]
        assert svc.release("client-a", "key-1") is True
        assert svc.release("client-a", "key-1") is False
        op, state = make_op()
        assert svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)["status"] == 201
        assert state["count"] == 1
        assert svc.release("client-a", "key-1") is False  # completed keys are not released


# IDEM-11
def test_resolve_stores_reconciled_response():
    """resolve() on an 'uncertain' key stores the response as completed (expires 24 h later); a retry returns it
    without running; a second resolve() or a release() returns False; resolve() on other keys returns False.
    In: both stores. Out: assertions. Why: IDEM-11 (spec amended 2026-11-10).
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only."""
    for store in both_stores():
        clock = FakeClock()
        svc, _, _ = make_service(store, clock)

        def crash_op():
            raise ConnectionError("connection reset")

        with pytest.raises(ConnectionError):
            svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', crash_op)
        assert svc.resolve("client-a", "missing", 201, '{"n":7}') is False
        clock.t = T0 + 100
        assert svc.resolve("client-a", "key-1", 201, '{"charge":"ch_1"}') is True
        assert svc.resolve("client-a", "key-1", 201, '{"charge":"ch_2"}') is False
        assert svc.release("client-a", "key-1") is False
        op, state = make_op()
        result = svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)
        assert result == {"status": 201, "content_type": "application/json", "body": '{"charge":"ch_1"}'}
        assert state["count"] == 0
        assert store.get("client-a", "key-1").expires_at == T0 + 100 + 86400
        assert svc.list_uncertain() == []


# IDEM-10
def test_concurrent_release_exactly_one_wins():
    """Two threads releasing the same uncertain key: exactly one gets True (one conditional write each).
    In: both stores, 2 threads x 20 rounds. Out: assertions. Why: IDEM-10/11 caller rule (spec amended
    2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only."""
    for store in both_stores():
        clock = FakeClock()
        svc, _, _ = make_service(store, clock)
        for i in range(20):
            key = f"key-{i}"
            with pytest.raises(RuntimeError):
                svc.handle("client-a", key, "POST", "/charges", "{}", lambda: (_ for _ in ()).throw(RuntimeError("x")))
            barrier = threading.Barrier(2)
            results = []

            def worker(fn):
                barrier.wait()
                results.append(fn())

            threads = [threading.Thread(target=worker, args=(lambda: svc.release("client-a", key),)),
                       threading.Thread(target=worker, args=(lambda: svc.resolve("client-a", key, 200, "{}"),))]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert sorted(results) == [False, True]


# IDEM-09
def test_error_responses_are_problem_json():
    for StoreCls in [InMemoryStore, SqlStore]:
        if StoreCls == SqlStore:
            conn = sqlite3.connect(":memory:")
            store = SqlStore(conn)
        else:
            store = StoreCls()
        clock = FakeClock()
        svc, _, _ = make_service(store, clock)
        op, state = make_op()
        # 400 missing key
        r1 = svc.handle("client-a", None, "POST", "/charges", '{"amount":100}', op)
        assert r1["status"] == 400
        assert r1["content_type"] == "application/problem+json"
        body1 = json.loads(r1["body"])
        assert set(body1.keys()) == {"type", "title", "detail"}
        assert all(isinstance(v, str) for v in body1.values())
        # 409 in progress
        def op_in_progress():
            inner_svc, _, _ = make_service(store, clock)
            inner_result = inner_svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', lambda: {"status": 200, "body": '{"x":1}'})
            assert inner_result["status"] == 409
            assert inner_result["content_type"] == "application/problem+json"
            body2 = json.loads(inner_result["body"])
            assert set(body2.keys()) == {"type", "title", "detail"}
            assert all(isinstance(v, str) for v in body2.values())
            return {"status": 201, "body": '{"n":1}'}
        r2 = svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op_in_progress)
        assert r2["status"] == 201
        # 422 reused
        svc.handle("client-a", "key-2", "POST", "/charges", '{"amount":100}', op)
        r3 = svc.handle("client-a", "key-2", "POST", "/charges", '{"amount":200}', op)
        assert r3["status"] == 422
        assert r3["content_type"] == "application/problem+json"
        body3 = json.loads(r3["body"])
        assert set(body3.keys()) == {"type", "title", "detail"}
        assert all(isinstance(v, str) for v in body3.values())

def test_in_progress_with_different_body_is_422():
    for StoreCls in [InMemoryStore, SqlStore]:
        if StoreCls == SqlStore:
            conn = sqlite3.connect(":memory:")
            store = SqlStore(conn)
        else:
            store = StoreCls()
        clock = FakeClock()
        svc, _, _ = make_service(store, clock)
        op2_ran = {"count": 0}
        def op():
            op2_ran["count"] += 1
            inner_svc, _, _ = make_service(store, clock)
            inner_result = inner_svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":200}', lambda: {"status": 200, "body": '{"x":1}'})
            assert inner_result["status"] == 422
            assert inner_result["content_type"] == "application/problem+json"
            assert json.loads(inner_result["body"]) == {
                "type": "https://developer.example.com/problems/idempotency-key-reused",
                "title": "Idempotency-Key is already used",
                "detail": "This Idempotency-Key was already used with a different request payload."
            }
            return {"status": 201, "body": '{"n":1}'}
        result = svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)
        assert result["status"] == 201
        assert json.loads(result["body"]) == {"n": 1}
        assert op2_ran["count"] == 1

def test_expiry_boundary_and_purge():
    for StoreCls in [InMemoryStore, SqlStore]:
        if StoreCls == SqlStore:
            conn = sqlite3.connect(":memory:")
            store = SqlStore(conn)
        else:
            store = StoreCls()
        clock = FakeClock()
        svc, _, _ = make_service(store, clock)
        op, state = make_op()
        svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)
        # T0 + 86399: replay, purge returns 0
        clock.t = T0 + 86399
        result = svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)
        assert result["status"] == 201
        assert json.loads(result["body"]) == {"n": 1}
        assert state["count"] == 1
        assert svc.purge_expired() == 0
        # T0 + 86400: purge returns 1, then handle gives 201 {"n":2}
        clock.t = T0 + 86400
        assert svc.purge_expired() == 1
        result = svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)
        assert result["status"] == 201
        assert json.loads(result["body"]) == {"n": 2}
        assert state["count"] == 2

def test_scope_and_key_never_collide():
    for StoreCls in [InMemoryStore, SqlStore]:
        if StoreCls == SqlStore:
            conn = sqlite3.connect(":memory:")
            store = SqlStore(conn)
        else:
            store = StoreCls()
        clock = FakeClock()
        svc, _, _ = make_service(store, clock)
        op, state = make_op()
        pairs = [("a:b", "c"), ("a", "b:c"), ("a|b", "c"), ("a", "b|c")]
        for scope, key in pairs:
            result = svc.handle(scope, key, "POST", "/charges", '{"amount":100}', op)
            assert result["status"] == 201
        assert state["count"] == 4

def test_no_rerun_after_operation_returned():
    # (a) Store that throws STORE_ERROR from complete
    class FailingCompleteStore(InMemoryStore):
        def complete(self, scope, idem_key, created_at, response_status, response_body):
            raise IdempotencyError("STORE_ERROR", 500, "down")

    clock = FakeClock()
    store = FailingCompleteStore()
    svc, _, _ = make_service(store, clock)
    op, state = make_op()
    with pytest.raises(IdempotencyError) as exc_info:
        svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)
    assert exc_info.value.code == "STORE_ERROR"
    # Retry gives 409
    result = svc.handle("client-a", "key-1", "POST", "/charges", '{"amount":100}', op)
    assert result["status"] == 409
    assert state["count"] == 1

    # (b) New key where op returns status 0
    clock2 = FakeClock()
    store2 = InMemoryStore()
    svc2, _, _ = make_service(store2, clock2)
    def bad_op():
        return {"status": 0, "body": '{"x":1}'}
    with pytest.raises(IdempotencyError) as exc_info2:
        svc2.handle("client-a", "key-2", "POST", "/charges", '{"amount":100}', bad_op)
    assert exc_info2.value.code == "INVALID_OPERATION_RESULT"
    result2 = svc2.handle("client-a", "key-2", "POST", "/charges", '{"amount":100}', bad_op)
    assert result2["status"] == 409
    assert state["count"] == 1

def test_fingerprint_vectors():
    assert compute_fingerprint("POST", "/charges", '{"amount":100}') == "70cf65c7a3ff49d51f1453b276fad9d916ef23b88bcd6eaf7be5560757fbffac"
    assert compute_fingerprint("post", "/charges", '{"amount":100}') == "70cf65c7a3ff49d51f1453b276fad9d916ef23b88bcd6eaf7be5560757fbffac"
    assert compute_fingerprint("POST", "/charges", '{"amount":200}') == "bf84a34ee8f1f73a21d2ab06fa5bdbc2a44163460468db84a24cc19163a8dc19"
    assert compute_fingerprint("POST", "/charges", "") == "aacec4b81fc95fe65af0e605dc76dc5705975f54fb2b55c1a3d36ff76f133334"
    assert compute_fingerprint("POST", "/caf\u00e9", "\u20ac") == "514e90be1195bdd29a59a54bc13392840ae09b70da2fdbb3a30817f7028688ba"
    assert compute_fingerprint("p\u00f6st", "/charges", "") == "3e0d88ec545d0bfa3805145243041df631292b351dae46b446b4c7f1b6dc54b3"

def test_input_validation_and_pass_through():
    for StoreCls in [InMemoryStore, SqlStore]:
        if StoreCls == SqlStore:
            conn = sqlite3.connect(":memory:")
            store = SqlStore(conn)
        else:
            store = StoreCls()
        clock = FakeClock()
        svc, _, _ = make_service(store, clock)
        op, state = make_op()
        # "0" and 255 x "k" run
        result1 = svc.handle("client-a", "0", "POST", "/charges", '{"amount":100}', op)
        assert result1["status"] == 201
        key255 = "k" * 255
        result2 = svc.handle("client-a", key255, "POST", "/charges", '{"amount":100}', op)
        assert result2["status"] == 201
        # 256 x "k" gives 400
        key256 = "k" * 256
        result3 = svc.handle("client-a", key256, "POST", "/charges", '{"amount":100}', op)
        assert result3["status"] == 400
        assert result3["content_type"] == "application/problem+json"
        assert json.loads(result3["body"]) == {
            "type": "https://developer.example.com/problems/idempotency-key-invalid",
            "title": "Idempotency-Key is invalid",
            "detail": "An Idempotency-Key must be 1 to 255 printable ASCII characters."
        }
        # "bad\nkey" gives 400
        result4 = svc.handle("client-a", "bad\nkey", "POST", "/charges", '{"amount":100}', op)
        assert result4["status"] == 400
        assert result4["content_type"] == "application/problem+json"
        # scope "" with key null THROWS SCOPE_REQUIRED
        with pytest.raises(IdempotencyError) as exc_info:
            svc.handle("", None, "POST", "/charges", '{"amount":100}', op)
        assert exc_info.value.code == "SCOPE_REQUIRED"
        # GET twice with no key runs op both times
        result5 = svc.handle("client-a", None, "GET", "/items", None, op)
        assert result5["status"] == 201
        assert result5["content_type"] == "application/json"
        result6 = svc.handle("client-a", None, "GET", "/items", None, op)
        assert result6["status"] == 201
        assert state["count"] == 4  # 2 from POST + 2 from GET
        # is_required checks
        assert svc.is_required("post", "/items") is True
        assert svc.is_required("PATCH", "/items") is True
        assert svc.is_required("GET", "/items") is False
        assert svc.is_required("DELETE", "/items") is False
        # with required_methods ["put"], PUT true and POST false
        svc_put, _, _ = make_service(store, clock, methods=("PUT",))
        assert svc_put.is_required("PUT", "/items") is True
        assert svc_put.is_required("POST", "/items") is False