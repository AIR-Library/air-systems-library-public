import pytest
import time
import threading
from health_checks_python import (
    register_check,
    liveness,
    readiness,
    set_store,
    InMemoryHealthCheckStore,
    SqliteHealthCheckStore
)


def setup_module(module):
    set_store(InMemoryHealthCheckStore())


def teardown_module(module):
    set_store(InMemoryHealthCheckStore())


# HEALTH-01
def test_all_checks_pass_returns_200_pass():
    def check_ok():
        return {"status": "pass", "observedValue": 100, "observedUnit": "ms"}
    
    register_check("db", "datastore", check_ok, critical=True, timeout_ms=1000)
    register_check("cache", "cache", check_ok, critical=False, timeout_ms=1000)
    
    result = readiness()
    
    assert result["http_status"] == 200
    assert result["content_type"] == "application/health+json"
    assert result["body"]["status"] == "pass"
    assert "db:datastore" in result["body"]["checks"]
    assert "cache:cache" in result["body"]["checks"]
    assert result["body"]["checks"]["db:datastore"][0]["status"] == "pass"
    assert result["body"]["checks"]["cache:cache"][0]["status"] == "pass"


# HEALTH-02
def test_critical_check_fails_returns_503_fail():
    def check_fail():
        return {"status": "fail", "observedValue": 0, "observedUnit": "ms"}
    
    register_check("db", "datastore", check_fail, critical=True, timeout_ms=1000)
    
    result = readiness()
    
    assert result["http_status"] == 503
    assert result["content_type"] == "application/health+json"
    assert result["body"]["status"] == "fail"
    assert result["body"]["checks"]["db:datastore"][0]["status"] == "fail"


# HEALTH-03
def test_only_non_critical_fails_returns_200_warn():
    def check_ok():
        return {"status": "pass", "observedValue": 100, "observedUnit": "ms"}
    
    def check_fail():
        return {"status": "fail", "observedValue": 0, "observedUnit": "ms"}
    
    register_check("db", "datastore", check_ok, critical=True, timeout_ms=1000)
    register_check("cache", "cache", check_fail, critical=False, timeout_ms=1000)
    
    result = readiness()
    
    assert result["http_status"] == 200
    assert result["content_type"] == "application/health+json"
    assert result["body"]["status"] == "warn"
    assert result["body"]["checks"]["db:datastore"][0]["status"] == "pass"
    assert result["body"]["checks"]["cache:cache"][0]["status"] == "fail"


# HEALTH-04
def test_slow_check_past_timeout_returns_fail_for_that_check():
    def slow_check():
        time.sleep(0.5)
        return {"status": "pass", "observedValue": 500, "observedUnit": "ms"}
    
    register_check("slow", "service", slow_check, critical=True, timeout_ms=100)
    
    result = readiness()
    
    assert result["http_status"] == 503
    assert result["content_type"] == "application/health+json"
    assert result["body"]["status"] == "fail"
    assert result["body"]["checks"]["slow:service"][0]["status"] == "fail"


# HEALTH-05
def test_liveness_stays_pass_even_when_dependency_check_would_fail():
    def check_fail():
        return {"status": "fail", "observedValue": 0, "observedUnit": "ms"}
    
    register_check("db", "datastore", check_fail, critical=True, timeout_ms=1000)
    
    result = liveness()
    
    assert result["http_status"] == 200
    assert result["content_type"] == "application/health+json"
    assert result["body"]["status"] == "pass"
    assert "checks" in result["body"]
    assert result["body"]["checks"] == {}


# HEALTH-06
def test_output_contains_no_connection_string():
    def check_with_secret():
        return {"status": "pass", "observedValue": 1, "observedUnit": "ms"}
    
    register_check("db", "datastore", check_with_secret, critical=True, timeout_ms=1000)
    
    result = readiness()
    
    body_str = str(result["body"])
    assert "password" not in body_str.lower()
    assert "connection" not in body_str.lower()
    assert "secret" not in body_str.lower()
    assert "token" not in body_str.lower()


# HEALTH-06
def test_failing_check_error_with_connection_string_is_not_in_output():
    """A check that fails with a connection string in its error must not leak it into readiness().

    In: a critical check raising an error whose message holds a DSN with a password. Out: asserts the
    response is 503 "fail" and the JSON body holds neither the DSN nor its password.
    Why: HEALTH-06 ("the output contains no connection string"); the older HEALTH-06 test never fed one in.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory check registry only.
    """
    import json
    set_store(InMemoryHealthCheckStore())
    dsn = "postgres://admin:hunter2@db.internal:5432/app"

    def check_raises():
        raise RuntimeError(f"could not connect to {dsn}")

    register_check("db", "datastore", check_raises, critical=True, timeout_ms=1000)
    result = readiness()
    body = json.dumps(result["body"])
    assert result["http_status"] == 503
    assert result["body"]["status"] == "fail"
    assert dsn not in body
    assert "hunter2" not in body
    assert "postgres://" not in body


def test_sqlite_store_persists_across_calls():
    store = SqliteHealthCheckStore(":memory:")
    set_store(store)
    
    def check_ok():
        return {"status": "pass", "observedValue": 100, "observedUnit": "ms"}
    
    register_check("db", "datastore", check_ok, critical=True, timeout_ms=1000)
    
    result1 = readiness()
    assert result1["body"]["status"] == "pass"
    
    result2 = readiness()
    assert result2["body"]["status"] == "pass"
    assert "db:datastore" in result2["body"]["checks"]


def test_multiple_threads_see_same_store():
    store = InMemoryHealthCheckStore()
    set_store(store)
    
    def check_ok():
        return {"status": "pass", "observedValue": 100, "observedUnit": "ms"}
    
    # [2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP] Each thread gets its own index for the name. The
    # name used to be the thread's ident, but Python reuses the ident of a finished thread (documented in
    # threading.get_ident), so on 3.12 all five threads registered "comp-<same ident>" and one check remained.
    def register_from_thread(index):
        register_check(f"comp-{index}", "service", check_ok, critical=True, timeout_ms=1000)
    
    threads = [threading.Thread(target=register_from_thread, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    result = readiness()
    assert result["body"]["status"] == "pass"
    assert len(result["body"]["checks"]) == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])