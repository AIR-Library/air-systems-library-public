//! Idempotency keys tests (TIER 3 spec, system 5).
//! Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: a `fn main()` that re-ran copies of these
//! tests by hand was removed (a library crate never calls it, and it could not compile because the
//! helpers it used are private to `mod tests`); every test function is kept. Touches: memory and in-memory
//! SQLite only.
//! Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-07/08/10/11 amendment): operations fail with
//! `OpError` and `handle` returns `Result` (the operation's own error is returned, i.e. re-raised), so every
//! call that expects a response now ends in `.unwrap()`; IDEM-07/10/11 tests were added.
mod idempotency_keys_rust;
use idempotency_keys_rust::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, Duration};

    fn make_store() -> Arc<InMemoryStore> {
        Arc::new(InMemoryStore::new())
    }

    /// What: an operation that counts its runs and returns 200 {"result":"success"}. Changed 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP: operations now fail with `OpError` (IDEM-08/10). Touches: memory.
    fn make_operation(counter: Arc<AtomicUsize>) -> impl FnOnce() -> Result<(i32, String), OpError> {
        move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok((200, "{\"result\":\"success\"}".to_string()))
        }
    }

    /// What: the last path segment of a problem body's `type` (e.g. "outcome_unknown"). In: JSON text.
    /// Out: the slug. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn problem_type(body: &str) -> String {
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        v["type"].as_str().unwrap().rsplit('/').next().unwrap().to_string()
    }

    /// What: one POST /charge with key1 for `scope`, running `op`. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
    fn charge(store: &dyn Store, scope: &str, op: impl FnOnce() -> Result<(i32, String), OpError>) -> Result<(i32, String, String), OpError> {
        handle(store, scope.to_string(), Some("key1".to_string()), "POST".to_string(), "/charge".to_string(), "{\"amount\":100}".to_string(), op)
    }

    // IDEM-01
    #[test]
    fn test_first_call_runs_operation_once() {
        let store = make_store();
        let counter = Arc::new(AtomicUsize::new(0));
        let operation = make_operation(counter.clone());

        let (status, content_type, body) = handle(
            &*store,
            "client1".to_string(),
            Some("key1".to_string()),
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":100}".to_string(),
            operation,
        ).unwrap();

        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json");
        assert_eq!(body, "{\"result\":\"success\"}");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // IDEM-02
    #[test]
    fn test_second_identical_call_returns_stored_response() {
        let store = make_store();
        let counter = Arc::new(AtomicUsize::new(0));

        let operation1 = make_operation(counter.clone());
        let (status1, _, body1) = handle(
            &*store,
            "client1".to_string(),
            Some("key1".to_string()),
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":100}".to_string(),
            operation1,
        ).unwrap();
        assert_eq!(status1, 200);
        assert_eq!(body1, "{\"result\":\"success\"}");

        let operation2 = make_operation(counter.clone());
        let (status2, content_type2, body2) = handle(
            &*store,
            "client1".to_string(),
            Some("key1".to_string()),
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":100}".to_string(),
            operation2,
        ).unwrap();

        assert_eq!(status2, 200);
        assert_eq!(content_type2, "application/json");
        assert_eq!(body2, "{\"result\":\"success\"}");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // IDEM-03
    #[test]
    fn test_same_key_different_body_returns_422() {
        let store = make_store();
        let counter = Arc::new(AtomicUsize::new(0));

        let operation1 = make_operation(counter.clone());
        let _ = handle(
            &*store,
            "client1".to_string(),
            Some("key1".to_string()),
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":100}".to_string(),
            operation1,
        ).unwrap();

        let operation2 = make_operation(counter.clone());
        let (status, content_type, body) = handle(
            &*store,
            "client1".to_string(),
            Some("key1".to_string()),
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":200}".to_string(),
            operation2,
        ).unwrap();

        assert_eq!(status, 422);
        assert_eq!(content_type, "application/problem+json");
        assert!(body.contains("\"type\""));
        assert!(body.contains("\"title\""));
        assert!(body.contains("\"detail\""));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    /// Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the old body sent the second request
    /// after the first had COMPLETED, which the spec (and test_second_identical_call_returns_stored_response,
    /// the same sequence) answers with the stored 200, so it could never return 409. The retry is now sent
    /// from inside the first operation, while the first request is still in progress; its assertions
    /// are unchanged.
    // IDEM-04
    #[test]
    fn test_same_key_while_in_progress_returns_409() {
        let store = make_store();
        let counter = Arc::new(AtomicUsize::new(0));
        let inner = std::cell::RefCell::new(None);

        let operation1 = || {
            counter.fetch_add(1, Ordering::SeqCst);
            let operation2 = make_operation(counter.clone());
            *inner.borrow_mut() = Some(handle(
                &*store,
                "client1".to_string(),
                Some("key1".to_string()),
                "POST".to_string(),
                "/charge".to_string(),
                "{\"amount\":100}".to_string(),
                operation2,
            ).unwrap());
            Ok((200, "{\"result\":\"success\"}".to_string()))
        };
        let (outer_status, _, _) = handle(
            &*store,
            "client1".to_string(),
            Some("key1".to_string()),
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":100}".to_string(),
            operation1,
        ).unwrap();
        assert_eq!(outer_status, 200);

        let (status, content_type, body) = inner.into_inner().expect("retry was sent while in progress");
        assert_eq!(status, 409);
        assert_eq!(content_type, "application/problem+json");
        assert!(body.contains("\"type\""));
        assert!(body.contains("\"title\""));
        assert!(body.contains("\"detail\""));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // IDEM-05
    #[test]
    fn test_required_operation_with_no_key_returns_400() {
        let store = make_store();
        let counter = Arc::new(AtomicUsize::new(0));

        let operation = make_operation(counter.clone());
        let (status, content_type, body) = handle(
            &*store,
            "client1".to_string(),
            None,
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":100}".to_string(),
            operation,
        ).unwrap();

        assert_eq!(status, 400);
        assert_eq!(content_type, "application/problem+json");
        assert!(body.contains("\"type\""));
        assert!(body.contains("\"title\""));
        assert!(body.contains("\"detail\""));
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    // IDEM-06
    #[test]
    fn test_same_key_under_different_scopes_runs_twice() {
        let store = make_store();
        let counter = Arc::new(AtomicUsize::new(0));

        let operation1 = make_operation(counter.clone());
        let _ = handle(
            &*store,
            "client1".to_string(),
            Some("key1".to_string()),
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":100}".to_string(),
            operation1,
        ).unwrap();

        let operation2 = make_operation(counter.clone());
        let (status, _, body) = handle(
            &*store,
            "client2".to_string(),
            Some("key1".to_string()),
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":100}".to_string(),
            operation2,
        ).unwrap();

        assert_eq!(status, 200);
        assert_eq!(body, "{\"result\":\"success\"}");
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    // IDEM-07
    #[test]
    fn test_expired_key_runs_operation_again() {
        let store = make_store();
        let counter = Arc::new(AtomicUsize::new(0));

        let operation1 = make_operation(counter.clone());
        let _ = handle(
            &*store,
            "client1".to_string(),
            Some("key1".to_string()),
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":100}".to_string(),
            operation1,
        ).unwrap();

        {
            let mut records = store.records.lock().unwrap();
            if let Some(record) = records.get_mut(&("client1".to_string(), "key1".to_string())) {
                record.expires_at = SystemTime::now() - Duration::from_secs(1);
            }
        }

        let operation2 = make_operation(counter.clone());
        let (status, _, body) = handle(
            &*store,
            "client1".to_string(),
            Some("key1".to_string()),
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":100}".to_string(),
            operation2,
        ).unwrap();

        assert_eq!(status, 200);
        assert_eq!(body, "{\"result\":\"success\"}");
        assert_eq!(counter.load(Ordering::SeqCst), 2);

        // 2026-11-10 amendment, session_012zDydZCZ4AChqhEZ4oVtaP: only a completed record expires. An
        // in_progress record past expires_at (a killed process) is uncertain: 409 outcome_unknown, no run.
        {
            let mut records = store.records.lock().unwrap();
            let record = records.get_mut(&("client1".to_string(), "key1".to_string())).unwrap();
            record.status = RecordStatus::InProgress;
            record.response_status = None;
            record.response_body = None;
            record.expires_at = SystemTime::now() - Duration::from_secs(1);
        }
        let (status, content_type, body) = handle(
            &*store,
            "client1".to_string(),
            Some("key1".to_string()),
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":100}".to_string(),
            make_operation(counter.clone()),
        ).unwrap();
        assert_eq!(status, 409);
        assert_eq!(content_type, "application/problem+json");
        assert_eq!(problem_type(&body), "outcome_unknown");
        assert_eq!(counter.load(Ordering::SeqCst), 2);
        // purge_expired keeps it (only completed records expire)
        assert_eq!(store.purge_expired(SystemTime::now()).unwrap(), 0);
        assert_eq!(store.records.lock().unwrap().len(), 1);
    }

    /// What: IDEM-08: an operation failing with OpError::Failed frees the key (the error is returned) and a
    /// retry runs it. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: see the comment in the body. Touches: memory only.
    // IDEM-08
    #[test]
    fn test_operation_that_raises_frees_key() {
        let store = make_store();
        let counter = Arc::new(AtomicUsize::new(0));

        let failing_operation = || {
            counter.fetch_add(1, Ordering::SeqCst);
            Err(OpError::Failed("operation failed".to_string()))
        };

        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: IDEM-08 now says OperationFailed is re-raised (the
        // old test expected a 500 problem); in Rust the error is returned to the caller.
        let result = handle(
            &*store,
            "client1".to_string(),
            Some("key1".to_string()),
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":100}".to_string(),
            failing_operation,
        );
        assert_eq!(result, Err(OpError::Failed("operation failed".to_string())));
        assert!(store.records.lock().unwrap().is_empty(), "a definite failure frees the key");

        let success_operation = make_operation(counter.clone());
        let (status2, _, body2) = handle(
            &*store,
            "client1".to_string(),
            Some("key1".to_string()),
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":100}".to_string(),
            success_operation,
        ).unwrap();

        assert_eq!(status2, 200);
        assert_eq!(body2, "{\"result\":\"success\"}");
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    // IDEM-09
    #[test]
    fn test_error_responses_carry_problem_json_content_type() {
        let store = make_store();
        let counter = Arc::new(AtomicUsize::new(0));

        let operation = make_operation(counter.clone());
        let (status, content_type, body) = handle(
            &*store,
            "client1".to_string(),
            None,
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":100}".to_string(),
            operation,
        ).unwrap();

        assert_eq!(status, 400);
        assert_eq!(content_type, "application/problem+json");
        assert!(body.contains("\"type\""));
        assert!(body.contains("\"title\""));
        assert!(body.contains("\"detail\""));
    }

    /// What: IDEM-10: an operation that fails with any error other than `OpError::Failed` leaves the key
    /// 'uncertain'; a retry gets 409 outcome_unknown and does not run; release() frees it and a retry
    /// runs; a panic is treated the same way. In: none. Out: panics on a wrong answer.
    /// Why: 2026-11-10 amendment (IDEM-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    // IDEM-10
    #[test]
    fn test_other_error_leaves_key_uncertain_until_released() {
        let store = make_store();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let first = charge(&*store, "client1", move || {
            c.fetch_add(1, Ordering::SeqCst);
            Err(OpError::Other("timeout after the provider was called".into()))
        });
        assert_eq!(first, Err(OpError::Other("timeout after the provider was called".into())));
        assert_eq!(store.records.lock().unwrap()[&("client1".to_string(), "key1".to_string())].status, RecordStatus::Uncertain);

        let (status, content_type, body) = charge(&*store, "client1", make_operation(counter.clone())).unwrap();
        assert_eq!(status, 409);
        assert_eq!(content_type, "application/problem+json");
        assert_eq!(problem_type(&body), "outcome_unknown");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        // a different body under the same key is still 422 first (check order)
        let (status, _, _) = handle(&*store, "client1".into(), Some("key1".into()), "POST".into(), "/charge".into(), "{}".into(), make_operation(counter.clone())).unwrap();
        assert_eq!(status, 422);
        // listed for reconciliation; purge keeps it
        let listed = list_uncertain(&*store, 10).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!((listed[0].scope.as_str(), listed[0].idem_key.as_str()), ("client1", "key1"));
        assert_eq!(purge_expired(&*store).unwrap(), 0);
        assert_eq!(store.purge_expired(SystemTime::now() + Duration::from_secs(48 * 3600)).unwrap(), 0);

        assert!(release(&*store, "client1", "key1").unwrap());
        let (status, _, body) = charge(&*store, "client1", make_operation(counter.clone())).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "{\"result\":\"success\"}");
        assert_eq!(counter.load(Ordering::SeqCst), 2);
        // release on a completed key changes nothing
        assert!(!release(&*store, "client1", "key1").unwrap());

        // a panic inside the operation is an unknown outcome too, and is re-raised
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = charge(&*store, "client2", || -> Result<(i32, String), OpError> { panic!("crash after the charge") });
        }));
        assert!(panicked.is_err());
        let (status, _, body) = charge(&*store, "client2", make_operation(counter.clone())).unwrap();
        assert_eq!((status, problem_type(&body).as_str()), (409, "outcome_unknown"));
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    /// What: IDEM-11: resolve() on an uncertain key stores the response with expires_at = now + 24h; a
    /// retry returns it without running; a second resolve() or release() returns false; resolve() on a
    /// key that is not uncertain returns false. In: none. Out: panics on a wrong answer.
    /// Why: 2026-11-10 amendment (IDEM-11). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    // IDEM-11
    #[test]
    fn test_resolve_stores_reconciled_response() {
        let store = make_store();
        let counter = Arc::new(AtomicUsize::new(0));
        assert!(!resolve(&*store, "client1", "key1", 201, "{}").unwrap(), "no record: nothing to resolve");
        let _ = charge(&*store, "client1", || Err(OpError::Other("connection dropped".into())));

        let before = SystemTime::now();
        assert!(resolve(&*store, "client1", "key1", 201, "{\"charge\":\"ch_1\"}").unwrap());
        {
            let records = store.records.lock().unwrap();
            let r = &records[&("client1".to_string(), "key1".to_string())];
            assert_eq!(r.status, RecordStatus::Completed);
            assert!(r.expires_at >= before + KEY_TTL && r.expires_at <= SystemTime::now() + KEY_TTL);
        }
        let (status, content_type, body) = charge(&*store, "client1", make_operation(counter.clone())).unwrap();
        assert_eq!((status, content_type.as_str(), body.as_str()), (201, "application/json", "{\"charge\":\"ch_1\"}"));
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        assert!(!resolve(&*store, "client1", "key1", 500, "{}").unwrap());
        assert!(!release(&*store, "client1", "key1").unwrap());
        assert!(list_uncertain(&*store, 10).unwrap().is_empty());
    }

    /// What: IDEM-10/11 race rule: of two concurrent release()/resolve() calls on one uncertain key,
    /// exactly one returns true, on both stores. In: none. Out: panics on a wrong answer.
    /// Why: 2026-11-10 amendment ("each release/resolve is ONE conditional write").
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory and in-memory SQLite.
    // IDEM-11
    #[test]
    fn test_concurrent_release_and_resolve_exactly_one_wins() {
        let mem: Arc<dyn Store> = Arc::new(InMemoryStore::new());
        let sql: Arc<dyn Store> = Arc::new(SqlStore::new_in_memory().unwrap());
        for store in [mem, sql] {
            for round in 0..20 {
                let key = format!("k{}", round);
                let _ = handle(&*store, "c".into(), Some(key.clone()), "POST".into(), "/x".into(), "{}".into(), || Err(OpError::Other("lost".into())));
                let barrier = Arc::new(std::sync::Barrier::new(2));
                let (s1, b1, k1) = (store.clone(), barrier.clone(), key.clone());
                let t1 = std::thread::spawn(move || { b1.wait(); release(&*s1, "c", &k1).unwrap() });
                let (s2, b2, k2) = (store.clone(), barrier.clone(), key.clone());
                let t2 = std::thread::spawn(move || { b2.wait(); resolve(&*s2, "c", &k2, 200, "{}").unwrap() });
                let wins = [t1.join().unwrap(), t2.join().unwrap()].iter().filter(|w| **w).count();
                assert_eq!(wins, 1);
            }
        }
    }

    /// Added 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the SQLite store gives the same answers as
    /// the in-memory one (replay, 422, scopes, freed key after a definite failure, uncertain key after any
    /// other error, an expired completed record replaced, purge keeping uncertain rows). Changed the same
    /// day for the IDEM-07/08/10/11 amendment: operations fail with `OpError`, and `handle` returns the
    /// operation's error instead of a 500 problem.
    // IDEM-07
    #[test]
    fn test_sql_store_behaves_like_in_memory_store() {
        let store = SqlStore::new_in_memory().unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        type Op = Box<dyn FnOnce() -> Result<(i32, String), OpError>>;
        let call = |scope: &str, body: &str, op: Op| {
            handle(&store, scope.to_string(), Some("key1".to_string()), "POST".to_string(), "/charge".to_string(), body.to_string(), op)
        };
        let ok = |c: Arc<AtomicUsize>| -> Op { Box::new(make_operation(c)) };
        assert_eq!(call("c1", "{}", ok(counter.clone())).unwrap().0, 200);
        assert_eq!(call("c1", "{}", ok(counter.clone())).unwrap().2, "{\"result\":\"success\"}");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(call("c1", "{\"x\":1}", ok(counter.clone())).unwrap().0, 422);
        assert_eq!(call("c2", "{}", ok(counter.clone())).unwrap().0, 200);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
        assert!(call("c3", "{}", Box::new(|| Err(OpError::Failed("declined".to_string())))).is_err());
        assert_eq!(call("c3", "{}", ok(counter.clone())).unwrap().0, 200);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
        assert!(call("c4", "{}", Box::new(|| Err(OpError::Other("timeout".to_string())))).is_err());
        let (status, _, body) = call("c4", "{}", ok(counter.clone())).unwrap();
        assert_eq!((status, problem_type(&body).as_str()), (409, "outcome_unknown"));
        assert_eq!(counter.load(Ordering::SeqCst), 3);
        assert_eq!(list_uncertain(&store, 10).unwrap().len(), 1);
        // only the three completed rows expire; the uncertain one stays
        assert_eq!(store.purge_expired(SystemTime::now() + Duration::from_secs(25 * 3600)).unwrap(), 3);
        assert_eq!(call("c1", "{}", ok(counter.clone())).unwrap().0, 200);
        assert_eq!(counter.load(Ordering::SeqCst), 4);
        // an expired completed row is replaced by a claim (same store, aged clock)
        let later = SystemTime::now() + Duration::from_secs(25 * 3600);
        let c = counter.clone();
        let (status, _, _) = handle_at(&store, later, "c1".into(), Some("key1".into()), "POST".into(), "/charge".into(), "{}".into(), make_operation(c)).unwrap();
        assert_eq!(status, 200);
        assert_eq!(counter.load(Ordering::SeqCst), 5);
        // an in_progress row past expires_at (a killed process) is uncertain: 409 outcome_unknown, listed,
        // never replaced by a claim, and freed by release()
        let then = SystemTime::now() - 2 * KEY_TTL;
        let stale = IdempotencyRecord {
            scope: "c5".into(),
            idem_key: "key1".into(),
            request_fingerprint: compute_fingerprint("POST", "/charge", "{}"),
            status: RecordStatus::InProgress,
            response_status: None,
            response_body: None,
            created_at: then,
            expires_at: then + KEY_TTL,
            seq: 0,
        };
        assert_eq!(store.claim(stale, then).unwrap(), Claim::Claimed);
        let (status, _, body) = call("c5", "{}", ok(counter.clone())).unwrap();
        assert_eq!((status, problem_type(&body).as_str()), (409, "outcome_unknown"));
        assert_eq!(counter.load(Ordering::SeqCst), 5);
        assert_eq!(list_uncertain(&store, 10).unwrap().iter().map(|k| k.scope.as_str()).collect::<Vec<_>>(), vec!["c5", "c4"]);
        assert!(release(&store, "c5", "key1").unwrap());
        assert_eq!(call("c5", "{}", ok(counter.clone())).unwrap().0, 200);
        assert_eq!(counter.load(Ordering::SeqCst), 6);
        assert!(resolve(&store, "c4", "key1", 202, "{\"ok\":true}").unwrap());
        assert_eq!(call("c4", "{}", ok(counter.clone())).unwrap(), (202, "application/json".to_string(), "{\"ok\":true}".to_string()));
    }
}
