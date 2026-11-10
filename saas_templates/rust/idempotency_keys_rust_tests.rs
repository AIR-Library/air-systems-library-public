//! Idempotency keys tests (TIER 3 spec, system 5).
//! Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: a `fn main()` that re-ran copies of these
//! tests by hand was removed (a library crate never calls it, and it could not compile because the
//! helpers it used are private to `mod tests`); every test function is kept. Touches: memory and in-memory
//! SQLite only.
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

    fn make_operation(counter: Arc<AtomicUsize>) -> impl FnOnce() -> Result<(i32, String), String> {
        move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok((200, "{\"result\":\"success\"}".to_string()))
        }
    }

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
        );

        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json");
        assert_eq!(body, "{\"result\":\"success\"}");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

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
        );
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
        );

        assert_eq!(status2, 200);
        assert_eq!(content_type2, "application/json");
        assert_eq!(body2, "{\"result\":\"success\"}");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

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
        );

        let operation2 = make_operation(counter.clone());
        let (status, content_type, body) = handle(
            &*store,
            "client1".to_string(),
            Some("key1".to_string()),
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":200}".to_string(),
            operation2,
        );

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
            ));
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
        );
        assert_eq!(outer_status, 200);

        let (status, content_type, body) = inner.into_inner().expect("retry was sent while in progress");
        assert_eq!(status, 409);
        assert_eq!(content_type, "application/problem+json");
        assert!(body.contains("\"type\""));
        assert!(body.contains("\"title\""));
        assert!(body.contains("\"detail\""));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

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
        );

        assert_eq!(status, 400);
        assert_eq!(content_type, "application/problem+json");
        assert!(body.contains("\"type\""));
        assert!(body.contains("\"title\""));
        assert!(body.contains("\"detail\""));
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

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
        );

        let operation2 = make_operation(counter.clone());
        let (status, _, body) = handle(
            &*store,
            "client2".to_string(),
            Some("key1".to_string()),
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":100}".to_string(),
            operation2,
        );

        assert_eq!(status, 200);
        assert_eq!(body, "{\"result\":\"success\"}");
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

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
        );

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
        );

        assert_eq!(status, 200);
        assert_eq!(body, "{\"result\":\"success\"}");
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_operation_that_raises_frees_key() {
        let store = make_store();
        let counter = Arc::new(AtomicUsize::new(0));

        let failing_operation = || {
            counter.fetch_add(1, Ordering::SeqCst);
            Err("operation failed".to_string())
        };

        let (status, content_type, body) = handle(
            &*store,
            "client1".to_string(),
            Some("key1".to_string()),
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":100}".to_string(),
            failing_operation,
        );

        assert_eq!(status, 500);
        assert_eq!(content_type, "application/problem+json");
        assert!(body.contains("\"type\""));
        assert!(body.contains("\"title\""));
        assert!(body.contains("\"detail\""));

        let success_operation = make_operation(counter.clone());
        let (status2, _, body2) = handle(
            &*store,
            "client1".to_string(),
            Some("key1".to_string()),
            "POST".to_string(),
            "/charge".to_string(),
            "{\"amount\":100}".to_string(),
            success_operation,
        );

        assert_eq!(status2, 200);
        assert_eq!(body2, "{\"result\":\"success\"}");
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

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
        );

        assert_eq!(status, 400);
        assert_eq!(content_type, "application/problem+json");
        assert!(body.contains("\"type\""));
        assert!(body.contains("\"title\""));
        assert!(body.contains("\"detail\""));
    }

    /// Added 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the SQLite store gives the same answers as
    /// the in-memory one (replay, 422, scopes, freed key after a failure, expired record replaced).
    #[test]
    fn test_sql_store_behaves_like_in_memory_store() {
        let store = SqlStore::new_in_memory().unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let call = |scope: &str, body: &str, op: Box<dyn FnOnce() -> Result<(i32, String), String>>| {
            handle(&store, scope.to_string(), Some("key1".to_string()), "POST".to_string(), "/charge".to_string(), body.to_string(), op)
        };
        let ok = |c: Arc<AtomicUsize>| -> Box<dyn FnOnce() -> Result<(i32, String), String>> { Box::new(make_operation(c)) };
        assert_eq!(call("c1", "{}", ok(counter.clone())).0, 200);
        assert_eq!(call("c1", "{}", ok(counter.clone())).2, "{\"result\":\"success\"}");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(call("c1", "{\"x\":1}", ok(counter.clone())).0, 422);
        assert_eq!(call("c2", "{}", ok(counter.clone())).0, 200);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
        assert_eq!(call("c3", "{}", Box::new(|| Err("boom".to_string()))).0, 500);
        assert_eq!(call("c3", "{}", ok(counter.clone())).0, 200);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
        assert_eq!(store.purge_expired(SystemTime::now() + Duration::from_secs(25 * 3600)).unwrap(), 3);
        assert_eq!(call("c1", "{}", ok(counter.clone())).0, 200);
        assert_eq!(counter.load(Ordering::SeqCst), 4);
    }
}
