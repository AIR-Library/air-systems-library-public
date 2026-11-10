//! Webhooks tests (TIER 3 spec, system 1).
//! Corrected 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the runner mounts this file as a child
//! module of the implementation, so the nested `mod tests` sees the implementation as `crate`, not
//! `super` (`use super::*` imported nothing and no test compiled). Touches: memory only.
#[cfg(test)]
mod tests {
    use crate::*;
    use std::collections::HashMap;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn fake_sender_ok(_url: &str, _headers: &HashMap<String, String>, _body: &[u8]) -> Result<(u16, Vec<u8>), Box<dyn Error>> {
        Ok((200, vec![]))
    }
    fn fake_sender_fail(_url: &str, _headers: &HashMap<String, String>, _body: &[u8]) -> Result<(u16, Vec<u8>), Box<dyn Error>> {
        Ok((400, vec![]))
    }

    // HOOK-01
    #[test]
    fn test_sign_verify_roundtrip() {
        let store = InMemoryStore::new();
        let (ep_id, secret) = create_endpoint(&store, "org1", "https://example.com", &["order.created".into()]).unwrap();
        let payload = serde_json::json!({"id":1});
        let msg_id = send_event(&store, "org1", "order.created", payload.clone()).unwrap();
        let message = store.get_message(&msg_id).unwrap();
        let body = serde_json::to_vec(&message.payload).unwrap();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let signature = sign(&secret, &msg_id, timestamp, &body).unwrap();
        let mut headers = HashMap::new();
        headers.insert("webhook-id".to_string(), msg_id.clone());
        headers.insert("webhook-timestamp".to_string(), timestamp.to_string());
        headers.insert("webhook-signature".to_string(), signature.clone());
        assert!(verify(&secret, &headers, &body, 300).unwrap());
    }

    // HOOK-02
    #[test]
    fn test_body_or_timestamp_change_fails() {
        let store = InMemoryStore::new();
        let (ep_id, secret) = create_endpoint(&store, "org1", "https://example.com", &["order.created".into()]).unwrap();
        let payload = serde_json::json!({"id":1});
        let msg_id = send_event(&store, "org1", "order.created", payload.clone()).unwrap();
        let message = store.get_message(&msg_id).unwrap();
        let body = serde_json::to_vec(&message.payload).unwrap();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let signature = sign(&secret, &msg_id, timestamp, &body).unwrap();
        let mut headers = HashMap::new();
        headers.insert("webhook-id".to_string(), msg_id.clone());
        headers.insert("webhook-timestamp".to_string(), timestamp.to_string());
        headers.insert("webhook-signature".to_string(), signature.clone());
        // change body
        let bad_body = serde_json::to_vec(&serde_json::json!({"id":2})).unwrap();
        assert!(verify(&secret, &headers, &bad_body, 300).is_err());
        // change timestamp
        let bad_ts = timestamp + 1000;
        headers.insert("webhook-timestamp".to_string(), bad_ts.to_string());
        assert!(verify(&secret, &headers, &body, 300).is_err());
    }

    // HOOK-03
    #[test]
    fn test_timestamp_out_of_range() {
        let store = InMemoryStore::new();
        let (ep_id, secret) = create_endpoint(&store, "org1", "https://example.com", &["order.created".into()]).unwrap();
        let payload = serde_json::json!({"id":1});
        let msg_id = send_event(&store, "org1", "order.created", payload.clone()).unwrap();
        let message = store.get_message(&msg_id).unwrap();
        let body = serde_json::to_vec(&message.payload).unwrap();
        let old_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 1000;
        let signature = sign(&secret, &msg_id, old_ts, &body).unwrap();
        let mut headers = HashMap::new();
        headers.insert("webhook-id".to_string(), msg_id.clone());
        headers.insert("webhook-timestamp".to_string(), old_ts.to_string());
        headers.insert("webhook-signature".to_string(), signature.clone());
        assert!(verify(&secret, &headers, &body, 300).is_err());
    }

    // HOOK-04
    #[test]
    fn test_multiple_signatures() {
        let store = InMemoryStore::new();
        let (ep_id1, secret1) = create_endpoint(&store, "org1", "https://example.com", &["order.created".into()]).unwrap();
        let (ep_id2, secret2) = create_endpoint(&store, "org1", "https://example.com", &["order.created".into()]).unwrap();
        let payload = serde_json::json!({"id":1});
        let msg_id = send_event(&store, "org1", "order.created", payload.clone()).unwrap();
        let message = store.get_message(&msg_id).unwrap();
        let body = serde_json::to_vec(&message.payload).unwrap();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let sig1 = sign(&secret1, &msg_id, timestamp, &body).unwrap();
        let sig2 = sign(&secret2, &msg_id, timestamp, &body).unwrap();
        let mut headers = HashMap::new();
        headers.insert("webhook-id".to_string(), msg_id.clone());
        headers.insert("webhook-timestamp".to_string(), timestamp.to_string());
        headers.insert("webhook-signature".to_string(), format!("{} {}", sig1, sig2));
        assert!(verify(&secret1, &headers, &body, 300).unwrap());
    }

    #[test]
    fn test_success_and_retry() {
        let store = InMemoryStore::new();
        let (ep_id, secret) = create_endpoint(&store, "org1", "https://example.com", &["order.created".into()]).unwrap();
        let payload = serde_json::json!({"id":1});
        let msg_id = send_event(&store, "org1", "order.created", payload.clone()).unwrap();
        let delivery = store.deliveries.lock().unwrap().values().next().unwrap().clone();
        deliver(&store, &delivery.id, fake_sender_ok).unwrap();
        let updated = store.get_delivery(&delivery.id).unwrap();
        assert!(updated.success);
        assert!(updated.status_code == Some(200));
        // failure
        let delivery2 = store.deliveries.lock().unwrap().values().next().unwrap().clone();
        deliver(&store, &delivery2.id, fake_sender_fail).unwrap();
        let updated2 = store.get_delivery(&delivery2.id).unwrap();
        assert!(!updated2.success);
        assert!(updated2.status_code == Some(400));
        assert!(updated2.next_attempt_at.is_some());
    }

    // HOOK-06
    #[test]
    fn test_org_isolation() {
        let store = InMemoryStore::new();
        create_endpoint(&store, "orgA", "https://a.com", &["order.created".into()]).unwrap();
        create_endpoint(&store, "orgB", "https://b.com", &["order.created".into()]).unwrap();
        let payload = serde_json::json!({"id":1});
        let msg_id = send_event(&store, "orgA", "order.created", payload.clone()).unwrap();
        let deliveries: Vec<_> = store.deliveries.lock().unwrap().values().cloned().collect();
        assert_eq!(deliveries.len(), 1);
        let delivery = deliveries[0].clone();
        let endpoint = store.get_endpoint(&delivery.endpoint_id).unwrap();
        assert_eq!(endpoint.org_id, "orgA");
    }

    #[test]
    fn test_webhook_id_consistency() {
        let store = InMemoryStore::new();
        let (ep_id, secret) = create_endpoint(&store, "org1", "https://example.com", &["order.created".into()]).unwrap();
        let payload = serde_json::json!({"id":1});
        let msg_id = send_event(&store, "org1", "order.created", payload.clone()).unwrap();
        let delivery = store.deliveries.lock().unwrap().values().next().unwrap().clone();
        let mut headers1 = HashMap::new();
        let body = serde_json::to_vec(&store.get_message(&msg_id).unwrap().payload).unwrap();
        let timestamp1 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let sig1 = sign(&secret, &msg_id, timestamp1, &body).unwrap();
        headers1.insert("webhook-id".to_string(), msg_id.clone());
        headers1.insert("webhook-timestamp".to_string(), timestamp1.to_string());
        headers1.insert("webhook-signature".to_string(), sig1);
        // second attempt
        let timestamp2 = timestamp1 + 10;
        let sig2 = sign(&secret, &msg_id, timestamp2, &body).unwrap();
        let mut headers2 = HashMap::new();
        headers2.insert("webhook-id".to_string(), msg_id.clone());
        headers2.insert("webhook-timestamp".to_string(), timestamp2.to_string());
        headers2.insert("webhook-signature".to_string(), sig2);
        assert_eq!(headers1.get("webhook-id"), headers2.get("webhook-id"));
    }

    // HOOK-08
    #[test]
    fn test_secret_generation() {
        let store = InMemoryStore::new();
        let (_ep_id, secret) = create_endpoint(&store, "org1", "https://example.com", &["order.created".into()]).unwrap();
        assert!(secret.starts_with("whsec_"));
        let decoded = STANDARD.decode(secret.trim_start_matches("whsec_")).unwrap();
        assert!(decoded.len() >= 24 && decoded.len() <= 64);
    }

    /// What: HOOK-05: a 200 or 299 response marks the delivery successful (no further attempt); 301, 400
    /// and 500 leave it unsuccessful with the next attempt scheduled 5 s later (the first retry).
    /// In: none. Out: panics on a wrong outcome. Why: the old test covered only 200 and 400.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
    // HOOK-05
    #[test]
    fn test_status_classes_success_or_retry() {
        let now = 1_767_225_600u64;
        for (status, ok) in [(200u16, true), (299, true), (301, false), (400, false), (500, false)] {
            let store = InMemoryStore::new();
            create_endpoint(&store, "org1", "https://example.com", &["order.created".into()]).unwrap();
            send_event(&store, "org1", "order.created", serde_json::json!({"id": 1})).unwrap();
            let id = store.deliveries.lock().unwrap().values().next().unwrap().id.clone();
            deliver_at(&store, &id, |_u: &str, _h: &HashMap<String, String>, _b: &[u8]| -> Result<(u16, Vec<u8>), Box<dyn Error>> { Ok((status, vec![])) }, now).unwrap();
            let d = store.get_delivery(&id).unwrap();
            assert_eq!((d.success, d.status_code), (ok, Some(status)), "status {}", status);
            assert_eq!(d.next_attempt_at, if ok { None } else { Some(now + RETRY_SCHEDULE_SECS[0]) }, "status {}", status);
        }
    }

    /// What: HOOK-07: the webhook-id header is identical across retries of one message (it is the
    /// message id), while each attempt is signed with its own timestamp and verifies. In: none.
    /// Out: panics on a wrong header. Why: the old test compared two header maps it built itself and
    /// never called `deliver`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
    // HOOK-07
    #[test]
    fn test_webhook_id_identical_across_retries() {
        let store = InMemoryStore::new();
        let (_ep, secret) = create_endpoint(&store, "org1", "https://example.com", &["order.created".into()]).unwrap();
        let msg_id = send_event(&store, "org1", "order.created", serde_json::json!({"id": 1})).unwrap();
        let id = store.deliveries.lock().unwrap().values().next().unwrap().id.clone();
        let seen: std::cell::RefCell<Vec<(HashMap<String, String>, Vec<u8>)>> = std::cell::RefCell::new(Vec::new());
        let t0 = 1_767_225_600u64;
        for (attempt, status) in [(0u64, 500u16), (5, 200)] {
            deliver_at(&store, &id, |_u: &str, h: &HashMap<String, String>, b: &[u8]| -> Result<(u16, Vec<u8>), Box<dyn Error>> {
                seen.borrow_mut().push((h.clone(), b.to_vec()));
                Ok((status, vec![]))
            }, t0 + attempt).unwrap();
        }
        let seen = seen.into_inner();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0["webhook-id"], msg_id);
        assert_eq!(seen[1].0["webhook-id"], msg_id);
        assert_ne!(seen[0].0["webhook-timestamp"], seen[1].0["webhook-timestamp"]);
        assert!(verify_at(&secret, &seen[0].0, &seen[0].1, 300, t0).unwrap());
        assert!(verify_at(&secret, &seen[1].0, &seen[1].1, 300, t0 + 5).unwrap());
        assert!(store.get_delivery(&id).unwrap().success);
    }
}
