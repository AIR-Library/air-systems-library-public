use std::collections::HashMap;
use serde_json::json;
use full_text_search_indexing_rust::{
    IndexDocumentRequest, ReindexRequest, SearchIndex, SearchRequest,
};

fn idx(doc_type: &str, id: i64, content: &str, meta: serde_json::Value) -> IndexDocumentRequest {
    let metadata = meta
        .as_object()
        .cloned()
        .map(|m| {
            m.into_iter()
                .map(|(k, v)| (k, v))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();
    IndexDocumentRequest {
        document_type: doc_type.to_string(),
        document_id: id,
        content: content.to_string(),
        metadata,
    }
}

#[test]
fn index_user_search_finds_it() {
    let si = SearchIndex::new();
    si.index_document(idx(
        "user",
        123,
        "john doe john@example.com team member active",
        json!({"user_id":123,"email":"john@example.com","tier":"team","status":"active"}),
    ));
    let res = si.search(SearchRequest {
        q: "john".into(),
        document_type: Some("user".into()),
        filters: vec![],
        facets: vec![],
        limit: 20,
        offset: 0,
    });
    assert_eq!(res.total, 1);
    assert_eq!(res.results[0].document_id, 123);
    assert!(res.results[0].relevance > 0.9);
}

#[test]
fn index_deployment_query_works() {
    let si = SearchIndex::new();
    si.index_document(idx(
        "deployment",
        1,
        "stripe integration payment gateway",
        json!({"tier":"team","status":"active"}),
    ));
    let res = si.search(SearchRequest {
        q: "stripe integration".into(),
        document_type: Some("deployment".into()),
        filters: vec![],
        facets: vec![],
        limit: 20,
        offset: 0,
    });
    assert_eq!(res.total, 1);
    assert_eq!(res.results[0].document_id, 1);
}

#[test]
fn partial_match_stri_finds_stripe() {
    let si = SearchIndex::new();
    si.index_document(idx(
        "deployment",
        1,
        "stripe integration",
        json!({}),
    ));
    let res = si.search(SearchRequest {
        q: "stri".into(),
        document_type: Some("deployment".into()),
        filters: vec![],
        facets: vec![],
        limit: 20,
        offset: 0,
    });
    assert_eq!(res.total, 1);
    assert!(res.results[0].relevance < 1.0);
}

#[test]
fn filters_tier_team_returns_only_team() {
    let si = SearchIndex::new();
    si.index_document(idx("user", 1, "alice", json!({"tier":"team","status":"active"})));
    si.index_document(idx("user", 2, "bob", json!({"tier":"solo","status":"active"})));
    let res = si.search(SearchRequest {
        q: "alice".into(),
        document_type: Some("user".into()),
        filters: vec!["tier:team".into()],
        facets: vec![],
        limit: 20,
        offset: 0,
    });
    assert_eq!(res.total, 1);
    assert_eq!(res.results[0].document_id, 1);
}

#[test]
fn facets_show_count_per_status() {
    let si = SearchIndex::new();
    si.index_document(idx("deployment", 1, "a", json!({"status":"active","tier":"team"})));
    si.index_document(idx("deployment", 2, "b", json!({"status":"active","tier":"team"})));
    si.index_document(idx("deployment", 3, "c", json!({"status":"draft","tier":"solo"})));
    let res = si.search(SearchRequest {
        q: "".into(),
        document_type: Some("deployment".into()),
        filters: vec![],
        facets: vec!["status".into(), "tier".into()],
        limit: 20,
        offset: 0,
    });
    let facets = res.facets.unwrap();
    assert_eq!(facets["status"]["active"], 2);
    assert_eq!(facets["status"]["draft"], 1);
    assert_eq!(facets["tier"]["team"], 2);
    assert_eq!(facets["tier"]["solo"], 1);
}

#[test]
fn unindex_document_no_longer_found() {
    let si = SearchIndex::new();
    si.index_document(idx("user", 9, "carol", json!({})));
    assert_eq!(
        si.search(SearchRequest {
            q: "carol".into(),
            document_type: Some("user".into()),
            filters: vec![],
            facets: vec![],
            limit: 20,
            offset: 0,
        })
        .total,
        1
    );
    si.delete_document("user", 9);
    assert_eq!(
        si.search(SearchRequest {
            q: "carol".into(),
            document_type: Some("user".into()),
            filters: vec![],
            facets: vec![],
            limit: 20,
            offset: 0,
        })
        .total,
        0
    );
}

#[test]
fn real_time_index_updated_immediately() {
    let si = SearchIndex::new();
    let start = std::time::Instant::now();
    si.index_document(idx("user", 5, "dave", json!({})));
    let res = si.search(SearchRequest {
        q: "dave".into(),
        document_type: Some("user".into()),
        filters: vec![],
        facets: vec![],
        limit: 20,
        offset: 0,
    });
    assert!(start.elapsed().as_millis() < 100);
    assert_eq!(res.total, 1);
}

#[test]
fn performance_one_million_documents_under_200ms() {
    let si = SearchIndex::new();
    for i in 0..1_000_000 {
        si.index_document(idx(
            "user",
            i,
            &format!("user{} uniqueword{}", i, i),
            json!({"tier":"team","status":"active"}),
        ));
    }
    let start = std::time::Instant::now();
    let res = si.search(SearchRequest {
        q: "uniqueword500000".into(),
        document_type: Some("user".into()),
        filters: vec![],
        facets: vec![],
        limit: 20,
        offset: 0,
    });
    assert!(start.elapsed().as_millis() < 200);
    assert_eq!(res.total, 1);
    assert_eq!(res.results[0].document_id, 500000);
}

#[test]
fn relevance_exact_ranks_higher_than_partial() {
    let si = SearchIndex::new();
    si.index_document(idx("user", 1, "stripe", json!({})));
    si.index_document(idx("user", 2, "stripey", json!({})));
    let res = si.search(SearchRequest {
        q: "stripe".into(),
        document_type: Some("user".into()),
        filters: vec![],
        facets: vec![],
        limit: 20,
        offset: 0,
    });
    assert_eq!(res.total, 2);
    assert_eq!(res.results[0].document_id, 1);
    assert!(res.results[0].relevance > res.results[1].relevance);
}

#[test]
fn reindex_returns_enqueued_job() {
    let si = SearchIndex::new();
    let res = si.reindex(ReindexRequest {
        document_type: Some("user".into()),
    });
    assert!(res.success);
    assert_eq!(res.status, "enqueued");
    assert!(!res.job_id.is_empty());
}

#[test]
fn response_shapes_match_spec() {
    let si = SearchIndex::new();
    si.index_document(idx("user", 1, "john", json!({"tier":"team","status":"active"})));
    let res = si.search(SearchRequest {
        q: "john".into(),
        document_type: Some("user".into()),
        filters: vec![],
        facets: vec!["tier".into()],
        limit: 20,
        offset: 0,
    });
    let v = serde_json::to_value(&res).unwrap();
    assert!(v["results"].is_array());
    assert!(v["total"].is_number());
    assert!(v["has_more"].is_boolean());
    assert!(v["facets"]["tier"]["team"].is_number());
}
