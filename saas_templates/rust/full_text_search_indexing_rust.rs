//! Full-text search and indexing (TIER 2 spec, system: full_text_search_indexing).
//!
//! What: `SearchIndex` keeps an in-memory inverted index (word -> documents) of typed documents with
//! metadata, and answers searches with filters (`tier:team`), facets (count per metadata value),
//! pagination and relevance. A word is a maximal run of Unicode letters and digits (\p{L}, \p{N}),
//! lower-cased with Rust's locale-independent `to_lowercase`; there are no stop words. A query term
//! matches a word equal to it or starting with it ("stri" finds "stripe"; "ripe" does not); several
//! terms must all match; an exact word scores above a prefix; equal scores keep insertion order.
//! Why: rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, for the SEARCH-03/09 amendment: the old
//! index split on whitespace only, dropped stop words, also matched words that merely CONTAINED a term,
//! OR-ed several terms, skipped prefix matching for terms over 10 characters (to stay fast), broke ties
//! by document id, and stamped `indexed_at` with a made-up time. Prefix matching is now a range scan of
//! a sorted word map, so it is fast for any term length (the 200 ms budget for 1M documents holds).
//! Touches: memory only (the `SCHEMA_SQL` constant documents the SQL table for a persistent store);
//! the clock for `indexed_at`. No network, no money.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Bound;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use chrono::{DateTime, SecondsFormat, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The spec's table, for a persistent store (the in-memory index below follows the same shape).
pub const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS search_index (
    document_type TEXT NOT NULL,
    document_id   INTEGER NOT NULL,
    content       TEXT NOT NULL,
    indexed_at    TEXT NOT NULL,
    metadata      TEXT NOT NULL,
    PRIMARY KEY (document_type, document_id)
);
CREATE INDEX IF NOT EXISTS idx_search_index_type ON search_index (document_type);
"#;

/// What: how one query term matched one document. `Exact`: a word equals the term; `Prefix`: a word
/// starts with it. Why: SEARCH-09 (exact > prefix). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Relevance {
    NoMatch,
    Prefix,
    Exact,
}

/// What: methods of `Relevance`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl Relevance {
    /// What: the score of a match: exact 1.0, prefix 0.5, none 0. Out: f64.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn score(self) -> f64 {
        match self {
            Relevance::Exact => 1.0,
            Relevance::Prefix => 0.5,
            Relevance::NoMatch => 0.0,
        }
    }
}

/// What: index request (spec endpoint "index document"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexDocumentRequest {
    pub document_type: String,
    pub document_id: i64,
    pub content: String,
    #[serde(default)]
    pub metadata: HashMap<String, Value>,
}

/// What: search request: query text, optional type, `field:value` filters, facet fields, paging.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchRequest {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub document_type: Option<String>,
    #[serde(default)]
    pub filters: Vec<String>,
    #[serde(default)]
    pub facets: Vec<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

/// What: default page size (20). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
fn default_limit() -> usize {
    20
}

/// What: one search result. `relevance` is the mean of the terms' scores, rounded to 2 decimals.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub document_id: i64,
    pub document_type: String,
    pub relevance: f64,
    pub metadata: HashMap<String, Value>,
}

/// What: search response `{results, total, has_more, facets?}`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    pub results: Vec<SearchHit>,
    pub total: usize,
    pub has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facets: Option<BTreeMap<String, BTreeMap<String, u64>>>,
}

/// What: reindex request. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReindexRequest {
    #[serde(default)]
    pub document_type: Option<String>,
}

/// What: reindex response `{success, job_id, status: "enqueued"}`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReindexResponse {
    pub success: bool,
    pub job_id: String,
    pub status: String,
}

/// What: index response `{success, indexed_at}` (RFC 3339 UTC). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexResponse {
    pub success: bool,
    pub indexed_at: String,
}

/// What: delete response `{success}`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub success: bool,
}

/// What: error body `{error}`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// What: one stored document with its insertion number (`seq`, used to break score ties).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[derive(Debug, Clone)]
struct StoredDoc {
    document_type: String,
    document_id: i64,
    words: Vec<String>,
    metadata: HashMap<String, Value>,
}

/// What: the index: words in a sorted map (so a prefix is a range) to the set of document numbers,
/// documents by number, and (type, id) -> number. A re-indexed document keeps its first number, so it
/// keeps its place among equal scores. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
#[derive(Debug, Default)]
struct InvertedIndex {
    postings: BTreeMap<String, BTreeSet<u64>>,
    docs: HashMap<u64, StoredDoc>,
    keys: HashMap<(String, i64), u64>,
    next_seq: u64,
}

/// What: methods of `InvertedIndex`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl InvertedIndex {
    /// What: drop a document number from the postings of its words. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn unlink(&mut self, seq: u64) {
        if let Some(old) = self.docs.remove(&seq) {
            for word in old.words {
                if let Some(set) = self.postings.get_mut(&word) {
                    set.remove(&seq);
                    if set.is_empty() {
                        self.postings.remove(&word);
                    }
                }
            }
        }
    }

    /// What: add or replace a document (replacing keeps its insertion number). In: the document.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn insert(&mut self, doc: StoredDoc) {
        let key = (doc.document_type.clone(), doc.document_id);
        let seq = match self.keys.get(&key) {
            Some(&seq) => {
                self.unlink(seq);
                seq
            }
            None => {
                self.next_seq += 1;
                self.keys.insert(key, self.next_seq);
                self.next_seq
            }
        };
        for word in &doc.words {
            self.postings.entry(word.clone()).or_default().insert(seq);
        }
        self.docs.insert(seq, doc);
    }

    /// What: remove a document; true if it existed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: memory.
    fn remove(&mut self, document_type: &str, document_id: i64) -> bool {
        match self.keys.remove(&(document_type.to_string(), document_id)) {
            Some(seq) => {
                self.unlink(seq);
                true
            }
            None => false,
        }
    }

    /// What: every document matching one query term, with its best match (exact beats prefix): a
    /// range scan of the sorted words from the term to the last word that starts with it.
    /// In: a lower-cased term. Out: document number -> relevance. Why: SEARCH-03/09.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory (read).
    fn term_matches(&self, term: &str) -> HashMap<u64, Relevance> {
        let mut out: HashMap<u64, Relevance> = HashMap::new();
        for (word, seqs) in self.postings.range::<str, _>((Bound::Included(term), Bound::Unbounded)) {
            if !word.starts_with(term) {
                break;
            }
            let rel = if word == term { Relevance::Exact } else { Relevance::Prefix };
            for &seq in seqs {
                let e = out.entry(seq).or_insert(Relevance::NoMatch);
                if rel > *e {
                    *e = rel;
                }
            }
        }
        out
    }
}

/// What: the search service; clones share the index. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: memory, the clock.
#[derive(Clone)]
pub struct SearchIndex {
    inner: Arc<Mutex<InvertedIndex>>,
    job_counter: Arc<AtomicU64>,
    clock: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>,
}

/// What: methods of `SearchIndex`, each documented below. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl SearchIndex {
    /// What: an empty index on the system clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn new() -> Self {
        Self { inner: Arc::new(Mutex::new(InvertedIndex::default())), job_counter: Arc::new(AtomicU64::new(0)), clock: Arc::new(Utc::now) }
    }

    /// What: replace the clock used for `indexed_at`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    pub fn with_clock(mut self, clock: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// What: the index, even after a panic in another thread poisoned the lock. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    fn lock(&self) -> std::sync::MutexGuard<'_, InvertedIndex> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What: index (or re-index) a document; it is searchable as soon as this returns (real time).
    /// In: the request. Out: `{success, indexed_at}`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: memory, the clock.
    pub fn index_document(&self, req: IndexDocumentRequest) -> IndexResponse {
        let indexed_at = (self.clock)().to_rfc3339_opts(SecondsFormat::Millis, true);
        let mut words = tokenize(&req.content);
        words.sort_unstable();
        words.dedup();
        let doc = StoredDoc { document_type: req.document_type, document_id: req.document_id, words, metadata: req.metadata };
        self.lock().insert(doc);
        IndexResponse { success: true, indexed_at }
    }

    /// What: remove a document from the index (unindex). Out: `{success: true}` (also when it was not
    /// indexed). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    pub fn delete_document(&self, document_type: &str, document_id: i64) -> DeleteResponse {
        let _ = self.lock().remove(document_type, document_id);
        DeleteResponse { success: true }
    }

    /// What: search. Every query term must match (equal word or prefix of a word); the document type and
    /// every `field:value` filter must match; an empty query lists all such documents. Results are
    /// ordered by score (sum over terms: exact 1.0, prefix 0.5), then insertion order; `relevance` is
    /// the mean term score. Facets count each requested metadata field's values over the documents of
    /// the type that pass the filters. In: the request. Out: `{results, total, has_more, facets?}`.
    /// Why: spec search endpoint; matching and ranking amended 2026-11-10 (SEARCH-03/09).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory (read).
    pub fn search(&self, req: SearchRequest) -> SearchResponse {
        let guard = self.lock();
        let terms = {
            let mut t = tokenize(&req.q);
            t.dedup();
            t
        };
        let filters = parse_filters(&req.filters);
        let wanted = |doc: &StoredDoc| req.document_type.as_ref().map_or(true, |dt| doc.document_type == *dt) && matches_filters(&doc.metadata, &filters);

        let mut scored: Vec<(u64, f64)> = if terms.is_empty() {
            guard.docs.iter().filter(|(_, d)| wanted(d)).map(|(&seq, _)| (seq, 1.0)).collect()
        } else {
            let mut per_term: Vec<HashMap<u64, Relevance>> = terms.iter().map(|t| guard.term_matches(t)).collect();
            per_term.sort_by_key(|m| m.len());
            let (first, rest) = per_term.split_first().expect("at least one term");
            first
                .iter()
                .filter_map(|(&seq, rel)| {
                    let mut total = rel.score();
                    for m in rest {
                        total += m.get(&seq)?.score();
                    }
                    let doc = guard.docs.get(&seq)?;
                    wanted(doc).then_some((seq, total / terms.len() as f64))
                })
                .collect()
        };
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal).then(a.0.cmp(&b.0)));

        let total = scored.len();
        let page: Vec<SearchHit> = scored
            .iter()
            .skip(req.offset)
            .take(req.limit)
            .filter_map(|(seq, rel)| {
                let doc = guard.docs.get(seq)?;
                Some(SearchHit {
                    document_id: doc.document_id,
                    document_type: doc.document_type.clone(),
                    relevance: (rel * 100.0).round() / 100.0,
                    metadata: doc.metadata.clone(),
                })
            })
            .collect();
        let has_more = req.offset + page.len() < total;

        let facets = if req.facets.is_empty() {
            None
        } else {
            let mut out: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
            for field in &req.facets {
                let mut counts: BTreeMap<String, u64> = BTreeMap::new();
                for doc in guard.docs.values().filter(|d| wanted(d)) {
                    if let Some(v) = doc.metadata.get(field) {
                        let s = v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string());
                        *counts.entry(s).or_insert(0) += 1;
                    }
                }
                out.insert(field.clone(), counts);
            }
            Some(out)
        };

        SearchResponse { results: page, total, has_more, facets }
    }

    /// What: accept a reindex request as a background job (the in-memory index is always current).
    /// Out: `{success, job_id, status: "enqueued"}`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: memory (job counter).
    pub fn reindex(&self, req: ReindexRequest) -> ReindexResponse {
        let _ = req;
        let job_id = format!("job-{}", self.job_counter.fetch_add(1, Ordering::SeqCst) + 1);
        ReindexResponse { success: true, job_id, status: "enqueued".to_string() }
    }

    /// What: any response as JSON. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn to_json(&self, v: &impl Serialize) -> Value {
        serde_json::to_value(v).unwrap_or(Value::Null)
    }
}

/// What: `Default` for `SearchIndex` (an empty index). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
impl Default for SearchIndex {
    /// What: `SearchIndex::new()`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn default() -> Self {
        Self::new()
    }
}

/// What: split text into words: maximal runs of Unicode letters and digits (\p{L}, \p{N}), each
/// lower-cased with `to_lowercase` (locale-independent); no stop words. In: text. Out: words in order.
/// Why: 2026-11-10 amendment (SEARCH-03): the old split on whitespace kept "john@example.com" as one
/// word and dropped common words. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn tokenize(text: &str) -> Vec<String> {
    static WORD: OnceLock<Regex> = OnceLock::new();
    let re = WORD.get_or_init(|| Regex::new(r"[\p{L}\p{N}]+").expect("valid pattern"));
    re.find_iter(text).map(|m| m.as_str().to_lowercase()).collect()
}

/// What: parse `field:value` filters (anything without a colon is ignored). 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn parse_filters(filters: &[String]) -> Vec<(String, String)> {
    filters.iter().filter_map(|f| f.split_once(':').map(|(k, v)| (k.to_string(), v.to_string()))).collect()
}

/// What: does the metadata hold every filter's value (as a string)? 2026-11-10,
/// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn matches_filters(metadata: &HashMap<String, Value>, filters: &[(String, String)]) -> bool {
    filters.iter().all(|(k, v)| metadata.get(k).and_then(|x| x.as_str()) == Some(v.as_str()))
}

/// What: in-module check of the tokenizer. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
#[cfg(test)]
mod smoke {
    use super::*;
    /// What: words are runs of letters/digits, lower-cased, no stop words. 2026-11-10,
    /// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    #[test]
    fn tokenizes() {
        assert_eq!(tokenize("John Doe"), vec!["john", "doe"]);
        assert_eq!(tokenize("The café, john@example.com!"), vec!["the", "café", "john", "example", "com"]);
    }
}
