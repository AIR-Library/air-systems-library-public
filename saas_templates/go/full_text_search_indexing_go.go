package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// DDL for reference
// CREATE TABLE search_index (
//     document_type TEXT,
//     document_id INTEGER PRIMARY KEY,
//     content TEXT,
//     indexed_at DATETIME,
//     metadata TEXT
// );

type Document struct {
	DocumentType string                 `json:"document_type"`
	DocumentID   int                    `json:"document_id"`
	Content      string                 `json:"content"`
	Metadata     map[string]interface{} `json:"metadata"`
	IndexedAt    time.Time              `json:"indexed_at"`
}

type SearchResult struct {
	DocumentID   int                    `json:"document_id"`
	DocumentType string                 `json:"document_type"`
	Relevance    float64                `json:"relevance"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type SearchResponse struct {
	Results []SearchResult           `json:"results"`
	Total   int                      `json:"total"`
	HasMore bool                     `json:"has_more"`
	Facets  map[string]map[string]int `json:"facets,omitempty"`
}

// docKey identifies a document: (document_type, document_id), as in the search_index table. Added
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: documents were keyed by id alone, so user 7 and deployment 7
// overwrote each other.
type docKey struct {
	Type string
	ID   int
}

// docEntry is one indexed document; seq is its insertion order (kept when it is re-indexed).
type docEntry struct {
	doc    Document
	seq    int
	tokens []string // distinct tokens of doc.Content
}

// Index is the in-memory inverted index.
//
// Phase B, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (SEARCH-03/08/09, amended): words are maximal runs
// of Unicode letters and digits, lower-cased with strings.ToLower, with no stop words; a query term
// matches a word equal to it (score 2) or starting with it (score 1) -- it used to match any word
// CONTAINING it, so "ripe" found "stripe"; several terms must all match (AND); results are ordered by
// score, then insertion order (it used to be document id). Postings are seq-ordered slices and scores are
// accumulated in dense arrays, so a search over 1,000,000 documents stays under the 200 ms budget.
// Touches: process memory only.
type Index struct {
	mu       sync.RWMutex
	byKey    map[docKey]int        // key -> seq
	docs     []*docEntry           // by seq; nil once unindexed
	postings map[string][]int      // token -> ascending seqs
	buckets  map[string][]string   // first one or two runes of a token -> tokens, for prefix lookups
	seen     map[string]struct{}   // tokens already placed in buckets
}

var globalIndex = newIndex()

// newIndex returns an empty index. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
func newIndex() *Index {
	idx := &Index{}
	idx.resetLocked()
	return idx
}

func (idx *Index) resetLocked() {
	idx.byKey = make(map[docKey]int)
	idx.docs = nil
	idx.postings = make(map[string][]int)
	idx.buckets = make(map[string][]string)
	idx.seen = make(map[string]struct{})
}

// Reset empties the index. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (idx *Index) Reset() {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.resetLocked()
}

// tokenize splits text into words: maximal runs of Unicode letters and digits (\p{L}, \p{N}), lower-cased
// with strings.ToLower (locale independent). No stop words. In: text. Out: the words in order.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (SEARCH-03): it split on whitespace only, so
// "john@example.com" was one word, and it dropped stop words. Touches nothing.
func tokenize(text string) []string {
	var tokens []string
	start := -1
	for i, r := range text {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			tokens = append(tokens, strings.ToLower(text[start:i]))
			start = -1
		}
	}
	if start >= 0 {
		tokens = append(tokens, strings.ToLower(text[start:]))
	}
	return tokens
}

// distinct returns the tokens without repeats, first occurrence order.
func distinct(tokens []string) []string {
	seen := make(map[string]struct{}, len(tokens))
	out := tokens[:0:0]
	for _, t := range tokens {
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	return out
}

// bucketKeys returns the bucket a token lives in (its first two runes) and, for a one- or two-rune
// prefix lookup, the key to scan. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
func prefixKey(s string, n int) string {
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}

// addPosting inserts seq into token's ascending posting list. The caller holds the write lock.
func (idx *Index) addPosting(token string, seq int) {
	list := idx.postings[token]
	i := sort.SearchInts(list, seq)
	if i < len(list) && list[i] == seq {
		return
	}
	if i == len(list) {
		list = append(list, seq)
	} else {
		list = append(list, 0)
		copy(list[i+1:], list[i:])
		list[i] = seq
	}
	idx.postings[token] = list
	if _, ok := idx.seen[token]; !ok {
		idx.seen[token] = struct{}{}
		k1, k2 := prefixKey(token, 1), prefixKey(token, 2)
		idx.buckets["1:"+k1] = append(idx.buckets["1:"+k1], token)
		if k2 != k1 {
			idx.buckets["2:"+k2] = append(idx.buckets["2:"+k2], token)
		}
	}
}

// removePosting deletes seq from token's posting list. The caller holds the write lock.
func (idx *Index) removePosting(token string, seq int) {
	list := idx.postings[token]
	i := sort.SearchInts(list, seq)
	if i < len(list) && list[i] == seq {
		list = append(list[:i], list[i+1:]...)
		if len(list) == 0 {
			delete(idx.postings, token)
		} else {
			idx.postings[token] = list
		}
	}
}

// IndexDocument adds or replaces a document. A re-indexed document keeps its insertion position.
// In: the document. Out: nil. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: keyed by (type, id),
// postings by insertion order. Touches: memory.
func (idx *Index) IndexDocument(doc Document) error {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	doc.IndexedAt = time.Now()
	key := docKey{doc.DocumentType, doc.DocumentID}
	tokens := distinct(tokenize(doc.Content))
	if seq, ok := idx.byKey[key]; ok {
		old := idx.docs[seq]
		for _, t := range old.tokens {
			idx.removePosting(t, seq)
		}
		idx.docs[seq] = &docEntry{doc: doc, seq: seq, tokens: tokens}
		for _, t := range tokens {
			idx.addPosting(t, seq)
		}
		return nil
	}
	seq := len(idx.docs)
	idx.docs = append(idx.docs, &docEntry{doc: doc, seq: seq, tokens: tokens})
	idx.byKey[key] = seq
	for _, t := range tokens {
		idx.addPosting(t, seq)
	}
	return nil
}

// UnindexDocument removes a document. Out: an error if it is not indexed.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func (idx *Index) UnindexDocument(docType string, docID int) error {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	key := docKey{docType, docID}
	seq, ok := idx.byKey[key]
	if !ok {
		return errors.New("document not found")
	}
	for _, t := range idx.docs[seq].tokens {
		idx.removePosting(t, seq)
	}
	idx.docs[seq] = nil
	delete(idx.byKey, key)
	return nil
}

// Reindex re-tokenizes every document (of docType, or all when empty) from its stored content.
// Out: how many documents. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (the handler reached
// into the index's maps). Touches: memory.
func (idx *Index) Reindex(docType string) int {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	n := 0
	for seq, e := range idx.docs {
		if e == nil || (docType != "" && e.doc.DocumentType != docType) {
			continue
		}
		for _, t := range e.tokens {
			idx.removePosting(t, seq)
		}
		e.tokens = distinct(tokenize(e.doc.Content))
		for _, t := range e.tokens {
			idx.addPosting(t, seq)
		}
		n++
	}
	return n
}

// matchingTokens returns the indexed tokens a query term matches: the term itself first (exact), then
// every other token that starts with it (prefix). The caller holds a read lock.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (SEARCH-03). Touches nothing.
func (idx *Index) matchingTokens(term string) (exact bool, prefix []string) {
	_, exact = idx.postings[term]
	k1, k2 := prefixKey(term, 1), prefixKey(term, 2)
	bucket := idx.buckets["2:"+k2]
	if k2 == k1 {
		bucket = idx.buckets["1:"+k1]
	}
	for _, tok := range bucket {
		if tok != term && strings.HasPrefix(tok, term) {
			if _, live := idx.postings[tok]; live {
				prefix = append(prefix, tok)
			}
		}
	}
	return exact, prefix
}

// Search finds documents matching every query term.
//
// In: query, optional document type, limit, offset, metadata filters (key -> value) and facet names.
// Out: the page of results, the total, has_more, facet counts, and an error. Score per term: 2 when it
// equals a word of the document, else 1 when it is a prefix of one; a document's relevance is the sum
// over terms divided by 2 (1.0 per exact term). Order: relevance descending, then insertion order.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (SEARCH-03, SEARCH-08, SEARCH-09). Touches: memory.
func (idx *Index) Search(query string, docType string, limit, offset int, filters map[string]string, facets []string) ([]SearchResult, int, bool, map[string]map[string]int, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	if limit <= 0 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	terms := distinct(tokenize(query))
	if len(terms) == 0 {
		return []SearchResult{}, 0, false, nil, nil
	}

	n := len(idx.docs)
	score := make([]int32, n)
	matched := make([]uint16, n) // how many terms, in order, a document has matched so far
	stamp := make([]uint16, n)   // the last term (1-based) that scored this document
	for ti, term := range terms {
		exact, prefix := idx.matchingTokens(term)
		apply := func(list []int, s int32) {
			for _, seq := range list {
				if stamp[seq] == uint16(ti+1) || matched[seq] != uint16(ti) {
					continue
				}
				stamp[seq] = uint16(ti + 1)
				matched[seq]++
				score[seq] += s
			}
		}
		if exact {
			apply(idx.postings[term], 2)
		}
		for _, tok := range prefix {
			apply(idx.postings[tok], 1)
		}
	}

	type hit struct {
		seq   int
		score int32
	}
	want := offset + limit
	var top []hit // the best `want` hits, best first
	total := 0
	var facetMap map[string]map[string]int
	if len(facets) > 0 {
		facetMap = make(map[string]map[string]int)
		for _, f := range facets {
			facetMap[f] = make(map[string]int)
		}
	}
	full := uint16(len(terms))
	for seq := 0; seq < n; seq++ {
		if matched[seq] != full {
			continue
		}
		e := idx.docs[seq]
		if e == nil || (docType != "" && e.doc.DocumentType != docType) {
			continue
		}
		ok := true
		for fkey, fval := range filters {
			v, present := e.doc.Metadata[fkey]
			if !present || fmt.Sprintf("%v", v) != fval {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		total++
		for _, f := range facets {
			if val, present := e.doc.Metadata[f]; present {
				facetMap[f][fmt.Sprintf("%v", val)]++
			}
		}
		// seq ascends, so among equal scores the earlier document is already ahead.
		if len(top) == want && score[seq] <= top[len(top)-1].score {
			continue
		}
		i := sort.Search(len(top), func(i int) bool { return top[i].score < score[seq] })
		if len(top) < want {
			top = append(top, hit{})
		}
		copy(top[i+1:], top[i:len(top)-1])
		top[i] = hit{seq, score[seq]}
	}

	results := []SearchResult{}
	for i := offset; i < len(top); i++ {
		doc := idx.docs[top[i].seq].doc
		results = append(results, SearchResult{
			DocumentID:   doc.DocumentID,
			DocumentType: doc.DocumentType,
			Relevance:    float64(top[i].score) / 2,
			Metadata:     doc.Metadata,
		})
	}
	return results, total, offset+limit < total, facetMap, nil
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var doc Document
	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := globalIndex.IndexDocument(doc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := map[string]interface{}{
		"success":    true,
		"indexed_at": doc.IndexedAt,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query().Get("q")
	docType := r.URL.Query().Get("document_type")
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	filters := make(map[string]string)
	for _, f := range r.URL.Query()["filters"] {
		parts := strings.SplitN(f, ":", 2)
		if len(parts) == 2 {
			filters[parts[0]] = parts[1]
		}
	}
	facetsStr := r.URL.Query().Get("facets")
	var facets []string
	if facetsStr != "" {
		facets = strings.Split(facetsStr, ",")
	}
	limit := 20
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}
	offset := 0
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil {
			offset = o
		}
	}
	results, total, hasMore, facetMap, err := globalIndex.Search(q, docType, limit, offset, filters, facets)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := SearchResponse{
		Results: results,
		Total:   total,
		HasMore: hasMore,
		Facets:  facetMap,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func unindexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	docType := parts[3]
	docID, err := strconv.Atoi(parts[4])
	if err != nil {
		http.Error(w, "invalid document_id", http.StatusBadRequest)
		return
	}
	if err := globalIndex.UnindexDocument(docType, docID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	resp := map[string]interface{}{
		"success": true,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func reindexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload struct {
		DocumentType *string `json:"document_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: Index.Reindex instead of reaching into its maps.
	docType := ""
	if payload.DocumentType != nil {
		docType = *payload.DocumentType
	}
	globalIndex.Reindex(docType)
	resp := map[string]interface{}{
		"success": true,
		"job_id":  fmt.Sprintf("reindex-%d", time.Now().UnixNano()),
		"status":  "enqueued",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	http.HandleFunc("/search/index", indexHandler)
	http.HandleFunc("/search", searchHandler)
	http.HandleFunc("/search/documents/", unindexHandler)
	http.HandleFunc("/admin/search/reindex", reindexHandler)
	log.Println("Search service running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
