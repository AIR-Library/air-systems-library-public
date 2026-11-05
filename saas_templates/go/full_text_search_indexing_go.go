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

type Index struct {
	mu        sync.RWMutex
	docs      map[int]Document
	inverted  map[string]map[int]struct{}
	stopWords map[string]struct{}
}

var globalIndex = &Index{
	docs:     make(map[int]Document),
	inverted: make(map[string]map[int]struct{}),
	stopWords: map[string]struct{}{
		"a": {}, "an": {}, "the": {}, "and": {}, "or": {}, "but": {}, "is": {}, "are": {}, "was": {}, "were": {}, "in": {}, "on": {}, "at": {}, "by": {}, "for": {}, "with": {}, "without": {}, "to": {}, "from": {},
	},
}

func (idx *Index) Reset() {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.docs = make(map[int]Document)
	idx.inverted = make(map[string]map[int]struct{})
}

func tokenize(text string) []string {
	words := strings.Fields(text)
	var tokens []string
	for _, w := range words {
		w = strings.ToLower(w)
		if _, ok := globalIndex.stopWords[w]; ok {
			continue
		}
		tokens = append(tokens, w)
	}
	return tokens
}

func (idx *Index) IndexDocument(doc Document) error {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	doc.IndexedAt = time.Now()
	idx.docs[doc.DocumentID] = doc
	tokens := tokenize(doc.Content)
	for _, t := range tokens {
		if _, ok := idx.inverted[t]; !ok {
			idx.inverted[t] = make(map[int]struct{})
		}
		idx.inverted[t][doc.DocumentID] = struct{}{}
	}
	return nil
}

func (idx *Index) UnindexDocument(docType string, docID int) error {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	doc, ok := idx.docs[docID]
	if !ok || doc.DocumentType != docType {
		return errors.New("document not found")
	}
	delete(idx.docs, docID)
	tokens := tokenize(doc.Content)
	for _, t := range tokens {
		if ids, ok := idx.inverted[t]; ok {
			delete(ids, docID)
			if len(ids) == 0 {
				delete(idx.inverted, t)
			}
		}
	}
	return nil
}

func (idx *Index) Search(query string, docType string, limit, offset int, filters map[string]string, facets []string) ([]SearchResult, int, bool, map[string]map[string]int, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	terms := tokenize(query)
	if len(terms) == 0 {
		return []SearchResult{}, 0, false, nil, nil
	}

	docScores := make(map[int]float64)

	for _, term := range terms {
		for indexToken, docIDs := range idx.inverted {
			matchType := 0 // 0=no match, 1=prefix, 2=contains, 3=exact
			if indexToken == term {
				matchType = 3
			} else if strings.Contains(indexToken, term) {
				matchType = 2
			} else if strings.HasPrefix(indexToken, term) {
				matchType = 1
			}

			if matchType > 0 {
				for docID := range docIDs {
					doc := idx.docs[docID]
					if docType != "" && doc.DocumentType != docType {
						continue
					}
					matched := true
					for fkey, fval := range filters {
						if v, ok := doc.Metadata[fkey]; ok {
							if fmt.Sprintf("%v", v) != fval {
								matched = false
								break
							}
						} else {
							matched = false
							break
						}
					}
					if !matched {
						continue
					}

					var score float64
					switch matchType {
					case 3:
						score = 1.0
					case 2:
						score = 0.8
					case 1:
						score = 0.5
					}
					docScores[docID] += score
				}
			}
		}
	}

	if len(docScores) == 0 {
		return []SearchResult{}, 0, false, nil, nil
	}

	type kv struct {
		id    int
		score float64
	}
	var kvs []kv
	for id, s := range docScores {
		kvs = append(kvs, kv{id: id, score: s})
	}
	sort.Slice(kvs, func(i, j int) bool {
		if kvs[i].score != kvs[j].score {
			return kvs[i].score > kvs[j].score
		}
		return kvs[i].id < kvs[j].id
	})

	total := len(kvs)
	hasMore := offset+limit < total

	var results []SearchResult
	for i := offset; i < offset+limit && i < total; i++ {
		doc := idx.docs[kvs[i].id]
		results = append(results, SearchResult{
			DocumentID:   doc.DocumentID,
			DocumentType: doc.DocumentType,
			Relevance:    kvs[i].score,
			Metadata:     doc.Metadata,
		})
	}

	facetMap := make(map[string]map[string]int)
	if len(facets) > 0 {
		for _, f := range facets {
			facetMap[f] = make(map[string]int)
		}
		for _, kv := range kvs {
			doc := idx.docs[kv.id]
			for _, f := range facets {
				if val, ok := doc.Metadata[f]; ok {
					facetMap[f][fmt.Sprintf("%v", val)]++
				}
			}
		}
	}

	return results, total, hasMore, facetMap, nil
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
	// For simplicity, reindex all documents of the type
	globalIndex.mu.Lock()
	defer globalIndex.mu.Unlock()
	for id, doc := range globalIndex.docs {
		if payload.DocumentType != nil && doc.DocumentType != *payload.DocumentType {
			continue
		}
		// remove old tokens
		tokens := tokenize(doc.Content)
		for _, t := range tokens {
			if ids, ok := globalIndex.inverted[t]; ok {
				delete(ids, id)
				if len(ids) == 0 {
					delete(globalIndex.inverted, t)
				}
			}
		}
		// re-add
		newTokens := tokenize(doc.Content)
		for _, t := range newTokens {
			if _, ok := globalIndex.inverted[t]; !ok {
				globalIndex.inverted[t] = make(map[int]struct{})
			}
			globalIndex.inverted[t][id] = struct{}{}
		}
	}
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
