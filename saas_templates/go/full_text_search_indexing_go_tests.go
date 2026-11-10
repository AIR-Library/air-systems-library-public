package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func setupServer() *httptest.Server {
	globalIndex.Reset()
	mux := http.NewServeMux()
	mux.HandleFunc("/search/index", indexHandler)
	mux.HandleFunc("/search", searchHandler)
	mux.HandleFunc("/search/documents/", unindexHandler)
	mux.HandleFunc("/admin/search/reindex", reindexHandler)
	return httptest.NewServer(mux)
}

// postJSON posts payload and returns the response with its body already read and the connection
// released. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: bodies were never closed, so the
// 10,000 posts of TestPerformance each kept a connection open and ran out of file descriptors.
func postJSON(t *testing.T, url string, payload interface{}) *http.Response {
	body, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST error: %v", err)
	}
	return buffered(t, resp)
}

// getJSON is postJSON for GET. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (same reason).
func getJSON(t *testing.T, url string) *http.Response {
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	return buffered(t, resp)
}

// buffered reads and closes resp.Body and replaces it with an in-memory copy.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test HTTP connection.
func buffered(t *testing.T, resp *http.Response) *http.Response {
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	return resp
}

// SEARCH-01
func TestIndexAndSearchUser(t *testing.T) {
	server := setupServer()
	defer server.Close()

	doc := Document{
		DocumentType: "user",
		DocumentID:   123,
		Content:      "john doe john@example.com team member active",
		Metadata: map[string]interface{}{
			"user_id": 123,
			"email":   "john@example.com",
			"tier":    "team",
			"status":  "active",
		},
	}
	resp := postJSON(t, server.URL+"/search/index", doc)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var idxResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&idxResp)
	if !idxResp["success"].(bool) {
		t.Fatalf("index failed")
	}

	// Search
	searchURL := server.URL + "/search?q=john&document_type=user&limit=20&offset=0"
	resp = getJSON(t, searchURL)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("search status %d", resp.StatusCode)
	}
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 1 {
		t.Fatalf("expected total 1, got %d", sr.Total)
	}
	if sr.Results[0].DocumentID != 123 {
		t.Fatalf("expected document_id 123, got %d", sr.Results[0].DocumentID)
	}
}

// SEARCH-02
func TestIndexDeploymentAndSearch(t *testing.T) {
	server := setupServer()
	defer server.Close()

	doc := Document{
		DocumentType: "deployment",
		DocumentID:   200,
		Content:      "stripe integration for deployment",
		Metadata: map[string]interface{}{
			"deployment_id": 200,
			"tier":          "team",
			"status":        "active",
		},
	}
	postJSON(t, server.URL+"/search/index", doc)

	searchURL := server.URL + "/search?q=stripe&document_type=deployment&limit=20"
	resp := getJSON(t, searchURL)
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 1 {
		t.Fatalf("expected total 1, got %d", sr.Total)
	}
	if sr.Results[0].DocumentID != 200 {
		t.Fatalf("expected document_id 200, got %d", sr.Results[0].DocumentID)
	}
}

// SEARCH-03
func TestPartialMatch(t *testing.T) {
	server := setupServer()
	defer server.Close()

	doc := Document{
		DocumentType: "deployment",
		DocumentID:   300,
		Content:      "stripe integration",
		Metadata: map[string]interface{}{
			"tier":   "team",
			"status": "active",
		},
	}
	postJSON(t, server.URL+"/search/index", doc)

	searchURL := server.URL + "/search?q=stri&document_type=deployment"
	resp := getJSON(t, searchURL)
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 1 {
		t.Fatalf("expected total 1, got %d", sr.Total)
	}

	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (SEARCH-03, amended): a term matches a word equal to it
	// or starting with it, never one merely containing it.
	resp = getJSON(t, server.URL+"/search?q=ripe&document_type=deployment")
	sr = SearchResponse{}
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 0 {
		t.Fatalf(`"ripe" must not find "stripe"; got total %d`, sr.Total)
	}
}

// SEARCH-04
func TestFilters(t *testing.T) {
	server := setupServer()
	defer server.Close()

	doc1 := Document{
		DocumentType: "deployment",
		DocumentID:   400,
		Content:      "deployment one",
		Metadata: map[string]interface{}{
			"tier":   "team",
			"status": "active",
		},
	}
	doc2 := Document{
		DocumentType: "deployment",
		DocumentID:   401,
		Content:      "deployment two",
		Metadata: map[string]interface{}{
			"tier":   "solo",
			"status": "draft",
		},
	}
	postJSON(t, server.URL+"/search/index", doc1)
	postJSON(t, server.URL+"/search/index", doc2)

	searchURL := server.URL + "/search?q=deployment&document_type=deployment&filters=tier:team&filters=status:active"
	resp := getJSON(t, searchURL)
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 1 {
		t.Fatalf("expected total 1, got %d", sr.Total)
	}
	if sr.Results[0].DocumentID != 400 {
		t.Fatalf("expected document_id 400, got %d", sr.Results[0].DocumentID)
	}
}

// SEARCH-05
func TestFacets(t *testing.T) {
	server := setupServer()
	defer server.Close()

	doc1 := Document{
		DocumentType: "deployment",
		DocumentID:   500,
		Content:      "deployment one",
		Metadata: map[string]interface{}{
			"tier":   "team",
			"status": "active",
		},
	}
	doc2 := Document{
		DocumentType: "deployment",
		DocumentID:   501,
		Content:      "deployment two",
		Metadata: map[string]interface{}{
			"tier":   "team",
			"status": "draft",
		},
	}
	doc3 := Document{
		DocumentType: "deployment",
		DocumentID:   502,
		Content:      "deployment three",
		Metadata: map[string]interface{}{
			"tier":   "solo",
			"status": "active",
		},
	}
	postJSON(t, server.URL+"/search/index", doc1)
	postJSON(t, server.URL+"/search/index", doc2)
	postJSON(t, server.URL+"/search/index", doc3)

	searchURL := server.URL + "/search?q=deployment&facets=status,tier"
	resp := getJSON(t, searchURL)
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Facets == nil {
		t.Fatalf("expected facets")
	}
	if sr.Facets["status"]["active"] != 2 {
		t.Fatalf("expected active count 2, got %d", sr.Facets["status"]["active"])
	}
	if sr.Facets["tier"]["team"] != 2 {
		t.Fatalf("expected team count 2, got %d", sr.Facets["tier"]["team"])
	}
}

// SEARCH-06
func TestUnindex(t *testing.T) {
	server := setupServer()
	defer server.Close()

	doc := Document{
		DocumentType: "user",
		DocumentID:   600,
		Content:      "alice alice@example.com",
		Metadata: map[string]interface{}{
			"tier":   "solo",
			"status": "active",
		},
	}
	postJSON(t, server.URL+"/search/index", doc)

	// Delete
	req, _ := http.NewRequest(http.MethodDelete, server.URL+"/search/documents/user/600", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status %d", resp.StatusCode)
	}
	var delResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&delResp)
	if !delResp["success"].(bool) {
		t.Fatalf("delete failed")
	}

	// Search
	searchURL := server.URL + "/search?q=alice&document_type=user"
	resp = getJSON(t, searchURL)
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 0 {
		t.Fatalf("expected total 0 after delete, got %d", sr.Total)
	}
}

// SEARCH-07
func TestRealTimeIndexing(t *testing.T) {
	server := setupServer()
	defer server.Close()

	doc := Document{
		DocumentType: "user",
		DocumentID:   700,
		Content:      "bob bob@example.com",
		Metadata: map[string]interface{}{
			"tier":   "solo",
			"status": "active",
		},
	}
	start := time.Now()
	postJSON(t, server.URL+"/search/index", doc)
	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Fatalf("indexing took %v, expected <100ms", elapsed)
	}

	// Search
	searchURL := server.URL + "/search?q=bob&document_type=user"
	resp := getJSON(t, searchURL)
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 1 {
		t.Fatalf("expected total 1, got %d", sr.Total)
	}
}

// TestRelevanceOrdering proves SEARCH-09 (amended): an exact word match ranks above a prefix match, and
// equal scores keep insertion order (not document id order).
// Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the old documents ("exact match" and "examine
// match") did not both match the query, so the ordering was never tested.
// SEARCH-09
func TestRelevanceOrdering(t *testing.T) {
	server := setupServer()
	defer server.Close()

	meta := map[string]interface{}{"tier": "solo", "status": "active"}
	for _, d := range []Document{
		{DocumentType: "user", DocumentID: 900, Content: "stripes and more", Metadata: meta}, // prefix, indexed first
		{DocumentType: "user", DocumentID: 801, Content: "stripe billing", Metadata: meta},   // exact
		{DocumentType: "user", DocumentID: 500, Content: "stripe again", Metadata: meta},     // exact, indexed after 801
	} {
		postJSON(t, server.URL+"/search/index", d)
	}

	resp := getJSON(t, server.URL+"/search?q=stripe&document_type=user")
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 3 {
		t.Fatalf("expected total 3, got %d", sr.Total)
	}
	got := []int{sr.Results[0].DocumentID, sr.Results[1].DocumentID, sr.Results[2].DocumentID}
	if got[0] != 801 || got[1] != 500 || got[2] != 900 {
		t.Fatalf("expected exact matches in insertion order then the prefix match [801 500 900], got %v", got)
	}
	if sr.Results[0].Relevance <= sr.Results[2].Relevance {
		t.Fatalf("exact relevance %v should exceed prefix relevance %v", sr.Results[0].Relevance, sr.Results[2].Relevance)
	}
}

// TestOneMillionDocumentsUnder200ms proves SEARCH-08: with 1,000,000 documents indexed, a search returns
// in under 200 ms (the contract budget). It calls the index directly, as the other languages do, so the
// time measured is the search, not 1M HTTP requests. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP:
// the Go suite only indexed 10,000. Touches: process memory (about a few hundred MB).
// SEARCH-08
func TestOneMillionDocumentsUnder200ms(t *testing.T) {
	idx := newIndex()
	meta := map[string]interface{}{"tier": "team", "status": "active"} // shared: every document has the same metadata
	for i := 0; i < 1_000_000; i++ {
		idx.IndexDocument(Document{
			DocumentType: "deployment",
			DocumentID:   i,
			Content:      "document " + strconv.Itoa(i) + " stripe integration deployment active",
			Metadata:     meta,
		})
	}
	start := time.Now()
	results, total, _, _, err := idx.Search("stripe", "deployment", 20, 0, nil, nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed >= 200*time.Millisecond {
		t.Fatalf("search over 1M documents took %v, budget 200ms", elapsed)
	}
	if total != 1_000_000 || len(results) != 20 || results[0].DocumentID != 0 || results[19].DocumentID != 19 {
		t.Fatalf("expected all 1M in insertion order, got total %d, first %v", total, results[:1])
	}
	t.Logf("1M-document search: %v", elapsed)
}

func TestPerformance(t *testing.T) {
	server := setupServer()
	defer server.Close()

	// Insert 10000 documents
	for i := 0; i < 10000; i++ {
		doc := Document{
			DocumentType: "user",
			DocumentID:   1000 + i,
			Content:      "user number " + strconv.Itoa(i),
			Metadata: map[string]interface{}{
				"tier":   "team",
				"status": "active",
			},
		}
		postJSON(t, server.URL+"/search/index", doc)
	}

	start := time.Now()
	searchURL := server.URL + "/search?q=number&document_type=user&limit=10"
	resp := getJSON(t, searchURL)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("search status %d", resp.StatusCode)
	}
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	elapsed := time.Since(start)
	if elapsed > 200*time.Millisecond {
		t.Fatalf("search took %v, expected <200ms", elapsed)
	}
	if sr.Total != 10000 {
		t.Fatalf("expected total 10000, got %d", sr.Total)
	}
}

func TestReindexJob(t *testing.T) {
	server := setupServer()
	defer server.Close()

	doc := Document{
		DocumentType: "user",
		DocumentID:   900,
		Content:      "old content",
		Metadata: map[string]interface{}{
			"tier":   "solo",
			"status": "active",
		},
	}
	postJSON(t, server.URL+"/search/index", doc)

	// Reindex
	payload := map[string]interface{}{
		"document_type": "user",
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(server.URL+"/admin/search/reindex", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("reindex error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reindex status %d", resp.StatusCode)
	}
	var reResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&reResp)
	if !reResp["success"].(bool) {
		t.Fatalf("reindex failed")
	}
	if reResp["status"] != "enqueued" {
		t.Fatalf("expected status enqueued, got %v", reResp["status"])
	}
}

func TestSearchWithMultipleTerms(t *testing.T) {
	server := setupServer()
	defer server.Close()

	doc := Document{
		DocumentType: "deployment",
		DocumentID:   1001,
		Content:      "stripe integration deployment",
		Metadata: map[string]interface{}{
			"tier":   "team",
			"status": "active",
		},
	}
	postJSON(t, server.URL+"/search/index", doc)

	searchURL := server.URL + "/search?q=stripe+integration&document_type=deployment"
	resp := getJSON(t, searchURL)
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 1 {
		t.Fatalf("expected total 1, got %d", sr.Total)
	}
	if sr.Results[0].DocumentID != 1001 {
		t.Fatalf("expected document_id 1001, got %d", sr.Results[0].DocumentID)
	}
}

func TestSearchWithPrefixMatch(t *testing.T) {
	server := setupServer()
	defer server.Close()

	doc := Document{
		DocumentType: "deployment",
		DocumentID:   1002,
		Content:      "prefix test",
		Metadata: map[string]interface{}{
			"tier":   "team",
			"status": "active",
		},
	}
	postJSON(t, server.URL+"/search/index", doc)

	searchURL := server.URL + "/search?q=pre&document_type=deployment"
	resp := getJSON(t, searchURL)
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 1 {
		t.Fatalf("expected total 1, got %d", sr.Total)
	}
	if sr.Results[0].DocumentID != 1002 {
		t.Fatalf("expected document_id 1002, got %d", sr.Results[0].DocumentID)
	}
}

func TestSearchWithOffsetAndLimit(t *testing.T) {
	server := setupServer()
	defer server.Close()

	for i := 0; i < 5; i++ {
		doc := Document{
			DocumentType: "user",
			DocumentID:   2000 + i,
			Content:      "offset test " + strconv.Itoa(i),
			Metadata: map[string]interface{}{
				"tier":   "team",
				"status": "active",
			},
		}
		postJSON(t, server.URL+"/search/index", doc)
	}

	searchURL := server.URL + "/search?q=offset&document_type=user&limit=2&offset=1"
	resp := getJSON(t, searchURL)
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 5 {
		t.Fatalf("expected total 5, got %d", sr.Total)
	}
	if len(sr.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(sr.Results))
	}
	if sr.Results[0].DocumentID != 2001 {
		t.Fatalf("expected first result 2001, got %d", sr.Results[0].DocumentID)
	}
	if sr.Results[1].DocumentID != 2002 {
		t.Fatalf("expected second result 2002, got %d", sr.Results[1].DocumentID)
	}
}

func TestSearchWithNoResults(t *testing.T) {
	server := setupServer()
	defer server.Close()

	searchURL := server.URL + "/search?q=nonexistent&document_type=user"
	resp := getJSON(t, searchURL)
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 0 {
		t.Fatalf("expected total 0, got %d", sr.Total)
	}
	if sr.HasMore {
		t.Fatalf("expected has_more false")
	}
}

func TestSearchWithInvalidFilter(t *testing.T) {
	server := setupServer()
	defer server.Close()

	doc := Document{
		DocumentType: "user",
		DocumentID:   3000,
		Content:      "filter test",
		Metadata: map[string]interface{}{
			"tier":   "team",
			"status": "active",
		},
	}
	postJSON(t, server.URL+"/search/index", doc)

	searchURL := server.URL + "/search?q=filter&document_type=user&filters=unknown:val"
	resp := getJSON(t, searchURL)
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 0 {
		t.Fatalf("expected total 0 due to invalid filter, got %d", sr.Total)
	}
}

func TestSearchWithMultipleFilters(t *testing.T) {
	server := setupServer()
	defer server.Close()

	doc1 := Document{
		DocumentType: "user",
		DocumentID:   4000,
		Content:      "multi filter",
		Metadata: map[string]interface{}{
			"tier":   "team",
			"status": "active",
		},
	}
	doc2 := Document{
		DocumentType: "user",
		DocumentID:   4001,
		Content:      "multi filter",
		Metadata: map[string]interface{}{
			"tier":   "solo",
			"status": "draft",
		},
	}
	postJSON(t, server.URL+"/search/index", doc1)
	postJSON(t, server.URL+"/search/index", doc2)

	searchURL := server.URL + "/search?q=filter&document_type=user&filters=tier:team&filters=status:active"
	resp := getJSON(t, searchURL)
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 1 {
		t.Fatalf("expected total 1, got %d", sr.Total)
	}
	if sr.Results[0].DocumentID != 4000 {
		t.Fatalf("expected document_id 4000, got %d", sr.Results[0].DocumentID)
	}
}

func TestSearchWithEmptyQuery(t *testing.T) {
	server := setupServer()
	defer server.Close()

	searchURL := server.URL + "/search?q=&document_type=user"
	resp := getJSON(t, searchURL)
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 0 {
		t.Fatalf("expected total 0 for empty query, got %d", sr.Total)
	}
}

func TestSearchWithSpecialCharacters(t *testing.T) {
	server := setupServer()
	defer server.Close()

	doc := Document{
		DocumentType: "user",
		DocumentID:   5000,
		Content:      "special!@# chars",
		Metadata: map[string]interface{}{
			"tier":   "solo",
			"status": "active",
		},
	}
	postJSON(t, server.URL+"/search/index", doc)

	searchURL := server.URL + "/search?q=special!@#&document_type=user"
	resp := getJSON(t, searchURL)
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 1 {
		t.Fatalf("expected total 1, got %d", sr.Total)
	}
	if sr.Results[0].DocumentID != 5000 {
		t.Fatalf("expected document_id 5000, got %d", sr.Results[0].DocumentID)
	}
}

func TestSearchWithCaseInsensitive(t *testing.T) {
	server := setupServer()
	defer server.Close()

	doc := Document{
		DocumentType: "user",
		DocumentID:   6000,
		Content:      "CaseInsensitive",
		Metadata: map[string]interface{}{
			"tier":   "solo",
			"status": "active",
		},
	}
	postJSON(t, server.URL+"/search/index", doc)

	searchURL := server.URL + "/search?q=caseinsensitive&document_type=user"
	resp := getJSON(t, searchURL)
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 1 {
		t.Fatalf("expected total 1, got %d", sr.Total)
	}
	if sr.Results[0].DocumentID != 6000 {
		t.Fatalf("expected document_id 6000, got %d", sr.Results[0].DocumentID)
	}
}

func TestSearchWithMultipleDocumentTypes(t *testing.T) {
	server := setupServer()
	defer server.Close()

	docUser := Document{
		DocumentType: "user",
		DocumentID:   7000,
		Content:      "common term",
		Metadata: map[string]interface{}{
			"tier":   "solo",
			"status": "active",
		},
	}
	docDeployment := Document{
		DocumentType: "deployment",
		DocumentID:   7001,
		Content:      "common term",
		Metadata: map[string]interface{}{
			"tier":   "team",
			"status": "active",
		},
	}
	postJSON(t, server.URL+"/search/index", docUser)
	postJSON(t, server.URL+"/search/index", docDeployment)

	searchURL := server.URL + "/search?q=common+term"
	resp := getJSON(t, searchURL)
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 2 {
		t.Fatalf("expected total 2, got %d", sr.Total)
	}
}

func TestSearchWithInvalidJSON(t *testing.T) {
	server := setupServer()
	defer server.Close()

	resp, err := http.Post(server.URL+"/search/index", "application/json", strings.NewReader("{invalid json}"))
	if err != nil {
		t.Fatalf("post error: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSearchWithMissingFields(t *testing.T) {
	server := setupServer()
	defer server.Close()

	doc := Document{
		DocumentType: "user",
		DocumentID:   8000,
		Content:      "",
		Metadata: map[string]interface{}{
			"tier":   "solo",
			"status": "active",
		},
	}
	postJSON(t, server.URL+"/search/index", doc)

	searchURL := server.URL + "/search?q=&document_type=user"
	resp := getJSON(t, searchURL)
	var sr SearchResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	if sr.Total != 0 {
		t.Fatalf("expected total 0 for empty content, got %d", sr.Total)
	}
}
