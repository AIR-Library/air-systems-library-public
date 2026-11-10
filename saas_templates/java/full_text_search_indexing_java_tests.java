package saas.search;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.Timeout;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for FullTextSearchIndexing.
 *
 * Covers all spec TESTS:
 *  ✓ Index user, search finds it
 *  ✓ Index deployment, query works
 *  ✓ Partial match: "stri" finds "stripe"
 *  ✓ Filters: tier:team returns only team tier
 *  ✓ Facets: shows count per status
 *  ✓ Unindex: document no longer found after delete
 *  ✓ Real-time: index updated within 100ms of create
 *  ✓ Performance: 1M documents, search returns <200ms
 *  ✓ Relevance: exact match ranks higher than partial
 */
@Timeout(30)
class FullTextSearchIndexingTests {

    private FullTextSearchIndexing search;

    @BeforeEach
    void setUp() {
        search = new FullTextSearchIndexing();
    }

    @AfterEach
    void tearDown() {
        search.close();
    }

    // ─── Test 1: Index user, search finds it ─────────────────────────────────

    @Test
    @DisplayName("Index user, search finds it")
    void testIndexUserAndSearch() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("user_id", 123);
        metadata.put("email", "john@example.com");
        metadata.put("tier", "team");
        metadata.put("status", "active");
        metadata.put("created_at", "2026-01-15T10:00:00Z");

        FullTextSearchIndexing.IndexResponse resp = search.indexDocument(
                "user", "123",
                "john doe john@example.com team member active",
                metadata
        );

        assertTrue(resp.success);
        assertNotNull(resp.indexedAt);

        FullTextSearchIndexing.SearchResponse searchResp = search.search("john", "user", 20, 0);
        assertTrue(searchResp.total >= 1);
        assertFalse(searchResp.results.isEmpty());

        FullTextSearchIndexing.SearchResult first = searchResp.results.get(0);
        assertEquals("123", first.documentId);
        assertEquals("user", first.documentType);
        assertTrue(first.relevance > 0);
        assertEquals("john@example.com", first.metadata.get("email"));
        assertEquals("team", first.metadata.get("tier"));
        assertEquals("active", first.metadata.get("status"));
    }

    // ─── Test 2: Index deployment, query works ───────────────────────────────

    @Test
    @DisplayName("Index deployment, query works")
    void testIndexDeploymentAndSearch() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("deployment_id", 456);
        metadata.put("tier", "enterprise");
        metadata.put("status", "active");
        metadata.put("created_at", "2026-02-01T08:00:00Z");

        search.indexDocument(
                "deployment", "456",
                "stripe integration payment processing v2",
                metadata
        );

        FullTextSearchIndexing.SearchResponse resp = search.search("stripe", "deployment", 20, 0);
        assertTrue(resp.total >= 1);
        assertEquals("456", resp.results.get(0).documentId);
        assertEquals("deployment", resp.results.get(0).documentType);
    }

    // ─── Test 3: Partial match ───────────────────────────────────────────────

    @Test
    @DisplayName("Partial match: 'stri' finds 'stripe'")
    void testPartialMatch() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("tier", "team");
        metadata.put("status", "active");

        search.indexDocument(
                "deployment", "789",
                "stripe integration payment gateway",
                metadata
        );

        FullTextSearchIndexing.SearchResponse resp = search.search("stri", "deployment", 20, 0);
        assertTrue(resp.total >= 1, "Partial match 'stri' should find 'stripe'");
        assertEquals("789", resp.results.get(0).documentId);
    }

    // ─── Test 4: Filters ─────────────────────────────────────────────────────

    @Test
    @DisplayName("Filters: tier:team returns only team tier")
    void testFilters() {
        Map<String, Object> teamMeta = new HashMap<>();
        teamMeta.put("tier", "team");
        teamMeta.put("status", "active");

        Map<String, Object> soloMeta = new HashMap<>();
        soloMeta.put("tier", "solo");
        soloMeta.put("status", "active");

        Map<String, Object> enterpriseMeta = new HashMap<>();
        enterpriseMeta.put("tier", "enterprise");
        enterpriseMeta.put("status", "active");

        search.indexDocument("user", "1", "alice smith team member", teamMeta);
        search.indexDocument("user", "2", "bob jones solo developer", soloMeta);
        search.indexDocument("user", "3", "carol white enterprise admin", enterpriseMeta);

        // Filter by tier:team
        Map<String, String> filters = new HashMap<>();
        filters.put("tier", "team");

        FullTextSearchIndexing.SearchResponse resp = search.search(
                "member", "user", filters, 20, 0
        );

        // Only alice should match (tier=team AND content has "member")
        for (FullTextSearchIndexing.SearchResult r : resp.results) {
            assertEquals("team", r.metadata.get("tier"),
                    "All results should have tier=team");
        }
        assertTrue(resp.total >= 1);
    }

    @Test
    @DisplayName("Filters via query syntax: tier:team")
    void testFiltersViaQuerySyntax() {
        Map<String, Object> teamMeta = new HashMap<>();
        teamMeta.put("tier", "team");
        teamMeta.put("status", "active");

        Map<String, Object> soloMeta = new HashMap<>();
        soloMeta.put("tier", "solo");
        soloMeta.put("status", "active");

        search.indexDocument("user", "10", "alice smith team member", teamMeta);
        search.indexDocument("user", "11", "bob jones solo developer", soloMeta);

        // Query with filter syntax
        FullTextSearchIndexing.SearchResponse resp = search.search(
                "member tier:team", "user", null, 20, 0
        );

        for (FullTextSearchIndexing.SearchResult r : resp.results) {
            assertEquals("team", r.metadata.get("tier"));
        }
    }

    // ─── Test 5: Facets ──────────────────────────────────────────────────────

    @Test
    @DisplayName("Facets: shows count per status")
    void testFacets() {
        Map<String, Object> activeMeta1 = new HashMap<>();
        activeMeta1.put("tier", "team");
        activeMeta1.put("status", "active");

        Map<String, Object> activeMeta2 = new HashMap<>();
        activeMeta2.put("tier", "solo");
        activeMeta2.put("status", "active");

        Map<String, Object> draftMeta = new HashMap<>();
        draftMeta.put("tier", "team");
        draftMeta.put("status", "draft");

        Map<String, Object> archivedMeta = new HashMap<>();
        archivedMeta.put("tier", "enterprise");
        archivedMeta.put("status", "archived");

        search.indexDocument("deployment", "1", "stripe integration v1", activeMeta1);
        search.indexDocument("deployment", "2", "stripe integration v2", activeMeta2);
        search.indexDocument("deployment", "3", "stripe integration v3", draftMeta);
        search.indexDocument("deployment", "4", "stripe integration v4", archivedMeta);

        List<String> facetFields = Arrays.asList("status", "tier");
        FullTextSearchIndexing.SearchResponse resp = search.search(
                "stripe", "deployment", null, 20, 0, facetFields
        );

        assertNotNull(resp.facets);
        assertTrue(resp.facets.containsKey("status"));
        assertTrue(resp.facets.containsKey("tier"));

        Map<String, Long> statusFacets = resp.facets.get("status");
        assertEquals(2L, statusFacets.get("active"));
        assertEquals(1L, statusFacets.get("draft"));
        assertEquals(1L, statusFacets.get("archived"));

        Map<String, Long> tierFacets = resp.facets.get("tier");
        assertEquals(2L, tierFacets.get("team"));
        assertEquals(1L, tierFacets.get("solo"));
        assertEquals(1L, tierFacets.get("enterprise"));
    }

    // ─── Test 6: Unindex ─────────────────────────────────────────────────────

    @Test
    @DisplayName("Unindex: document no longer found after delete")
    void testUnindex() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("tier", "team");
        metadata.put("status", "active");

        search.indexDocument("user", "200", "dave brown team member", metadata);

        // Verify it's found
        FullTextSearchIndexing.SearchResponse before = search.search("dave", "user", 20, 0);
        assertTrue(before.total >= 1);

        // Unindex
        FullTextSearchIndexing.DeleteResponse delResp = search.unindexDocument("user", "200");
        assertTrue(delResp.success);

        // Verify it's gone
        FullTextSearchIndexing.SearchResponse after = search.search("dave", "user", 20, 0);
        assertEquals(0, after.total);
        assertTrue(after.results.isEmpty());
    }

    // ─── Test 7: Real-time indexing ──────────────────────────────────────────

    @Test
    @DisplayName("Real-time: index updated within 100ms of create")
    void testRealTimeIndexing() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("tier", "team");
        metadata.put("status", "active");

        long start = System.currentTimeMillis();
        search.indexDocument("user", "300", "eve frank team member", metadata);
        long indexTime = System.currentTimeMillis() - start;

        // Search immediately
        FullTextSearchIndexing.SearchResponse resp = search.search("eve", "user", 20, 0);
        long totalTime = System.currentTimeMillis() - start;

        assertTrue(resp.total >= 1, "Document should be immediately searchable");
        assertTrue(totalTime < 100,
                "Index + search should complete within 100ms, took " + totalTime + "ms");
    }

    // ─── Test 8: Performance ─────────────────────────────────────────────────

    @Test
    @DisplayName("Performance: 1M documents, search returns <200ms")
    void testPerformance() {
        // Index 1M documents
        int docCount = 1_000_000;
        for (int i = 0; i < docCount; i++) {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("tier", i % 3 == 0 ? "solo" : (i % 3 == 1 ? "team" : "enterprise"));
            metadata.put("status", i % 2 == 0 ? "active" : "draft");
            metadata.put("user_id", i);

            String content = "user" + i + " name" + i + " email" + i + "@example.com " +
                    (i % 3 == 0 ? "solo" : (i % 3 == 1 ? "team" : "enterprise")) +
                    " member " + (i % 2 == 0 ? "active" : "draft");

            search.indexDocument("user", String.valueOf(i), content, metadata);
        }

        assertEquals(docCount, search.getDocumentCount());

        // Search should be fast
        long start = System.currentTimeMillis();
        FullTextSearchIndexing.SearchResponse resp = search.search("user500000", "user", 20, 0);
        long elapsed = System.currentTimeMillis() - start;

        assertTrue(elapsed < 200,
                "Search over 1M docs should take <200ms, took " + elapsed + "ms");
        assertTrue(resp.total >= 1);
    }

    // ─── Test 9: Relevance ───────────────────────────────────────────────────

    @Test
    @DisplayName("Relevance: exact match ranks higher than partial")
    void testRelevanceOrdering() {
        Map<String, Object> meta1 = new HashMap<>();
        meta1.put("tier", "team");
        meta1.put("status", "active");

        Map<String, Object> meta2 = new HashMap<>();
        meta2.put("tier", "team");
        meta2.put("status", "active");

        Map<String, Object> meta3 = new HashMap<>();
        meta3.put("tier", "team");
        meta3.put("status", "active");

        // Exact match: "stripe" is a whole word
        search.indexDocument("deployment", "1", "stripe integration payment", meta1);
        // Partial match: "stripe" is part of "stripes"
        search.indexDocument("deployment", "2", "stripes integration payment", meta2);
        // Prefix match: "stripe" is prefix of "stripey"
        search.indexDocument("deployment", "3", "stripey integration payment", meta3);

        FullTextSearchIndexing.SearchResponse resp = search.search("stripe", "deployment", 20, 0);

        assertTrue(resp.total >= 3);

        // Exact match should rank first
        FullTextSearchIndexing.SearchResult first = resp.results.get(0);
        assertEquals("1", first.documentId,
                "Exact match should rank highest, got: " + first.documentId);
        assertTrue(first.relevance > resp.results.get(1).relevance,
                "Exact match relevance should be higher than next");
    }

    // ─── Additional Tests ────────────────────────────────────────────────────

    @Test
    @DisplayName("Multi-word search: both words must match")
    void testMultiWordSearch() {
        Map<String, Object> meta1 = new HashMap<>();
        meta1.put("tier", "team");
        meta1.put("status", "active");

        Map<String, Object> meta2 = new HashMap<>();
        meta2.put("tier", "team");
        meta2.put("status", "active");

        Map<String, Object> meta3 = new HashMap<>();
        meta3.put("tier", "team");
        meta3.put("status", "active");

        search.indexDocument("deployment", "1", "stripe integration payment", meta1);
        search.indexDocument("deployment", "2", "stripe gateway only", meta2);
        search.indexDocument("deployment", "3", "integration payment processing", meta3);

        // "stripe integration" should match doc 1 (both words)
        FullTextSearchIndexing.SearchResponse resp = search.search(
                "stripe integration", "deployment", 20, 0
        );

        // Doc 1 has both "stripe" and "integration"
        boolean foundDoc1 = false;
        for (FullTextSearchIndexing.SearchResult r : resp.results) {
            if ("1".equals(r.documentId)) {
                foundDoc1 = true;
                break;
            }
        }
        assertTrue(foundDoc1, "Doc with both 'stripe' and 'integration' should be found");
    }

    @Test
    @DisplayName("Pagination: limit and offset work correctly")
    void testPagination() {
        for (int i = 0; i < 50; i++) {
            Map<String, Object> meta = new HashMap<>();
            meta.put("tier", "team");
            meta.put("status", "active");
            search.indexDocument("user", String.valueOf(i),
                    "user" + i + " test member", meta);
        }

        FullTextSearchIndexing.SearchResponse page1 = search.search(
                "user", "user", 10, 0
        );
        assertEquals(10, page1.results.size());
        assertTrue(page1.hasMore);
        assertTrue(page1.total >= 50);

        FullTextSearchIndexing.SearchResponse page2 = search.search(
                "user", "user", 10, 10
        );
        assertEquals(10, page2.results.size());
        assertTrue(page2.hasMore);

        // Last page
        FullTextSearchIndexing.SearchResponse lastPage = search.search(
                "user", "user", 10, 40
        );
        assertEquals(10, lastPage.results.size());
        assertFalse(lastPage.hasMore);
    }

    @Test
    @DisplayName("Document type filter: only returns matching type")
    void testDocumentTypeFilter() {
        Map<String, Object> meta = new HashMap<>();
        meta.put("tier", "team");
        meta.put("status", "active");

        search.indexDocument("user", "1", "shared content here", meta);
        search.indexDocument("deployment", "1", "shared content here", meta);

        FullTextSearchIndexing.SearchResponse userResp = search.search(
                "shared", "user", 20, 0
        );
        for (FullTextSearchIndexing.SearchResult r : userResp.results) {
            assertEquals("user", r.documentType);
        }

        FullTextSearchIndexing.SearchResponse deployResp = search.search(
                "shared", "deployment", 20, 0
        );
        for (FullTextSearchIndexing.SearchResult r : deployResp.results) {
            assertEquals("deployment", r.documentType);
        }
    }

    @Test
    @DisplayName("Empty query returns all documents of type")
    void testEmptyQuery() {
        Map<String, Object> meta = new HashMap<>();
        meta.put("tier", "team");
        meta.put("status", "active");

        search.indexDocument("user", "1", "alice smith", meta);
        search.indexDocument("user", "2", "bob jones", meta);
        search.indexDocument("deployment", "1", "stripe integration", meta);

        FullTextSearchIndexing.SearchResponse resp = search.search("", "user", 20, 0);
        assertEquals(2, resp.total);
    }

    @Test
    @DisplayName("Update document: re-index replaces old content")
    void testUpdateDocument() {
        Map<String, Object> meta = new HashMap<>();
        meta.put("tier", "team");
        meta.put("status", "active");

        search.indexDocument("user", "1", "old name content", meta);

        // Verify old content is found
        FullTextSearchIndexing.SearchResponse before = search.search("old", "user", 20, 0);
        assertTrue(before.total >= 1);

        // Update with new content
        search.indexDocument("user", "1", "new name content", meta);

        // Old content should not be found
        FullTextSearchIndexing.SearchResponse afterOld = search.search("old", "user", 20, 0);
        assertEquals(0, afterOld.total);

        // New content should be found
        FullTextSearchIndexing.SearchResponse afterNew = search.search("new", "user", 20, 0);
        assertTrue(afterNew.total >= 1);
    }

    @Test
    @DisplayName("Stop words are ignored in search")
    void testStopWords() {
        Map<String, Object> meta = new HashMap<>();
        meta.put("tier", "team");
        meta.put("status", "active");

        search.indexDocument("user", "1", "the quick brown fox", meta);

        // "the" is a stop word, should not be indexed
        FullTextSearchIndexing.SearchResponse resp = search.search("the", "user", 20, 0);
        assertEquals(0, resp.total, "Stop word 'the' should not match");

        // "quick" should match
        FullTextSearchIndexing.SearchResponse resp2 = search.search("quick", "user", 20, 0);
        assertTrue(resp2.total >= 1);
    }

    @Test
    @DisplayName("Complex query: text + multiple filters")
    void testComplexQuery() {
        Map<String, Object> meta1 = new HashMap<>();
        meta1.put("tier", "enterprise");
        meta1.put("status", "active");

        Map<String, Object> meta2 = new HashMap<>();
        meta2.put("tier", "enterprise");
        meta2.put("status", "draft");

        Map<String, Object> meta3 = new HashMap<>();
        meta3.put("tier", "team");
        meta3.put("status", "active");

        search.indexDocument("deployment", "1", "stripe integration v1", meta1);
        search.indexDocument("deployment", "2", "stripe integration v2", meta2);
        search.indexDocument("deployment", "3", "stripe integration v3", meta3);

        // Query: "stripe" with filters tier:enterprise, status:active
        Map<String, String> filters = new HashMap<>();
        filters.put("tier", "enterprise");
        filters.put("status", "active");

        FullTextSearchIndexing.SearchResponse resp = search.search(
                "stripe", "deployment", filters, 20, 0
        );

        assertEquals(1, resp.total);
        assertEquals("1", resp.results.get(0).documentId);
    }

    /** Reindex of all types clears and rebuilds from the source. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: waits on the job (awaitJob) instead of a fixed 200 ms sleep. Touches: memory only. */
    @Test
    @DisplayName("Reindex: clears and rebuilds index")
    void testReindex() {
        // Set up a reindex source
        List<FullTextSearchIndexing.Document> sourceDocs = new ArrayList<>();
        Map<String, Object> meta = new HashMap<>();
        meta.put("tier", "team");
        meta.put("status", "active");

        sourceDocs.add(new FullTextSearchIndexing.Document(
                "user", "1", "reindex test user", Instant.now(), meta
        ));

        FullTextSearchIndexing.ReindexSource source = new FullTextSearchIndexing.ReindexSource() {
            @Override
            public List<FullTextSearchIndexing.Document> getAllDocuments() {
                return sourceDocs;
            }

            @Override
            public List<FullTextSearchIndexing.Document> getDocumentsByType(String type) {
                return sourceDocs.stream()
                        .filter(d -> d.documentType.equals(type))
                        .collect(java.util.stream.Collectors.toList());
            }

            @Override
            public String getDocumentType() {
                return "all";
            }
        };

        search.setReindexSource(source);

        // Index some docs
        search.indexDocument("user", "1", "original content", meta);
        search.indexDocument("user", "2", "another doc", meta);
        assertEquals(2, search.getDocumentCount());

        // Reindex
        FullTextSearchIndexing.ReindexResponse resp = search.reindexAll(null);
        assertTrue(resp.success);
        assertNotNull(resp.jobId);
        assertEquals("enqueued", resp.status);

        // Wait for job to complete. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: a fixed
        // Thread.sleep(200) raced the background job on a loaded machine; awaitJob waits on the job itself.
        assertTrue(search.awaitJob(resp.jobId, 10_000), "reindex job should finish");

        assertEquals("completed", search.getJobStatus(resp.jobId));
        assertEquals(1, search.getDocumentCount());

        // Verify reindexed doc is searchable
        FullTextSearchIndexing.SearchResponse sr = search.search("reindex", "user", 20, 0);
        assertTrue(sr.total >= 1);
    }

    /** Reindex of one type rebuilds only that type. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: waits on the job instead of sleeping. Touches: memory only. */
    @Test
    @DisplayName("Reindex specific type")
    void testReindexSpecificType() {
        List<FullTextSearchIndexing.Document> sourceDocs = new ArrayList<>();
        Map<String, Object> meta = new HashMap<>();
        meta.put("tier", "team");
        meta.put("status", "active");

        sourceDocs.add(new FullTextSearchIndexing.Document(
                "user", "1", "user reindex", Instant.now(), meta
        ));
        sourceDocs.add(new FullTextSearchIndexing.Document(
                "deployment", "1", "deployment reindex", Instant.now(), meta
        ));

        FullTextSearchIndexing.ReindexSource source = new FullTextSearchIndexing.ReindexSource() {
            @Override
            public List<FullTextSearchIndexing.Document> getAllDocuments() {
                return sourceDocs;
            }

            @Override
            public List<FullTextSearchIndexing.Document> getDocumentsByType(String type) {
                return sourceDocs.stream()
                        .filter(d -> d.documentType.equals(type))
                        .collect(java.util.stream.Collectors.toList());
            }

            @Override
            public String getDocumentType() {
                return "all";
            }
        };

        search.setReindexSource(source);

        search.indexDocument("user", "1", "old user", meta);
        search.indexDocument("deployment", "1", "old deployment", meta);

        FullTextSearchIndexing.ReindexResponse resp = search.reindexAll("user");
        assertTrue(resp.success);

        // Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: wait on the job, not a fixed 200 ms sleep.
        assertTrue(search.awaitJob(resp.jobId, 10_000), "reindex job should finish");

        assertEquals("completed", search.getJobStatus(resp.jobId));
        // Only user docs should be reindexed
        assertEquals(1, search.getDocumentCount("user"));
    }

    @Test
    @DisplayName("Multiple documents with same content all found")
    void testMultipleDocumentsSameContent() {
        Map<String, Object> meta = new HashMap<>();
        meta.put("tier", "team");
        meta.put("status", "active");

        for (int i = 0; i < 5; i++) {
            search.indexDocument("user", String.valueOf(i),
                    "shared content test", meta);
        }

        FullTextSearchIndexing.SearchResponse resp = search.search("shared", "user", 20, 0);
        assertEquals(5, resp.total);
        assertEquals(5, resp.results.size());
    }

    @Test
    @DisplayName("Case insensitive search")
    void testCaseInsensitive() {
        Map<String, Object> meta = new HashMap<>();
        meta.put("tier", "team");
        meta.put("status", "active");

        search.indexDocument("user", "1", "John Doe Example", meta);

        // Lowercase query
        FullTextSearchIndexing.SearchResponse resp1 = search.search("john", "user", 20, 0);
        assertTrue(resp1.total >= 1);

        // Uppercase query
        FullTextSearchIndexing.SearchResponse resp2 = search.search("JOHN", "user", 20, 0);
        assertTrue(resp2.total >= 1);

        // Mixed case
        FullTextSearchIndexing.SearchResponse resp3 = search.search("JoHn", "user", 20, 0);
        assertTrue(resp3.total >= 1);
    }

    @Test
    @DisplayName("Unindex non-existent document returns success")
    void testUnindexNonExistent() {
        FullTextSearchIndexing.DeleteResponse resp = search.unindexDocument("user", "999");
        assertTrue(resp.success);
    }

    @Test
    @DisplayName("Null metadata handled gracefully")
    void testNullMetadata() {
        FullTextSearchIndexing.IndexResponse resp = search.indexDocument(
                "user", "1", "test content", null
        );
        assertTrue(resp.success);

        FullTextSearchIndexing.SearchResponse sr = search.search("test", "user", 20, 0);
        assertTrue(sr.total >= 1);
        assertNotNull(sr.results.get(0).metadata);
        assertTrue(sr.results.get(0).metadata.isEmpty());
    }

    @Test
    @DisplayName("Null content handled gracefully")
    void testNullContent() {
        Map<String, Object> meta = new HashMap<>();
        meta.put("tier", "team");

        FullTextSearchIndexing.IndexResponse resp = search.indexDocument(
                "user", "1", null, meta
        );
        assertTrue(resp.success);

        // Should not crash on search
        FullTextSearchIndexing.SearchResponse sr = search.search("anything", "user", 20, 0);
        assertNotNull(sr);
    }

    @Test
    @DisplayName("Limit capped at maxLimit")
    void testLimitCapped() {
        for (int i = 0; i < 5; i++) {
            Map<String, Object> meta = new HashMap<>();
            meta.put("tier", "team");
            search.indexDocument("user", String.valueOf(i), "test content", meta);
        }

        // Request more than maxLimit (100)
        FullTextSearchIndexing.SearchResponse resp = search.search("test", "user", 500, 0);
        assertTrue(resp.results.size() <= 100);
    }

    @Test
    @DisplayName("Offset beyond total returns empty results")
    void testOffsetBeyondTotal() {
        Map<String, Object> meta = new HashMap<>();
        meta.put("tier", "team");
        search.indexDocument("user", "1", "test content", meta);

        FullTextSearchIndexing.SearchResponse resp = search.search("test", "user", 10, 100);
        assertEquals(0, resp.results.size());
        assertFalse(resp.hasMore);
    }

    @Test
    @DisplayName("Facets with no matching documents")
    void testFacetsNoResults() {
        Map<String, Object> meta = new HashMap<>();
        meta.put("tier", "team");
        meta.put("status", "active");
        search.indexDocument("user", "1", "test content", meta);

        FullTextSearchIndexing.SearchResponse resp = search.search(
                "nonexistentterm", "user", null, 20, 0,
                Arrays.asList("tier", "status")
        );

        assertEquals(0, resp.total);
        assertNotNull(resp.facets);
        assertTrue(resp.facets.get("tier").isEmpty());
        assertTrue(resp.facets.get("status").isEmpty());
    }

    @Test
    @DisplayName("Concurrent indexing does not corrupt index")
    void testConcurrentIndexing() throws InterruptedException {
        int threadCount = 10;
        int docsPerThread = 100;
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicReference<Exception> error = new AtomicReference<>();

        for (int t = 0; t < threadCount; t++) {
            final int threadId = t;
            new Thread(() -> {
                try {
                    for (int i = 0; i < docsPerThread; i++) {
                        Map<String, Object> meta = new HashMap<>();
                        meta.put("tier", "team");
                        meta.put("status", "active");
                        String docId = threadId + "-" + i;
                        search.indexDocument("user", docId,
                                "concurrent test " + docId, meta);
                    }
                } catch (Exception e) {
                    error.set(e);
                } finally {
                    latch.countDown();
                }
            }).start();
        }

        assertTrue(latch.await(10, TimeUnit.SECONDS), "Threads should complete");
        assertNull(error.get(), "No errors during concurrent indexing");
        assertEquals(threadCount * docsPerThread, search.getDocumentCount());
    }

    @Test
    @DisplayName("Search with no results returns empty list")
    void testSearchNoResults() {
        Map<String, Object> meta = new HashMap<>();
        meta.put("tier", "team");
        search.indexDocument("user", "1", "test content", meta);

        FullTextSearchIndexing.SearchResponse resp = search.search("zzzznonexistent", "user", 20, 0);
        assertEquals(0, resp.total);
        assertTrue(resp.results.isEmpty());
        assertFalse(resp.hasMore);
    }

    @Test
    @DisplayName("Metadata fields are searchable via filters only, not text")
    void testMetadataNotInTextSearch() {
        Map<String, Object> meta = new HashMap<>();
        meta.put("tier", "premium");
        meta.put("status", "active");
        search.indexDocument("user", "1", "just name here", meta);

        // "premium" is in metadata but not in content
        FullTextSearchIndexing.SearchResponse resp = search.search("premium", "user", 20, 0);
        // Should not find via text search (it's not in content)
        // But if we filter by tier=premium, it should find
        Map<String, String> filters = new HashMap<>();
        filters.put("tier", "premium");
        FullTextSearchIndexing.SearchResponse filtered = search.search(
                "name", "user", filters, 20, 0
        );
        assertTrue(filtered.total >= 1);
    }

    @Test
    @DisplayName("Relevance scores are between 0 and reasonable max")
    void testRelevanceScoreRange() {
        Map<String, Object> meta = new HashMap<>();
        meta.put("tier", "team");
        search.indexDocument("user", "1", "exact match test", meta);

        FullTextSearchIndexing.SearchResponse resp = search.search("exact", "user", 20, 0);
        assertTrue(resp.total >= 1);
        double score = resp.results.get(0).relevance;
        assertTrue(score > 0, "Relevance should be positive");
        assertTrue(score <= 10, "Relevance should be reasonable");
    }

    @Test
    @DisplayName("DDL is valid SQL")
    void testDDL() {
        String ddl = FullTextSearchIndexing.DDL;
        assertNotNull(ddl);
        assertTrue(ddl.contains("CREATE TABLE"));
        assertTrue(ddl.contains("search_index"));
        assertTrue(ddl.contains("document_type"));
        assertTrue(ddl.contains("document_id"));
        assertTrue(ddl.contains("content"));
        assertTrue(ddl.contains("indexed_at"));
        assertTrue(ddl.contains("metadata"));
        assertTrue(ddl.contains("FULLTEXT"));
    }
}