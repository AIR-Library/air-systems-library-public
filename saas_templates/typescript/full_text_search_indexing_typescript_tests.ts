/**
 * Full-text search & indexing tests, one jest test per check, run in order against one shared service.
 * Why: this file was a hand-written runner (runTests) that the library's runner counted as 0 framework tests.
 * Converted to jest 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: every check, message and budget is kept
 * (100 ms real-time, 200 ms search over 1,000,000 documents); each numbered block is now its own test.
 * Touches: process memory only.
 */
import { describe, test } from '@jest/globals';
import { FullTextSearchService, tokenize, parseQuery } from './full_text_search_indexing_typescript';

describe("Full-Text Search & Indexing", () => {
  const searchService = new FullTextSearchService();

  test("Test 1: Index user, search finds it", async () => {
    searchService.clear();
    const indexRes = await searchService.indexDocument({
      document_type: 'user',
      document_id: 123,
      content: 'john doe john@example.com team member active',
      metadata: {
        user_id: 123,
        email: 'john@example.com',
        tier: 'team',
        status: 'active',
        created_at: '2026-01-15T00:00:00.000Z'
      }
    });
    if (!indexRes.success || !indexRes.indexed_at) {
      throw new Error("Test 1 Failed: Indexing returned unsuccessful response");
    }

    const searchRes = await searchService.search({ q: 'john', document_type: 'user' });
    if (searchRes.total !== 1 || searchRes.results[0].document_id !== 123) {
      throw new Error(`Test 1 Failed: Expected 1 result with ID 123, got total ${searchRes.total}`);
    }
    console.log("✓ Test 1 Passed: Index user, search finds it");
  });

  test("Test 2: Index deployment, query works", async () => {
    await searchService.indexDocument({
      document_type: 'deployment',
      document_id: 'dep-999',
      content: 'stripe integration production deployment success',
      metadata: {
        tier: 'enterprise',
        status: 'active'
      }
    });

    const searchRes = await searchService.search({ q: 'stripe integration', document_type: 'deployment' });
    if (searchRes.total !== 1 || searchRes.results[0].document_id !== 'dep-999') {
      throw new Error(`Test 2 Failed: Expected deployment dep-999, got total ${searchRes.total}`);
    }
    console.log("✓ Test 2 Passed: Index deployment, query works");
  });

  test("Test 3: Partial match: 'stri' finds 'stripe'", async () => {
    const searchRes = await searchService.search({ q: 'stri' });
    const found = searchRes.results.some(r => r.document_id === 'dep-999');
    if (!found) {
      throw new Error("Test 3 Failed: Partial match 'stri' did not find 'stripe' deployment");
    }
    console.log("✓ Test 3 Passed: Partial match: 'stri' finds 'stripe'");
  });

  test("Test 4: Filters: tier:team returns only team tier", async () => {
    await searchService.indexDocument({
      document_type: 'user',
      document_id: 124,
      content: 'jane doe jane@example.com solo member active',
      metadata: {
        user_id: 124,
        email: 'jane@example.com',
        tier: 'solo',
        status: 'active'
      }
    });

    const searchRes = await searchService.search({ q: 'doe', filters: ['tier:team'] });
    if (searchRes.total !== 1 || searchRes.results[0].document_id !== 123) {
      throw new Error(`Test 4 Failed: Expected only team tier user (123), got total ${searchRes.total}`);
    }
    console.log("✓ Test 4 Passed: Filters: tier:team returns only team tier");
  });

  test("Test 5: Facets: shows count per status", async () => {
    await searchService.indexDocument({
      document_type: 'deployment',
      document_id: 'dep-100',
      content: 'draft deployment',
      metadata: { tier: 'solo', status: 'draft' }
    });
    await searchService.indexDocument({
      document_type: 'deployment',
      document_id: 'dep-101',
      content: 'archived deployment',
      metadata: { tier: 'solo', status: 'archived' }
    });

    const searchRes = await searchService.search({
      q: 'deployment',
      facets: ['status', 'tier']
    });

    const statusFacets = searchRes.facets?.status;
    const tierFacets = searchRes.facets?.tier;

    if (!statusFacets || statusFacets['active'] !== 1 || statusFacets['draft'] !== 1 || statusFacets['archived'] !== 1) {
      throw new Error(`Test 5 Failed: Incorrect status facet counts: ${JSON.stringify(statusFacets)}`);
    }
    if (!tierFacets || tierFacets['solo'] !== 2 || tierFacets['enterprise'] !== 1) {
      throw new Error(`Test 5 Failed: Incorrect tier facet counts: ${JSON.stringify(tierFacets)}`);
    }
    console.log("✓ Test 5 Passed: Facets: shows count per status");
  });

  test("Test 6: Unindex: document no longer found after delete", async () => {
    await searchService.unindexDocument('deployment', 'dep-101');
    const searchRes = await searchService.search({ q: 'archived' });
    if (searchRes.total !== 0) {
      throw new Error("Test 6 Failed: Unindexed document was still found in search");
    }
    console.log("✓ Test 6 Passed: Unindex: document no longer found after delete");
  });

  test("Test 7: Real-time: index updated within 100ms of create", async () => {
    const startTime = Date.now();
    await searchService.indexDocument({
      document_type: 'user',
      document_id: 555,
      content: 'realtime test user',
      metadata: { tier: 'team', status: 'active' }
    });
    const searchRes = await searchService.search({ q: 'realtime' });
    const duration = Date.now() - startTime;

    if (searchRes.total !== 1 || searchRes.results[0].document_id !== 555) {
      throw new Error("Test 7 Failed: Real-time document not found immediately");
    }
    if (duration > 100) {
      throw new Error(`Test 7 Failed: Indexing and searching took too long: ${duration}ms`);
    }
    console.log(`✓ Test 7 Passed: Real-time: index updated within 100ms of create (${duration}ms)`);
  });

  test("Test 8: Performance: 1M documents, search returns <200ms", async () => {
    searchService.clear();
    console.log("Generating 1,000,000 lightweight documents for performance test...");
    
    // We generate 1M documents in memory. To make it extremely fast and memory efficient,
    // we can pre-populate the internal maps directly or run a highly optimized loop.
    const startPopulate = Date.now();
    for (let i = 0; i < 1000000; i++) {
      const docId = `perf-${i}`;
      // We index a few distinct words to keep vocabulary size small and realistic
      const tier = i % 2 === 0 ? 'team' : 'solo';
      const status = i % 3 === 0 ? 'active' : 'draft';
      
      // Call indexDocument directly to test real-world performance
      await searchService.indexDocument({
        document_type: 'user',
        document_id: docId,
        content: `performance test user number ${i} ${tier} ${status}`,
        metadata: { tier, status }
      });
    }
    console.log(`Populated 1,000,000 documents in ${Date.now() - startPopulate}ms`);

    const startSearch = Date.now();
    const searchRes = await searchService.search({
      q: 'performance user tier:team status:active',
      limit: 20
    });
    const searchDuration = Date.now() - startSearch;

    console.log(`Search returned ${searchRes.total} results in ${searchDuration}ms`);
    if (searchDuration > 200) {
      throw new Error(`Test 8 Failed: Search took ${searchDuration}ms, which is > 200ms`);
    }
    if (searchRes.total === 0) {
      throw new Error("Test 8 Failed: Search returned 0 results, expected matches");
    }
    console.log(`✓ Test 8 Passed: Performance: 1M documents, search returns <200ms (${searchDuration}ms)`);
  });

  test("Test 9: Relevance: exact match ranks higher than partial", async () => {
    searchService.clear();
    await searchService.indexDocument({
      document_type: 'deployment',
      document_id: 'dep-exact',
      content: 'stripe',
      metadata: { tier: 'team' }
    });
    await searchService.indexDocument({
      document_type: 'deployment',
      document_id: 'dep-partial',
      content: 'stripe-integration-long-name',
      metadata: { tier: 'team' }
    });

    const searchRes = await searchService.search({ q: 'stripe' });
    if (searchRes.results[0].document_id !== 'dep-exact') {
      throw new Error("Test 9 Failed: Exact match did not rank higher than partial match");
    }
    if (searchRes.results[0].relevance <= searchRes.results[1].relevance) {
      throw new Error("Test 9 Failed: Exact match relevance score should be strictly greater than partial match");
    }
    console.log("✓ Test 9 Passed: Relevance: exact match ranks higher than partial");
  });
});
