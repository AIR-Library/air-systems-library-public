const searchEngine = require('./full_text_search_indexing_javascript');

// Helper to pause
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

describe('Full-Text Search & Indexing', () => {
  // Test 1: Index user, search finds it
  test('Index user, search finds it', () => {
    const userPayload = {
      document_type: 'user',
      document_id: 123,
      content: 'john doe john@example.com team member active',
      metadata: {
        user_id: 123,
        email: 'john@example.com',
        tier: 'team',
        status: 'active',
        created_at: '2026-01-15T12:00:00Z'
      }
    };
    const idxRes = searchEngine.indexDocument(userPayload);
    expect(idxRes.success).toBe(true);
    const searchRes = searchEngine.search({ q: 'john', document_type: 'user' });
    expect(searchRes.total).toBe(1);
    expect(searchRes.results[0].document_id).toBe(123);
    expect(searchRes.results[0].metadata.email).toBe('john@example.com');
  });

  // Test 2: Index deployment, query works
  test('Index deployment, query works', () => {
    const depPayload = {
      document_type: 'deployment',
      document_id: 200,
      content: 'stripe integration for payments',
      metadata: {
        deployment_id: 200,
        tier: 'team',
        status: 'active',
        created_at: '2026-02-01T08:30:00Z'
      }
    };
    const idxRes = searchEngine.indexDocument(depPayload);
    expect(idxRes.success).toBe(true);
    const searchRes = searchEngine.search({ q: 'stripe', document_type: 'deployment' });
    expect(searchRes.total).toBe(1);
    expect(searchRes.results[0].document_id).toBe(200);
  });

  // Test 3: Partial match: "stri" finds "stripe"
  test('Partial match: stri finds stripe', () => {
    const searchRes = searchEngine.search({ q: 'stri', document_type: 'deployment' });
    expect(searchRes.total).toBe(1);
    expect(searchRes.results[0].document_id).toBe(200);
  });

  // Test 4: Filters: tier:team returns only team tier
  test('Filters: tier:team returns only team tier', () => {
    const searchRes = searchEngine.search({
      q: '',
      document_type: 'deployment',
      filters: ['tier:team']
    });
    expect(searchRes.total).toBe(1);
    expect(searchRes.results[0].metadata.tier).toBe('team');
  });

  // Test 5: Facets: shows count per status
  test('Facets: shows count per status', () => {
    // Add another deployment with different status
    const dep2 = {
      document_type: 'deployment',
      document_id: 201,
      content: 'aws integration',
      metadata: {
        deployment_id: 201,
        tier: 'solo',
        status: 'draft',
        created_at: '2026-02-02T09:00:00Z'
      }
    };
    searchEngine.indexDocument(dep2);
    const facetRes = searchEngine.search({
      q: '',
      document_type: 'deployment',
      facets: 'status,tier'
    });
    expect(facetRes.facets.status.active).toBe(1);
    expect(facetRes.facets.status.draft).toBe(1);
    expect(facetRes.facets.tier.team).toBe(1);
    expect(facetRes.facets.tier.solo).toBe(1);
  });

  // Test 6: Unindex: document no longer found after delete
  test('Unindex: document no longer found after delete', () => {
    const delRes = searchEngine.unindexDocument('user', 123);
    expect(delRes.success).toBe(true);
    const searchRes = searchEngine.search({ q: 'john', document_type: 'user' });
    expect(searchRes.total).toBe(0);
  });

  // Test 7: Real-time: index updated within 100ms of create
  test('Real-time: index updated within 100ms of create', () => {
    const start = Date.now();
    const payload = {
      document_type: 'user',
      document_id: 124,
      content: 'alice smith alice@example.com',
      metadata: {
        user_id: 124,
        email: 'alice@example.com',
        tier: 'solo',
        status: 'active',
        created_at: '2026-03-01T10:00:00Z'
      }
    };
    searchEngine.indexDocument(payload);
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(100);
    const searchRes = searchEngine.search({ q: 'alice', document_type: 'user' });
    expect(searchRes.total).toBe(1);
  });

  // Test 8: Reindex all (admin task)
  test('Reindex all (admin task)', async () => {
    const reRes = searchEngine.reindexAll({ document_type: null });
    expect(reRes.success).toBe(true);
    expect(reRes.job_id).toBeDefined();
    // Wait a short moment for async reindex to finish
    await delay(50);
    const searchRes = searchEngine.search({ q: 'stripe', document_type: 'deployment' });
    expect(searchRes.total).toBe(1);
  });

  // Test 9: Relevance: exact match ranks higher than partial
  test('Relevance: exact match ranks higher than partial', () => {
    // Add a document with partial match
    const dep3 = {
      document_type: 'deployment',
      document_id: 202,
      content: 'striped background pattern',
      metadata: {
        deployment_id: 202,
        tier: 'team',
        status: 'active',
        created_at: '2026-02-03T10:00:00Z'
      }
    };
    searchEngine.indexDocument(dep3);
    
    // Search for "stripe" - exact match (deployment 200) should rank higher than partial (deployment 202)
    const searchRes = searchEngine.search({ q: 'stripe', document_type: 'deployment', limit: 10 });
    expect(searchRes.total).toBe(2);
    // First result should be the exact match (document_id 200)
    expect(searchRes.results[0].document_id).toBe(200);
    expect(searchRes.results[0].relevance).toBeGreaterThan(searchRes.results[1].relevance);
  });

  // A row that cannot be parsed fails the reindex without emptying the live index (CodeRabbit, PR 18).
  test('Reindex with a bad row reports reindex_failed and keeps search working', async () => {
    const before = searchEngine.search({ q: 'stripe', document_type: 'deployment' }).total;
    searchEngine.db.prepare(
      `INSERT INTO search_index (document_type, document_id, content, indexed_at, metadata) VALUES (?, ?, ?, ?, ?)`
    ).run('deployment', 999999, 'broken row', new Date().toISOString(), '{not json');
    try {
      const failed = new Promise(resolve => searchEngine.once('reindex_failed', resolve));
      const res = searchEngine.reindexAll({ document_type: null });
      expect(res.success).toBe(true);
      const event = await failed;
      expect(event.job_id).toBe(res.job_id);
      expect(searchEngine.search({ q: 'stripe', document_type: 'deployment' }).total).toBe(before);
    } finally {
      searchEngine.db.prepare(`DELETE FROM search_index WHERE document_type = ? AND document_id = ?`)
        .run('deployment', 999999);
    }
  });
});
