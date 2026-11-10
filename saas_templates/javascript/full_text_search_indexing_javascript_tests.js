const searchEngine = require('./full_text_search_indexing_javascript');

// Helper to pause
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

describe('Full-Text Search & Indexing', () => {
  // Test 1: Index user, search finds it
  // SEARCH-01
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
  // SEARCH-02
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
  // SEARCH-03
  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the amended row adds '"ripe" does not' (prefix of a word only).
  test('Partial match: stri finds stripe; ripe does not', () => {
    const searchRes = searchEngine.search({ q: 'stri', document_type: 'deployment' });
    expect(searchRes.total).toBe(1);
    expect(searchRes.results[0].document_id).toBe(200);
    expect(searchEngine.search({ q: 'ripe', document_type: 'deployment' }).total).toBe(0);
    expect(searchEngine.search({ q: 'STRI', document_type: 'deployment' }).total).toBe(1);
  });

  /**
   * SEARCH-03: words are maximal runs of Unicode letters and digits, lower-cased, with no stop words: "café" is one
   * word (found by "caf" and "CAFÉ", not by "fé"), "@" and "." separate words, and "the" is searchable.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches an engine of its own (memory and an in-memory table).
   */
  // SEARCH-03
  test('Words are Unicode letter/digit runs, lower-cased, no stop words', () => {
    const engine = new searchEngine.SearchEngine();
    engine.indexDocument({ document_type: 'note', document_id: 1, content: 'Café de la Gare, the owner: ana@example.com', metadata: { k: 'v' } });
    expect(engine._tokenize('Café de la Gare, the owner: ana@example.com'))
      .toEqual(['café', 'de', 'la', 'gare', 'the', 'owner', 'ana', 'example', 'com']);
    for (const q of ['café', 'CAFÉ', 'caf', 'the', 'example', 'ana@example', 'gare,']) {
      expect(engine.search({ q }).total).toBe(1);
    }
    for (const q of ['fé', 'afe', 'cafe', 'xample']) {
      expect(engine.search({ q }).total).toBe(0);
    }
  });

  // Test 4: Filters: tier:team returns only team tier
  // SEARCH-04
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
  // SEARCH-05
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
  // SEARCH-06
  test('Unindex: document no longer found after delete', () => {
    const delRes = searchEngine.unindexDocument('user', 123);
    expect(delRes.success).toBe(true);
    const searchRes = searchEngine.search({ q: 'john', document_type: 'user' });
    expect(searchRes.total).toBe(0);
  });

  // Test 7: Real-time: index updated within 100ms of create
  // SEARCH-07
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
  // SEARCH-09
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

  /**
   * SEARCH-09: an exact word outranks a prefix even when the prefix document was indexed first; equal scores keep
   * insertion order (re-indexing a document keeps its place); several terms return only documents matching every
   * term. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec amended). Touches an engine of its own.
   */
  // SEARCH-09
  test('Relevance: exact word above prefix; equal scores keep insertion order; terms are ANDed', () => {
    const engine = new searchEngine.SearchEngine();
    const add = (id, content) => engine.indexDocument({ document_type: 'd', document_id: id, content, metadata: { id } });
    add(1, 'payments striped');
    add(2, 'payments stripe');
    add(3, 'stripe webhooks');
    add(4, 'payments stripe');
    add(1, 'payments striped again'); // re-index keeps document 1 first among equals
    const ids = (q) => engine.search({ q, limit: 10 }).results.map(r => r.document_id);
    expect(ids('stripe')).toEqual([2, 3, 4, 1]);
    const res = engine.search({ q: 'stripe', limit: 10 });
    expect(res.results[0].relevance).toBeGreaterThan(res.results[3].relevance);
    expect(res.results[0].relevance).toBe(res.results[1].relevance);
    expect(ids('payments stripe')).toEqual([2, 4, 1]);
    expect(ids('payments webhooks')).toEqual([]);
    expect(ids('pay')).toEqual([1, 2, 4]);
    expect(engine.search({ q: 'stripe', limit: 2, offset: 2 }).results.map(r => r.document_id)).toEqual([4, 1]);
  });

  /**
   * SEARCH-08: 1,000,000 indexed documents, one search answers in under 200 ms (contract budget, never loosened).
   * Every document holds "stripe", so the search ranks and counts all one million matches.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches an engine of its own (memory and an in-memory table).
   */
  // SEARCH-08
  test('Performance: 1M documents, search returns <200ms', () => {
    const engine = new searchEngine.SearchEngine(':memory:', { clock: () => 1767225600000 });
    const n = 1000000;
    engine.db.exec('BEGIN');
    for (let i = 0; i < n; i++) {
      engine.indexDocument({
        document_type: 'deployment',
        document_id: i,
        content: `document ${i} stripe integration deployment active`,
        metadata: { tier: 'team', status: 'active', seq: i }
      });
    }
    engine.db.exec('COMMIT');
    expect(engine.size).toBe(n);
    for (const q of ['stripe', 'stri', '123456', 'document stripe']) {
      const start = process.hrtime.bigint();
      const res = engine.search({ q, document_type: 'deployment', limit: 20 });
      const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
      expect(res.total).toBeGreaterThan(0);
      expect(elapsedMs).toBeLessThan(200);
    }
    expect(engine.search({ q: 'stripe', document_type: 'deployment', limit: 3 }).results.map(r => r.document_id)).toEqual([0, 1, 2]);
    expect(engine.search({ q: '123456', document_type: 'deployment' }).results[0].document_id).toBe(123456);
  }, 120000);

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
