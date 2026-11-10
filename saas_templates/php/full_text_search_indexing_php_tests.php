<?php
/**
 * Full-Text Search & Indexing tests (TIER 2 spec, system 6: nine required tests, plus six more
 * the library added).
 *
 * Converted 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP, from a self-running script
 * whose checks the runner could not count (0 tests), and which stopped with a fatal error at the
 * performance check because it called the private SearchEngine::$db. Every check of the script
 * is kept, with its message, as an assertion in the test named after its block. Blocks 2-7 ran on
 * the engine the earlier blocks had filled; each test now builds that same state itself
 * (sharedEngine()). The 1M-document check opens its batches with SearchEngine::transaction().
 *
 * Touches: in-memory SQLite databases only. The 1M-document test takes about a minute and
 * several hundred MB of memory.
 */

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use SaaS\Search\SearchController as Controller;
use SaaS\Search\SearchEngine;

require_once __DIR__ . '/full_text_search_indexing_php.php';

final class FullTextSearchIndexingTest extends TestCase
{
    /** A migrated engine on a fresh in-memory SQLite database (the script's make_engine()). */
    private function makeEngine(): SearchEngine
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $engine = new SearchEngine($pdo);
        $engine->migrate();
        return $engine;
    }

    /**
     * The engine the script's blocks 1-7 shared, after the first $steps of its index calls:
     * 1 user 123, 2 deployment 456, 3 deployment 789 (enterprise), 4 deployment 1001 (draft).
     */
    private function sharedEngine(int $steps): SearchEngine
    {
        $engine = $this->makeEngine();
        if ($steps >= 1) {
            $engine->indexDocument(
                'user',
                123,
                'john doe john@example.com team member active',
                ['user_id' => 123, 'email' => 'john@example.com', 'tier' => 'team', 'status' => 'active', 'created_at' => '2026-01-15T00:00:00Z']
            );
        }
        if ($steps >= 2) {
            $engine->indexDocument(
                'deployment',
                456,
                'stripe integration payment gateway production',
                ['deployment_id' => 456, 'tier' => 'team', 'status' => 'active', 'created_at' => '2026-01-16T00:00:00Z']
            );
        }
        if ($steps >= 3) {
            $engine->indexDocument(
                'deployment',
                789,
                'stripe integration payment gateway staging',
                ['deployment_id' => 789, 'tier' => 'enterprise', 'status' => 'active', 'created_at' => '2026-01-17T00:00:00Z']
            );
        }
        if ($steps >= 4) {
            $engine->indexDocument(
                'deployment',
                1001,
                'stripe integration draft',
                ['deployment_id' => 1001, 'tier' => 'team', 'status' => 'draft', 'created_at' => '2026-01-18T00:00:00Z']
            );
        }
        return $engine;
    }

    /** TEST 1: Index user, search finds it */
    // SEARCH-01
    public function testIndexUserSearchFindsIt(): void
    {
        $engine = $this->makeEngine();
        $engine->indexDocument(
            'user',
            123,
            'john doe john@example.com team member active',
            ['user_id' => 123, 'email' => 'john@example.com', 'tier' => 'team', 'status' => 'active', 'created_at' => '2026-01-15T00:00:00Z']
        );
        $res = $engine->search('john', 'user');
        $this->assertSame(1, $res['total'], 'search for "john" returns 1 result');
        $this->assertSame(123, $res['results'][0]['document_id'], 'result document_id is 123');
        $this->assertSame('user', $res['results'][0]['document_type'], 'result document_type is user');
        $this->assertTrue($res['results'][0]['relevance'] > 0, 'relevance is positive');
        $this->assertSame('john@example.com', $res['results'][0]['metadata']['email'], 'metadata email present');
    }

    /** TEST 2: Index deployment, query works */
    // SEARCH-02
    public function testIndexDeploymentQueryWorks(): void
    {
        $engine = $this->sharedEngine(2); // the script ran this block on the engine built by the blocks before it
        $res = $engine->search('stripe', 'deployment');
        $this->assertSame(1, $res['total'], 'search for "stripe" in deployments returns 1');
        $this->assertSame(456, $res['results'][0]['document_id'], 'deployment id 456 found');
    }

    /** TEST 3: Partial match: "stri" finds "stripe" */
    // SEARCH-03
    public function testPartialMatchStriFindsStripe(): void
    {
        $engine = $this->sharedEngine(2); // the script ran this block on the engine built by the blocks before it
        $res = $engine->search('stri', 'deployment');
        $this->assertSame(1, $res['total'], '"stri" finds "stripe" via prefix/partial match');
        $this->assertSame(456, $res['results'][0]['document_id'], 'correct deployment found');
        // Amended SEARCH-03: a term inside a word is not a prefix (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
        $this->assertSame(0, $engine->search('ripe', 'deployment')['total'], '"ripe" does not find "stripe"');
        $this->assertSame(0, $engine->search('tegration', 'deployment')['total'], '"tegration" does not find "integration"');
    }

    /**
     * SEARCH-03 word rules: a word is a maximal run of Unicode letters and digits, lower-cased; "café" is
     * one word; punctuation separates words; a prefix still matches when more than 128 distinct words
     * share it (the old expansion cap dropped documents). Why: amended spec. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: in-memory SQLite.
     */
    // SEARCH-03
    public function testWordsAreUnicodeLetterDigitRuns(): void
    {
        $engine = $this->makeEngine();
        $engine->indexDocument('doc', 1, 'Café-Owner: ÉCOLE42 naïve', []);
        $this->assertSame(1, $engine->search('café', 'doc')['total'], '"café" is one word');
        $this->assertSame(1, $engine->search('CAF', 'doc')['total'], 'queries are lower-cased too');
        $this->assertSame(1, $engine->search('école42', 'doc')['total'], 'letters and digits form one word');
        $this->assertSame(0, $engine->search('42', 'doc')['total'], 'digits inside a word are not a word');
        $this->assertSame(1, $engine->search('owner', 'doc')['total'], 'punctuation separates words');
        $this->assertSame(0, $engine->search('caf owner zzz', 'doc')['total'], 'AND: every term must match');
        for ($i = 0; $i < 200; $i++) {
            $engine->indexDocument('many', $i, sprintf('pre%03dfix', $i), []);
        }
        $this->assertSame(200, $engine->search('pre', 'many', [], [], 100)['total'], 'all 200 words with the prefix match');
    }

    /** TEST 4: Filters: tier:team returns only team tier */
    // SEARCH-04
    public function testFiltersTierTeamReturnsOnlyTeamTier(): void
    {
        $engine = $this->sharedEngine(3); // the script ran this block on the engine built by the blocks before it
        $res = $engine->search('stripe', 'deployment', ['tier' => 'team']);
        $this->assertSame(1, $res['total'], 'filter tier:team returns 1 result');
        $this->assertSame(456, $res['results'][0]['document_id'], 'only team-tier deployment returned');

        $res2 = $engine->search('stripe', 'deployment', ['tier' => 'enterprise']);
        $this->assertSame(1, $res2['total'], 'filter tier:enterprise returns 1 result');
        $this->assertSame(789, $res2['results'][0]['document_id'], 'only enterprise-tier deployment returned');
    }

    /** TEST 5: Facets: shows count per status */
    // SEARCH-05
    public function testFacetsShowCountPerStatus(): void
    {
        $engine = $this->sharedEngine(4); // the script ran this block on the engine built by the blocks before it
        $res = $engine->search('stripe', 'deployment', [], ['status', 'tier']);
        $this->assertTrue(isset($res['facets']), 'facets key present');
        $this->assertTrue(isset($res['facets']['status']), 'status facet present');
        $this->assertTrue(isset($res['facets']['tier']), 'tier facet present');
        // status: active (456, 789), draft (1001)
        $this->assertSame(2, $res['facets']['status']['active'] ?? 0, 'status active count = 2');
        $this->assertSame(1, $res['facets']['status']['draft'] ?? 0, 'status draft count = 1');
        // tier: team (456, 1001), enterprise (789)
        $this->assertSame(2, $res['facets']['tier']['team'] ?? 0, 'tier team count = 2');
        $this->assertSame(1, $res['facets']['tier']['enterprise'] ?? 0, 'tier enterprise count = 1');
    }

    /** TEST 6: Unindex: document no longer found after delete */
    // SEARCH-06
    public function testUnindexDocumentNoLongerFound(): void
    {
        $engine = $this->sharedEngine(4); // the script ran this block on the engine built by the blocks before it
        $engine->unindexDocument('deployment', 456);
        $res = $engine->search('stripe', 'deployment');
        $this->assertSame(2, $res['total'], 'after unindex, 2 deployments remain');
        $ids = array_column($res['results'], 'document_id');
        $this->assertTrue(!in_array(456, $ids, true), 'document 456 no longer in results');
    }

    /** TEST 7: Real-time: index updated within 100ms of create */
    // SEARCH-07
    public function testRealTimeIndexUpdatedWithin100ms(): void
    {
        $engine = $this->sharedEngine(4); // the script ran this block on the engine built by the blocks before it
        $start = microtime(true);
        $engine->indexDocument(
            'user',
            200,
            'realtime test user realtime@example.com',
            ['user_id' => 200, 'tier' => 'solo', 'status' => 'active', 'created_at' => '2026-01-19T00:00:00Z']
        );
        $res = $engine->search('realtime', 'user');
        $elapsed = (microtime(true) - $start) * 1000; // ms
        $this->assertSame(1, $res['total'], 'document immediately searchable after index');
        $this->assertLessThanOrEqual(100.0, $elapsed, "index+search completed in {$elapsed}ms (< 100ms)");
    }

    /** TEST 8: Performance: 1M documents, search returns < 200ms */
    // SEARCH-08
    public function testPerformanceOneMillionDocumentsSearchUnder200ms(): void
    {
        $perfEngine = $this->makeEngine();
        $batchSize = 10000;
        $totalDocs = 1000000;
        $batchStart = microtime(true);
        for ($i = 0; $i < $totalDocs; $i += $batchSize) {
            // Was $perfEngine->db->beginTransaction()/commit(): $db is private (the fatal error
            // that stopped the script); SearchEngine::transaction() is the public equivalent.
            $perfEngine->transaction(function (SearchEngine $perfEngine) use ($i, $batchSize, $totalDocs): void {
                for ($j = 0; $j < $batchSize && ($i + $j) < $totalDocs; $j++) {
                    $id = $i + $j;
                    $perfEngine->indexDocument(
                        'user',
                        $id,
                        "user{$id} performance test document content",
                        ['user_id' => $id, 'tier' => 'team', 'status' => 'active', 'created_at' => '2026-01-20T00:00:00Z']
                    );
                }
            });
        }
        $indexTime = (microtime(true) - $batchStart) * 1000;
        fwrite(STDERR, "  (indexed {$totalDocs} docs in " . round($indexTime) . "ms)\n");

        $searchStart = microtime(true);
        $perfRes = $perfEngine->search('performance', 'user', [], [], 20, 0);
        $searchTime = (microtime(true) - $searchStart) * 1000;
        fwrite(STDERR, "  (search returned in " . round($searchTime, 2) . "ms, total={$perfRes['total']})\n");
        $this->assertLessThanOrEqual(200.0, $searchTime, "search over 1M docs in {$searchTime}ms (< 200ms)");
        $this->assertTrue($perfRes['total'] > 0, 'performance search found results');
        $this->assertSame($totalDocs, $perfRes['total'], 'every document contains "performance"');
        $this->assertSame([0, 1, 2], array_slice(array_column($perfRes['results'], 'document_id'), 0, 3), 'ties keep insertion order');
    }

    /** TEST 9: Relevance: exact match ranks higher than partial */
    // SEARCH-09
    public function testRelevanceExactMatchRanksHigherThanPartial(): void
    {
        $relEngine = $this->makeEngine();
        $relEngine->indexDocument('user', 1, 'exact match document', ['tier' => 'team', 'status' => 'active']);
        $relEngine->indexDocument('user', 2, 'exactness is a quality', ['tier' => 'team', 'status' => 'active']);
        $res = $relEngine->search('exact', 'user');
        $this->assertSame(2, $res['total'], 'both docs match "exact"');
        $this->assertSame(1, $res['results'][0]['document_id'], 'exact match (doc 1) ranks first');
        $this->assertSame(2, $res['results'][1]['document_id'], 'partial match (doc 2) ranks second');
        $this->assertTrue(
            $res['results'][0]['relevance'] > $res['results'][1]['relevance'],
            'exact match relevance > partial match relevance'
        );
        // Amended SEARCH-09: the exact word wins even when the prefix document was indexed first, and
        // equal scores keep insertion order (not id order) (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
        $e2 = $this->makeEngine();
        $e2->indexDocument('user', 50, 'exactly prefix first', []);
        $e2->indexDocument('user', 40, 'exact second', []);
        $e2->indexDocument('user', 30, 'exact third', []);
        $e2->indexDocument('user', 20, 'exactness prefix fourth', []);
        $order = array_column($e2->search('exact', 'user')['results'], 'document_id');
        $this->assertSame([40, 30, 50, 20], $order, 'exact words first, then prefixes, each in insertion order');
        $order = array_column($e2->search('exact', 'user', [], ['status'])['results'], 'document_id');
        $this->assertSame([40, 30, 50, 20], $order, 'same order on the general path (facets requested)');
    }

    /** TEST 10: Multi-word query (AND semantics) */
    public function testMultiWordQueryUsesAndSemantics(): void
    {
        $mwEngine = $this->makeEngine();
        $mwEngine->indexDocument('deployment', 10, 'stripe integration payment', ['tier' => 'team', 'status' => 'active']);
        $mwEngine->indexDocument('deployment', 11, 'stripe only', ['tier' => 'team', 'status' => 'active']);
        $mwEngine->indexDocument('deployment', 12, 'integration only', ['tier' => 'team', 'status' => 'active']);
        $res = $mwEngine->search('stripe integration', 'deployment');
        $this->assertSame(1, $res['total'], 'multi-word "stripe integration" matches only doc 10');
        $this->assertSame(10, $res['results'][0]['document_id'], 'correct doc for multi-word query');
    }

    /** TEST 11: Controller endpoint shapes */
    public function testControllerEndpointResponseShapes(): void
    {
        $ctrlEngine = $this->makeEngine();
        $ctrl = new Controller($ctrlEngine);

        // POST /search/index
        $idxRes = $ctrl->handleIndex([
            'document_type' => 'user',
            'document_id' => 500,
            'content' => 'controller test user',
            'metadata' => ['user_id' => 500, 'tier' => 'solo', 'status' => 'active'],
        ]);
        $this->assertTrue($idxRes['success'] === true, 'index response has success=true');
        $this->assertTrue(isset($idxRes['indexed_at']), 'index response has indexed_at');

        // GET /search
        $searchRes = $ctrl->handleSearch(['q' => 'controller', 'document_type' => 'user', 'limit' => 20, 'offset' => 0]);
        $this->assertTrue(isset($searchRes['results']), 'search response has results');
        $this->assertTrue(isset($searchRes['total']), 'search response has total');
        $this->assertTrue(isset($searchRes['has_more']), 'search response has has_more');
        $this->assertSame(1, $searchRes['total'], 'controller search finds 1 result');

        // GET /search with filters
        $ctrlEngine->indexDocument('user', 501, 'controller test user two', ['user_id' => 501, 'tier' => 'team', 'status' => 'active']);
        $ctrlEngine->indexDocument('user', 502, 'controller test user three', ['user_id' => 502, 'tier' => 'enterprise', 'status' => 'active']);
        $filteredRes = $ctrl->handleSearch(['q' => 'controller', 'document_type' => 'user', 'filters' => ['tier:team']]);
        $this->assertSame(1, $filteredRes['total'], 'controller filter tier:team returns 1');
        $this->assertSame(501, $filteredRes['results'][0]['document_id'], 'correct doc for filtered search');

        // GET /search with facets
        $facetRes = $ctrl->handleSearch(['q' => 'controller', 'document_type' => 'user', 'facets' => 'tier,status']);
        $this->assertTrue(isset($facetRes['facets']), 'controller facets present');
        $this->assertTrue(isset($facetRes['facets']['tier']), 'tier facet present');
        $this->assertTrue(isset($facetRes['facets']['status']), 'status facet present');

        // DELETE /search/documents/:type/:id
        $delRes = $ctrl->handleUnindex('user', 500);
        $this->assertTrue($delRes['success'] === true, 'unindex response has success=true');
        $afterDel = $ctrl->handleSearch(['q' => 'controller', 'document_type' => 'user']);
        $this->assertSame(2, $afterDel['total'], 'after unindex, 2 users remain');

        // POST /admin/search/reindex
        $reindexRes = $ctrl->handleReindex(['document_type' => 'user']);
        $this->assertTrue($reindexRes['success'] === true, 'reindex response has success=true');
        $this->assertTrue(isset($reindexRes['job_id']), 'reindex response has job_id');
        $this->assertSame('enqueued', $reindexRes['status'], 'reindex status is enqueued');

        // Reindex with null type
        $reindexAll = $ctrl->handleReindex([]);
        $this->assertTrue($reindexAll['success'] === true, 'reindex all types success');
        $this->assertSame('enqueued', $reindexAll['status'], 'reindex all status enqueued');
    }

    /** TEST 12: Empty query returns all filtered docs */
    public function testEmptyQueryReturnsAllFilteredDocs(): void
    {
        $eqEngine = $this->makeEngine();
        $eqEngine->indexDocument('user', 1, 'alpha', ['tier' => 'team', 'status' => 'active']);
        $eqEngine->indexDocument('user', 2, 'beta', ['tier' => 'team', 'status' => 'draft']);
        $eqEngine->indexDocument('user', 3, 'gamma', ['tier' => 'solo', 'status' => 'active']);
        $res = $eqEngine->search('', 'user');
        $this->assertSame(3, $res['total'], 'empty query returns all 3 users');
        $res = $eqEngine->search('', 'user', ['status' => 'active']);
        $this->assertSame(2, $res['total'], 'empty query with filter returns 2');
    }

    /** TEST 13: Pagination */
    public function testPagination(): void
    {
        $pgEngine = $this->makeEngine();
        for ($i = 1; $i <= 25; $i++) {
            $pgEngine->indexDocument('user', $i, "pagination test user {$i}", ['tier' => 'team', 'status' => 'active']);
        }
        $res = $pgEngine->search('pagination', 'user', [], [], 10, 0);
        $this->assertSame(25, $res['total'], 'total is 25');
        $this->assertSame(10, count($res['results']), 'first page has 10 results');
        $this->assertTrue($res['has_more'] === true, 'has_more is true for first page');

        $res2 = $pgEngine->search('pagination', 'user', [], [], 10, 20);
        $this->assertSame(5, count($res2['results']), 'last page has 5 results');
        $this->assertTrue($res2['has_more'] === false, 'has_more is false for last page');
    }

    /**
     * TEST 14: there are no stop words.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: it asserted that "the" found nothing (stop words removed); the amended
     * spec has no stop words, so "the" is an ordinary word.
     */
    public function testStopWordsAreRemoved(): void
    {
        $swEngine = $this->makeEngine();
        $swEngine->indexDocument('user', 1, 'the quick brown fox', ['tier' => 'team', 'status' => 'active']);
        $res = $swEngine->search('the', 'user');
        $this->assertSame(1, $res['total'], '"the" is an ordinary word (no stop words)');
        $res = $swEngine->search('quick', 'user');
        $this->assertSame(1, $res['total'], 'non-stop word "quick" returns 1 result');
    }

    /** TEST 15: Upsert (re-index same document) */
    public function testUpsertReindexSameDocument(): void
    {
        $upEngine = $this->makeEngine();
        $upEngine->indexDocument('user', 1, 'original content', ['tier' => 'team', 'status' => 'active']);
        $upEngine->indexDocument('user', 1, 'updated content', ['tier' => 'team', 'status' => 'draft']);
        $res = $upEngine->search('updated', 'user');
        $this->assertSame(1, $res['total'], 'updated content is searchable');
        $this->assertSame('draft', $res['results'][0]['metadata']['status'], 'metadata updated to draft');
        $res2 = $upEngine->search('original', 'user');
        $this->assertSame(0, $res2['total'], 'original content no longer searchable');
    }
}
