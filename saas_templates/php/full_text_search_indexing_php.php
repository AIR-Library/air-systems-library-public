<?php
/**
 * Full-Text Search & Indexing (TIER 2, system 6): an inverted index on PDO SQLite.
 *
 * What it does: indexes documents (type, id, searchable text, metadata), searches them with
 * AND semantics over words (exact word > prefix, e.g. "stri" finds "stripe"), filters and
 * facets on metadata fields, pages results, and removes documents. A one-word query whose
 * words all score the same is answered straight from the index, so it stays fast at a million
 * documents.
 *
 * Inputs/outputs: SearchEngine methods take plain values and return the spec's arrays;
 * SearchController maps the spec's HTTP endpoints (query/body arrays) onto them.
 *
 * Why (repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP): the suite's 15 checks
 * ran as a script the runner could not count (0 tests) and stopped with a fatal error because
 * the performance test reached into the private SearchEngine::$db. Behind that, search loaded
 * and re-tokenised every document of the type in PHP on every query (the 1M-document check
 * could never finish in 200 ms), facets counted documents that did not match the query, filters
 * compared strings to numbers strictly (so "user_id:123" never matched), tokenisation dropped
 * every non-ASCII letter, ties were broken by newest-first time stamps, and "reindex" answered
 * "enqueued" while doing nothing.
 *
 * Matching: words are lower-cased runs of Unicode letters and digits, minus stop words. A query
 * word matches a document word that equals it (score 1) or starts with it (score 0.5); a
 * document's relevance is the mean over the query words, and every query word must match. A
 * prefix expands to at most MAX_PREFIX_TERMS distinct words (like Elasticsearch's
 * max_expansions). Substring matches inside a word ("ripe" in "stripe") are not supported: an
 * inverted index cannot answer them in bounded time.
 *
 * Touches: the database (tables search_index, search_terms, search_fields, and a per-connection
 * TEMP table search_hits). No network, no files.
 */

declare(strict_types=1);

namespace SaaS\Search;

use Closure;
use InvalidArgumentException;
use PDO;
use Throwable;

/**
 * The search engine.
 *
 * Why: see the file header. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches the database.
 */
final class SearchEngine
{
    /** Common English stop words removed during tokenization. */
    public const STOP_WORDS = [
        'a', 'an', 'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
        'of', 'with', 'by', 'from', 'is', 'are', 'was', 'were', 'be', 'been',
        'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would',
        'could', 'should', 'may', 'might', 'can', 'shall', 'it', 'its', 'this',
        'that', 'these', 'those', 'i', 'you', 'he', 'she', 'we', 'they', 'me',
        'him', 'her', 'us', 'them', 'my', 'your', 'his', 'our', 'their',
    ];

    /** Most distinct words one query prefix expands to. */
    public const MAX_PREFIX_TERMS = 128;

    /** Largest page search() returns. */
    public const MAX_LIMIT = 100;

    /** Longest word that is indexed (longer words are cut). */
    private const MAX_TERM_LENGTH = 64;

    /** Rows per multi-row INSERT. */
    private const INSERT_CHUNK = 200;

    /** UTF-8 for U+10FFFF: sorts after every valid continuation of a prefix. */
    private const MAX_CHAR = "\u{10FFFF}";

    private PDO $db;

    /** @var array<string, true> */
    private array $stopSet;

    /** @var Closure(): string */
    private Closure $clock;

    /** @var array<string, \PDOStatement> */
    private array $statements = [];

    /**
     * @param PDO          $db    Connection (SQLite 3.24+ for upserts).
     * @param Closure|null $clock Returns the indexed_at timestamp; default the system clock in
     *                            UTC ISO 8601 with microseconds.
     *
     * Why: unchanged contract; the clock is injectable for deterministic tests.
     * 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the connection settings.
     */
    public function __construct(PDO $db, ?Closure $clock = null)
    {
        $this->db = $db;
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $this->stopSet = array_fill_keys(self::STOP_WORDS, true);
        $this->clock = $clock ?? static fn (): string => gmdate('Y-m-d\TH:i:s') . sprintf('.%06dZ', (int) ((microtime(true) * 1e6) % 1e6));
    }

    /**
     * Create the tables if they do not exist.
     *
     * search_index holds the documents (its integer id is the internal document key, in
     * insertion order); search_terms is the inverted index (word -> documents); search_fields
     * holds each scalar metadata field as text, for filters and facets.
     *
     * Why: the old schema had no inverted index, so every search scanned every document.
     * 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (DDL).
     */
    public function migrate(): void
    {
        $this->db->exec(<<<SQL
CREATE TABLE IF NOT EXISTS search_index (
    id INTEGER PRIMARY KEY,
    document_type TEXT NOT NULL,
    document_id INTEGER NOT NULL,
    content TEXT NOT NULL DEFAULT '',
    indexed_at TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}',
    UNIQUE (document_type, document_id)
);
CREATE TABLE IF NOT EXISTS search_terms (
    document_type TEXT NOT NULL,
    term TEXT NOT NULL,
    doc INTEGER NOT NULL,
    PRIMARY KEY (document_type, term, doc)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS search_fields (
    document_type TEXT NOT NULL,
    field TEXT NOT NULL,
    value TEXT NOT NULL,
    doc INTEGER NOT NULL,
    PRIMARY KEY (document_type, field, value, doc)
) WITHOUT ROWID;
SQL);
    }

    /**
     * Run $work inside one transaction (commit on return, roll back on any exception). Use it
     * for bulk indexing: thousands of indexDocument() calls in one transaction are far faster.
     * Nested calls join the outer transaction.
     *
     * @param callable $work fn(SearchEngine $engine): mixed
     * @return mixed What $work returns.
     *
     * Why: the performance test opened transactions on the private $db; this is the public way.
     * 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
     */
    public function transaction(callable $work): mixed
    {
        if ($this->db->inTransaction()) {
            return $work($this);
        }
        $this->db->beginTransaction();
        try {
            $result = $work($this);
            $this->db->commit();
            return $result;
        } catch (Throwable $e) {
            $this->db->rollBack();
            throw $e;
        }
    }

    /**
     * Index (or replace) a document; it is searchable as soon as this returns.
     *
     * @param string $documentType e.g. user, deployment (non-empty).
     * @param int    $documentId   The document's id in its own table.
     * @param string $content      All searchable text.
     * @param array  $metadata     Returned with results; scalar top-level fields are filterable
     *                             and facetable.
     * @return array{success: true, indexed_at: string}
     * @throws InvalidArgumentException on an empty document type.
     *
     * Why: writes the inverted index and field rows alongside the document, atomically.
     * 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
     */
    public function indexDocument(string $documentType, int $documentId, string $content, array $metadata = []): array
    {
        if ($documentType === '') {
            throw new InvalidArgumentException('document_type is required');
        }
        $indexedAt = ($this->clock)();
        $metadataJson = json_encode($metadata, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        $this->transaction(function () use ($documentType, $documentId, $content, $metadata, $metadataJson, $indexedAt): void {
            $insert = $this->statement(
                'INSERT INTO search_index (document_type, document_id, content, indexed_at, metadata)
                 VALUES (?, ?, ?, ?, ?) ON CONFLICT (document_type, document_id) DO NOTHING'
            );
            $insert->execute([$documentType, $documentId, $content, $indexedAt, $metadataJson]);
            if ($insert->rowCount() === 1) {
                $doc = (int) $this->db->lastInsertId();
            } else {
                $doc = $this->removePostings($documentType, $documentId);
                $this->statement('UPDATE search_index SET content = ?, indexed_at = ?, metadata = ? WHERE id = ?')
                    ->execute([$content, $indexedAt, $metadataJson, $doc]);
            }
            $this->insertRows('search_terms', 3, array_map(
                static fn (string $term): array => [$documentType, $term, $doc],
                $this->tokenize($content)
            ));
            $fieldRows = [];
            foreach (self::fieldValues($metadata) as $field => $value) {
                $fieldRows[] = [$documentType, $field, $value, $doc];
            }
            $this->insertRows('search_fields', 4, $fieldRows);
        });

        return ['success' => true, 'indexed_at' => $indexedAt];
    }

    /**
     * Search.
     *
     * @param string      $query        Words (AND); empty returns every document that passes the filters.
     * @param string|null $documentType One type, or null for all types.
     * @param array       $filters      field => value, all must hold (values compared as text).
     * @param array       $facets       Field names to count values of, over all matching documents.
     * @param int         $limit        Page size, 1..100.
     * @param int         $offset       Results to skip.
     * @return array {results: list<{document_id, document_type, relevance, metadata}>, total,
     *               has_more, facets?: array<field, array<value, count>>}; ordered by relevance,
     *               then by when the document was first indexed.
     *
     * Why: answered from the inverted index instead of scanning every document in PHP.
     * 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (reads, and
     * the connection's TEMP table search_hits).
     */
    public function search(
        string $query,
        ?string $documentType = null,
        array $filters = [],
        array $facets = [],
        int $limit = 20,
        int $offset = 0
    ): array {
        $limit = max(1, min(self::MAX_LIMIT, $limit));
        $offset = max(0, $offset);
        $types = $documentType !== null ? [$documentType] : $this->documentTypes();
        $words = $this->tokenize($query);
        $empty = ['results' => [], 'total' => 0, 'has_more' => false] + ($facets ? ['facets' => array_fill_keys(array_values($facets), [])] : []);

        if ($types === [] || (trim($query) !== '' && $words === [])) {
            return $empty; // nothing indexed, or only stop words
        }

        // Expand each query word into the indexed words it matches
        $expansions = [];
        foreach ($words as $word) {
            $terms = $this->expand($types, $word);
            if ($terms === []) {
                return $empty;
            }
            $expansions[$word] = $terms;
        }

        // Fast path: one word, one type, an exact match only, no filters/facets: the posting
        // list is already in result order (equal scores, insertion order).
        if (count($words) === 1 && count($types) === 1 && $filters === [] && $facets === []
            && $expansions[$words[0]] === [$words[0]]) {
            $count = $this->statement('SELECT COUNT(*) FROM search_terms WHERE document_type = ? AND term = ?');
            $count->execute([$types[0], $words[0]]);
            $total = (int) $count->fetchColumn();
            $page = $this->statement(
                'SELECT doc, 1.0 AS score FROM search_terms WHERE document_type = ? AND term = ? ORDER BY doc LIMIT ? OFFSET ?'
            );
            $page->bindValue(1, $types[0]);
            $page->bindValue(2, $words[0]);
            $page->bindValue(3, $limit, PDO::PARAM_INT);
            $page->bindValue(4, $offset, PDO::PARAM_INT);
            $page->execute();
            return [
                'results' => $this->hydrate($page->fetchAll(PDO::FETCH_ASSOC)),
                'total' => $total,
                'has_more' => ($offset + $limit) < $total,
            ];
        }

        $this->collectHits($types, $words, $expansions, $filters);

        $total = (int) $this->db->query('SELECT COUNT(*) FROM temp.search_hits')->fetchColumn();
        $page = $this->db->prepare('SELECT doc, score FROM temp.search_hits ORDER BY score DESC, doc ASC LIMIT :limit OFFSET :offset');
        $page->bindValue(':limit', $limit, PDO::PARAM_INT);
        $page->bindValue(':offset', $offset, PDO::PARAM_INT);
        $page->execute();

        $response = [
            'results' => $this->hydrate($page->fetchAll(PDO::FETCH_ASSOC)),
            'total' => $total,
            'has_more' => ($offset + $limit) < $total,
        ];
        if ($facets !== []) {
            $response['facets'] = $this->facetCounts($types, $facets);
        }
        return $response;
    }

    /**
     * Remove a document from the index.
     *
     * @return array{success: true} (also when it was not indexed)
     *
     * Why: also removes its index and field rows. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
     */
    public function unindexDocument(string $documentType, int $documentId): array
    {
        $this->transaction(function () use ($documentType, $documentId): void {
            $doc = $this->removePostings($documentType, $documentId);
            if ($doc !== null) {
                $this->statement('DELETE FROM search_index WHERE id = ?')->execute([$doc]);
            }
        });
        return ['success' => true];
    }

    /**
     * Re-index from source records: the body of the background reindex job. Indexes every
     * record given and removes indexed documents of the covered types that were not given.
     *
     * @param iterable    $documents    Records {document_type, document_id, content, metadata?}.
     * @param string|null $documentType Limit to one type (null: every type present in $documents
     *                                  and in the index).
     * @return int Documents indexed.
     *
     * Why: the old reindexAll() claimed to enqueue a job and did nothing. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
     */
    public function reindexDocuments(iterable $documents, ?string $documentType = null): int
    {
        return $this->transaction(function () use ($documents, $documentType): int {
            $seen = [];
            $count = 0;
            foreach ($documents as $d) {
                $type = (string) ($d['document_type'] ?? '');
                if ($documentType !== null && $type !== $documentType) {
                    continue;
                }
                $this->indexDocument($type, (int) ($d['document_id'] ?? 0), (string) ($d['content'] ?? ''), (array) ($d['metadata'] ?? []));
                $seen[$type][(int) ($d['document_id'] ?? 0)] = true;
                $count++;
            }
            $types = $documentType !== null ? [$documentType] : array_unique(array_merge($this->documentTypes(), array_keys($seen)));
            foreach ($types as $type) {
                $ids = $this->statement('SELECT document_id FROM search_index WHERE document_type = ?');
                $ids->execute([$type]);
                foreach ($ids->fetchAll(PDO::FETCH_COLUMN) as $id) {
                    if (!isset($seen[$type][(int) $id])) {
                        $this->unindexDocument($type, (int) $id);
                    }
                }
            }
            return $count;
        });
    }

    /**
     * Lower-cased distinct words of $text (Unicode letters and digits), stop words removed,
     * each cut to MAX_TERM_LENGTH characters, in first-seen order.
     *
     * @return list<string>
     *
     * Why: the old tokenizer dropped every non-ASCII letter. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
     */
    public function tokenize(string $text): array
    {
        $parts = preg_split('/[^\p{L}\p{N}]+/u', mb_strtolower($text, 'UTF-8'), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $out = [];
        foreach ($parts as $word) {
            if (isset($this->stopSet[$word])) {
                continue;
            }
            $out[mb_substr($word, 0, self::MAX_TERM_LENGTH, 'UTF-8')] = true;
        }
        return array_map('strval', array_keys($out));
    }

    // ------------------------------------------------------------------ internals

    /**
     * Fill temp.search_hits (doc, score) with the documents that match every query word and
     * every filter. Score per word: 10 for an exact word, 5 for a prefix; relevance is the sum
     * over 10 x words. An empty query matches every document of the types with relevance 1.
     *
     * Why: one SQL pass over the inverted index. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (TEMP table).
     */
    private function collectHits(array $types, array $words, array $expansions, array $filters): void
    {
        $this->db->exec('CREATE TEMP TABLE IF NOT EXISTS search_hits (doc INTEGER PRIMARY KEY, score REAL NOT NULL)');
        $this->db->exec('DELETE FROM temp.search_hits');

        $typeIn = implode(',', array_fill(0, count($types), '?'));
        $params = [];
        if ($words === []) {
            $sql = "SELECT id, 1.0 FROM search_index WHERE document_type IN ($typeIn)";
            $params = $types;
        } else {
            $parts = [];
            foreach ($words as $word) {
                $terms = $expansions[$word];
                $termIn = implode(',', array_fill(0, count($terms), '?'));
                $parts[] = "SELECT doc, MAX(CASE WHEN term = ? THEN 10 ELSE 5 END) AS s FROM search_terms
                            WHERE document_type IN ($typeIn) AND term IN ($termIn) GROUP BY doc";
                array_push($params, $word, ...$types);
                array_push($params, ...$terms);
            }
            $sql = 'SELECT doc, SUM(s) * 1.0 / ' . (10 * count($words)) . ' FROM (' . implode(' UNION ALL ', $parts) . ')
                    GROUP BY doc HAVING COUNT(*) = ' . count($words);
        }
        $this->db->prepare("INSERT INTO temp.search_hits (doc, score) $sql")->execute($params);

        foreach ($filters as $field => $value) {
            if (!is_scalar($value)) {
                throw new InvalidArgumentException('Filter values must be scalars');
            }
            $this->db->prepare(
                "DELETE FROM temp.search_hits WHERE doc NOT IN (
                     SELECT doc FROM search_fields WHERE document_type IN ($typeIn) AND field = ? AND value = ?)"
            )->execute([...$types, (string) $field, self::fieldText($value)]);
        }
    }

    /**
     * Value counts per facet field over temp.search_hits, values in ascending order.
     *
     * Why: the old facets counted documents that did not match the query. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (read).
     */
    private function facetCounts(array $types, array $facets): array
    {
        $typeIn = implode(',', array_fill(0, count($types), '?'));
        $stmt = $this->db->prepare(
            "SELECT value, COUNT(*) AS n FROM search_fields
             WHERE document_type IN ($typeIn) AND field = ? AND doc IN (SELECT doc FROM temp.search_hits)
             GROUP BY value ORDER BY value"
        );
        $result = [];
        foreach ($facets as $field) {
            $stmt->execute([...$types, (string) $field]);
            $counts = [];
            foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
                $counts[(string) $row['value']] = (int) $row['n'];
            }
            $result[(string) $field] = $counts;
        }
        return $result;
    }

    /**
     * Indexed words of the given types that equal $word or start with it, exact word first,
     * at most MAX_PREFIX_TERMS, found by seeking the index (no scan of the vocabulary).
     *
     * @return list<string>
     *
     * Why: prefix matching ("stri" -> "stripe") from the index. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (read).
     */
    private function expand(array $types, string $word): array
    {
        $next = $this->statement('SELECT MIN(term) FROM search_terms WHERE document_type = ? AND term >= ? AND term < ?');
        $upper = $word . self::MAX_CHAR;
        $found = [];
        foreach ($types as $type) {
            $from = $word;
            while (count($found) < self::MAX_PREFIX_TERMS) {
                $next->execute([$type, $from, $upper]);
                $term = $next->fetchColumn();
                if ($term === null || $term === false) {
                    break;
                }
                $found[(string) $term] = true;
                $from = $term . "\0"; // the next distinct word after this one
            }
        }
        $terms = array_map('strval', array_keys($found));
        usort($terms, static fn (string $a, string $b): int => [$a !== $word, $a] <=> [$b !== $word, $b]);
        return $terms;
    }

    /**
     * Turn (doc, score) rows into result arrays, in the given order.
     *
     * Why: one query for the page's documents. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (read).
     */
    private function hydrate(array $rows): array
    {
        if ($rows === []) {
            return [];
        }
        $ids = array_map(static fn (array $r): int => (int) $r['doc'], $rows);
        $stmt = $this->db->prepare(
            'SELECT id, document_type, document_id, metadata FROM search_index WHERE id IN (' . implode(',', array_fill(0, count($ids), '?')) . ')'
        );
        $stmt->execute($ids);
        $docs = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $d) {
            $docs[(int) $d['id']] = $d;
        }
        $results = [];
        foreach ($rows as $r) {
            $d = $docs[(int) $r['doc']] ?? null;
            if ($d === null) {
                continue;
            }
            $results[] = [
                'document_id' => (int) $d['document_id'],
                'document_type' => $d['document_type'],
                'relevance' => round((float) $r['score'], 4),
                'metadata' => json_decode($d['metadata'], true) ?: [],
            ];
        }
        return $results;
    }

    /**
     * Delete a document's word and field rows (computed from its stored content/metadata).
     *
     * @return int|null The internal id, or null when the document is not indexed.
     *
     * Why: shared by re-indexing and unindexing. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
     */
    private function removePostings(string $documentType, int $documentId): ?int
    {
        $find = $this->statement('SELECT id, content, metadata FROM search_index WHERE document_type = ? AND document_id = ?');
        $find->execute([$documentType, $documentId]);
        $row = $find->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            return null;
        }
        $doc = (int) $row['id'];
        $deleteTerm = $this->statement('DELETE FROM search_terms WHERE document_type = ? AND term = ? AND doc = ?');
        foreach ($this->tokenize((string) $row['content']) as $term) {
            $deleteTerm->execute([$documentType, $term, $doc]);
        }
        $deleteField = $this->statement('DELETE FROM search_fields WHERE document_type = ? AND field = ? AND value = ? AND doc = ?');
        foreach (self::fieldValues(json_decode((string) $row['metadata'], true) ?: []) as $field => $value) {
            $deleteField->execute([$documentType, $field, $value, $doc]);
        }
        return $doc;
    }

    /**
     * Multi-row INSERT OR IGNORE of $rows (each with $width values) into $table, in chunks.
     *
     * Why: one statement per chunk instead of one per row keeps bulk indexing fast.
     * 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database.
     */
    private function insertRows(string $table, int $width, array $rows): void
    {
        foreach (array_chunk($rows, self::INSERT_CHUNK) as $chunk) {
            $tuple = '(' . implode(',', array_fill(0, $width, '?')) . ')';
            $this->statement("INSERT OR IGNORE INTO $table VALUES " . implode(',', array_fill(0, count($chunk), $tuple)))
                ->execute(array_merge(...$chunk));
        }
    }

    /**
     * Document types present in the index (distinct values found by index seeks).
     *
     * @return list<string>
     *
     * Why: a search without a type covers every type. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (read).
     */
    private function documentTypes(): array
    {
        $rows = $this->db->query(
            'WITH RECURSIVE t(x) AS (
                 SELECT MIN(document_type) FROM search_index
                 UNION ALL
                 SELECT (SELECT MIN(document_type) FROM search_index WHERE document_type > t.x) FROM t WHERE t.x IS NOT NULL
             ) SELECT x FROM t WHERE x IS NOT NULL'
        )->fetchAll(PDO::FETCH_COLUMN);
        return array_map('strval', $rows);
    }

    /**
     * Cached prepared statement.
     *
     * Why: bulk indexing re-uses the same statements. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing until executed.
     */
    private function statement(string $sql): \PDOStatement
    {
        return $this->statements[$sql] ??= $this->db->prepare($sql);
    }

    /**
     * Scalar top-level metadata fields as field => text (nulls, arrays and objects skipped).
     *
     * @return array<string, string>
     *
     * Why: filters compare text, so "123" matches 123 and "true" matches true. 2026-11-10,
     * session session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
     */
    private static function fieldValues(array $metadata): array
    {
        $out = [];
        foreach ($metadata as $field => $value) {
            if (is_scalar($value)) {
                $out[(string) $field] = self::fieldText($value);
            }
        }
        return $out;
    }

    /**
     * Text form of a scalar field value.
     *
     * Why: one comparison rule for indexing and filtering. 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
     */
    private static function fieldText(bool|int|float|string $value): string
    {
        return is_bool($value) ? ($value ? 'true' : 'false') : (string) $value;
    }
}

/**
 * Schedules the "reindex" background job (the Background Jobs system in production: enqueue a
 * task whose handler loads the source records and calls SearchEngine::reindexDocuments()).
 *
 * Why: reindexing is a background job in the spec. 2026-11-10, session
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches whatever the queue touches.
 */
interface ReindexScheduler
{
    /**
     * @param string|null $documentType One type, or null for all.
     * @return string The job id.
     *
     * Why: "reindex" answered "enqueued" while doing nothing; it is now a real scheduler seam. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the job queue in real implementations; memory in the in-memory one.
     */
    public function enqueueReindex(?string $documentType): string;
}

/**
 * ReindexScheduler that only records requests (tests, or until a queue is wired in).
 *
 * Why: lets the controller answer without a queue. 2026-11-10, session
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */
final class InMemoryReindexScheduler implements ReindexScheduler
{
    /** @var list<array{job_id: string, document_type: ?string}> */
    public array $enqueued = [];

    /**
     * Records the request and returns a random job id.
     *
     * Why: "reindex" answered "enqueued" while doing nothing; it is now a real scheduler seam. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the job queue in real implementations; memory in the in-memory one.
     */
    public function enqueueReindex(?string $documentType): string
    {
        $jobId = 'job_' . bin2hex(random_bytes(12));
        $this->enqueued[] = ['job_id' => $jobId, 'document_type' => $documentType];
        return $jobId;
    }
}

/**
 * HTTP-style handlers for the spec's endpoints; framework adapters delegate to it. Protect
 * handleIndex, handleUnindex and handleReindex (admin) with your authentication.
 *
 * Why: unchanged role; parses filters given inside q ("deployment tier:team") and reports bad
 * input as {success: false, error}. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches the database through the engine.
 */
final class SearchController
{
    private ReindexScheduler $scheduler;

    /**
     * @param SearchEngine          $engine
     * @param ReindexScheduler|null $scheduler Default: InMemoryReindexScheduler (records only).
     *
     * Why: the reindex scheduler is injectable. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public function __construct(private SearchEngine $engine, ?ReindexScheduler $scheduler = null)
    {
        $this->scheduler = $scheduler ?? new InMemoryReindexScheduler();
    }

    /**
     * POST /search/index {document_type, document_id, content, metadata}
     *
     * @return array {success: true, indexed_at} or {success: false, error}
     *
     * Why: invalid input is reported instead of indexing document 0 under an empty type. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database through the engine.
     */
    public function handleIndex(array $body): array
    {
        $type = $body['document_type'] ?? null;
        $id = $body['document_id'] ?? null;
        if (!is_string($type) || $type === '' || !is_int($id) || !is_string($body['content'] ?? '')
            || !is_array($body['metadata'] ?? [])) {
            return ['success' => false, 'error' => 'invalid_document'];
        }
        return $this->engine->indexDocument($type, $id, (string) ($body['content'] ?? ''), (array) ($body['metadata'] ?? []));
    }

    /**
     * GET /search?q=&document_type=&filters=field:value (repeatable)&facets=a,b&limit=&offset=
     * Words of the form field:value inside q are filters too.
     *
     * @return array The engine's search response.
     *
     * Why: filters can also be written inside q ("deployment tier:team"), as in the spec. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database through the engine (read).
     */
    public function handleSearch(array $query): array
    {
        $filters = [];
        $words = [];
        foreach (preg_split('/\s+/u', (string) ($query['q'] ?? ''), -1, PREG_SPLIT_NO_EMPTY) ?: [] as $part) {
            if (preg_match('/^([\p{L}\p{N}_]+):(\S+)$/u', $part, $m)) {
                $filters[$m[1]] = $m[2];
            } else {
                $words[] = $part;
            }
        }
        $rawFilters = $query['filters'] ?? [];
        foreach (is_array($rawFilters) ? $rawFilters : [$rawFilters] as $f) {
            if (is_string($f) && str_contains($f, ':')) {
                [$key, $val] = explode(':', $f, 2);
                $filters[trim($key)] = trim($val);
            }
        }
        $facets = [];
        if (is_string($query['facets'] ?? null)) {
            $facets = array_values(array_filter(array_map('trim', explode(',', $query['facets'])), static fn ($s) => $s !== ''));
        }
        $type = isset($query['document_type']) && $query['document_type'] !== '' ? (string) $query['document_type'] : null;

        return $this->engine->search(
            implode(' ', $words),
            $type,
            $filters,
            $facets,
            (int) ($query['limit'] ?? 20),
            (int) ($query['offset'] ?? 0)
        );
    }

    /**
     * DELETE /search/documents/:document_type/:document_id
     *
     * @return array {success: true}
     *
     * Why: unchanged contract; documented. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database through the engine.
     */
    public function handleUnindex(string $documentType, int $documentId): array
    {
        return $this->engine->unindexDocument($documentType, $documentId);
    }

    /**
     * POST /admin/search/reindex {document_type: string|null} (admin only).
     *
     * @return array {success: true, job_id, status: 'enqueued'}
     *
     * Why: enqueues through ReindexScheduler instead of a no-op. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the scheduler.
     */
    public function handleReindex(array $body): array
    {
        $type = isset($body['document_type']) && $body['document_type'] !== '' ? (string) $body['document_type'] : null;
        return ['success' => true, 'job_id' => $this->scheduler->enqueueReindex($type), 'status' => 'enqueued'];
    }
}
