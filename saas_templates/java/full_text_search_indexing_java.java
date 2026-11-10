package saas.search;

import java.sql.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Full-Text Search & Indexing system.
 *
 * Provides an inverted-index based search engine with:
 *  - Document indexing (create/update)
 *  - Full-text search with relevance scoring
 *  - Metadata filtering (tier, status, custom fields)
 *  - Faceting (counts per metadata field value)
 *  - Document unindexing (delete)
 *  - Batch reindexing (background job)
 *
 * Storage: In-memory inverted index kept in a sorted map (token -> keys in insertion order),
 * plus a forward index per document, so an update or delete touches only that document's tokens.
 * Tokenization: whitespace split, lowercase, stop-word removal.
 * Relevance: exact match > partial match > prefix match; ties break by insertion order.
 * Multi-word queries: every text token must match (spec: "stripe integration" finds deployments with both words).
 * Thread safety: every read and write of the index holds this object's monitor.
 *
 * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the class did not compile (a second
 * search(...) overload with the same signature that called itself), every index/update scanned the whole
 * inverted index (the 1M-document test never finished), prefix search scanned every token, results with equal
 * scores came back in hash order, and a reindex without a source wiped the index. Touches: memory only.
 */
public class FullTextSearchIndexing implements AutoCloseable {

    // ─── Configuration ───────────────────────────────────────────────────────

    public static class Config {
        public int defaultLimit = 20;
        public int maxLimit = 100;
        public int maxOffset = 10_000;
        public Set<String> stopWords = new HashSet<>(Arrays.asList(
                "a", "an", "the", "is", "are", "was", "were", "be", "been",
                "being", "have", "has", "had", "do", "does", "did", "will",
                "would", "could", "should", "may", "might", "shall", "can",
                "need", "dare", "to", "of", "in", "for", "on", "with", "at",
                "by", "from", "as", "into", "through", "during", "before",
                "after", "above", "below", "between", "out", "off", "over",
                "under", "again", "further", "then", "once", "here", "there",
                "all", "any", "both", "each", "few", "more", "most", "other",
                "some", "such", "no", "nor", "not", "only", "own", "same",
                "so", "than", "too", "very", "just", "because", "but", "and",
                "or", "if", "while", "about", "up", "down", "it", "its",
                "this", "that", "these", "those", "i", "you", "he", "she",
                "we", "they", "me", "him", "her", "us", "them", "my", "your",
                "his", "our", "their", "what", "which", "who", "whom", "when",
                "where", "why", "how", "am", "is", "are", "was", "were"
        ));
        public int reindexBatchSize = 500;
        public long reindexDelayMs = 10;
    }

    // ─── Data Models ─────────────────────────────────────────────────────────

    /**
     * One indexed document. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: gains the package-private seq (insertion order, for
     * deterministic ties) and tokens (forward index) fields; its public constructor is unchanged.
     */
    public static class Document {
        public String documentType;
        public String documentId;
        public String content;
        public Instant indexedAt;
        public Map<String, Object> metadata;
        /** Insertion sequence, used to break relevance ties deterministically (set by indexDocument). */
        long seq;
        /** Distinct normalized tokens of content, the forward index used for removal and scoring. */
        String[] tokens = new String[0];

        public Document(String documentType, String documentId, String content,
                        Instant indexedAt, Map<String, Object> metadata) {
            this.documentType = documentType;
            this.documentId = documentId;
            this.content = content;
            this.indexedAt = indexedAt;
            this.metadata = metadata != null ? new HashMap<>(metadata) : new HashMap<>();
        }
    }

    public static class SearchResult {
        public String documentId;
        public String documentType;
        public double relevance;
        public Map<String, Object> metadata;

        public SearchResult(String documentId, String documentType, double relevance,
                            Map<String, Object> metadata) {
            this.documentId = documentId;
            this.documentType = documentType;
            this.relevance = relevance;
            this.metadata = metadata;
        }
    }

    public static class SearchResponse {
        public List<SearchResult> results;
        public long total;
        public boolean hasMore;
        public Map<String, Map<String, Long>> facets;

        public SearchResponse(List<SearchResult> results, long total, boolean hasMore,
                              Map<String, Map<String, Long>> facets) {
            this.results = results;
            this.total = total;
            this.hasMore = hasMore;
            this.facets = facets;
        }
    }

    public static class IndexResponse {
        public boolean success;
        public Instant indexedAt;

        public IndexResponse(boolean success, Instant indexedAt) {
            this.success = success;
            this.indexedAt = indexedAt;
        }
    }

    public static class DeleteResponse {
        public boolean success;

        public DeleteResponse(boolean success) {
            this.success = success;
        }
    }

    public static class ReindexResponse {
        public boolean success;
        public String jobId;
        public String status;

        public ReindexResponse(boolean success, String jobId, String status) {
            this.success = success;
            this.jobId = jobId;
            this.status = status;
        }
    }

    // ─── Internal Index Structures ───────────────────────────────────────────

    /** Inverted index: token -> "type:id" keys in insertion order. Sorted so prefix lookups are a range scan. */
    private final TreeMap<String, Set<String>> invertedIndex = new TreeMap<>();

    /** Document store: "type:id" -> Document, in insertion order. */
    private final Map<String, Document> documentStore = new LinkedHashMap<>();

    /** Metadata index: field -> value -> "type:id" keys in insertion order. */
    private final Map<String, Map<String, Set<String>>> metadataIndex = new HashMap<>();

    /** Monotonic insertion counter for Document.seq. Guarded by this. */
    private long nextSeq = 0;

    /** Futures of submitted reindex jobs, so callers can wait for one deterministically. */
    private final Map<String, Future<?>> jobFutures = new ConcurrentHashMap<>();

    private static final Pattern LEADING_NON_ALNUM = Pattern.compile("^[^a-z0-9]+");
    private static final Pattern TRAILING_NON_ALNUM = Pattern.compile("[^a-z0-9]+$");
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    private final Config config;
    private final ExecutorService reindexExecutor;
    private final AtomicLong jobIdCounter = new AtomicLong(0);
    private final Map<String, String> jobStatus = new ConcurrentHashMap<>();

    // ─── Constructor ─────────────────────────────────────────────────────────

    public FullTextSearchIndexing() {
        this(new Config());
    }

    public FullTextSearchIndexing(Config config) {
        this.config = config != null ? config : new Config();
        this.reindexExecutor = Executors.newFixedThreadPool(2, r -> {
            Thread t = new Thread(r, "search-reindex-worker");
            t.setDaemon(true);
            return t;
        });
    }

    // ─── Tokenization ────────────────────────────────────────────────────────

    /**
     * Splits text on whitespace, lowercases it, trims non-alphanumerics from each word's edges and drops stop words.
     * Input: any text (null gives an empty list). Output: tokens in their order of appearance.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: precompiled patterns (the 1M-document test).
     * Touches: nothing (pure).
     */
    private List<String> tokenize(String text) {
        if (text == null || text.isEmpty()) {
            return Collections.emptyList();
        }
        String lower = text.toLowerCase(Locale.ROOT);
        String[] parts = WHITESPACE.split(lower);
        List<String> tokens = new ArrayList<>();
        for (String part : parts) {
            String trimmed = normalizeWord(part);
            if (trimmed.isEmpty()) continue;
            if (config.stopWords.contains(trimmed)) continue;
            tokens.add(trimmed);
        }
        return tokens;
    }

    /**
     * Normalizes one already-lowercased word the way indexed words are normalized: trims whitespace and
     * non-alphanumerics from its edges. Input: a word. Output: the normalized word, possibly empty.
     * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP, so query words and indexed words match the
     * same way ("stripe," finds "stripe"). Touches: nothing (pure).
     */
    private static String normalizeWord(String word) {
        String trimmed = word.trim();
        if (trimmed.isEmpty()) return trimmed;
        trimmed = LEADING_NON_ALNUM.matcher(trimmed).replaceAll("");
        return TRAILING_NON_ALNUM.matcher(trimmed).replaceAll("");
    }

    private String docKey(String documentType, String documentId) {
        return documentType + ":" + documentId;
    }

    // ─── 1. Index Document ───────────────────────────────────────────────────

    /**
     * Index or update a document.
     *
     * @param documentType e.g. "user", "deployment"
     * @param documentId   unique ID within the type
     * @param content      full searchable text
     * @param metadata     filterable fields
     * @return IndexResponse with success and indexedAt
     *
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: removal of the old version now uses the
     * document's own forward index instead of scanning every token (that made 1M inserts quadratic), and each
     * document gets an insertion sequence for deterministic tie-breaking. Touches: memory only.
     */
    public synchronized IndexResponse indexDocument(String documentType, String documentId,
                                       String content, Map<String, Object> metadata) {
        if (documentType == null || documentType.isEmpty()) {
            throw new IllegalArgumentException("document_type is required");
        }
        if (documentId == null || documentId.isEmpty()) {
            throw new IllegalArgumentException("document_id is required");
        }

        String key = docKey(documentType, documentId);
        Instant now = Instant.now();

        // Remove old index entries if document exists
        removeIndexEntries(key);

        // Store document (remove first so a re-index moves it to the end of insertion order)
        documentStore.remove(key);
        Document doc = new Document(documentType, documentId, content, now, metadata);
        doc.seq = nextSeq++;
        doc.tokens = new LinkedHashSet<>(tokenize(content)).toArray(new String[0]);
        documentStore.put(key, doc);

        // Build inverted index
        for (String token : doc.tokens) {
            invertedIndex.computeIfAbsent(token, k -> new LinkedHashSet<>(2)).add(key);
        }

        // Build metadata index
        if (metadata != null) {
            for (Map.Entry<String, Object> entry : metadata.entrySet()) {
                String field = entry.getKey();
                Object value = entry.getValue();
                if (value == null) continue;
                String strValue = value.toString();
                metadataIndex
                        .computeIfAbsent(field, k -> new HashMap<>())
                        .computeIfAbsent(strValue, k -> new LinkedHashSet<>(2))
                        .add(key);
            }
        }

        return new IndexResponse(true, now);
    }

    // ─── 2. Search ───────────────────────────────────────────────────────────

    /**
     * Search documents.
     *
     * @param query          search query (may contain filter syntax like "tier:team")
     * @param documentType   optional filter by document type
     * @param filters        map of metadata field -> value for filtering
     * @param limit          max results (default 20, max 100)
     * @param offset         pagination offset
     * @param facetFields    list of metadata fields to facet on
     * @return SearchResponse
     *
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: every text token must match (exactly or
     * as a prefix), as the spec's "stripe integration" example requires; prefix lookups are a range scan of the
     * sorted index instead of a scan of every token; equal scores keep insertion order; facets count the
     * documents actually returned by the query. Touches: memory only (reads the index).
     */
    public synchronized SearchResponse search(String query, String documentType,
                                 Map<String, String> filters, int limit, int offset,
                                 List<String> facetFields) {
        if (limit <= 0) limit = config.defaultLimit;
        if (limit > config.maxLimit) limit = config.maxLimit;
        if (offset < 0) offset = 0;
        if (offset > config.maxOffset) offset = config.maxOffset;

        // Parse query: extract filter tokens (field:value) and text tokens
        QueryParts parts = parseQuery(query);

        // Merge explicit filters with query-parsed filters
        Map<String, String> allFilters = new HashMap<>();
        if (filters != null) {
            allFilters.putAll(filters);
        }
        allFilters.putAll(parts.filters);

        // Determine candidate document keys: every text token must match (exact or prefix)
        Set<String> candidates = null;

        if (!parts.textTokens.isEmpty()) {
            for (String token : parts.textTokens) {
                Set<String> matches = new HashSet<>();
                // Exact and prefix matches: the sorted range [token, token + U+FFFF)
                for (Set<String> docs : invertedIndex.subMap(token, true, token + Character.MAX_VALUE, false).values()) {
                    matches.addAll(docs);
                }
                if (candidates == null) {
                    candidates = matches;
                } else {
                    candidates.retainAll(matches);
                }
                if (candidates.isEmpty()) break;
            }
        }

        if (candidates == null && parts.hadTextWords) {
            // Only stop words were typed: they are not indexed, so nothing matches ("the" finds nothing)
            candidates = new HashSet<>();
        }

        // If no text at all (empty query or filters only), all documents are candidates
        if (candidates == null) {
            candidates = new HashSet<>(documentStore.keySet());
        }

        // Apply document type filter
        if (documentType != null && !documentType.isEmpty()) {
            candidates = candidates.stream()
                    .filter(k -> k.startsWith(documentType + ":"))
                    .collect(Collectors.toSet());
        }

        // Apply metadata filters
        for (Map.Entry<String, String> filter : allFilters.entrySet()) {
            String field = filter.getKey();
            String value = filter.getValue();
            Map<String, Set<String>> fieldIndex = metadataIndex.get(field);
            if (fieldIndex == null) {
                candidates.clear();
                break;
            }
            Set<String> matching = fieldIndex.get(value);
            if (matching == null) {
                candidates.clear();
                break;
            }
            candidates.retainAll(matching);
        }

        // Score and sort: relevance descending, then insertion order (deterministic ties)
        List<ScoredDoc> scored = new ArrayList<>();
        for (String key : candidates) {
            Document doc = documentStore.get(key);
            if (doc == null) continue;
            double score = computeRelevance(doc, parts.textTokens);
            if (score > 0 || parts.textTokens.isEmpty()) {
                scored.add(new ScoredDoc(key, doc, score));
            }
        }

        scored.sort((a, b) -> {
            int c = Double.compare(b.score, a.score);
            return c != 0 ? c : Long.compare(a.doc.seq, b.doc.seq);
        });

        long total = scored.size();

        // Pagination
        int fromIndex = Math.min(offset, scored.size());
        int toIndex = Math.min(offset + limit, scored.size());
        List<SearchResult> results = new ArrayList<>();
        for (int i = fromIndex; i < toIndex; i++) {
            ScoredDoc sd = scored.get(i);
            results.add(new SearchResult(
                    sd.doc.documentId,
                    sd.doc.documentType,
                    sd.score,
                    new HashMap<>(sd.doc.metadata)
            ));
        }

        boolean hasMore = (offset + limit) < total;

        // Facets
        Map<String, Map<String, Long>> facets = null;
        if (facetFields != null && !facetFields.isEmpty()) {
            facets = computeFacets(scored, facetFields);
        }

        return new SearchResponse(results, total, hasMore, facets);
    }

    /**
     * Convenience overload: search all types with the default limit. Output: SearchResponse.
     * Touches: memory only. Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (the duplicate
     * six-argument overload that called itself forever was removed in this repair).
     */
    public SearchResponse search(String query) {
        return search(query, null, null, config.defaultLimit, 0, null);
    }

    /**
     * Convenience overload: text query within one document type, paginated. Output: SearchResponse.
     * Touches: memory only. Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
     */
    public SearchResponse search(String query, String documentType, int limit, int offset) {
        return search(query, documentType, null, limit, offset, null);
    }

    /**
     * Convenience overload: text query plus metadata filters, paginated, no facets. Output: SearchResponse.
     * Touches: memory only. Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
     */
    public SearchResponse search(String query, String documentType,
                                 Map<String, String> filters, int limit, int offset) {
        return search(query, documentType, filters, limit, offset, null);
    }

    // ─── 3. Search with Filters (convenience) ────────────────────────────────

    /**
     * Search with explicit filters.
     * Example: search("stripe", "deployment", Map.of("tier","team","status","active"), 20, 0)
     */
    public SearchResponse searchWithFilters(String query, String documentType,
                                            Map<String, String> filters, int limit, int offset) {
        return search(query, documentType, filters, limit, offset, null);
    }

    // ─── 4. Search with Facets (convenience) ─────────────────────────────────

    /**
     * Search with faceting.
     */
    public SearchResponse searchWithFacets(String query, String documentType,
                                           List<String> facetFields, int limit, int offset) {
        return search(query, documentType, null, limit, offset, facetFields);
    }

    // ─── 5. Unindex Document ─────────────────────────────────────────────────

    /**
     * Remove a document from the index. Removing an unknown document succeeds (idempotent delete).
     * Input: document type and id. Output: DeleteResponse(success=true).
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: synchronized, and removal uses the forward
     * index. Touches: memory only.
     */
    public synchronized DeleteResponse unindexDocument(String documentType, String documentId) {
        if (documentType == null || documentType.isEmpty()) {
            throw new IllegalArgumentException("document_type is required");
        }
        if (documentId == null || documentId.isEmpty()) {
            throw new IllegalArgumentException("document_id is required");
        }

        String key = docKey(documentType, documentId);
        removeIndexEntries(key);
        documentStore.remove(key);

        return new DeleteResponse(true);
    }

    // ─── 6. Re-index All ─────────────────────────────────────────────────────

    /**
     * Enqueue a background reindex job.
     *
     * @param documentType specific type or null for all
     * @return ReindexResponse with job_id and status
     *
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the job's Future is kept so awaitJob can
     * wait for it instead of callers sleeping and hoping. Touches: memory only, one background thread.
     */
    public ReindexResponse reindexAll(String documentType) {
        String jobId = "reindex-" + jobIdCounter.incrementAndGet();
        jobStatus.put(jobId, "enqueued");

        final String type = documentType;
        Future<?> future = reindexExecutor.submit(() -> {
            try {
                jobStatus.put(jobId, "running");
                performReindex(type);
                jobStatus.put(jobId, "completed");
            } catch (Exception e) {
                jobStatus.put(jobId, "failed");
            }
        });
        jobFutures.put(jobId, future);

        return new ReindexResponse(true, jobId, "enqueued");
    }

    /**
     * Waits until a reindex job has finished (completed or failed), up to timeoutMs.
     * Input: job id from reindexAll, timeout in milliseconds. Output: true if the job finished in time,
     * false if it is unknown, still running, or the wait was interrupted.
     * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP so tests and callers wait on the job itself
     * rather than on a fixed sleep (a wall-clock race). Touches: memory only.
     */
    public boolean awaitJob(String jobId, long timeoutMs) {
        Future<?> future = jobFutures.get(jobId);
        if (future == null) return false;
        try {
            future.get(timeoutMs, TimeUnit.MILLISECONDS);
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (ExecutionException e) {
            return true; // the job ended; its status says "failed"
        } catch (TimeoutException e) {
            return false;
        }
    }

    /**
     * Synchronous reindex from the registered ReindexSource (the source of truth, e.g. the database).
     * Input: a document type, or null for all types. Output: none; the index for that scope is rebuilt.
     * With a type, only documents of that type are dropped and reloaded (getDocumentsByType); with null, the
     * whole index is dropped and reloaded (getAllDocuments).
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: it cleared the whole index even for a
     * one-type reindex, and with no source registered it wiped every document and rebuilt nothing. It now
     * refuses (IllegalStateException, so the job is marked failed) and leaves the index untouched.
     * Touches: memory only (reads the source).
     */
    public synchronized void performReindex(String documentType) {
        if (reindexSource == null) {
            throw new IllegalStateException("no reindex source registered; index left unchanged");
        }
        List<Document> docs = documentType == null
                ? reindexSource.getAllDocuments()
                : reindexSource.getDocumentsByType(documentType);

        if (documentType == null) {
            invertedIndex.clear();
            documentStore.clear();
            metadataIndex.clear();
        } else {
            for (String key : new ArrayList<>(documentStore.keySet())) {
                if (key.startsWith(documentType + ":")) {
                    removeIndexEntries(key);
                    documentStore.remove(key);
                }
            }
        }

        for (Document doc : docs) {
            if (documentType != null && !documentType.equals(doc.documentType)) continue;
            indexDocument(doc.documentType, doc.documentId, doc.content, doc.metadata);
        }
    }

    // ─── Reindex Source Interface ────────────────────────────────────────────

    public interface ReindexSource {
        List<Document> getAllDocuments();
        List<Document> getDocumentsByType(String type);
        String getDocumentType(); // "all" or specific type
    }

    private ReindexSource reindexSource;

    /**
     * Registers the source of truth used by reindex jobs. Input: a ReindexSource. Output: none.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: synchronized with the jobs that read it.
     * Touches: memory only.
     */
    public synchronized void setReindexSource(ReindexSource source) {
        this.reindexSource = source;
    }

    // ─── Query Parsing ───────────────────────────────────────────────────────

    private static class QueryParts {
        List<String> textTokens = new ArrayList<>();
        Map<String, String> filters = new HashMap<>();
        /** True when the query held free-text words, even if every one was a stop word. */
        boolean hadTextWords = false;
    }

    /**
     * Splits a query into free-text tokens and field:value filters ("member tier:team").
     * Input: raw query (may be null). Output: QueryParts.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: text tokens are normalized like indexed
     * words, and hadTextWords marks a stop-word-only query so it matches nothing. Touches: nothing (pure).
     */
    private QueryParts parseQuery(String query) {
        QueryParts parts = new QueryParts();
        if (query == null || query.trim().isEmpty()) {
            return parts;
        }

        String[] tokens = query.trim().split("\\s+");
        for (String token : tokens) {
            int colonIdx = token.indexOf(':');
            if (colonIdx > 0) {
                String field = token.substring(0, colonIdx).toLowerCase(Locale.ROOT);
                String value = token.substring(colonIdx + 1).toLowerCase(Locale.ROOT);
                if (!field.isEmpty() && !value.isEmpty()) {
                    parts.filters.put(field, value);
                }
            } else {
                String lower = normalizeWord(token.toLowerCase(Locale.ROOT));
                if (!lower.isEmpty()) parts.hadTextWords = true;
                if (!config.stopWords.contains(lower) && !lower.isEmpty()) {
                    parts.textTokens.add(lower);
                }
            }
        }
        return parts;
    }

    // ─── Relevance Scoring ───────────────────────────────────────────────────

    private static class ScoredDoc {
        String key;
        Document doc;
        double score;

        ScoredDoc(String key, Document doc, double score) {
            this.key = key;
            this.doc = doc;
            this.score = score;
        }
    }

    /**
     * Scores a document for the query: per token, exact word 3.0, word containing the token 2.0, word starting
     * with it 1.0; averaged over tokens, with a 1.5x bonus when a multi-word query matches every word exactly.
     * Input: document, query tokens. Output: score (0 when nothing matches; 1.0 for an empty query).
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: scores against the document's normalized
     * tokens (the same words the index holds) instead of re-splitting raw content on every call.
     * Touches: nothing (pure).
     */
    private double computeRelevance(Document doc, List<String> queryTokens) {
        if (queryTokens == null || queryTokens.isEmpty()) {
            return 1.0; // No text query, all equal
        }

        double totalScore = 0.0;
        boolean allExact = true;

        for (String qt : queryTokens) {
            double tokenScore = 0.0;
            for (String w : doc.tokens) {
                if (w.equals(qt)) {
                    tokenScore = 3.0; // exact match
                    break;
                } else if (w.contains(qt)) {
                    tokenScore = Math.max(tokenScore, 2.0); // partial match (substring)
                } else if (w.startsWith(qt)) {
                    tokenScore = Math.max(tokenScore, 1.0); // prefix match
                }
            }
            if (tokenScore < 3.0) allExact = false;
            totalScore += tokenScore;
        }

        // Normalize: divide by number of query tokens so multi-word queries
        // don't get unfairly high scores
        double normalized = totalScore / queryTokens.size();

        // Bonus: if all tokens matched exactly, boost
        if (allExact && queryTokens.size() > 1) {
            normalized *= 1.5; // multi-word exact bonus
        }

        return normalized;
    }

    // ─── Facets ──────────────────────────────────────────────────────────────

    /**
     * Counts, per requested metadata field, how many matching documents hold each value; values sorted by count
     * descending, then by value for a stable order. Input: the scored matches, field names. Output: field ->
     * value -> count (an empty map for a field no match has).
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: counts the documents the query returned
     * (not raw candidates) and orders ties deterministically. Touches: nothing (pure).
     */
    private Map<String, Map<String, Long>> computeFacets(List<ScoredDoc> matches,
                                                         List<String> facetFields) {
        Map<String, Map<String, Long>> facets = new LinkedHashMap<>();

        for (String field : facetFields) {
            Map<String, Long> counts = new LinkedHashMap<>();
            for (ScoredDoc sd : matches) {
                Document doc = sd.doc;
                Object value = doc.metadata.get(field);
                if (value != null) {
                    String strValue = value.toString();
                    counts.merge(strValue, 1L, Long::sum);
                }
            }
            // Sort by count descending
            Map<String, Long> sorted = counts.entrySet().stream()
                    .sorted(Map.Entry.<String, Long>comparingByValue().reversed()
                            .thenComparing(Map.Entry.comparingByKey()))
                    .collect(Collectors.toMap(
                            Map.Entry::getKey,
                            Map.Entry::getValue,
                            (a, b) -> a,
                            LinkedHashMap::new
                    ));
            facets.put(field, sorted);
        }

        return facets;
    }

    // ─── Internal: Remove Index Entries ──────────────────────────────────────

    /**
     * Removes one document's entries from the inverted and metadata indexes, using its forward index (its own
     * tokens and metadata values), and drops postings that become empty. The document itself stays in
     * documentStore; callers remove it. Input: "type:id" key (unknown keys are a no-op). Output: none.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: it walked every token and every metadata
     * value in the index on each call, so indexing N documents cost O(N^2) and the 1M-document test never ended.
     * Touches: memory only. Caller holds this object's monitor.
     */
    private void removeIndexEntries(String key) {
        Document old = documentStore.get(key);
        if (old == null) return;

        for (String token : old.tokens) {
            Set<String> postings = invertedIndex.get(token);
            if (postings != null) {
                postings.remove(key);
                if (postings.isEmpty()) invertedIndex.remove(token);
            }
        }

        for (Map.Entry<String, Object> entry : old.metadata.entrySet()) {
            if (entry.getValue() == null) continue;
            Map<String, Set<String>> fieldIndex = metadataIndex.get(entry.getKey());
            if (fieldIndex == null) continue;
            String strValue = entry.getValue().toString();
            Set<String> postings = fieldIndex.get(strValue);
            if (postings != null) {
                postings.remove(key);
                if (postings.isEmpty()) fieldIndex.remove(strValue);
            }
            if (fieldIndex.isEmpty()) metadataIndex.remove(entry.getKey());
        }
    }

    // ─── Utility ─────────────────────────────────────────────────────────────

    /**
     * Number of indexed documents. Touches: memory only.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: synchronized (the store is no longer a
     * concurrent map).
     */
    public synchronized int getDocumentCount() {
        return documentStore.size();
    }

    /**
     * Number of indexed documents of one type. Touches: memory only.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: synchronized.
     */
    public synchronized int getDocumentCount(String documentType) {
        return (int) documentStore.keySet().stream()
                .filter(k -> k.startsWith(documentType + ":"))
                .count();
    }

    public String getJobStatus(String jobId) {
        return jobStatus.getOrDefault(jobId, "unknown");
    }

    @Override
    public void close() {
        reindexExecutor.shutdown();
        try {
            if (!reindexExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                reindexExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            reindexExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    // ─── DDL (for reference / migration) ─────────────────────────────────────

    public static final String DDL =
            "CREATE TABLE IF NOT EXISTS search_index (\n" +
            "    id BIGINT AUTO_INCREMENT PRIMARY KEY,\n" +
            "    document_type VARCHAR(100) NOT NULL,\n" +
            "    document_id VARCHAR(255) NOT NULL,\n" +
            "    content TEXT,\n" +
            "    indexed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,\n" +
            "    metadata JSON,\n" +
            "    UNIQUE KEY uk_doc (document_type, document_id),\n" +
            "    FULLTEXT KEY ft_content (content)\n" +
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
}