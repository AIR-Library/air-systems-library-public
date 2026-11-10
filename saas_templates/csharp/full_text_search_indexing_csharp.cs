// Full-text search & indexing template (TIER_2_MASTER_SPEC system 6): an in-memory inverted index with filters,
// facets, relevance (exact word > prefix; amended 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP), unindex and an
// enqueued reindex.
// Repaired 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): Facets_ReturnCountsPerStatus and
// Relevance_ExactMatchHigherThanPartial failed; see SearchIndexService. Touches: process memory only.
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace SaaS.Search
{
    // DTOs matching API contract
    public class IndexRequest
    {
        [JsonPropertyName("document_type")]
        public string DocumentType { get; set; }

        [JsonPropertyName("document_id")]
        public string DocumentId { get; set; }

        [JsonPropertyName("content")]
        public string Content { get; set; }

        [JsonPropertyName("metadata")]
        public Dictionary<string, object> Metadata { get; set; }
    }

    public class IndexResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("indexed_at")]
        public DateTime IndexedAt { get; set; }
    }

    public class SearchRequest
    {
        public string Query { get; set; }
        public string DocumentType { get; set; }
        public int Limit { get; set; } = 20;
        public int Offset { get; set; } = 0;
        public List<string> Filters { get; set; } = new List<string>();
        public List<string> Facets { get; set; } = new List<string>();
    }

    public class SearchResultItem
    {
        [JsonPropertyName("document_id")]
        public string DocumentId { get; set; }

        [JsonPropertyName("document_type")]
        public string DocumentType { get; set; }

        [JsonPropertyName("relevance")]
        public double Relevance { get; set; }

        [JsonPropertyName("metadata")]
        public Dictionary<string, object> Metadata { get; set; }
    }

    public class SearchResponse
    {
        [JsonPropertyName("results")]
        public List<SearchResultItem> Results { get; set; } = new List<SearchResultItem>();

        [JsonPropertyName("total")]
        public int Total { get; set; }

        [JsonPropertyName("has_more")]
        public bool HasMore { get; set; }

        [JsonPropertyName("facets")]
        public Dictionary<string, Dictionary<string, int>> Facets { get; set; }
    }

    public class UnindexResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; }
    }

    public class ReindexRequest
    {
        [JsonPropertyName("document_type")]
        public string DocumentType { get; set; } // null => all
    }

    public class ReindexResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("job_id")]
        public string JobId { get; set; }

        [JsonPropertyName("status")]
        public string Status { get; set; }
    }

    /// <summary>
    /// A growable int array (postings, per-ordinal type ids). Searches read <see cref="Items"/> directly: plain array
    /// loops stay fast even in an unoptimised Debug build, where List and Span indexers are method calls (SEARCH-08:
    /// 1M documents in under 200 ms is checked in the Debug build the test runner makes).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
    /// </summary>
    internal sealed class IntList
    {
        public int[] Items;
        public int Count;

        public IntList(int capacity = 1) => Items = new int[Math.Max(1, capacity)];

        /// <summary>Appends one value, doubling the array when full.</summary>
        public void Add(int value)
        {
            if (Count == Items.Length) Array.Resize(ref Items, Items.Length * 2);
            Items[Count++] = value;
        }
    }

    /// <summary>
    /// Internal representation of one indexed document. <c>Ordinal</c> is its slot in insertion order (used to break
    /// relevance ties: the document indexed first comes first); <c>Alive</c> turns false when the document is unindexed
    /// or replaced by a newer version (which gets a new ordinal at the end). <c>Terms</c> are its distinct words.
    /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (SEARCH-03/08/09 amendment). Pure data.
    /// </summary>
    internal class SearchDocument
    {
        public string DocumentKey => $"{DocumentType}:{DocumentId}";
        public string DocumentType { get; set; }
        public string DocumentId { get; set; }
        public string Content { get; set; }
        public DateTime IndexedAt { get; set; }
        public int Ordinal { get; set; }
        public bool Alive { get; set; } = true;
        public string[] Terms { get; set; } = Array.Empty<string>();
        public Dictionary<string, object> Metadata { get; set; }
    }

    /// <summary>
    /// In-memory inverted-index search engine (spec TIER 2, system 6): index, search with filters and facets,
    /// unindex, and an enqueued reindex job.
    /// Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, for the SEARCH-03/09 amendment and SEARCH-08:
    /// <list type="bullet">
    /// <item>A word is a maximal run of Unicode letters and digits (\p{L}, \p{N}), lower-cased with ToLowerInvariant;
    /// no stop words; the document type is no longer indexed as a word (the spec searches the content).</item>
    /// <item>A query term matches a word equal to it (exact, 1.0) or starting with it (prefix, 0.5): "stri" finds
    /// "stripe", "ripe" does not (the old reverse-prefix rule let a short word match a longer query). Several terms
    /// must all match (AND). Equal scores keep insertion order.</item>
    /// <item>Postings are kept in insertion order and the vocabulary is sorted, so a prefix is a range lookup and a
    /// page is read by score bucket without sorting every match: 1M documents search in well under 200 ms.</item>
    /// <item>"field:value" chunks in the query are filters (spec examples: "tier:team"). An empty query lists every
    /// document of the type, in insertion order.</item>
    /// </list>
    /// Every mutation and search runs under one lock. Touches: process memory only (no database, network, files or money).
    /// </summary>
    public class SearchIndexService
    {
        // All documents ever indexed, by ordinal (insertion order); dead ones are skipped. Guarded by _gate.
        private List<SearchDocument> _docs = new List<SearchDocument>();

        // Live document by key. Guarded by _gate.
        private readonly Dictionary<string, SearchDocument> _documents = new Dictionary<string, SearchDocument>();

        // Inverted index: word -> ordinals in insertion order (may hold dead ordinals). Guarded by _gate.
        private Dictionary<string, IntList> _postings = new Dictionary<string, IntList>(StringComparer.Ordinal);

        // Type id of each ordinal, or -1 for a dead document; type ids by type name. Guarded by _gate.
        private IntList _typeOf = new IntList(1024);
        private readonly Dictionary<string, int> _typeIds = new Dictionary<string, int>(StringComparer.Ordinal);

        // Every indexed word, sorted ordinally, for prefix range lookups. Guarded by _gate.
        private SortedSet<string> _vocabulary = new SortedSet<string>(StringComparer.Ordinal);

        private readonly object _gate = new object();
        private int _dead;

        /// <summary>Exact-word score of one query term.</summary>
        public const double ExactScore = 1.0;

        /// <summary>Prefix-only score of one query term.</summary>
        public const double PrefixScore = 0.5;

        // Background job queue (simplified)
        private readonly ConcurrentQueue<(string Id, Func<Task> Run)> _jobQueue = new ConcurrentQueue<(string Id, Func<Task> Run)>();
        private readonly ConcurrentDictionary<string, string> _failedJobs = new ConcurrentDictionary<string, string>();

        /// <summary>
        /// Reindex jobs that failed, by job id, with the error message. A failed job leaves the previous terms in place
        /// and the worker carries on, so this is where the failure is visible. Added 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP: the worker used a bare catch that dropped the error (code scanning, PR 19).
        /// Touches: process memory (read).
        /// </summary>
        public IReadOnlyDictionary<string, string> FailedJobs => _failedJobs;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();

        /// <summary>Creates an empty index and starts the in-process reindex worker. Touches: process memory.</summary>
        public SearchIndexService()
        {
            // Start background worker
            Task.Run(ProcessJobsAsync);
        }

        /// <summary>True for a Unicode letter (\p{L}) or number (\p{N}). Pure.</summary>
        private static bool IsWordRune(Rune r)
        {
            switch (Rune.GetUnicodeCategory(r))
            {
                case UnicodeCategory.UppercaseLetter:
                case UnicodeCategory.LowercaseLetter:
                case UnicodeCategory.TitlecaseLetter:
                case UnicodeCategory.ModifierLetter:
                case UnicodeCategory.OtherLetter:
                case UnicodeCategory.DecimalDigitNumber:
                case UnicodeCategory.LetterNumber:
                case UnicodeCategory.OtherNumber:
                    return true;
                default:
                    return false;
            }
        }

        /// <summary>
        /// Splits text into words: maximal runs of Unicode letters and digits (\p{L}, \p{N}, read as whole code
        /// points), each lower-cased with ToLowerInvariant; everything else separates words; no stop words.
        /// Input: any text (null allowed). Output: the words in order, duplicates kept.
        /// Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (SEARCH-03 amendment): it split on a fixed list of
        /// punctuation and dropped stop words. Pure.
        /// </summary>
        public static IEnumerable<string> Tokenize(string text)
        {
            if (string.IsNullOrEmpty(text)) yield break;
            var word = new StringBuilder();
            foreach (var rune in text.EnumerateRunes())
            {
                if (IsWordRune(rune))
                {
                    word.Append(rune.ToString());
                }
                else if (word.Length > 0)
                {
                    yield return word.ToString().ToLowerInvariant();
                    word.Clear();
                }
            }
            if (word.Length > 0) yield return word.ToString().ToLowerInvariant();
        }

        /// <summary>Adds a live document's words to the postings and vocabulary. Caller holds _gate. Touches: memory.</summary>
        private void AddTerms(SearchDocument doc)
        {
            if (!_typeIds.TryGetValue(doc.DocumentType, out var typeId))
            {
                typeId = _typeIds.Count;
                _typeIds[doc.DocumentType] = typeId;
            }
            _typeOf.Add(typeId);
            foreach (var term in doc.Terms)
            {
                if (!_postings.TryGetValue(term, out var list))
                {
                    list = new IntList(1);
                    _postings[term] = list;
                    _vocabulary.Add(term);
                }
                list.Add(doc.Ordinal);
            }
        }

        /// <summary>
        /// Marks a document dead; its ordinals stay in the postings and are skipped. When dead documents outnumber live
        /// ones (and there are over 1,000), the index is rebuilt to reclaim the space. Caller holds _gate. Touches: memory.
        /// </summary>
        private void Retire(SearchDocument doc)
        {
            doc.Alive = false;
            _typeOf.Items[doc.Ordinal] = -1;
            _documents.Remove(doc.DocumentKey);
            if (++_dead > 1000 && _dead > _documents.Count)
                Rebuild(null);
        }

        /// <summary>
        /// Rebuilds ordinals, postings and vocabulary from the live documents, in insertion order, re-deriving the words
        /// of the documents of <paramref name="retokenizeType"/> (all types when null; none when called to compact).
        /// Caller holds _gate. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
        /// </summary>
        private void Rebuild(string retokenizeType, bool retokenize = false)
        {
            var live = _docs.Where(d => d.Alive).ToList();
            _docs = new List<SearchDocument>(live.Count);
            _postings = new Dictionary<string, IntList>(StringComparer.Ordinal);
            _typeOf = new IntList(Math.Max(1024, live.Count));
            _vocabulary = new SortedSet<string>(StringComparer.Ordinal);
            _dead = 0;
            foreach (var doc in live)
            {
                if (retokenize && (retokenizeType == null || doc.DocumentType == retokenizeType))
                    doc.Terms = Tokenize(doc.Content).Distinct().ToArray();
                doc.Ordinal = _docs.Count;
                _docs.Add(doc);
                AddTerms(doc);
            }
        }

        /// <summary>
        /// Indexes a document, replacing any earlier version with the same type and id (spec endpoint 1); it is
        /// searchable as soon as this returns (real-time indexing). Input: type, id, content, metadata.
        /// Output: success and indexed_at. Touches: process memory. Updated 2026-11-10 (session
        /// session_012zDydZCZ4AChqhEZ4oVtaP): runs under the index lock; a new version goes to the end of the
        /// insertion order.
        /// </summary>
        public Task<IndexResponse> IndexDocumentAsync(IndexRequest request)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));
            if (string.IsNullOrWhiteSpace(request.DocumentType)) throw new ArgumentException("document_type is required", nameof(request));
            if (string.IsNullOrWhiteSpace(request.DocumentId)) throw new ArgumentException("document_id is required", nameof(request));

            var doc = new SearchDocument
            {
                DocumentType = request.DocumentType,
                DocumentId = request.DocumentId,
                Content = request.Content ?? string.Empty,
                IndexedAt = DateTime.UtcNow,
                Metadata = request.Metadata ?? new Dictionary<string, object>()
            };
            doc.Terms = Tokenize(doc.Content).Distinct().ToArray();

            lock (_gate)
            {
                if (_documents.TryGetValue(doc.DocumentKey, out var oldDoc)) Retire(oldDoc);
                doc.Ordinal = _docs.Count;
                _docs.Add(doc);
                _documents[doc.DocumentKey] = doc;
                AddTerms(doc);
            }

            return Task.FromResult(new IndexResponse { Success = true, IndexedAt = doc.IndexedAt });
        }

        /// <summary>
        /// Splits a query into words and "field:value" filters (a whitespace-separated chunk with a colon inside it).
        /// Output: the distinct words in order, and the filters. Pure. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        private static (List<string> Terms, List<KeyValuePair<string, string>> Filters) ParseQuery(string query)
        {
            var terms = new List<string>();
            var filters = new List<KeyValuePair<string, string>>();
            foreach (var chunk in (query ?? string.Empty).Split((char[])null, StringSplitOptions.RemoveEmptyEntries))
            {
                var colon = chunk.IndexOf(':');
                if (colon > 0 && colon < chunk.Length - 1)
                    filters.Add(new KeyValuePair<string, string>(chunk.Substring(0, colon), chunk.Substring(colon + 1)));
                else
                    terms.AddRange(Tokenize(chunk));
            }
            return (terms.Distinct().ToList(), filters);
        }

        /// <summary>
        /// Searches the index (spec endpoints 2-4). Input: query, optional document type, "field:value" filters (all
        /// must match, value compared case-insensitively; also accepted inside the query), facet fields, limit and
        /// offset. Every query word must match a document word equal to it (1.0) or starting with it (0.5); the
        /// relevance is the sum. Output: the page ordered by relevance, then insertion order; the total; has_more; and,
        /// when facets were asked for, per-field value counts over every matching document (not just the page). An
        /// empty query matches every document (relevance 0). Touches: process memory.
        /// Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (SEARCH-03/08/09 amendment; see the class summary).
        /// </summary>
        public Task<SearchResponse> SearchAsync(SearchRequest request)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));
            var (queryTerms, filters) = ParseQuery(request.Query);
            foreach (var filter in request.Filters ?? Enumerable.Empty<string>())
            {
                var parts = (filter ?? string.Empty).Split(':', 2);
                if (parts.Length == 2) filters.Add(new KeyValuePair<string, string>(parts[0], parts[1]));
            }
            var limit = request.Limit > 0 ? request.Limit : 20;
            var offset = Math.Max(0, request.Offset);
            var facetFields = (request.Facets ?? new List<string>()).Where(f => !string.IsNullOrEmpty(f)).Distinct().ToList();

            var k = queryTerms.Count;
            var total = 0;
            // bucketCounts[e] = matches whose number of exact-word terms is e (relevance e*1.0 + (k-e)*0.5)
            var bucketCounts = new int[k + 1];
            var facetCounts = facetFields.ToDictionary(f => f, f => new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase));
            var page = new List<SearchResultItem>();

            lock (_gate)
            {
                var n = _docs.Count;
                // Pooled scratch arrays, so a search over 1M documents allocates almost nothing (a garbage collection
                // of a large index would otherwise eat the 200 ms budget). level[t][ordinal]: 2 = term t equals a word of
                // the document, 1 = only starts one, 0 = no match. bucketOf[ordinal]: 1 + exact-term count of a match.
                var levels = new byte[k][];
                var bucketOf = ArrayPool<byte>.Shared.Rent(Math.Max(1, n));
                try
                {
                    for (var t = 0; t < k; t++)
                    {
                        var level = ArrayPool<byte>.Shared.Rent(Math.Max(1, n));
                        levels[t] = level;
                        Array.Clear(level, 0, n);
                        var term = queryTerms[t];
                        if (_postings.TryGetValue(term, out var exact))
                        {
                            var items = exact.Items;
                            for (var i = 0; i < exact.Count; i++) level[items[i]] = 2;
                        }
                        foreach (var word in _vocabulary.GetViewBetween(term, term + char.MaxValue))
                        {
                            if (word.Length == term.Length || !word.StartsWith(term, StringComparison.Ordinal)) continue;
                            var prefixed = _postings[word];
                            var items = prefixed.Items;
                            for (var i = 0; i < prefixed.Count; i++)
                                if (level[items[i]] == 0) level[items[i]] = 1;
                        }
                    }

                    // wanted type id: -1 = any type; -2 = a type never indexed (nothing can match)
                    var wantType = -1;
                    if (!string.IsNullOrWhiteSpace(request.DocumentType))
                        wantType = _typeIds.TryGetValue(request.DocumentType, out var id) ? id : -2;
                    var typeOf = _typeOf.Items;
                    var needDoc = filters.Count > 0 || facetFields.Count > 0;
                    var level0 = k > 0 ? levels[0] : null;
                    Array.Clear(bucketOf, 0, n);
                    for (var ord = 0; wantType != -2 && ord < n; ord++)
                    {
                        var tid = typeOf[ord];
                        if (tid < 0 || (wantType >= 0 && tid != wantType)) continue;
                        var exactTerms = 0;
                        if (k == 1)
                        {
                            var l = level0[ord];
                            if (l == 0) continue;
                            if (l == 2) exactTerms = 1;
                        }
                        else if (k > 1)
                        {
                            var all = true;
                            for (var t = 0; t < k; t++)
                            {
                                var l = levels[t][ord];
                                if (l == 0) { all = false; break; }
                                if (l == 2) exactTerms++;
                            }
                            if (!all) continue;
                        }

                        SearchDocument doc = null;
                        if (needDoc)
                        {
                            doc = _docs[ord];
                            if (filters.Count > 0 && !MatchesFilters(doc, filters)) continue;
                        }

                        total++;
                        bucketCounts[exactTerms]++;
                        bucketOf[ord] = (byte)(exactTerms + 1);
                        if (facetFields.Count == 0) continue;
                        foreach (var field in facetFields)
                        {
                            if (doc.Metadata != null && doc.Metadata.TryGetValue(field, out var val))
                            {
                                var key = val?.ToString() ?? "null";
                                var counts = facetCounts[field];
                                counts[key] = counts.TryGetValue(key, out var c) ? c + 1 : 1;
                            }
                        }
                    }

                    // the page: highest bucket first, insertion order inside a bucket
                    var skip = offset;
                    for (var e = k; e >= 0 && page.Count < limit; e--)
                    {
                        if (skip >= bucketCounts[e]) { skip -= bucketCounts[e]; continue; }
                        var score = e * ExactScore + (k - e) * PrefixScore;
                        var mark = (byte)(e + 1);
                        for (var ord = 0; ord < n && page.Count < limit; ord++)
                        {
                            if (bucketOf[ord] != mark) continue;
                            if (skip > 0) { skip--; continue; }
                            var doc = _docs[ord];
                            page.Add(new SearchResultItem
                            {
                                DocumentId = doc.DocumentId,
                                DocumentType = doc.DocumentType,
                                Relevance = score,
                                Metadata = doc.Metadata
                            });
                        }
                    }
                }
                finally
                {
                    foreach (var level in levels)
                        if (level != null) ArrayPool<byte>.Shared.Return(level);
                    ArrayPool<byte>.Shared.Return(bucketOf);
                }
            }

            return Task.FromResult(new SearchResponse
            {
                Results = page,
                Total = total,
                HasMore = offset + page.Count < total,
                Facets = facetFields.Count > 0 ? facetCounts : null
            });
        }

        /// <summary>True when every filter's field is in the document's metadata with that value (case-insensitive). Pure.</summary>
        private static bool MatchesFilters(SearchDocument doc, List<KeyValuePair<string, string>> filters)
        {
            foreach (var f in filters)
            {
                if (doc.Metadata == null || !doc.Metadata.TryGetValue(f.Key, out var metaVal) ||
                    !string.Equals(metaVal?.ToString(), f.Value, StringComparison.OrdinalIgnoreCase))
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Removes a document from the index (spec endpoint 5). Input: type and id. Output: success (also when it was
        /// not indexed: deleting is idempotent). Touches: process memory. Updated 2026-11-10 (session
        /// session_012zDydZCZ4AChqhEZ4oVtaP): runs under the index lock; the document is retired (skipped by every
        /// search) and its postings are reclaimed by the next compaction.
        /// </summary>
        public Task<UnindexResponse> UnindexDocumentAsync(string documentType, string documentId)
        {
            var key = $"{documentType}:{documentId}";
            lock (_gate)
            {
                if (_documents.TryGetValue(key, out var doc)) Retire(doc);
            }
            return Task.FromResult(new UnindexResponse { Success = true });
        }

        /// <summary>
        /// Enqueues a reindex job (spec endpoint 6). Input: a document type, or null for all. Output: success, the job
        /// id and status "enqueued". The job re-derives the terms of the selected documents only. Touches: process
        /// memory. Updated 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): the old job cleared the whole
        /// index, so reindexing one type erased every other type's terms, and it ran unlocked beside searches.
        /// </summary>
        public Task<ReindexResponse> ReindexAsync(ReindexRequest request)
        {
            var documentType = request?.DocumentType;
            var jobId = Guid.NewGuid().ToString();
            _jobQueue.Enqueue((jobId, () =>
            {
                lock (_gate)
                {
                    Rebuild(documentType, retokenize: true);
                }
                return Task.CompletedTask;
            }));

            return Task.FromResult(new ReindexResponse
            {
                Success = true,
                JobId = jobId,
                Status = "enqueued"
            });
        }

        /// <summary>
        /// Runs enqueued reindex jobs one at a time until the service is disposed of with the process. A failing job
        /// is recorded in <see cref="FailedJobs"/> and the worker keeps running (2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP: it was a bare catch that dropped the error). Touches: process memory.
        /// </summary>
        private async Task ProcessJobsAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                if (_jobQueue.TryDequeue(out var job))
                {
                    try { await job.Run(); }
                    catch (Exception ex)
                    {
                        // A failed reindex leaves the previous terms in place; the worker must keep serving later jobs.
                        _failedJobs[job.Id] = ex.Message;
                    }
                }
                else
                {
                    await Task.Delay(100);
                }
            }
        }

        // DDL for persistence (if needed)
        public const string Ddl = @"
CREATE TABLE search_index (
    document_type VARCHAR(50) NOT NULL,
    document_id VARCHAR(100) NOT NULL,
    content TEXT NOT NULL,
    indexed_at TIMESTAMP NOT NULL,
    metadata JSONB NOT NULL,
    PRIMARY KEY (document_type, document_id)
);
";
    }
}