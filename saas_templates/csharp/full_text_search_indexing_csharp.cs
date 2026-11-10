// Full-text search & indexing template (TIER_2_MASTER_SPEC system 6): an in-memory inverted index with filters,
// facets, relevance (exact > partial > prefix), unindex and an enqueued reindex.
// Repaired 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): Facets_ReturnCountsPerStatus and
// Relevance_ExactMatchHigherThanPartial failed; see SearchIndexService. Touches: process memory only.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
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
    /// Internal representation of one indexed document. <c>Sequence</c> is the insertion order, used to break
    /// relevance ties deterministically (2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the old tie-break on
    /// IndexedAt was not deterministic when two documents were indexed in the same clock tick). Pure data.
    /// </summary>
    internal class SearchDocument
    {
        public string DocumentKey => $"{DocumentType}:{DocumentId}";
        public string DocumentType { get; set; }
        public string DocumentId { get; set; }
        public string Content { get; set; }
        public DateTime IndexedAt { get; set; }
        public long Sequence { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
    }

    /// <summary>
    /// In-memory inverted-index search engine (spec TIER 2, system 6): index, search with filters and facets,
    /// unindex, and an enqueued reindex job.
    /// Repaired 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP) for two failing tests:
    /// <list type="bullet">
    /// <item>Facets_ReturnCountsPerStatus: the spec's own example (<c>GET /search?q=deployment&amp;facets=status,tier</c>
    /// returning deployment facets) treats the document type as searchable, so each document's type name is now
    /// indexed as one of its terms.</item>
    /// <item>Relevance_ExactMatchHigherThanPartial: "partial match" now works both ways (a query that is a prefix of a
    /// word, and a word of at least 3 letters that is a prefix of the query), scored exact 1.0 &gt; partial 0.6 &gt;
    /// prefix 0.5, mirroring the passing Go template's exact &gt; contains &gt; prefix order.</item>
    /// </list>
    /// Also: every mutation and search runs under one lock (the old reindex cleared the whole index while searches
    /// ran, and a reindex of one type wiped every other type's terms), and ties sort by insertion order.
    /// Touches: process memory only (no database, network, files or money).
    /// </summary>
    public class SearchIndexService
    {
        // Inverted index: term -> set of document keys. Guarded by _gate.
        private readonly Dictionary<string, HashSet<string>> _invertedIndex = new Dictionary<string, HashSet<string>>();

        // Document store. Guarded by _gate.
        private readonly Dictionary<string, SearchDocument> _documents = new Dictionary<string, SearchDocument>();

        private readonly object _gate = new object();
        private long _sequence;

        /// <summary>Shortest indexed word that may match as a prefix of a longer query word ("stri" for "stripe").</summary>
        private const int MinReversePrefixLength = 3;

        // Stop words
        private static readonly HashSet<string> StopWords = new HashSet<string>
        {
            "the","and","or","a","an","of","to","in","for","on","with","at","by"
        };

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

        /// <summary>
        /// Splits text on whitespace and punctuation, lowercases it and drops stop words (spec: "split on whitespace,
        /// lowercase, remove common words"). Input: any text (null allowed). Output: the tokens in order. Pure.
        /// </summary>
        private static IEnumerable<string> Tokenize(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) yield break;
            var tokens = text.Split(new[] { ' ', '\t', '\r', '\n', ',', '.', ';', ':', '-', '_' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var raw in tokens)
            {
                var token = raw.Trim().ToLowerInvariant();
                if (token.Length == 0) continue;
                if (StopWords.Contains(token)) continue;
                yield return token;
            }
        }

        /// <summary>
        /// The distinct terms a document is indexed under: its content tokens plus its document type name, so that a
        /// query naming the type ("deployment") finds documents of that type, as in the spec's facet example.
        /// 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Pure.
        /// </summary>
        private static IEnumerable<string> TermsOf(SearchDocument doc) =>
            Tokenize(doc.Content).Concat(Tokenize(doc.DocumentType)).Distinct();

        /// <summary>Adds a document's terms to the inverted index. Caller holds _gate. Touches: process memory.</summary>
        private void AddTerms(SearchDocument doc)
        {
            foreach (var term in TermsOf(doc))
            {
                if (!_invertedIndex.TryGetValue(term, out var set))
                {
                    set = new HashSet<string>();
                    _invertedIndex[term] = set;
                }
                set.Add(doc.DocumentKey);
            }
        }

        /// <summary>Removes a document's terms from the inverted index. Caller holds _gate. Touches: process memory.</summary>
        private void RemoveTerms(SearchDocument doc)
        {
            foreach (var term in TermsOf(doc))
            {
                if (_invertedIndex.TryGetValue(term, out var set))
                {
                    set.Remove(doc.DocumentKey);
                    if (set.Count == 0) _invertedIndex.Remove(term);
                }
            }
        }

        /// <summary>
        /// Indexes a document, replacing any earlier version with the same type and id (spec endpoint 1); it is
        /// searchable as soon as this returns (real-time indexing). Input: type, id, content, metadata.
        /// Output: success and indexed_at. Touches: process memory. Updated 2026-11-10 (session
        /// session_012zDydZCZ4AChqhEZ4oVtaP): runs under the index lock and records the insertion order.
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

            lock (_gate)
            {
                // Remove old terms if updating
                if (_documents.TryGetValue(doc.DocumentKey, out var oldDoc)) RemoveTerms(oldDoc);
                doc.Sequence = ++_sequence;
                _documents[doc.DocumentKey] = doc;
                AddTerms(doc);
            }

            return Task.FromResult(new IndexResponse { Success = true, IndexedAt = doc.IndexedAt });
        }

        /// <summary>
        /// Scores how one indexed term matches one query term: 1.0 exact, 0.6 partial (an indexed word of at least
        /// <see cref="MinReversePrefixLength"/> letters that begins the query word: "stri" for "stripe"), 0.5 prefix
        /// (the query word begins an indexed word: "stri" finds "stripe"), 0 no match. Spec: "exact match &gt; partial
        /// match &gt; prefix match". 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Pure.
        /// </summary>
        private static double MatchScore(string indexTerm, string queryTerm)
        {
            if (indexTerm == queryTerm) return 1.0;
            if (indexTerm.Length >= MinReversePrefixLength && queryTerm.StartsWith(indexTerm, StringComparison.Ordinal)) return 0.6;
            if (indexTerm.StartsWith(queryTerm, StringComparison.Ordinal)) return 0.5;
            return 0;
        }

        /// <summary>
        /// Searches the index (spec endpoints 2-4). Input: query, optional document type, "field:value" filters (all
        /// must match), facet fields, limit and offset. Output: the page of results ordered by relevance, then by
        /// insertion order; the total; has_more; and, when facets were asked for, per-field value counts over every
        /// matching document (not just the page). Touches: process memory.
        /// Updated 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): per-term best-match scoring (exact &gt;
        /// partial &gt; prefix), document-type terms, deterministic tie-break, runs under the index lock.
        /// </summary>
        public Task<SearchResponse> SearchAsync(SearchRequest request)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));
            var queryTerms = Tokenize(request.Query).Distinct().ToList();
            var limit = request.Limit > 0 ? request.Limit : 20;
            var offset = Math.Max(0, request.Offset);

            var filters = new List<KeyValuePair<string, string>>();
            foreach (var filter in request.Filters ?? Enumerable.Empty<string>())
            {
                var parts = (filter ?? string.Empty).Split(':', 2);
                if (parts.Length == 2) filters.Add(new KeyValuePair<string, string>(parts[0], parts[1]));
            }

            var scored = new List<(SearchDocument Doc, double Score)>();
            lock (_gate)
            {
                // Best score of each query term per document, summed over the query terms.
                var scores = new Dictionary<string, double>();
                foreach (var term in queryTerms)
                {
                    var best = new Dictionary<string, double>();
                    foreach (var entry in _invertedIndex)
                    {
                        var s = MatchScore(entry.Key, term);
                        if (s <= 0) continue;
                        foreach (var key in entry.Value)
                        {
                            if (!best.TryGetValue(key, out var prev) || s > prev) best[key] = s;
                        }
                    }
                    foreach (var kv in best)
                        scores[kv.Key] = (scores.TryGetValue(kv.Key, out var acc) ? acc : 0) + kv.Value;
                }

                foreach (var kv in scores)
                {
                    var doc = _documents[kv.Key];
                    if (!string.IsNullOrWhiteSpace(request.DocumentType) && doc.DocumentType != request.DocumentType) continue;
                    var keep = true;
                    foreach (var f in filters)
                    {
                        if (!doc.Metadata.TryGetValue(f.Key, out var metaVal) ||
                            !string.Equals(metaVal?.ToString(), f.Value, StringComparison.OrdinalIgnoreCase))
                        {
                            keep = false;
                            break;
                        }
                    }
                    if (keep) scored.Add((doc, kv.Value));
                }
            }

            var ordered = scored
                .OrderByDescending(r => r.Score)
                .ThenBy(r => r.Doc.Sequence)
                .Select(r => new SearchResultItem
                {
                    DocumentId = r.Doc.DocumentId,
                    DocumentType = r.Doc.DocumentType,
                    Relevance = r.Score,
                    Metadata = r.Doc.Metadata
                })
                .ToList();

            var total = ordered.Count;

            // Facets: COUNT(*) GROUP BY metadata field over every matching document.
            Dictionary<string, Dictionary<string, int>> facets = null;
            if (request.Facets != null && request.Facets.Any())
            {
                facets = new Dictionary<string, Dictionary<string, int>>();
                foreach (var facetField in request.Facets)
                {
                    var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                    foreach (var item in ordered)
                    {
                        if (item.Metadata != null && item.Metadata.TryGetValue(facetField, out var val))
                        {
                            var key = val?.ToString() ?? "null";
                            counts[key] = counts.TryGetValue(key, out var c) ? c + 1 : 1;
                        }
                    }
                    facets[facetField] = counts;
                }
            }

            return Task.FromResult(new SearchResponse
            {
                Results = ordered.Skip(offset).Take(limit).ToList(),
                Total = total,
                HasMore = offset + limit < total,
                Facets = facets
            });
        }

        /// <summary>
        /// Removes a document from the index (spec endpoint 5). Input: type and id. Output: success (also when it was
        /// not indexed: deleting is idempotent). Touches: process memory. Updated 2026-11-10 (session
        /// session_012zDydZCZ4AChqhEZ4oVtaP): runs under the index lock and removes the type term too.
        /// </summary>
        public Task<UnindexResponse> UnindexDocumentAsync(string documentType, string documentId)
        {
            var key = $"{documentType}:{documentId}";
            lock (_gate)
            {
                if (_documents.TryGetValue(key, out var doc))
                {
                    RemoveTerms(doc);
                    _documents.Remove(key);
                }
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
                    var docs = _documents.Values
                        .Where(d => documentType == null || d.DocumentType == documentType)
                        .ToList();
                    foreach (var doc in docs)
                    {
                        RemoveTerms(doc);
                        AddTerms(doc);
                    }
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