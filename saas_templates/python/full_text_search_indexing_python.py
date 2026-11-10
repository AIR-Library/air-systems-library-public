"""
System 6: Full-Text Search & Indexing (TIER_2 spec, system 6)

A self-contained full-text search module for a reusable SaaS library, with the same API contract
as the other languages.

Storage: an in-memory inverted index per document type (term -> {doc_key: term_frequency}, each
         posting list kept in indexing order), a vocabulary string for partial matching, and a
         metadata index (field -> lower-cased value -> doc keys) for filters.
Tokenization: a word is a maximal run of Unicode letters and digits (\\p{L}, \\p{N}); each word is
          lower-cased with str.lower; no stop words (SEARCH-03 as amended 2026-11-10).
Matching: every query word must match the document (spec: "stripe integration" finds documents
          with both words). A query word matches a document word equal to it or starting with it
          ("stri" finds "stripe"; "ripe" does not).
Relevance: per query word 1.0 for an exact word match and 2/3 for a prefix match, averaged over the
           query words; so exact > prefix, in [0, 1]. Ties: insertion order, the document indexed first
           comes first (SEARCH-09 as amended 2026-11-10).
Filters: metadata field:value, case-insensitive, from the filters argument or embedded in q.
Facets: counts per metadata value over all matches (not just the returned page).

Repair 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP
    Why: the spec's performance test (1,000,000 documents, search under 200 ms) took 8.3 s. The old
    search scanned the whole vocabulary in Python for partial matches, scored every candidate
    document in Python and sorted them all. Now a one-word or empty query never touches documents
    one by one: the vocabulary scan is a C-level str.find over one string, the total is the length
    of the posting lists (or a C-level set intersection when filters apply), and only the returned
    page is read, newest first, from the ordered posting lists. Queries of two or more words
    intersect posting sets in C and score only the documents that match every word.
    The budget was not loosened. Other changes: queries are AND (spec), ties break by indexing order
    (deterministic, not by float timestamps), document types may not contain ':' (it made keys
    ambiguous), and the engine has a public clear().
Amendment 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec amended after review on PR 19)
    Words are runs of Unicode letters/digits ("café" is one word; it was split at "é"), no stop words,
    a query word matches by word prefix (was any substring, so "ripe" found "stripe"), and equal scores
    keep insertion order (was newest first).
Touches: memory only (no database, network or files). SCHEMA_SQL is reference DDL for persisting
documents; this module does not execute it.
"""

from __future__ import annotations

import heapq
import itertools
import re
import threading
import time
import uuid
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Database schema (executable DDL). Embedded for reference / migration use.
# ---------------------------------------------------------------------------
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS search_index (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    document_type   TEXT    NOT NULL,
    document_id     TEXT    NOT NULL,
    content         TEXT    NOT NULL,
    indexed_at      TEXT    NOT NULL,
    metadata        TEXT    NOT NULL,
    UNIQUE (document_type, document_id)
);
CREATE INDEX IF NOT EXISTS idx_search_index_type_id
    ON search_index (document_type, document_id);
"""

EXACT_SCORE = 1.0
PARTIAL_SCORE = 2.0 / 3.0

# [^\W_] is a Unicode letter or digit: for str patterns \w is exactly the characters for which isalnum() is
# true (letters L*, numbers N*) plus "_", so removing "_" leaves \p{L} and \p{N} (SEARCH-03, 2026-11-10).
_TOKEN_RE = re.compile(r"[^\W_]+")
_FILTER_RE = re.compile(r"(\w+):(\S+)")
_VOCAB_SEP = "\n"  # never part of a token (not a letter or digit)


# ---------------------------------------------------------------------------
# Tokenization
# ---------------------------------------------------------------------------
def tokenize(text: str) -> List[str]:
    """Split text into words and lower-case them. Input: text (None allowed).

    Output: the words in order, duplicates kept. A word is a maximal run of Unicode letters and digits;
    everything else separates words; each word is lower-cased with str.lower after the split; no stop words.
    Why: SEARCH-03 as amended 2026-11-10 (the old split was [a-z0-9]+ on the lower-cased text, so "café"
    became "caf", and it dropped stop words). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
    """
    if not text:
        return []
    return [w.lower() for w in _TOKEN_RE.findall(text)]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
class Document:
    """One indexed document. ``seq`` is its indexing order (higher = indexed later).

    ``term_tf`` maps each token to its count in the content. __slots__ keep a million of these
    affordable. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (was a dataclass holding the
    token list). Touches memory only.
    """

    __slots__ = ("document_type", "document_id", "key", "content", "indexed_at", "metadata", "term_tf", "seq")

    def __init__(self, document_type: str, document_id: str, key: str, content: str, indexed_at: float,
                 metadata: Dict[str, Any], term_tf: Dict[str, int], seq: int) -> None:
        self.document_type = document_type
        self.document_id = document_id
        self.key = key
        self.content = content
        self.indexed_at = indexed_at
        self.metadata = metadata
        self.term_tf = term_tf
        self.seq = seq

    @property
    def tokens(self) -> List[str]:
        """The document's tokens, re-derived from its content (kept for compatibility)."""
        return tokenize(self.content)


class _TypeIndex:
    """Documents and posting lists of one document type.

    ``docs``: key -> Document and ``postings``: term -> {key: tf}; both dicts are in indexing order
    because a re-indexed document is removed and added again at the end. 2026-11-10, session
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
    """

    __slots__ = ("docs", "postings")

    def __init__(self) -> None:
        self.docs: Dict[str, Document] = {}
        self.postings: Dict[str, Dict[str, int]] = {}


# ---------------------------------------------------------------------------
# Search engine
# ---------------------------------------------------------------------------
class SearchEngine:
    """In-memory inverted-index full-text search engine (see the module docstring).

    Thread-safe (one re-entrant lock). Rebuilt 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP
    for the 1M-document / 200 ms budget. Touches memory only.
    """

    def __init__(self) -> None:
        """Create an empty engine. Touches memory only."""
        self._lock = threading.RLock()
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self.clear()

    def clear(self) -> None:
        """Remove every document, index entry and reindex job. Added 2026-11-10, session
        session_012zDydZCZ4AChqhEZ4oVtaP, so callers (and tests) need not reach into internals."""
        with self._lock:
            self._types: Dict[str, _TypeIndex] = {}
            self._docs: Dict[str, Document] = {}
            # field -> lower-cased str(value) -> doc key (one document) or set of keys (several)
            self._meta: Dict[str, Dict[str, Any]] = {}
            self._vocab_blob = _VOCAB_SEP
            self._vocab_pending: List[str] = []
            self._vocab_entries = 0  # terms written to the vocabulary (live or dead)
            self._vocab_dead = 0
            self._seq = 0
            self._jobs.clear()

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _doc_key(document_type: str, document_id: Any) -> str:
        """Key of a document: '<type>:<id>' (types cannot contain ':', so keys are unambiguous)."""
        return f"{document_type}:{document_id}"

    def _term_alive(self, term: str) -> bool:
        """True if any document type still has a posting list for ``term``."""
        return any(term in ti.postings for ti in self._types.values())

    def _add(self, doc: Document) -> None:
        """Add a document to its type's postings, the global map and the metadata index (lock held).

        2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
        """
        ti = self._types.get(doc.document_type)
        if ti is None:
            ti = self._types[doc.document_type] = _TypeIndex()
        ti.docs[doc.key] = doc
        self._docs[doc.key] = doc
        postings = ti.postings
        for term, tf in doc.term_tf.items():
            bucket = postings.get(term)
            if bucket is None:
                if not self._term_alive(term):
                    self._vocab_pending.append(term)
                    self._vocab_entries += 1
                    if len(self._vocab_pending) >= max(4096, self._vocab_entries // 16):
                        self._flush_vocabulary()
                bucket = postings[term] = {}
            bucket[doc.key] = tf
        for field_name, value in doc.metadata.items():
            if value is None:
                continue
            values = self._meta.setdefault(field_name, {})
            norm = str(value).lower()
            held = values.get(norm)
            if held is None:
                values[norm] = doc.key
            elif isinstance(held, set):
                held.add(doc.key)
            else:
                values[norm] = {held, doc.key}

    def _remove(self, doc: Document) -> None:
        """Undo ``_add`` for one document (lock held). Emptied terms are marked dead in the vocabulary.

        2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
        """
        ti = self._types[doc.document_type]
        ti.docs.pop(doc.key, None)
        self._docs.pop(doc.key, None)
        for term in doc.term_tf:
            bucket = ti.postings.get(term)
            if bucket is None:
                continue
            bucket.pop(doc.key, None)
            if not bucket:
                del ti.postings[term]
                if not self._term_alive(term):
                    self._vocab_dead += 1
        if not ti.docs:
            del self._types[doc.document_type]
        for field_name, value in doc.metadata.items():
            if value is None:
                continue
            values = self._meta.get(field_name, {})
            norm = str(value).lower()
            held = values.get(norm)
            if isinstance(held, set):
                held.discard(doc.key)
                if len(held) == 1:
                    values[norm] = next(iter(held))
            elif held == doc.key:
                del values[norm]
            if not values:
                self._meta.pop(field_name, None)

    def _flush_vocabulary(self) -> None:
        """Append pending new terms to the vocabulary string (lock held).

        Called in batches of at least 4096 terms and 1/16 of the vocabulary, so indexing pays an amortised
        linear cost and a search never has to join a million new terms first. 2026-11-10, session
        session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
        """
        if self._vocab_pending:
            self._vocab_blob += _VOCAB_SEP.join(self._vocab_pending) + _VOCAB_SEP
            self._vocab_pending = []

    def _vocabulary(self) -> str:
        """The vocabulary as one '\\n'-separated string, merging pending terms and dropping dead ones
        when they pile up (lock held). 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP."""
        if self._vocab_dead > 1024 and self._vocab_dead * 2 > self._vocab_entries:
            live: Set[str] = set()
            for ti in self._types.values():
                live.update(ti.postings)
            self._vocab_blob = _VOCAB_SEP + _VOCAB_SEP.join(sorted(live)) + _VOCAB_SEP
            self._vocab_pending = []
            self._vocab_entries = len(live)
            self._vocab_dead = 0
        self._flush_vocabulary()
        return self._vocab_blob

    def _partial_terms(self, token: str) -> Set[str]:
        """Live vocabulary terms that START with ``token`` but are not equal to it (lock held).

        Every term in the vocabulary string follows a separator, so searching for separator + token finds
        exactly the terms with that prefix; str.find runs in C, one pass over the vocabulary's bytes plus
        Python work per matching term. Why: SEARCH-03 as amended 2026-11-10 ("ripe" must not find "stripe";
        this used to match any substring). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
        """
        blob = self._vocabulary()
        found: Set[str] = set()
        needle = _VOCAB_SEP + token
        i = blob.find(needle)
        while i != -1:
            start = i + 1
            end = blob.find(_VOCAB_SEP, start)
            term = blob[start:end]
            if term != token and self._term_alive(term):
                found.add(term)
            i = blob.find(needle, end)
        return found

    def _filter_keys(self, filters: Dict[str, str]) -> Optional[Set[str]]:
        """Keys of documents matching every field:value filter (case-insensitive), or None if no filters.

        2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: metadata is indexed separately (spec) instead
        of being checked on every candidate. Touches memory only.
        """
        result: Optional[Set[str]] = None
        for field_name, expected in filters.items():
            held = self._meta.get(field_name, {}).get(str(expected).lower())
            keys = set() if held is None else (held if isinstance(held, set) else {held})
            result = keys if result is None else (result & keys)  # '&' makes a new set: the index is never mutated
            if not result:
                return set()
        return result  # read-only: may be the index's own set

    @staticmethod
    def _oldest_first(dicts: List[Dict[str, Any]], docs: Dict[str, Document]) -> Iterator[str]:
        """Merge several insertion-ordered key dicts into one stream of keys, the first indexed first.

        Lazy: reads only as many keys as the caller consumes. Why: SEARCH-09 as amended 2026-11-10 (equal
        scores keep insertion order; this was newest first). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches memory only.
        """
        if len(dicts) == 1:
            return iter(dicts[0])
        streams = [((docs[k].seq, k) for k in d) for d in dicts]
        return (k for _seq, k in heapq.merge(*streams))

    # -- public API --------------------------------------------------------
    def index_document(
        self,
        document_type: str,
        document_id: Any,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """POST /search/index: index (or re-index) a document so it is searchable at once.

        Inputs: document_type (non-empty, no ':'), document_id (any, stored as str), content, metadata.
        Output: {success, indexed_at}. Raises ValueError on a missing type/id. 2026-11-10, session
        session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
        """
        if not document_type or not isinstance(document_type, str):
            raise ValueError("document_type is required")
        if ":" in document_type:
            raise ValueError("document_type must not contain ':'")
        if document_id is None:
            raise ValueError("document_id is required")

        content = content or ""
        term_tf: Dict[str, int] = {}
        for token in tokenize(content):
            term_tf[token] = term_tf.get(token, 0) + 1
        indexed_at = time.time()
        key = self._doc_key(document_type, document_id)
        with self._lock:
            existing = self._docs.get(key)
            if existing is not None:
                self._remove(existing)
            self._seq += 1
            self._add(Document(document_type, str(document_id), key, content, indexed_at,
                               dict(metadata or {}), term_tf, self._seq))
        return {"success": True, "indexed_at": indexed_at}

    def unindex_document(self, document_type: str, document_id: Any) -> Dict[str, Any]:
        """DELETE /search/documents/:type/:id: remove a document (no error if absent). Returns {success}.

        Touches memory only. Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
        """
        key = self._doc_key(document_type, document_id)
        with self._lock:
            doc = self._docs.get(key)
            if doc is not None:
                self._remove(doc)
        return {"success": True}

    def search(
        self,
        q: str = "",
        document_type: Optional[str] = None,
        filters: Optional[Dict[str, str]] = None,
        facets: Optional[List[str]] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        GET /search: documents matching every word of ``q``, ranked by relevance, insertion order on ties
        (SEARCH-09 as amended 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP; was newest first).

        Inputs: q (words plus optional field:value filters), document_type, filters, facets,
        limit (>= 0), offset (>= 0).
        Returns:
            {
              results: [{document_id, document_type, relevance, metadata}],
              total: int,
              has_more: bool,
              facets: {field: {value: count}}  # only when facets requested
            }
        2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: rebuilt for the 200 ms budget (module
        docstring). Touches memory only.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise ValueError("limit must be a non-negative integer")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("offset must be a non-negative integer")
        filters = dict(filters or {})
        facets = list(facets or [])
        query_tokens, embedded_filters = self._parse_query(q)
        for k, v in embedded_filters.items():
            filters.setdefault(k, v)
        query_tokens = list(dict.fromkeys(query_tokens))  # a repeated word adds nothing

        with self._lock:
            if document_type is not None:
                ti = self._types.get(document_type)
                type_indexes = [ti] if ti is not None else []
            else:
                type_indexes = list(self._types.values())
            allowed = self._filter_keys(filters) if filters else None
            want = offset + limit

            if len(query_tokens) <= 1:
                page, total, matched = self._search_grouped(query_tokens, type_indexes, allowed, offset, limit,
                                                             need_all=bool(facets))
            else:
                page, total, matched = self._search_scored(query_tokens, type_indexes, allowed, want)
                page = page[offset:want]

            results = [
                {
                    "document_id": doc.document_id,
                    "document_type": doc.document_type,
                    "relevance": round(score, 4),
                    "metadata": dict(doc.metadata),
                }
                for score, doc in page
            ]
            response: Dict[str, Any] = {
                "results": results,
                "total": total,
                "has_more": (offset + len(results)) < total,
            }
            if facets:
                response["facets"] = self._facet_counts(facets, matched)
            return response

    def _search_grouped(self, query_tokens: List[str], type_indexes: List[_TypeIndex],
                        allowed: Optional[Set[str]], offset: int, limit: int,
                        need_all: bool) -> Tuple[List[Tuple[float, Document]], int, Iterable[str]]:
        """Search for zero or one word without scoring documents one by one (lock held).

        Every match of a group has the same score: no word -> all documents (1.0); one word -> exact
        matches (1.0), then documents that only match partially (2/3). Totals come from posting-list
        lengths, or C-level set operations when filters apply or partial lists overlap. The page is read
        lazily, in insertion order (2026-11-10, SEARCH-09; was newest first), from the ordered posting lists (skipping ``offset`` in C where possible),
        or picked from the matching keys when filters leave few of them. Returns (the page as
        (score, doc) pairs, total, all matching keys when ``need_all`` else ()). 2026-11-10, session
        session_012zDydZCZ4AChqhEZ4oVtaP.
        """
        # (score, insertion-ordered key dicts, dicts whose keys are excluded from this group)
        groups: List[Tuple[float, List[Dict[str, Any]], List[Dict[str, Any]]]] = []
        if not query_tokens:
            groups.append((EXACT_SCORE, [ti.docs for ti in type_indexes if ti.docs], []))
        else:
            token = query_tokens[0]
            exact = [ti.postings[token] for ti in type_indexes if token in ti.postings]
            partial_terms = sorted(self._partial_terms(token))
            partial = [ti.postings[t] for ti in type_indexes for t in partial_terms if t in ti.postings]
            groups.append((EXACT_SCORE, exact, []))
            groups.append((PARTIAL_SCORE, partial, exact))

        page: List[Tuple[float, Document]] = []
        total = 0
        skip = offset
        matched: List[Iterable[str]] = []
        for score, dicts, exclude in groups:
            if not dicts:
                continue
            size = sum(len(d) for d in dicts)
            members: Optional[Set[str]] = None  # keys must be in here to count (None: every key counts)
            if not exclude and (score == EXACT_SCORE or len(dicts) == 1):
                # disjoint lists (one per document type, or a single list): no union needed
                if allowed is None:
                    hits: List[Iterable[str]] = list(dicts)
                    group_total = size
                else:
                    # count in C without building a set; the hits themselves stay lazy (C-level filter objects)
                    hits = [filter(d.__contains__, allowed) if len(allowed) < len(d) else filter(allowed.__contains__, d)
                            for d in dicts]
                    members = allowed
                    group_total = sum(sum(map(d.__contains__, allowed)) if len(allowed) < len(d)
                                      else sum(map(allowed.__contains__, d)) for d in dicts)
            else:
                union: Set[str] = set().union(*dicts)
                for d in exclude:
                    if len(d) > len(union):  # cost follows the smaller side
                        union = set(itertools.filterfalse(d.__contains__, union))
                    else:
                        union.difference_update(d)
                if allowed is not None:
                    union &= allowed
                hits, members, group_total = [union], union, len(union)
            total += group_total
            if need_all:
                hits = [h if isinstance(h, (set, dict)) else set(h) for h in hits]  # read twice: facets and page
                matched.extend(hits)
            if len(page) >= limit:
                continue
            if skip >= group_total:
                skip -= group_total
                continue
            take = limit - len(page)
            if members is not None and group_total * 8 < size:
                # few matches left by the filters: rank them directly instead of walking the lists
                oldest = heapq.nsmallest(skip + take, itertools.chain(*hits), key=lambda k: self._docs[k].seq)
                keys = oldest[skip:]
            else:
                stream: Iterable[str] = self._oldest_first(dicts, self._docs)
                if members is not None:
                    stream = (k for k, _ in itertools.groupby(stream) if k in members)  # groupby drops repeats
                keys = list(itertools.islice(stream, skip, skip + take))
            skip = 0
            page.extend((score, self._docs[k]) for k in keys)
        all_keys: Iterable[str] = itertools.chain(*matched) if need_all else ()
        return page, total, all_keys

    def _search_scored(self, query_tokens: List[str], type_indexes: List[_TypeIndex],
                       allowed: Optional[Set[str]], want: int) -> Tuple[List[Tuple[float, Document]], int, Set[str]]:
        """Search for two or more words: keep the documents that match every word (exact or partial), then
        score only those (lock held).

        Words are applied fewest matches first; each step is a C-level set operation, or a
        membership check per remaining candidate when that is cheaper. Score = mean over words of 1.0
        (exact) or 2/3 (prefix). Returns (best ``want`` pairs ordered by score desc then insertion order,
        total, matching keys). 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP; ties by insertion order
        since the SEARCH-09 amendment of 2026-11-10.
        """
        plans = []
        for token in query_tokens:
            terms = self._partial_terms(token)
            terms.add(token)
            buckets = [ti.postings[t] for ti in type_indexes for t in sorted(terms) if t in ti.postings]
            plans.append((sum(len(b) for b in buckets), buckets))
        plans.sort(key=lambda plan: plan[0])  # fewest matches first; stable, so ties keep query order
        candidates: Optional[Set[str]] = allowed  # never mutated in place: may be the metadata index's set
        for _size, buckets in plans:
            if candidates is not None and len(candidates) * len(buckets) < sum(len(b) for b in buckets):
                candidates = {k for k in candidates if any(k in b for b in buckets)}
            else:
                matches: Set[str] = set().union(*buckets)
                candidates = matches if candidates is None else (candidates & matches)
            if not candidates:
                return [], 0, set()
        assert candidates is not None
        n = len(query_tokens)

        def rank(key: str) -> Tuple[float, int]:
            """Sort key: higher score first, then insertion order (SEARCH-09 as amended; was newest first). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
            doc = self._docs[key]
            score = sum(EXACT_SCORE if t in doc.term_tf else PARTIAL_SCORE for t in query_tokens) / n
            return (-score, doc.seq)

        best = heapq.nsmallest(want, candidates, key=rank)
        page = [(-rank(k)[0], self._docs[k]) for k in best]
        return page, len(candidates), candidates

    def _facet_counts(self, fields: List[str], keys: Iterable[str]) -> Dict[str, Dict[str, int]]:
        """Count str(metadata[field]) values over all matching documents (missing values skipped).

        Values are listed by count desc, then value. Linear in the number of matches. 2026-11-10,
        session session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
        """
        counts: Dict[str, Dict[str, int]] = {f: {} for f in fields}
        for key in keys:
            metadata = self._docs[key].metadata
            for f in fields:
                value = metadata.get(f)
                if value is not None:
                    c = counts[f]
                    s = str(value)
                    c[s] = c.get(s, 0) + 1
        return {f: dict(sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))) for f, c in counts.items()}

    def reindex_all(
        self,
        document_type: Optional[str] = None,
        source: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ) -> Dict[str, Any]:
        """
        POST /admin/search/reindex: re-index all documents (admin/background task).

        `source` maps document_type -> list of raw documents ({document_id, content, metadata}). When
        omitted, the engine re-tokenizes the documents it already holds (of ``document_type``, or all).
        The work runs inline here; in production enqueue it with the background-jobs system.
        Returns {success, job_id, status: 'enqueued'} (spec); get_job(job_id) shows 'completed'.
        Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
        """
        job_id = str(uuid.uuid4())
        with self._lock:
            self._jobs[job_id] = {"document_type": document_type, "status": "enqueued", "created_at": time.time()}
        self._do_reindex(job_id, document_type, source)
        return {"success": True, "job_id": job_id, "status": "enqueued"}

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Return a copy of a reindex job ({document_type, status, created_at}) or None."""
        with self._lock:
            job = self._jobs.get(job_id)
            return dict(job) if job else None

    # -- internals ---------------------------------------------------------
    def _do_reindex(
        self,
        job_id: str,
        document_type: Optional[str],
        source: Optional[Dict[str, List[Dict[str, Any]]]],
    ) -> None:
        """Run a reindex job and mark it completed. Existing documents keep their relative order.

        2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: rebuilds from content (the old version only
        re-added the same token lists). Touches memory only.
        """
        with self._lock:
            if source is None:
                existing = sorted(
                    (d for d in self._docs.values() if document_type is None or d.document_type == document_type),
                    key=lambda d: d.seq,
                )
                for doc in existing:
                    self.index_document(doc.document_type, doc.document_id, doc.content, doc.metadata)
            else:
                types = [document_type] if document_type else list(source.keys())
                for dtype in types:
                    for raw in source.get(dtype, []):
                        self.index_document(dtype, raw["document_id"], raw.get("content", ""), raw.get("metadata", {}))
            job = self._jobs.get(job_id)
            if job is not None:
                job["status"] = "completed"

    @staticmethod
    def _parse_query(q: str) -> Tuple[List[str], Dict[str, str]]:
        """Split a query into free-text tokens and embedded field:value filters."""
        if not q:
            return [], {}
        filters: Dict[str, str] = {}
        tokens: List[str] = []
        for part in q.split():
            m = _FILTER_RE.fullmatch(part)
            if m:
                filters[m.group(1)] = m.group(2)
            else:
                tokens.extend(tokenize(part))
        return tokens, filters


# ---------------------------------------------------------------------------
# Module-level default engine (singleton) for drop-in use.
# ---------------------------------------------------------------------------
_default_engine = SearchEngine()


def get_engine() -> SearchEngine:
    """Return the shared default SearchEngine instance."""
    return _default_engine


# ---------------------------------------------------------------------------
# HTTP-style endpoint handlers (identical contract across languages).
# These wrap the engine and return JSON-shaped dicts.
# ---------------------------------------------------------------------------
def handle_index(payload: Dict[str, Any]) -> Dict[str, Any]:
    """POST /search/index"""
    return _default_engine.index_document(
        document_type=payload.get("document_type"),
        document_id=payload.get("document_id"),
        content=payload.get("content", ""),
        metadata=payload.get("metadata", {}),
    )


def handle_search(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    GET /search
    params: q, document_type, filters (list of 'field:value' or dict),
            facets (comma-separated list or list), limit, offset
    """
    filters: Dict[str, str] = {}
    raw_filters = params.get("filters")
    if isinstance(raw_filters, dict):
        filters = {str(k): str(v) for k, v in raw_filters.items()}
    elif isinstance(raw_filters, (list, tuple)):
        for item in raw_filters:
            if isinstance(item, str) and ":" in item:
                k, v = item.split(":", 1)
                filters[k] = v
    elif isinstance(raw_filters, str) and ":" in raw_filters:
        k, v = raw_filters.split(":", 1)
        filters[k] = v

    facets: List[str] = []
    raw_facets = params.get("facets")
    if isinstance(raw_facets, str):
        facets = [f.strip() for f in raw_facets.split(",") if f.strip()]
    elif isinstance(raw_facets, (list, tuple)):
        facets = [str(f) for f in raw_facets]

    return _default_engine.search(
        q=params.get("q", ""),
        document_type=params.get("document_type"),
        filters=filters,
        facets=facets,
        limit=int(params.get("limit", 20)),
        offset=int(params.get("offset", 0)),
    )


def handle_unindex(document_type: str, document_id: Any) -> Dict[str, Any]:
    """DELETE /search/documents/:document_type/:document_id"""
    return _default_engine.unindex_document(document_type, document_id)


def handle_reindex(payload: Dict[str, Any]) -> Dict[str, Any]:
    """POST /admin/search/reindex"""
    return _default_engine.reindex_all(
        document_type=payload.get("document_type"),
        source=payload.get("source"),
    )


__all__ = [
    "SearchEngine",
    "Document",
    "tokenize",
    "get_engine",
    "handle_index",
    "handle_search",
    "handle_unindex",
    "handle_reindex",
    "SCHEMA_SQL",
]
