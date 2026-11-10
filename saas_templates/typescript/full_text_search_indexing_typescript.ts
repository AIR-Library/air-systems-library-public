import { randomUUID } from 'crypto';

/**
 * SQL schema for a database-backed index (the service below keeps its index in memory). Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
 */
export const DDL = `
CREATE TABLE IF NOT EXISTS search_index (
    document_type VARCHAR(255) NOT NULL,
    document_id VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    indexed_at VARCHAR(64) NOT NULL,
    metadata TEXT NOT NULL, -- JSON string
    PRIMARY KEY (document_type, document_id)
);
CREATE INDEX IF NOT EXISTS idx_search_index_type ON search_index(document_type);
`;

export interface IndexRequest {
  document_type: string;
  document_id: string | number;
  content: string;
  metadata: Record<string, any>;
}

export interface IndexResponse {
  success: boolean;
  indexed_at: string;
}

export interface SearchQuery {
  q?: string;
  document_type?: string;
  limit?: number;
  offset?: number;
  filters?: string[];
  facets?: string[];
}

export interface SearchResult {
  document_id: string | number;
  document_type: string;
  relevance: number;
  metadata: Record<string, any>;
}

export interface SearchResponse {
  results: SearchResult[];
  total: number;
  has_more: boolean;
  facets?: Record<string, Record<string, number>>;
}

export interface UnindexResponse {
  success: boolean;
}

export interface ReindexResponse {
  success: boolean;
  job_id: string;
  status: 'enqueued';
}

/**
 * One indexed document as the engine holds it. `seq` is the internal number given when the document was (last)
 * indexed; posting lists hold these numbers in ascending order. `tokens` are the distinct terms of `content`.
 * Why: string keys in Sets made the 1,000,000-document search take 2.3 s (2026-11-10, session
 * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
 */
interface IndexDocument {
  seq: number;
  document_type: string;
  document_id: string | number;
  content: string;
  indexed_at: string;
  metadata: Record<string, any>;
  tokens: string[];
}

/** A word: a maximal run of Unicode letters and digits (spec SEARCH-03 amendment). */
const WORD_RUN = /[\p{L}\p{N}]+/gu;

/**
 * Splits text into search words as the spec now says: a word is a maximal run of Unicode letters and digits
 * (\p{L}, \p{N}); everything else separates words; each word is lower-cased with toLowerCase (JavaScript's
 * locale-independent default); there are no stop words. Queries are split the same way.
 * In: any text. Out: the words in order (repeats kept). ASCII-only text takes a fast character scan; anything
 * else uses the Unicode regex, so "café" is one word.
 * Why: SEARCH-03/09 amendment 2026-11-10 (review on PR 19). The previous rule split on whitespace only and removed
 * stop words, so "john@example.com" was one term and "the" was unsearchable, unlike the other languages.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
export function tokenize(text: string): string[] {
  if (!text) return [];
  const result: string[] = [];
  let ascii = true;
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) > 127) { ascii = false; break; }
  }
  if (!ascii) {
    for (const m of text.matchAll(WORD_RUN)) result.push(m[0].toLowerCase());
    return result;
  }
  const lower = text.toLowerCase();
  let start = -1;
  for (let i = 0; i <= lower.length; i++) {
    const c = i < lower.length ? lower.charCodeAt(i) : 32;
    const word = (c >= 97 && c <= 122) || (c >= 48 && c <= 57);
    if (word) {
      if (start < 0) start = i;
    } else if (start >= 0) {
      result.push(lower.slice(start, i));
      start = -1;
    }
  }
  return result;
}

/**
 * The distinct values of a short list, first occurrence first. In: an array. Out: a new array without repeats.
 * Why: a Set per document cost a fifth of the time to index 1,000,000 documents (2026-11-10, session
 * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
 */
function distinct(values: string[]): string[] {
  if (values.length > 32) return Array.from(new Set(values));
  const out: string[] = [];
  for (let i = 0; i < values.length; i++) {
    if (out.indexOf(values[i]) === -1) out.push(values[i]);
  }
  return out;
}

let lastStampMs = -1;
let lastStampIso = '';

/**
 * The current time as an ISO string, reusing the last string while the millisecond has not changed.
 * In: nothing. Out: e.g. "2026-11-10T12:00:00.000Z".
 * Why: formatting a fresh date for every one of 1,000,000 documents indexed in a burst took most of a second
 * (2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP). Touches: reads the clock.
 */
function nowIso(): string {
  const ms = Date.now();
  if (ms !== lastStampMs) {
    lastStampMs = ms;
    lastStampIso = new Date(ms).toISOString();
  }
  return lastStampIso;
}

/**
 * Splits a query into its text and its filters. `key:value` and `key:"quoted value"` inside the query are filters,
 * as are the explicit `filters` entries ("tier:team").
 * In: the query text and the explicit filters. Out: { queryText, filters }.
 * Why: unchanged behaviour; documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
export function parseQuery(q?: string, explicitFilters?: string[]): { queryText: string; filters: Map<string, string> } {
  const filters = new Map<string, string>();

  if (explicitFilters) {
    for (const f of explicitFilters) {
      const idx = f.indexOf(':');
      if (idx > 0) {
        const key = f.substring(0, idx).trim();
        const val = f.substring(idx + 1).trim();
        filters.set(key, val);
      }
    }
  }

  if (!q) {
    return { queryText: '', filters };
  }

  const inlineFilterRegex = /(\w+):"([^"]+)"|(\w+):([^\s]+)/g;
  let match;
  let cleanedQuery = q;

  while ((match = inlineFilterRegex.exec(q)) !== null) {
    const key = match[1] || match[3];
    const val = match[2] || match[4];
    filters.set(key, val);
    cleanedQuery = cleanedQuery.replace(match[0], '');
  }

  cleanedQuery = cleanedQuery.replace(/\s+/g, ' ').trim();
  return { queryText: cleanedQuery, filters };
}

/**
 * Which characters a term contains, as bits: a-z are bits 0-25, any digit bit 26, anything else bit 27.
 * A term can contain a query word only if it has all of the word's bits, so the vocabulary is grouped by this mask and
 * a query scans only the groups that could match. In: a term. Out: the mask.
 * Why: scanning all 1,000,000 terms for every query word was most of the search time (2026-11-10, session
 * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
 */
function charMask(term: string): number {
  let mask = 0;
  for (let i = 0; i < term.length; i++) {
    const c = term.charCodeAt(i);
    if (c >= 97 && c <= 122) mask |= 1 << (c - 97);
    else if (c >= 48 && c <= 57) mask |= 1 << 26;
    else mask |= 1 << 27;
  }
  return mask;
}

/**
 * Relevance of one query word against one word: equal > prefix (spec SEARCH-09). A word that only CONTAINS the
 * query word no longer matches at all (SEARCH-03: "ripe" does not find "stripe"); amended 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP.
 */
const SCORE_EXACT = 1.0;
const SCORE_PREFIX = 0.75;

/**
 * Index of `value` in the ascending array `list`, or of where it would go. In: a sorted number array and a number.
 * Out: the first index i with list[i] >= value. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP, for the
 * sorted posting lists. Touches: nothing.
 */
function lowerBound(list: number[], value: number): number {
  let lo = 0;
  let hi = list.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (list[mid] < value) lo = mid + 1; else hi = mid;
  }
  return lo;
}

/**
 * Removes `value` from the ascending array `list` if it is there. In: a sorted array and a number. Out: nothing
 * (the array is changed in place). Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function removeSorted(list: number[], value: number): void {
  const i = lowerBound(list, value);
  if (i < list.length && list[i] === value) list.splice(i, 1);
}

/**
 * First index at or after `from` whose value is >= `value`, in the ascending array `list`: steps 1, 2, 4, ... ahead
 * and then binary-searches, so walking a long list in small steps stays cheap.
 * In: a sorted array, a start index and a value. Out: the index (list.length when none).
 * Why: lets the search intersect its lists in one pass without building intermediate arrays (the 1,000,000-document
 * search, 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
 */
function gallop(list: number[], from: number, value: number): number {
  if (from >= list.length || list[from] >= value) return from;
  let step = 1;
  let lo = from;
  let hi = from + 1;
  while (hi < list.length && list[hi] < value) {
    lo = hi;
    step *= 2;
    hi = from + step;
  }
  if (hi > list.length) hi = list.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (list[mid] < value) lo = mid + 1; else hi = mid;
  }
  return lo;
}

/**
 * Union of ascending arrays, without repeats. In: sorted arrays. Out: a new sorted array (the only input itself when
 * there is one). Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function unionSorted(lists: number[][]): number[] {
  if (lists.length === 1) return lists[0];
  const merged: number[] = [];
  for (const l of lists) for (let i = 0; i < l.length; i++) merged.push(l[i]);
  merged.sort((x, y) => x - y);
  const out: number[] = [];
  for (let i = 0; i < merged.length; i++) {
    if (i === 0 || merged[i] !== merged[i - 1]) out.push(merged[i]);
  }
  return out;
}

/**
 * In-memory full-text search engine (spec TIER_2 system 6): an inverted index (term -> ascending list of document
 * numbers), a metadata index (field -> value -> list) for filters and facets, and a per-type list.
 * - Matching: every query word must equal a word of the document or be a prefix of one ("stri" finds "stripe";
 *   "ripe" does not). Only the vocabulary groups whose characters could contain a query word are scanned.
 * - Relevance: the mean over query words of the best match in the document (1 equal, 0.75 prefix).
 *   (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: words inside other words no longer match, SEARCH-03/09.)
 * - Order: relevance, highest first; ties in the order the documents were (last) indexed, earliest first.
 *   The lists are intersected in one pass that builds no intermediate list; only offset + limit results are kept (a
 *   bounded heap); the total and the facets count every match.
 * - Real time: index and unindex take effect at once.
 * Why: the search copied every document key into a Set, scanned the whole vocabulary per query word, scored and
 * sorted every match by parsing dates, and took 2,328 ms over 1,000,000 documents against a 200 ms budget (failing
 * "Test 8", rebuilt 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP). Touches: process memory only.
 */
export class FullTextSearchService {
  private nextSeq = 1;
  /** Live documents by internal number (index = seq; removed ones are undefined). */
  private docs: (IndexDocument | undefined)[] = [];
  /** "type:id" -> internal number of the live document. */
  private seqByKey = new Map<string, number>();
  private documentsByType = new Map<string, number[]>();
  /** term -> its posting: the term string kept once (documents point at it) and the ascending document numbers. */
  private invertedIndex = new Map<string, { term: string; ids: number[] }>();
  /**
   * The vocabulary grouped by {@link charMask}. A term whose posting list empties stays in its group until the group
   * is compacted (stale entries are skipped at query time because they are no longer in the inverted index).
   */
  private vocabByMask = new Map<number, string[]>();
  private staleByMask = new Map<number, number>();
  private metadataIndex = new Map<string, Map<string, number[]>>();

  /**
   * Adds or replaces one document. In: { document_type, document_id, content, metadata }. Out: { success, indexed_at }.
   * Replacing removes the old terms first, so the old words no longer find it. Touches: process memory only.
   * Rewritten 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (see the class block).
   */
  public async indexDocument(doc: IndexRequest): Promise<IndexResponse> {
    const { document_type, document_id, content, metadata } = doc;
    const docKey = `${document_type}:${document_id}`;
    const indexed_at = nowIso();

    const previous = this.seqByKey.get(docKey);
    if (previous !== undefined) {
      this.unindexSeq(previous);
    }

    const seq = this.nextSeq++;
    const tokens = distinct(tokenize(content));
    const meta = metadata || {};
    const indexDoc: IndexDocument = { seq, document_type, document_id, content, indexed_at, metadata: meta, tokens };

    this.docs[seq] = indexDoc;
    this.seqByKey.set(docKey, seq);

    // seq is the largest number so far, so pushing keeps every list in ascending order.
    let typeList = this.documentsByType.get(document_type);
    if (!typeList) { typeList = []; this.documentsByType.set(document_type, typeList); }
    typeList.push(seq);

    for (let i = 0; i < tokens.length; i++) {
      let posting = this.invertedIndex.get(tokens[i]);
      if (!posting) {
        posting = { term: tokens[i], ids: [] };
        this.invertedIndex.set(tokens[i], posting);
        const mask = charMask(tokens[i]);
        const group = this.vocabByMask.get(mask);
        if (group) group.push(tokens[i]); else this.vocabByMask.set(mask, [tokens[i]]);
      }
      // Share the one stored copy of the term instead of keeping this document's own copy of the string.
      tokens[i] = posting.term;
      posting.ids.push(seq);
    }

    for (const key of Object.keys(meta)) {
      const valStr = String(meta[key]);
      let valMap = this.metadataIndex.get(key);
      if (!valMap) { valMap = new Map(); this.metadataIndex.set(key, valMap); }
      let list = valMap.get(valStr);
      if (!list) { list = []; valMap.set(valStr, list); }
      list.push(seq);
    }

    return { success: true, indexed_at };
  }

  /**
   * Removes one document from every index. In: its type and id. Out: { success: true } (also when it was not
   * indexed). Touches: process memory only. Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
   */
  public async unindexDocument(documentType: string, documentId: string | number): Promise<UnindexResponse> {
    const seq = this.seqByKey.get(`${documentType}:${documentId}`);
    if (seq !== undefined) this.unindexSeq(seq);
    return { success: true };
  }

  /**
   * Removes the document with internal number `seq` from the type list, the term lists and the metadata lists, and
   * drops lists left empty. In: the number. Out: nothing. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: process memory only.
   */
  private unindexSeq(seq: number): void {
    const doc = this.docs[seq];
    if (!doc) return;
    this.docs[seq] = undefined;
    this.seqByKey.delete(`${doc.document_type}:${doc.document_id}`);

    const typeList = this.documentsByType.get(doc.document_type);
    if (typeList) {
      removeSorted(typeList, seq);
      if (typeList.length === 0) this.documentsByType.delete(doc.document_type);
    }

    for (const token of doc.tokens) {
      const posting = this.invertedIndex.get(token);
      if (posting) {
        removeSorted(posting.ids, seq);
        if (posting.ids.length === 0) {
          this.invertedIndex.delete(token);
          this.markStale(token);
        }
      }
    }

    for (const key of Object.keys(doc.metadata)) {
      const valMap = this.metadataIndex.get(key);
      if (!valMap) continue;
      const valStr = String(doc.metadata[key]);
      const list = valMap.get(valStr);
      if (list) {
        removeSorted(list, seq);
        if (list.length === 0) valMap.delete(valStr);
      }
      if (valMap.size === 0) this.metadataIndex.delete(key);
    }
  }

  /**
   * Notes that `term` left the vocabulary; when over half of its mask group is stale, the group is rebuilt from the
   * live terms (each once). In: the term. Out: nothing. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: process memory only.
   */
  private markStale(term: string): void {
    const mask = charMask(term);
    const stale = (this.staleByMask.get(mask) ?? 0) + 1;
    const group = this.vocabByMask.get(mask);
    if (!group) return;
    if (stale * 2 > group.length) {
      const live = Array.from(new Set(group.filter((t) => this.invertedIndex.has(t))));
      if (live.length === 0) this.vocabByMask.delete(mask); else this.vocabByMask.set(mask, live);
      this.staleByMask.delete(mask);
    } else {
      this.staleByMask.set(mask, stale);
    }
  }

  /**
   * Searches. In: { q, document_type, filters, facets, limit (default 20), offset (default 0) }. Out: { results
   * (document_id, document_type, relevance, metadata), total, has_more, facets when asked }. Matching, relevance and
   * order are described on the class. Touches: process memory only. Rewritten 2026-11-10, session
   * session_012zDydZCZ4AChqhEZ4oVtaP.
   */
  public async search(query: SearchQuery): Promise<SearchResponse> {
    const { queryText, filters } = parseQuery(query.q, query.filters);
    if (query.document_type) {
      filters.set('document_type', query.document_type);
    }
    const empty = (): SearchResponse => {
      const r: SearchResponse = { results: [], total: 0, has_more: false };
      if (query.facets && query.facets.length > 0) {
        r.facets = {};
        for (const f of query.facets) r.facets[f] = {};
      }
      return r;
    };

    // 1. The lists every match must be in: the type, each filter and each query word.
    const required: number[][] = [];
    const typeFilter = filters.get('document_type');
    if (typeFilter !== undefined) {
      const list = this.documentsByType.get(typeFilter);
      if (!list) return empty();
      required.push(list);
    }
    for (const [fKey, fVal] of filters.entries()) {
      if (fKey === 'document_type') continue;
      const list = this.metadataIndex.get(fKey)?.get(fVal);
      if (!list) return empty();
      required.push(list);
    }

    const queryTokens = distinct(tokenize(queryText));
    // For each query word, the terms it matches and how well.
    const matches: Map<string, number>[] = queryTokens.map(() => new Map<string, number>());
    if (queryTokens.length > 0) {
      const queryMasks = queryTokens.map(charMask);
      for (const [mask, group] of this.vocabByMask) {
        for (let q = 0; q < queryTokens.length; q++) {
          if ((mask & queryMasks[q]) !== queryMasks[q]) continue;
          const qt = queryTokens[q];
          for (let g = 0; g < group.length; g++) {
            const term = group[g];
            // A word matches when it equals the query word or starts with it (never when it only contains it).
            if (term.length < qt.length || !term.startsWith(qt) || !this.invertedIndex.has(term)) continue;
            matches[q].set(term, term.length === qt.length ? SCORE_EXACT : SCORE_PREFIX);
          }
        }
      }
      for (let q = 0; q < queryTokens.length; q++) {
        if (matches[q].size === 0) return empty();
        const lists: number[][] = [];
        for (const term of matches[q].keys()) lists.push(this.invertedIndex.get(term)!.ids);
        required.push(unionSorted(lists));
      }
    }

    // 2. Relevance. A query word whose matched terms all score the same scores that for every candidate.
    const constantScore: (number | null)[] = matches.map((m) => {
      let only: number | null = null;
      for (const v of m.values()) {
        if (only === null) only = v; else if (only !== v) return null;
      }
      return only;
    });
    const allConstant = constantScore.every((c) => c !== null);
    const relevanceOf = (doc: IndexDocument): number => {
      if (queryTokens.length === 0) return 1.0;
      let sum = 0;
      for (let q = 0; q < queryTokens.length; q++) {
        const c = constantScore[q];
        if (c !== null) { sum += c; continue; }
        let best = 0;
        for (let t = 0; t < doc.tokens.length; t++) {
          const s = matches[q].get(doc.tokens[t]);
          if (s !== undefined && s > best) best = s;
        }
        sum += best;
      }
      return parseFloat((sum / queryTokens.length).toFixed(4));
    };

    // 3. Keep the best offset + limit by (relevance desc, seq asc) in a bounded heap whose root is the worst kept.
    const limit = query.limit !== undefined ? Math.max(0, query.limit) : 20;
    const offset = query.offset !== undefined ? Math.max(0, query.offset) : 0;
    const keep = offset + limit;
    const heapRel: number[] = [];
    const heapSeq: number[] = [];
    // a is worse than b when its relevance is lower, or equal and it was indexed later.
    const worse = (ra: number, sa: number, rb: number, sb: number) => ra < rb || (ra === rb && sa > sb);
    const swap = (i: number, j: number) => {
      const r = heapRel[i]; heapRel[i] = heapRel[j]; heapRel[j] = r;
      const t = heapSeq[i]; heapSeq[i] = heapSeq[j]; heapSeq[j] = t;
    };
    const siftDown = (i: number) => {
      const n = heapRel.length;
      for (;;) {
        const l = 2 * i + 1;
        const r = l + 1;
        let w = i;
        if (l < n && worse(heapRel[l], heapSeq[l], heapRel[w], heapSeq[w])) w = l;
        if (r < n && worse(heapRel[r], heapSeq[r], heapRel[w], heapSeq[w])) w = r;
        if (w === i) return;
        swap(i, w);
        i = w;
      }
    };
    let constantRel: number | null = null;
    const offer = (seq: number, doc: IndexDocument) => {
      if (allConstant) {
        // Every match has the same relevance and matches arrive in seq order: the first `keep` are the answer.
        if (heapSeq.length < keep) {
          if (constantRel === null) constantRel = relevanceOf(doc);
          heapRel.push(constantRel); heapSeq.push(seq);
        }
        return;
      }
      if (keep === 0) return;
      const rel = relevanceOf(doc);
      if (heapRel.length < keep) {
        heapRel.push(rel); heapSeq.push(seq);
        let c = heapRel.length - 1;
        while (c > 0) {
          const p = (c - 1) >> 1;
          if (worse(heapRel[c], heapSeq[c], heapRel[p], heapSeq[p])) { swap(c, p); c = p; } else break;
        }
      } else if (worse(heapRel[0], heapSeq[0], rel, seq)) {
        heapRel[0] = rel; heapSeq[0] = seq;
        siftDown(0);
      }
    };

    // 4. Facets count every match.
    const facetFields = query.facets && query.facets.length > 0 ? query.facets : null;
    let facetResults: Record<string, Record<string, number>> | undefined;
    if (facetFields) {
      facetResults = {};
      for (const f of facetFields) facetResults[f] = {};
    }

    // 5. One pass over the matches: walk the shortest list and gallop through the others, building no new lists.
    let total = 0;
    const visit = (seq: number) => {
      const doc = this.docs[seq]!;
      total++;
      if (facetResults) {
        for (const f of facetFields!) {
          const val = doc.metadata[f];
          if (val !== undefined && val !== null) {
            const valStr = String(val);
            facetResults[f][valStr] = (facetResults[f][valStr] || 0) + 1;
          }
        }
      }
      offer(seq, doc);
    };
    if (required.length === 0) {
      for (let seq = 1; seq < this.docs.length; seq++) if (this.docs[seq]) visit(seq);
    } else {
      required.sort((x, y) => x.length - y.length);
      const lead = required[0];
      const cursors = new Array<number>(required.length).fill(0);
      outer: for (let i = 0; i < lead.length; i++) {
        const v = lead[i];
        for (let k = 1; k < required.length; k++) {
          const list = required[k];
          const at = gallop(list, cursors[k], v);
          cursors[k] = at;
          if (at >= list.length) break outer;
          if (list[at] !== v) continue outer;
        }
        visit(v);
      }
    }
    if (total === 0) return empty();

    const order = heapRel.map((_, i) => i).sort((a, b) =>
      heapRel[b] - heapRel[a] || heapSeq[a] - heapSeq[b]);
    const page = order.slice(offset).map((i) => {
      const doc = this.docs[heapSeq[i]]!;
      return {
        document_id: doc.document_id,
        document_type: doc.document_type,
        relevance: heapRel[i],
        metadata: doc.metadata
      };
    });

    const response: SearchResponse = { results: page, total, has_more: offset + page.length < total };
    if (facetResults) response.facets = facetResults;
    return response;
  }

  /**
   * Re-tokenizes stored documents of one type (null: all) in the background. In: the type or null. Out: { success,
   * job_id (random UUID), status: 'enqueued' }. Touches: process memory; one zero-delay timer. Documented 2026-11-10,
   * session session_012zDydZCZ4AChqhEZ4oVtaP (job id now from crypto.randomUUID, not Math.random).
   */
  public async reindexAll(documentType: string | null): Promise<ReindexResponse> {
    const jobId = randomUUID();
    setTimeout(async () => {
      const docsToReindex = this.docs.filter(
        (doc): doc is IndexDocument => doc !== undefined && (documentType === null || doc.document_type === documentType)
      );
      for (const doc of docsToReindex) {
        await this.indexDocument({
          document_type: doc.document_type,
          document_id: doc.document_id,
          content: doc.content,
          metadata: doc.metadata
        });
      }
    }, 0);
    return { success: true, job_id: jobId, status: 'enqueued' };
  }

  /** Empties every index. In/out: nothing. Touches: process memory. Rewritten 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. */
  public clear(): void {
    this.docs = [];
    this.nextSeq = 1;
    this.seqByKey.clear();
    this.documentsByType.clear();
    this.invertedIndex.clear();
    this.vocabByMask.clear();
    this.staleByMask.clear();
    this.metadataIndex.clear();
  }
}

export const searchService = new FullTextSearchService();
