const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');

class SearchEngine extends EventEmitter {
  /**
   * Opens the better-sqlite3 database, creates the index table and the in-memory inverted index.
   * In: dbPath (default ':memory:') and options { clock: () => ms } (default Date.now) for indexed_at.
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] The index is keyed by an insertion sequence number: every
   * document gets a seq the first time it is indexed (kept when it is re-indexed), postings hold seqs, and ties in
   * relevance are broken by seq (SEARCH-09, "the document indexed first comes first"). No stop words (SEARCH-03).
   * Touches: the database. First reviewed in PR 18 (2026-11-09, session 04ec72ff).
   */
  constructor(dbPath = ':memory:', options = {}) {
    super();
    this.db = new Database(dbPath);
    this.clock = typeof options.clock === 'function' ? options.clock : () => Date.now();
    this._initSchema();
    this._upsertStmt = this.db.prepare(`
      INSERT OR REPLACE INTO search_index
      (document_type, document_id, content, indexed_at, metadata)
      VALUES (?, ?, ?, ?, ?)
    `);
    this._deleteStmt = this.db.prepare(`DELETE FROM search_index WHERE document_type = ? AND document_id = ?`);
    this._resetMemory();
  }

  /**
   * Empties the in-memory index (not the table). invertedIndex: word -> Set of seq; wordsByHead: the first two code
   * points of a word -> Set of words; docsBySeq[seq] -> doc or undefined; seqByKey: docKey -> seq. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
   */
  _resetMemory() {
    this.invertedIndex = new Map();
    this.wordsByHead = new Map(); // first two code points of a word -> Set of words (prefix lookup without a full scan)
    this.docsBySeq = [];
    this.seqByKey = new Map();
    this.liveCount = 0;
  }

  /** Number of documents currently indexed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
  get size() {
    return this.liveCount;
  }

  /**
   * Creates the search_index table. Touches: the database. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
   */
  _initSchema() {
    const createTableSQL = `
      CREATE TABLE IF NOT EXISTS search_index (
        document_type TEXT NOT NULL,
        document_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        indexed_at TEXT NOT NULL,
        metadata TEXT NOT NULL,
        PRIMARY KEY (document_type, document_id)
      );
    `;
    this.db.exec(createTableSQL);
  }

  /**
   * Splits text into words: maximal runs of Unicode letters and digits (\p{L}, \p{N}); everything else separates
   * words. Each word is lower-cased with String.prototype.toLowerCase (locale-independent). No stop words.
   * In: a string. Out: the words in order (duplicates kept). Why: SEARCH-03 amended 2026-11-10 ("café" is one word,
   * punctuation such as "@" and "." separates). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  _tokenize(text) {
    if (!text) return [];
    const words = String(text).match(/[\p{L}\p{N}]+/gu);
    return words ? words.map(w => w.toLowerCase()) : [];
  }

  _docKey(type, id) {
    return `${type}:${id}`;
  }

  /**
   * Adds or removes one document's distinct words in the inverted index. In: words, the document's seq.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (postings hold seqs, not keys). Touches memory only.
   */
  _addToInvertedIndex(words, seq) {
    for (const word of words) {
      let set = this.invertedIndex.get(word);
      if (!set) {
        set = new Set();
        this.invertedIndex.set(word, set);
        const head = this._head(word);
        let heads = this.wordsByHead.get(head);
        if (!heads) {
          heads = new Set();
          this.wordsByHead.set(head, heads);
        }
        heads.add(word);
      }
      set.add(seq);
    }
  }

  _removeFromInvertedIndex(words, seq) {
    for (const word of words) {
      const set = this.invertedIndex.get(word);
      if (set) {
        set.delete(seq);
        if (set.size === 0) {
          this.invertedIndex.delete(word);
          const head = this._head(word);
          const heads = this.wordsByHead.get(head);
          if (heads) {
            heads.delete(word);
            if (heads.size === 0) this.wordsByHead.delete(head);
          }
        }
      }
    }
  }

  /** The first two code points of a word (its prefix bucket). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
  _head(word) {
    const it = word[Symbol.iterator]();
    const a = it.next();
    const b = it.next();
    return b.done ? a.value : a.value + b.value;
  }

  /**
   * Puts one parsed document into memory, keeping its seq if it was indexed before. In: type, id, content words,
   * metadata. Out: nothing. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
   */
  _putInMemory(document_type, document_id, words, metadata) {
    const docKey = this._docKey(document_type, document_id);
    const unique = Array.from(new Set(words));
    let seq = this.seqByKey.get(docKey);
    const prev = seq === undefined ? undefined : this.docsBySeq[seq];
    if (prev) {
      this._removeFromInvertedIndex(prev.words, seq);
    } else {
      if (seq === undefined) {
        seq = this.docsBySeq.length;
        this.seqByKey.set(docKey, seq);
      }
      this.liveCount++;
    }
    this.docsBySeq[seq] = { document_type, document_id, words: unique, metadata };
    this._addToInvertedIndex(unique, seq);
  }

  /** Drops one document from memory. Out: true when it was there. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
  _dropFromMemory(docKey) {
    const seq = this.seqByKey.get(docKey);
    const doc = seq === undefined ? undefined : this.docsBySeq[seq];
    if (!doc) return false;
    this._removeFromInvertedIndex(doc.words, seq);
    this.docsBySeq[seq] = undefined;
    this.seqByKey.delete(docKey);
    this.liveCount--;
    return true;
  }

  /**
   * Stores or replaces one document and adds its words to the inverted index. Output: { success, indexed_at } or an
   * error. A re-indexed document keeps its place in insertion order. [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP]
   * prepared statement reused, injectable clock. Touches: the database and memory. First reviewed in PR 18.
   */
  indexDocument(payload) {
    const {
      document_type,
      document_id,
      content,
      metadata
    } = payload;

    if (!document_type || document_id == null || !content || !metadata) {
      throw new Error('Invalid payload');
    }

    const indexed_at = new Date(this.clock()).toISOString();
    this._upsertStmt.run(document_type, document_id, content, indexed_at, JSON.stringify(metadata));
    this._putInMemory(document_type, document_id, this._tokenize(content), metadata);

    this.emit('indexed', { document_type, document_id });
    return { success: true, indexed_at };
  }

  /**
   * Removes one document from the table and the inverted index. Output: { success }. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] works on the seq-keyed index; prepared statement reused. Touches: the database and memory.
   */
  unindexDocument(document_type, document_id) {
    const docKey = this._docKey(document_type, document_id);
    const had = this._dropFromMemory(docKey);
    // The table row is deleted either way, so the call is idempotent.
    this._deleteStmt.run(document_type, document_id);
    if (had) this.emit('unindexed', { document_type, document_id });
    return { success: true };
  }

  /**
   * True when a document's metadata has every field:value filter. A filter splits at its FIRST ":" so a value may
   * contain ":" (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches nothing.
   */
  _applyFilters(doc, filterParams) {
    for (const f of filterParams) {
      const at = String(f).indexOf(':');
      if (at <= 0) continue;
      const field = f.slice(0, at);
      const value = f.slice(at + 1);
      const docValue = doc.metadata[field];
      if (docValue == null || String(docValue) !== value) {
        return false;
      }
    }
    return true;
  }

  /**
   * For one query term, the postings that match it: the word equal to the term (exact) and every other word that
   * starts with it (prefix). In: a lower-cased term. Out: { exact: Set|null, prefix: Set[], size }.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (SEARCH-03: "ripe" never matches "stripe"). Touches memory only.
   */
  _termPostings(term) {
    const exact = this.invertedIndex.get(term) || null;
    const prefix = [];
    let size = exact ? exact.size : 0;
    const head = this._head(term);
    const scan = (words) => {
      for (const word of words) {
        if (word !== term && word.startsWith(term)) {
          const set = this.invertedIndex.get(word);
          prefix.push(set);
          size += set.size;
        }
      }
    };
    if (head.length === term.length && Array.from(term).length === 1) {
      // A one-character term: every bucket whose head starts with it.
      for (const [h, words] of this.wordsByHead) if (h.startsWith(term)) scan(words);
    } else {
      const words = this.wordsByHead.get(head);
      if (words) scan(words);
    }
    return { exact, prefix, size };
  }

  /**
   * Finds documents by words and prefixes, optional type and filters, ranked by relevance, with facets on request.
   * Matching (SEARCH-03/09, amended 2026-11-10): the query is split like content; a term matches a word equal to it
   * (scores 2) or starting with it (scores 1); a document must match EVERY term; relevance = score / (2 x terms), so
   * an exact word ranks above a prefix; equal scores keep insertion order (seq). Results are bucketed by score in
   * seq order instead of sorted, so 1M matches stay under the 200 ms budget (SEARCH-08).
   * Output: { results, total, has_more, facets? }. [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] rewritten.
   * Touches memory only. First reviewed in PR 18 (2026-11-09, session 04ec72ff).
   */
  search(params) {
    const {
      q = '',
      document_type,
      limit = 20,
      offset = 0,
      filters = [],
      facets = ''
    } = params;

    const terms = Array.from(new Set(this._tokenize(q)));
    const filterArray = Array.isArray(filters) ? filters : (filters ? [filters] : []);
    const facetFields = facets ? facets.split(',').map(f => f.trim()).filter(Boolean) : [];
    const facetsObj = {};
    for (const field of facetFields) facetsObj[field] = {};

    const postings = terms.map(t => this._termPostings(t));
    const nTerms = terms.length;
    const keep = offset + limit; // a score bucket never needs more than its first offset + limit documents
    // Buckets by score (index = score - nTerms); each holds its first `keep` seqs in seq order, plus a count.
    const buckets = Array.from({ length: nTerms + 1 }, () => ({ seqs: [], count: 0 }));
    let total = 0;

    const accept = (seq, score) => {
      const doc = this.docsBySeq[seq];
      if (!doc) return;
      if (document_type && doc.document_type !== document_type) return;
      if (filterArray.length && !this._applyFilters(doc, filterArray)) return;
      total++;
      const bucket = buckets[nTerms === 0 ? 0 : score - nTerms];
      if (bucket.count < keep) bucket.seqs.push(seq);
      bucket.count++;
      for (let f = 0; f < facetFields.length; f++) {
        const field = facetFields[f];
        const val = doc.metadata[field];
        if (val != null) facetsObj[field][val] = (facetsObj[field][val] || 0) + 1;
      }
    };
    const termScore = (p, seq) => {
      if (p.exact && p.exact.has(seq)) return 2;
      if (p.prefix.length > 16) {
        // Many prefix words (e.g. the term "1"): merge their postings once, so each check stays O(1).
        if (!p.merged) {
          p.merged = new Set();
          for (const set of p.prefix) for (const x of set) p.merged.add(x);
        }
        return p.merged.has(seq) ? 1 : 0;
      }
      for (let i = 0; i < p.prefix.length; i++) if (p.prefix[i].has(seq)) return 1;
      return 0;
    };
    const n = this.docsBySeq.length;

    if (nTerms === 0) {
      for (let seq = 0; seq < n; seq++) accept(seq, 0);
    } else if (postings.some(p => p.size === 0)) {
      // A term that matches no word: no document matches every term.
    } else if (Math.min(...postings.map(p => p.size)) * 8 < n) {
      // Selective query: walk the smallest term's postings in seq order and check the other terms.
      const smallest = postings.reduce((a, b) => (b.size < a.size ? b : a));
      const seqs = new Set(smallest.exact ? smallest.exact : []);
      for (const set of smallest.prefix) for (const seq of set) seqs.add(seq);
      const ordered = Array.from(seqs).sort((a, b) => a - b);
      for (const seq of ordered) {
        let score = 0;
        for (const p of postings) {
          const ts = termScore(p, seq);
          if (ts === 0) { score = -1; break; }
          score += ts;
        }
        if (score > 0) accept(seq, score);
      }
    } else {
      // Broad query: per-term scores in typed arrays (one pass over each posting), then one pass in seq order.
      const score = new Uint16Array(n);
      const matched = new Uint16Array(n);
      for (const p of postings) {
        const best = new Uint8Array(n);
        for (const set of p.prefix) for (const seq of set) best[seq] = 1;
        if (p.exact) for (const seq of p.exact) best[seq] = 2;
        for (let seq = 0; seq < n; seq++) {
          if (best[seq] !== 0) { score[seq] += best[seq]; matched[seq]++; }
        }
      }
      for (let seq = 0; seq < n; seq++) if (matched[seq] === nTerms) accept(seq, score[seq]);
    }

    // Highest score first; inside a score, insertion order.
    const paged = [];
    let skip = offset;
    for (let b = buckets.length - 1; b >= 0 && paged.length < limit; b--) {
      const bucket = buckets[b];
      if (skip >= bucket.count) { skip -= bucket.count; continue; }
      const bucketScore = nTerms === 0 ? 0 : b + nTerms;
      for (let i = skip; i < bucket.seqs.length && paged.length < limit; i++) {
        const doc = this.docsBySeq[bucket.seqs[i]];
        paged.push({
          document_id: doc.document_id,
          document_type: doc.document_type,
          relevance: nTerms === 0 ? 1 : bucketScore / (2 * nTerms),
          metadata: doc.metadata
        });
      }
      skip = 0;
    }

    const response = { results: paged, total, has_more: offset + limit < total };
    if (facetFields.length > 0) response.facets = facetsObj;
    return response;
  }

  /**
   * Rebuilds the in-memory index from the table (one type or all). Every row is parsed before the live index
   * changes; reindex_completed or reindex_failed is emitted on the next tick. Output: { success, job_id, status }. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] rebuilt on the seq-keyed index; documents keep their insertion order.
   * Touches: the database (read) and memory.
   */
  reindexAll(payload) {
    const { document_type } = payload || {};
    const job_id = uuidv4();
    // Simulate background job by immediate execution
    const whereClause = document_type ? 'WHERE document_type = ?' : '';
    const sql = `SELECT document_type, document_id, content, metadata FROM search_index ${whereClause}`;
    const params = document_type ? [document_type] : [];

    // Read and parse every row first; the live index changes only once all of them parsed, so a bad row
    // (metadata edited outside this class) leaves search as it was and reports reindex_failed (CodeRabbit, PR 18).
    let parsed;
    try {
      parsed = this.db.prepare(sql).all(...params).map(row => ({
        document_type: row.document_type,
        document_id: row.document_id,
        words: this._tokenize(row.content),
        metadata: JSON.parse(row.metadata)
      }));
    } catch (error) {
      // Events go out on the next tick, so a listener attached right after this call still hears them.
      setImmediate(() => this.emit('reindex_failed', { job_id, error }));
      return { success: true, job_id, status: 'enqueued' };
    }

    // Drop what is in memory for the affected types, then load the parsed rows. A document that was indexed before
    // keeps its seq, so insertion order (and tie-breaking) survives a reindex (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
    for (let seq = 0; seq < this.docsBySeq.length; seq++) {
      const doc = this.docsBySeq[seq];
      if (!doc || (document_type && doc.document_type !== document_type)) continue;
      this._removeFromInvertedIndex(doc.words, seq);
      this.docsBySeq[seq] = undefined;
      this.liveCount--;
    }
    for (const row of parsed) {
      this._putInMemory(row.document_type, row.document_id, row.words, row.metadata);
    }
    setImmediate(() => this.emit('reindex_completed', { job_id }));

    return { success: true, job_id, status: 'enqueued' };
  }
}

// Export a singleton instance for simplicity. The class rides along as `.SearchEngine` so a caller (or a test) can
// build an engine of its own (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
const engine = new SearchEngine();
engine.SearchEngine = SearchEngine;
module.exports = engine;
