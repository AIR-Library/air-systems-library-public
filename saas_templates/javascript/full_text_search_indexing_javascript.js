const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');

class SearchEngine extends EventEmitter {
  constructor(dbPath = ':memory:') {
    super();
    this.db = new Database(dbPath);
    this._initSchema();
    this.invertedIndex = new Map(); // word -> Set of docKey
    this.documents = new Map(); // docKey -> { document_type, document_id, contentTokens, metadata }
    this.stopWords = new Set(['the', 'and', 'or', 'a', 'an', 'of', 'to', 'in', 'is', 'it']);
  }

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

  _tokenize(text) {
    if (!text) return [];
    return text
      .toLowerCase()
      .split(/\s+/)
      .filter(word => word && !this.stopWords.has(word));
  }

  _docKey(type, id) {
    return `${type}:${id}`;
  }

  _addToInvertedIndex(tokens, docKey) {
    tokens.forEach(token => {
      if (!this.invertedIndex.has(token)) {
        this.invertedIndex.set(token, new Set());
      }
      this.invertedIndex.get(token).add(docKey);
    });
  }

  _removeFromInvertedIndex(tokens, docKey) {
    tokens.forEach(token => {
      const set = this.invertedIndex.get(token);
      if (set) {
        set.delete(docKey);
        if (set.size === 0) this.invertedIndex.delete(token);
      }
    });
  }

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

    const indexed_at = new Date().toISOString();
    const docKey = this._docKey(document_type, document_id);
    const tokens = this._tokenize(content);

    // Remove previous if exists
    const prev = this.documents.get(docKey);
    if (prev) {
      this._removeFromInvertedIndex(prev.contentTokens, docKey);
    }

    // Insert/replace DB row
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO search_index
      (document_type, document_id, content, indexed_at, metadata)
      VALUES (?, ?, ?, ?, ?)
    `);
    stmt.run(
      document_type,
      document_id,
      content,
      indexed_at,
      JSON.stringify(metadata)
    );

    // Update in-memory structures
    this._addToInvertedIndex(tokens, docKey);
    this.documents.set(docKey, {
      document_type,
      document_id,
      contentTokens: tokens,
      metadata
    });

    this.emit('indexed', { document_type, document_id });
    return { success: true, indexed_at };
  }

  unindexDocument(document_type, document_id) {
    const docKey = this._docKey(document_type, document_id);
    const doc = this.documents.get(docKey);
    if (!doc) {
      // Still attempt DB delete for idempotency
      const stmt = this.db.prepare(`
        DELETE FROM search_index WHERE document_type = ? AND document_id = ?
      `);
      stmt.run(document_type, document_id);
      return { success: true };
    }

    // Remove from inverted index
    this._removeFromInvertedIndex(doc.contentTokens, docKey);
    this.documents.delete(docKey);

    // Delete from DB
    const stmt = this.db.prepare(`
      DELETE FROM search_index WHERE document_type = ? AND document_id = ?
    `);
    stmt.run(document_type, document_id);

    this.emit('unindexed', { document_type, document_id });
    return { success: true };
  }

  _matchScore(doc, queryTokens) {
    let score = 0;
    const contentSet = new Set(doc.contentTokens);
    for (const q of queryTokens) {
      if (contentSet.has(q)) {
        score += 2; // exact match
      } else {
        // partial or prefix
        let partial = false;
        for (const token of contentSet) {
          if (token.includes(q)) {
            score += 1;
            partial = true;
            break;
          }
        }
        if (!partial) {
          for (const token of contentSet) {
            if (token.startsWith(q)) {
              score += 0.5;
              break;
            }
          }
        }
      }
    }
    return score;
  }

  _applyFilters(doc, filterParams) {
    for (const f of filterParams) {
      const [field, value] = f.split(':');
      if (!field) continue;
      const docValue = doc.metadata[field];
      if (docValue == null || String(docValue) !== value) {
        return false;
      }
    }
    return true;
  }

  search(params) {
    const {
      q = '',
      document_type,
      limit = 20,
      offset = 0,
      filters = [],
      facets = ''
    } = params;

    const queryTokens = this._tokenize(q);
    const filterArray = Array.isArray(filters) ? filters : (filters ? [filters] : []);
    const facetFields = facets ? facets.split(',').map(f => f.trim()).filter(Boolean) : [];

    // Gather candidate docKeys
    let candidateKeys = new Set();
    if (queryTokens.length === 0) {
      // If no query, start with all docs of type (if provided)
      for (const key of this.documents.keys()) {
        if (!document_type || key.startsWith(`${document_type}:`)) {
          candidateKeys.add(key);
        }
      }
    } else {
      queryTokens.forEach(token => {
        const set = this.invertedIndex.get(token);
        if (set) {
          for (const key of set) {
            if (!document_type || key.startsWith(`${document_type}:`)) {
              candidateKeys.add(key);
            }
          }
        }
        // also consider prefix matches
        for (const [word, keys] of this.invertedIndex.entries()) {
          if (word.startsWith(token)) {
            for (const key of keys) {
              if (!document_type || key.startsWith(`${document_type}:`)) {
                candidateKeys.add(key);
              }
            }
          }
        }
      });
    }

    // Score and filter
    const results = [];
    for (const key of candidateKeys) {
      const doc = this.documents.get(key);
      if (!doc) continue;
      if (document_type && doc.document_type !== document_type) continue;
      if (!this._applyFilters(doc, filterArray)) continue;
      const relevance = this._matchScore(doc, queryTokens);
      results.push({
        document_id: doc.document_id,
        document_type: doc.document_type,
        relevance,
        metadata: doc.metadata
      });
    }

    // Sort by relevance desc then by indexed_at desc (fallback)
    results.sort((a, b) => b.relevance - a.relevance);

    const total = results.length;
    const paged = results.slice(offset, offset + limit);
    const has_more = offset + limit < total;

    const response = {
      results: paged,
      total,
      has_more
    };

    if (facetFields.length > 0) {
      const facetsObj = {};
      for (const field of facetFields) {
        const counts = {};
        for (const r of results) {
          const val = r.metadata[field];
          if (val != null) {
            counts[val] = (counts[val] || 0) + 1;
          }
        }
        facetsObj[field] = counts;
      }
      response.facets = facetsObj;
    }

    return response;
  }

  reindexAll(payload) {
    const { document_type } = payload || {};
    const job_id = uuidv4();
    // Simulate background job by immediate execution
    const whereClause = document_type ? 'WHERE document_type = ?' : '';
    const sql = `SELECT document_type, document_id, content, metadata FROM search_index ${whereClause}`;
    const params = document_type ? [document_type] : [];

    let rows;
    try {
      rows = this.db.prepare(sql).all(...params);
    } catch (error) {
      // Events go out on the next tick, so a listener attached right after this call still hears them.
      setImmediate(() => this.emit('reindex_failed', { job_id, error }));
      return { success: true, job_id, status: 'enqueued' };
    }

    // Clear current in-memory index for affected types
    if (document_type) {
      for (const key of this.documents.keys()) {
        if (key.startsWith(`${document_type}:`)) {
          const doc = this.documents.get(key);
          this._removeFromInvertedIndex(doc.contentTokens, key);
          this.documents.delete(key);
        }
      }
    } else {
      this.invertedIndex.clear();
      this.documents.clear();
    }

    rows.forEach(row => {
      const docKey = this._docKey(row.document_type, row.document_id);
      const tokens = this._tokenize(row.content);
      const metadata = JSON.parse(row.metadata);
      this._addToInvertedIndex(tokens, docKey);
      this.documents.set(docKey, {
        document_type: row.document_type,
        document_id: row.document_id,
        contentTokens: tokens,
        metadata
      });
    });
    setImmediate(() => this.emit('reindex_completed', { job_id }));

    return { success: true, job_id, status: 'enqueued' };
  }
}

// Export a singleton instance for simplicity
module.exports = new SearchEngine();
