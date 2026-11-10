# Full-Text Search & Indexing

Reference contract for `saas_templates/<lang>/full_text_search_indexing_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# SEARCH-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `SEARCH-01` | Index user, search finds it |
| `SEARCH-02` | Index deployment, query works |
| `SEARCH-03` | Partial match: "stri" finds "stripe"; "ripe" does not |
| `SEARCH-04` | Filters: tier:team returns only team tier |
| `SEARCH-05` | Facets: shows count per status |
| `SEARCH-06` | Unindex: document no longer found after delete |
| `SEARCH-07` | Real-time: index updated within 100ms of create |
| `SEARCH-08` | Performance: 1M documents, search returns <200ms |
| `SEARCH-09` | Relevance: exact word match ranks higher than prefix match; equal scores keep insertion order |

## Contract

```text
PURPOSE:
Search users, deployments, activity, etc. by name, email, content.
Filter: tier, status, custom fields.
Sort: date, relevance, custom.
Faceting: show counts per category.

SCHEMA:
search_index (document_type, document_id, content [TEXT], indexed_at, metadata [JSON])
- content: all searchable text concatenated
- metadata: { user_id, tier, status, created_at, custom_field_1, ... }

ENDPOINTS:

1. Index document (called when user/deployment/etc created or updated)
   POST /search/index
   {
     document_type: 'user',
     document_id: 123,
     content: 'john doe john@example.com team member active',
     metadata: {
       user_id: 123,
       email: 'john@example.com',
       tier: 'team',
       status: 'active',
       created_at: '2026-01-15T...'
     }
   }
   Response: { success: true, indexed_at }

2. Search
   GET /search?q=john&document_type=user&limit=20&offset=0
   Response: {
     results: [
       { document_id: 123, document_type: 'user', relevance: 0.95, metadata: { email, tier, status } }
     ],
     total: 3,
     has_more: true
   }

3. Search with filters
   GET /search?q=stripe&document_type=deployment&filters=tier:team&filters=status:active&limit=20
   Response: { results: [...], total: 5 }

4. Search with facets (show counts)
   GET /search?q=deployment&facets=status,tier
   Response: {
     results: [...],
     facets: {
       status: { active: 45, draft: 12, archived: 3 },
       tier: { solo: 20, team: 30, enterprise: 10 }
     }
   }

5. Unindex document (called on delete)
   DELETE /search/documents/:document_type/:document_id
   Response: { success: true }

6. Re-index all (admin task, background job)
   POST /admin/search/reindex
   { document_type: 'user'|'deployment'|null }  // null = all types
   Response: { success: true, job_id: '...', status: 'enqueued' }

IMPLEMENTATION:
- Storage: Simple inverted index (word → [document_ids]) or Elasticsearch
- Tokenization: split on whitespace, lowercase, remove common words
- Matching: text is lower-cased and split into words on anything that is not a letter or digit. A query
  term matches a word that equals it or starts with it ("stri" finds "stripe"; "ripe" does not).
  A query of several terms returns only documents that match every term.
- Relevance: a term that equals a word scores higher than a term that is only a prefix of one. Equal
  scores keep insertion order (the document indexed first comes first). Amended 2026-11-10 after review on PR 19.
- Filters: metadata fields indexed separately, checked during query
- Facets: COUNT(*) GROUP BY metadata_field
- Real-time: index updated immediately on create/update
- Batch reindex: background job process (handled by background_jobs system)

SEARCH EXAMPLES:
- "john" → find all users with 'john' in name/email
- "stripe integration" → find deployments with both words
- "tier:team" → filter to team tier only
- "deployment tier:enterprise status:active" → complex query

TESTS:
- **SEARCH-01** Index user, search finds it
- **SEARCH-02** Index deployment, query works
- **SEARCH-03** Partial match: "stri" finds "stripe"; "ripe" does not
- **SEARCH-04** Filters: tier:team returns only team tier
- **SEARCH-05** Facets: shows count per status
- **SEARCH-06** Unindex: document no longer found after delete
- **SEARCH-07** Real-time: index updated within 100ms of create
- **SEARCH-08** Performance: 1M documents, search returns <200ms
- **SEARCH-09** Relevance: exact word match ranks higher than prefix match; equal scores keep insertion order
```
