"""
Test suite for System 6: Full-Text Search & Indexing.

Covers every case in the spec's TESTS section:
  - Index user, search finds it
  - Index deployment, query works
  - Partial match: "stri" finds "stripe"
  - Filters: tier:team returns only team tier
  - Facets: shows count per status
  - Unindex: document no longer found after delete
  - Real-time: index updated within 100ms of create
  - Performance: 1M documents, search returns <200ms
  - Relevance: exact match ranks higher than partial
"""

import time
import unittest

from full_text_search_indexing_python import (
    SearchEngine,
    tokenize,
    handle_index,
    handle_search,
    handle_unindex,
    handle_reindex,
    get_engine,
)


class TestTokenization(unittest.TestCase):
    def test_basic_tokenization(self):
        self.assertEqual(tokenize("John Doe"), ["john", "doe"])

    def test_stop_words_removed(self):
        self.assertEqual(tokenize("the quick brown fox"), ["quick", "brown", "fox"])

    def test_punctuation_stripped(self):
        self.assertEqual(tokenize("john@example.com, active!"), ["john", "example", "com", "active"])

    def test_empty(self):
        self.assertEqual(tokenize(""), [])
        self.assertEqual(tokenize(None), [])  # type: ignore[arg-type]


class TestIndexAndSearch(unittest.TestCase):
    def setUp(self):
        self.engine = SearchEngine()

    def test_index_user_search_finds_it(self):
        self.engine.index_document(
            "user", 123,
            "john doe john@example.com team member active",
            {"user_id": 123, "email": "john@example.com", "tier": "team", "status": "active"},
        )
        res = self.engine.search(q="john", document_type="user")
        self.assertEqual(res["total"], 1)
        self.assertEqual(res["results"][0]["document_id"], "123")
        self.assertEqual(res["results"][0]["document_type"], "user")
        self.assertIn("email", res["results"][0]["metadata"])

    def test_index_deployment_query_works(self):
        self.engine.index_document(
            "deployment", 456,
            "stripe integration production",
            {"tier": "team", "status": "active"},
        )
        res = self.engine.search(q="stripe integration", document_type="deployment")
        self.assertEqual(res["total"], 1)
        self.assertEqual(res["results"][0]["document_id"], "456")

    def test_partial_match(self):
        self.engine.index_document(
            "deployment", 789,
            "stripe payment gateway",
            {"tier": "team", "status": "active"},
        )
        res = self.engine.search(q="stri")
        self.assertGreaterEqual(res["total"], 1)
        self.assertEqual(res["results"][0]["document_id"], "789")

    def test_filters_tier_team_only(self):
        self.engine.index_document("user", 1, "alice", {"tier": "team", "status": "active"})
        self.engine.index_document("user", 2, "bob", {"tier": "solo", "status": "active"})
        self.engine.index_document("user", 3, "carol", {"tier": "team", "status": "draft"})
        res = self.engine.search(q="", document_type="user", filters={"tier": "team"})
        ids = {r["document_id"] for r in res["results"]}
        self.assertEqual(ids, {"1", "3"})
        self.assertEqual(res["total"], 2)

    def test_facets_show_count_per_status(self):
        self.engine.index_document("deployment", 1, "a", {"status": "active", "tier": "team"})
        self.engine.index_document("deployment", 2, "b", {"status": "active", "tier": "team"})
        self.engine.index_document("deployment", 3, "c", {"status": "draft", "tier": "solo"})
        self.engine.index_document("deployment", 4, "d", {"status": "archived", "tier": "enterprise"})
        res = self.engine.search(q="", document_type="deployment", facets=["status", "tier"])
        self.assertEqual(res["facets"]["status"], {"active": 2, "draft": 1, "archived": 1})
        self.assertEqual(res["facets"]["tier"], {"team": 2, "solo": 1, "enterprise": 1})

    def test_unindex_document_no_longer_found(self):
        self.engine.index_document("user", 10, "dave", {"tier": "team"})
        self.assertEqual(self.engine.search(q="dave")["total"], 1)
        self.engine.unindex_document("user", 10)
        self.assertEqual(self.engine.search(q="dave")["total"], 0)

    def test_real_time_index_update_within_100ms(self):
        start = time.time()
        self.engine.index_document("user", 20, "erin", {"tier": "team"})
        res = self.engine.search(q="erin")
        elapsed_ms = (time.time() - start) * 1000
        self.assertEqual(res["total"], 1)
        self.assertLess(elapsed_ms, 100)

    def test_relevance_exact_ranks_higher_than_partial(self):
        self.engine.index_document("user", 1, "stripe", {"tier": "team"})
        self.engine.index_document("user", 2, "stripes and more", {"tier": "team"})
        res = self.engine.search(q="stripe", document_type="user")
        self.assertEqual(res["total"], 2)
        # Exact match ("stripe") should rank above partial ("stripes").
        self.assertEqual(res["results"][0]["document_id"], "1")
        self.assertGreater(res["results"][0]["relevance"], res["results"][1]["relevance"])

    def test_has_more_and_pagination(self):
        for i in range(1, 6):
            self.engine.index_document("user", i, f"user{i}", {"tier": "team"})
        res = self.engine.search(q="user", document_type="user", limit=2, offset=0)
        self.assertEqual(len(res["results"]), 2)
        self.assertTrue(res["has_more"])
        self.assertEqual(res["total"], 5)
        res2 = self.engine.search(q="user", document_type="user", limit=2, offset=4)
        self.assertEqual(len(res2["results"]), 1)
        self.assertFalse(res2["has_more"])

    def test_complex_query_with_embedded_filters(self):
        self.engine.index_document("deployment", 1, "stripe integration", {"tier": "enterprise", "status": "active"})
        self.engine.index_document("deployment", 2, "stripe integration", {"tier": "team", "status": "active"})
        res = self.engine.search(q="stripe tier:enterprise", document_type="deployment")
        self.assertEqual(res["total"], 1)
        self.assertEqual(res["results"][0]["document_id"], "1")

    def test_all_query_words_must_match(self):
        """Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: spec example "stripe integration ->
        find deployments with both words"; exact words outrank partial ones; ties newest first."""
        self.engine.index_document("deployment", 1, "stripe integration", {})
        self.engine.index_document("deployment", 2, "stripe only", {})
        self.engine.index_document("deployment", 3, "stripes integrations", {})
        self.engine.index_document("deployment", 4, "stripe integration again", {})
        res = self.engine.search(q="stripe integration", document_type="deployment")
        self.assertEqual(res["total"], 3)
        self.assertEqual([r["document_id"] for r in res["results"]], ["4", "1", "3"])
        self.assertEqual(res["results"][0]["relevance"], 1.0)
        self.assertLess(res["results"][2]["relevance"], 1.0)

    def test_no_match_returns_empty(self):
        self.engine.index_document("user", 1, "alice", {"tier": "team"})
        res = self.engine.search(q="zzzznotfound")
        self.assertEqual(res["total"], 0)
        self.assertEqual(res["results"], [])
        self.assertFalse(res["has_more"])

    def test_reindex_all(self):
        self.engine.index_document("user", 1, "alice", {"tier": "team"})
        self.engine.index_document("deployment", 1, "stripe", {"tier": "team"})
        res = self.engine.reindex_all()
        self.assertTrue(res["success"])
        self.assertIn("job_id", res)
        self.assertEqual(res["status"], "enqueued")
        # Data still searchable after reindex.
        self.assertEqual(self.engine.search(q="alice")["total"], 1)
        self.assertEqual(self.engine.search(q="stripe")["total"], 1)

    def test_reindex_all_specific_type(self):
        self.engine.index_document("user", 1, "alice", {"tier": "team"})
        self.engine.index_document("deployment", 1, "stripe", {"tier": "team"})
        res = self.engine.reindex_all(document_type="user")
        self.assertTrue(res["success"])
        self.assertEqual(self.engine.search(q="alice")["total"], 1)

    def test_reindex_from_source(self):
        source = {
            "user": [
                {"document_id": 1, "content": "alice smith", "metadata": {"tier": "team"}},
                {"document_id": 2, "content": "bob jones", "metadata": {"tier": "solo"}},
            ]
        }
        res = self.engine.reindex_all(source=source)
        self.assertTrue(res["success"])
        self.assertEqual(self.engine.search(q="alice")["total"], 1)
        self.assertEqual(self.engine.search(q="bob")["total"], 1)


class TestPerformance(unittest.TestCase):
    def test_one_million_documents_search_under_200ms(self):
        engine = SearchEngine()
        # Build a realistic 1M-document corpus.
        n = 1_000_000
        for i in range(n):
            content = f"document {i} stripe integration deployment active"
            engine.index_document(
                "deployment", i, content,
                {"tier": "team", "status": "active", "seq": i},
            )
        start = time.time()
        res = engine.search(q="stripe", document_type="deployment", limit=20)
        elapsed_ms = (time.time() - start) * 1000
        self.assertGreater(res["total"], 0)
        self.assertLess(elapsed_ms, 200, f"search took {elapsed_ms:.1f}ms")


class TestEndpointHandlers(unittest.TestCase):
    def setUp(self):
        # Reset the shared engine for isolation.
        # [2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP] was eng._docs/_index/_jobs.clear(): private
        # attributes of the old engine, which had to be restructured to search 1M documents in under 200 ms.
        # SearchEngine.clear() is the public way to reset it (same effect: no documents, index or jobs).
        get_engine().clear()

    def test_handle_index_and_search(self):
        handle_index({
            "document_type": "user",
            "document_id": 123,
            "content": "john doe john@example.com team member active",
            "metadata": {"user_id": 123, "email": "john@example.com", "tier": "team", "status": "active"},
        })
        res = handle_search({"q": "john", "document_type": "user", "limit": 20, "offset": 0})
        self.assertEqual(res["total"], 1)
        self.assertEqual(res["results"][0]["document_id"], "123")

    def test_handle_search_with_filters_list(self):
        handle_index({"document_type": "deployment", "document_id": 1, "content": "stripe", "metadata": {"tier": "team", "status": "active"}})
        handle_index({"document_type": "deployment", "document_id": 2, "content": "stripe", "metadata": {"tier": "solo", "status": "active"}})
        res = handle_search({"q": "stripe", "document_type": "deployment", "filters": ["tier:team"]})
        self.assertEqual(res["total"], 1)
        self.assertEqual(res["results"][0]["document_id"], "1")

    def test_handle_search_with_facets_string(self):
        handle_index({"document_type": "deployment", "document_id": 1, "content": "a", "metadata": {"status": "active", "tier": "team"}})
        handle_index({"document_type": "deployment", "document_id": 2, "content": "b", "metadata": {"status": "draft", "tier": "team"}})
        res = handle_search({"q": "", "document_type": "deployment", "facets": "status,tier"})
        self.assertEqual(res["facets"]["status"], {"active": 1, "draft": 1})
        self.assertEqual(res["facets"]["tier"], {"team": 2})

    def test_handle_unindex(self):
        handle_index({"document_type": "user", "document_id": 9, "content": "zoe", "metadata": {}})
        res = handle_unindex("user", 9)
        self.assertTrue(res["success"])
        self.assertEqual(handle_search({"q": "zoe"})["total"], 0)

    def test_handle_reindex(self):
        handle_index({"document_type": "user", "document_id": 1, "content": "alice", "metadata": {}})
        res = handle_reindex({"document_type": None})
        self.assertTrue(res["success"])
        self.assertIn("job_id", res)
        self.assertEqual(res["status"], "enqueued")


if __name__ == "__main__":
    unittest.main(verbosity=2)