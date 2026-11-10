using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SaaS.Search;
using Xunit;

public class SearchIndexServiceTests
{
    private readonly SearchIndexService _service = new SearchIndexService();

    // SEARCH-01
    [Fact]
    public async Task IndexUser_ThenSearch_FindsDocument()
    {
        var indexReq = new IndexRequest
        {
            DocumentType = "user",
            DocumentId = "123",
            Content = "john doe john@example.com team member active",
            Metadata = new Dictionary<string, object>
            {
                {"user_id", 123},
                {"email", "john@example.com"},
                {"tier", "team"},
                {"status", "active"},
                {"created_at", "2026-01-15T00:00:00Z"}
            }
        };
        var idxResp = await _service.IndexDocumentAsync(indexReq);
        Assert.True(idxResp.Success);

        var searchReq = new SearchRequest
        {
            Query = "john",
            DocumentType = "user",
            Limit = 20,
            Offset = 0
        };
        var resp = await _service.SearchAsync(searchReq);
        Assert.Single(resp.Results);
        var item = resp.Results[0];
        Assert.Equal("123", item.DocumentId);
        Assert.Equal("user", item.DocumentType);
        Assert.True(item.Relevance > 0);
        Assert.Equal("john@example.com", item.Metadata["email"]);
        Assert.Equal("team", item.Metadata["tier"]);
        Assert.Equal("active", item.Metadata["status"]);
    }

    // SEARCH-02
    // SEARCH-04
    [Fact]
    public async Task IndexDeployment_SearchWithFilters_ReturnsCorrect()
    {
        // Index two deployments
        await _service.IndexDocumentAsync(new IndexRequest
        {
            DocumentType = "deployment",
            DocumentId = "d1",
            Content = "stripe integration for team",
            Metadata = new Dictionary<string, object>
            {
                {"tier", "team"},
                {"status", "active"}
            }
        });
        await _service.IndexDocumentAsync(new IndexRequest
        {
            DocumentType = "deployment",
            DocumentId = "d2",
            Content = "stripe integration for solo",
            Metadata = new Dictionary<string, object>
            {
                {"tier", "solo"},
                {"status", "draft"}
            }
        });

        var searchReq = new SearchRequest
        {
            Query = "stripe",
            DocumentType = "deployment",
            Filters = new List<string> { "tier:team", "status:active" },
            Limit = 20
        };
        var resp = await _service.SearchAsync(searchReq);
        Assert.Single(resp.Results);
        Assert.Equal("d1", resp.Results[0].DocumentId);
    }

    // SEARCH-03
    [Fact]
    public async Task PartialMatch_FindsDocument()
    {
        await _service.IndexDocumentAsync(new IndexRequest
        {
            DocumentType = "deployment",
            DocumentId = "d3",
            Content = "stripe payment gateway",
            Metadata = new Dictionary<string, object>()
        });

        var searchReq = new SearchRequest
        {
            Query = "stri",
            DocumentType = "deployment"
        };
        var resp = await _service.SearchAsync(searchReq);
        Assert.Single(resp.Results);
        Assert.Equal("d3", resp.Results[0].DocumentId);

        // a term matches only the START of a word (SEARCH-03 amendment; added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
        var ripe = await _service.SearchAsync(new SearchRequest { Query = "ripe", DocumentType = "deployment" });
        Assert.Empty(ripe.Results);
        Assert.Equal(0, ripe.Total);
    }

    /// <summary>
    /// Words are maximal runs of Unicode letters and digits, lower-cased invariantly, with no stop words; several
    /// terms must all match; "field:value" in the query is a filter. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
    /// (SEARCH-03 amendment). Touches: process memory.
    /// </summary>
    [Fact]
    public async Task Words_Unicode_NoStopWords_AllTermsMustMatch()
    {
        await _service.IndexDocumentAsync(new IndexRequest { DocumentType = "doc", DocumentId = "u1", Content = "Café-Crème the API_v2", Metadata = new Dictionary<string, object> { { "tier", "team" } } });
        await _service.IndexDocumentAsync(new IndexRequest { DocumentType = "doc", DocumentId = "u2", Content = "stripe integration", Metadata = new Dictionary<string, object> { { "tier", "solo" } } });
        await _service.IndexDocumentAsync(new IndexRequest { DocumentType = "doc", DocumentId = "u3", Content = "stripe billing", Metadata = new Dictionary<string, object> { { "tier", "team" } } });

        Assert.Equal(new[] { "café", "crème", "the", "api", "v2" }, SearchIndexService.Tokenize("Café-Crème the API_v2"));
        Assert.Equal("u1", Assert.Single((await _service.SearchAsync(new SearchRequest { Query = "CAFÉ", DocumentType = "doc" })).Results).DocumentId);
        Assert.Empty((await _service.SearchAsync(new SearchRequest { Query = "caf\u00e9s", DocumentType = "doc" })).Results);
        Assert.Equal("u1", Assert.Single((await _service.SearchAsync(new SearchRequest { Query = "the", DocumentType = "doc" })).Results).DocumentId);
        Assert.Equal("u2", Assert.Single((await _service.SearchAsync(new SearchRequest { Query = "stripe integ", DocumentType = "doc" })).Results).DocumentId);
        Assert.Equal(2, (await _service.SearchAsync(new SearchRequest { Query = "stripe", DocumentType = "doc" })).Total);
        Assert.Equal("u3", Assert.Single((await _service.SearchAsync(new SearchRequest { Query = "stripe tier:team", DocumentType = "doc" })).Results).DocumentId);
    }

    // SEARCH-05
    [Fact]
    public async Task Facets_ReturnCountsPerStatus()
    {
        // Ensure some docs with various statuses
        await _service.IndexDocumentAsync(new IndexRequest
        {
            DocumentType = "deployment",
            DocumentId = "d4",
            Content = "alpha",
            Metadata = new Dictionary<string, object> { {"status", "active"} }
        });
        await _service.IndexDocumentAsync(new IndexRequest
        {
            DocumentType = "deployment",
            DocumentId = "d5",
            Content = "beta",
            Metadata = new Dictionary<string, object> { {"status", "draft"} }
        });
        await _service.IndexDocumentAsync(new IndexRequest
        {
            DocumentType = "deployment",
            DocumentId = "d6",
            Content = "gamma",
            Metadata = new Dictionary<string, object> { {"status", "active"} }
        });

        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the query was "deployment", which matched only because the
        // document TYPE was indexed as a word; the spec searches content, so the facets are taken over every
        // deployment (empty query).
        var searchReq = new SearchRequest
        {
            Query = "",
            DocumentType = "deployment",
            Facets = new List<string> { "status" }
        };
        var resp = await _service.SearchAsync(searchReq);
        Assert.NotNull(resp.Facets);
        Assert.True(resp.Facets.ContainsKey("status"));
        var statusCounts = resp.Facets["status"];
        Assert.Equal(2, statusCounts["active"]);
        Assert.Equal(1, statusCounts["draft"]);
    }

    // SEARCH-06
    [Fact]
    public async Task Unindex_RemovesDocument()
    {
        await _service.IndexDocumentAsync(new IndexRequest
        {
            DocumentType = "user",
            DocumentId = "999",
            Content = "temp user",
            Metadata = new Dictionary<string, object>()
        });

        var before = await _service.SearchAsync(new SearchRequest
        {
            Query = "temp",
            DocumentType = "user"
        });
        Assert.Single(before.Results);

        var unidxResp = await _service.UnindexDocumentAsync("user", "999");
        Assert.True(unidxResp.Success);

        var after = await _service.SearchAsync(new SearchRequest
        {
            Query = "temp",
            DocumentType = "user"
        });
        Assert.Empty(after.Results);
    }

    [Fact]
    public async Task Reindex_AllTypes_EnqueuesJob()
    {
        var resp = await _service.ReindexAsync(new ReindexRequest { DocumentType = null });
        Assert.True(resp.Success);
        Assert.False(string.IsNullOrWhiteSpace(resp.JobId));
        Assert.Equal("enqueued", resp.Status);
    }

    // SEARCH-07
    [Fact]
    public async Task RealTime_Indexing_Within100ms()
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await _service.IndexDocumentAsync(new IndexRequest
        {
            DocumentType = "user",
            DocumentId = "rt1",
            Content = "real time test",
            Metadata = new Dictionary<string, object>()
        });
        var resp = await _service.SearchAsync(new SearchRequest
        {
            Query = "real",
            DocumentType = "user"
        });
        sw.Stop();
        Assert.Single(resp.Results);
        Assert.True(sw.ElapsedMilliseconds <= 100, $"Elapsed {sw.ElapsedMilliseconds}ms > 100ms");
    }

    /// <summary>
    /// SEARCH-09: an exact word outranks a prefix match even when indexed later, and equal scores keep insertion order,
    /// across pages. Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (SEARCH-09 amendment): the old test expected
    /// a document whose word "stri" is SHORTER than the query "stripe" to match, which the amended rule forbids.
    /// </summary>
    // SEARCH-09
    [Fact]
    public async Task Relevance_ExactMatchHigherThanPartial()
    {
        foreach (var (id, content) in new[] { ("a", "stripes"), ("b", "stripe"), ("c", "striped"), ("d", "stripe integration"), ("e", "stri payment") })
            await _service.IndexDocumentAsync(new IndexRequest { DocumentType = "doc", DocumentId = id, Content = content, Metadata = new Dictionary<string, object>() });

        var resp = await _service.SearchAsync(new SearchRequest
        {
            Query = "stripe",
            DocumentType = "doc"
        });
        Assert.Equal(new[] { "b", "d", "a", "c" }, resp.Results.Select(r => r.DocumentId).ToArray());
        Assert.True(resp.Results[1].Relevance > resp.Results[2].Relevance);
        Assert.Equal(resp.Results[2].Relevance, resp.Results[3].Relevance);

        var page2 = await _service.SearchAsync(new SearchRequest { Query = "stripe", DocumentType = "doc", Limit = 2, Offset = 2 });
        Assert.Equal(new[] { "a", "c" }, page2.Results.Select(r => r.DocumentId).ToArray());
        Assert.Equal(4, page2.Total);
        Assert.False(page2.HasMore);
    }

    /// <summary>
    /// Re-indexing and unindexing many documents compacts the index (dead entries past 1,000 and over half) and
    /// searches stay right: a replaced document moves to the end of the insertion order, an unindexed one is gone,
    /// and other types are untouched. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, with the rewritten index.
    /// Touches: process memory.
    /// </summary>
    [Fact]
    public async Task Replace_And_Unindex_Many_Compacts_And_Keeps_Results_Right()
    {
        await _service.IndexDocumentAsync(new IndexRequest { DocumentType = "user", DocumentId = "keep", Content = "alpha keeper", Metadata = new Dictionary<string, object>() });
        for (var i = 0; i < 1500; i++)
            await _service.IndexDocumentAsync(new IndexRequest { DocumentType = "doc", DocumentId = i.ToString(), Content = "alpha old" + i, Metadata = new Dictionary<string, object>() });
        for (var i = 0; i < 1500; i++)
            await _service.IndexDocumentAsync(new IndexRequest { DocumentType = "doc", DocumentId = i.ToString(), Content = "alpha new" + i, Metadata = new Dictionary<string, object>() });
        for (var i = 0; i < 1000; i++)
            await _service.UnindexDocumentAsync("doc", i.ToString());

        Assert.Equal(0, (await _service.SearchAsync(new SearchRequest { Query = "old1499", DocumentType = "doc" })).Total);
        var alpha = await _service.SearchAsync(new SearchRequest { Query = "alpha", DocumentType = "doc", Limit = 3 });
        Assert.Equal(500, alpha.Total);
        Assert.Equal(new[] { "1000", "1001", "1002" }, alpha.Results.Select(r => r.DocumentId).ToArray());
        Assert.Equal("keep", Assert.Single((await _service.SearchAsync(new SearchRequest { Query = "keeper" })).Results).DocumentId);
        Assert.Equal(501, (await _service.SearchAsync(new SearchRequest { Query = "alpha" })).Total);
    }

    /// <summary>
    /// SEARCH-08: 1,000,000 indexed documents, a search returns its first page and the full total in under 200 ms (the
    /// contract's budget). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (the suite had no SEARCH-08 test).
    /// The documents share one metadata dictionary to keep the test's memory small. Touches: process memory.
    /// </summary>
    // SEARCH-08
    [Fact]
    public async Task Performance_OneMillionDocuments_SearchUnder200ms()
    {
        const int n = 1_000_000;
        var metadata = new Dictionary<string, object> { { "tier", "team" }, { "status", "active" } };
        for (var i = 0; i < n; i++)
            await _service.IndexDocumentAsync(new IndexRequest
            {
                DocumentType = "deployment",
                DocumentId = i.ToString(),
                Content = $"document {i} stripe integration deployment active",
                Metadata = metadata
            });

        // one warm-up query, as a server would have served before
        await _service.SearchAsync(new SearchRequest { Query = "integration", DocumentType = "deployment", Limit = 20 });

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var resp = await _service.SearchAsync(new SearchRequest { Query = "stripe", DocumentType = "deployment", Limit = 20 });
        sw.Stop();

        Assert.Equal(n, resp.Total);
        Assert.Equal(20, resp.Results.Count);
        Assert.Equal("0", resp.Results[0].DocumentId);
        Assert.True(sw.ElapsedMilliseconds < 200, $"search took {sw.ElapsedMilliseconds} ms");
    }
}