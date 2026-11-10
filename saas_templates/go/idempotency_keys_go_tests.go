package idempotencykeys

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	_ "modernc.org/sqlite"
)

// IDEM-01
func TestFirstCallRunsOperationOnce(t *testing.T) {
	store := NewInMemoryStore()
	svc, _ := NewIdempotencyService(store, IdempotencyOptions{})
	count := 0
	op := func() (OperationResult, error) {
		count++
		return OperationResult{Status: 201, Body: `{"n":1}`}, nil
	}
	resp, err := svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, op)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 201 || resp.ContentType != "application/json" || resp.Body != `{"n":1}` {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}
}

// IDEM-02
func TestIdenticalRetryReplaysStoredResponse(t *testing.T) {
	store := NewInMemoryStore()
	svc, _ := NewIdempotencyService(store, IdempotencyOptions{})
	count := 0
	op := func() (OperationResult, error) {
		count++
		return OperationResult{Status: 201, Body: `{"n":1}`}, nil
	}
	resp1, _ := svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, op)
	resp2, _ := svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, op)
	if resp1 != resp2 {
		t.Fatalf("responses differ: %+v vs %+v", resp1, resp2)
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}
}

// IDEM-03
func TestSameKeyDifferentBodyIs422(t *testing.T) {
	store := NewInMemoryStore()
	svc, _ := NewIdempotencyService(store, IdempotencyOptions{})
	count := 0
	op := func() (OperationResult, error) {
		count++
		return OperationResult{Status: 201, Body: `{"n":1}`}, nil
	}
	svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, op)
	resp, _ := svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":200}`, op)
	if resp.Status != 422 || resp.ContentType != "application/problem+json" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.Body != `{"type":"https://developer.example.com/problems/idempotency-key-reused","title":"Idempotency-Key is already used","detail":"This Idempotency-Key was already used with a different request payload."}` {
		t.Fatalf("unexpected body: %s", resp.Body)
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}
}

// IDEM-04
func TestSameKeyWhileInProgressIs409(t *testing.T) {
	store := NewInMemoryStore()
	svc, _ := NewIdempotencyService(store, IdempotencyOptions{})
	count := 0
	var innerResp HttpResponse
	op := func() (OperationResult, error) {
		count++
		innerResp, _ = svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, func() (OperationResult, error) {
			return OperationResult{Status: 201, Body: `{"n":2}`}, nil
		})
		return OperationResult{Status: 201, Body: `{"n":1}`}, nil
	}
	resp, _ := svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, op)
	if resp.Status != 201 || resp.Body != `{"n":1}` {
		t.Fatalf("unexpected outer response: %+v", resp)
	}
	if innerResp.Status != 409 || innerResp.ContentType != "application/problem+json" {
		t.Fatalf("unexpected inner response: %+v", innerResp)
	}
	if innerResp.Body != `{"type":"https://developer.example.com/problems/idempotency-request-outstanding","title":"A request is outstanding for this Idempotency-Key","detail":"A request with the same Idempotency-Key is still being processed. Retry later."}` {
		t.Fatalf("unexpected inner body: %s", innerResp.Body)
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}
}

// IDEM-05
func TestRequiredMethodWithoutKeyIs400(t *testing.T) {
	store := NewInMemoryStore()
	svc, _ := NewIdempotencyService(store, IdempotencyOptions{})
	count := 0
	op := func() (OperationResult, error) {
		count++
		return OperationResult{Status: 201, Body: `{"n":1}`}, nil
	}
	resp1, _ := svc.Handle("client-a", "", "POST", "/charges", `{"amount":100}`, op)
	resp2, _ := svc.Handle("client-a", "", "POST", "/charges", `{"amount":100}`, op)
	if resp1.Status != 400 || resp1.ContentType != "application/problem+json" {
		t.Fatalf("unexpected response 1: %+v", resp1)
	}
	if resp1.Body != `{"type":"https://developer.example.com/problems/idempotency-key-missing","title":"Idempotency-Key is missing","detail":"This operation requires an Idempotency-Key request header."}` {
		t.Fatalf("unexpected body 1: %s", resp1.Body)
	}
	if resp2.Status != 400 || resp2.ContentType != "application/problem+json" {
		t.Fatalf("unexpected response 2: %+v", resp2)
	}
	if resp2.Body != `{"type":"https://developer.example.com/problems/idempotency-key-missing","title":"Idempotency-Key is missing","detail":"This operation requires an Idempotency-Key request header."}` {
		t.Fatalf("unexpected body 2: %s", resp2.Body)
	}
	if count != 0 {
		t.Fatalf("expected count 0, got %d", count)
	}
}

// IDEM-06
func TestSameKeyInTwoScopesRunsTwice(t *testing.T) {
	store := NewInMemoryStore()
	svc, _ := NewIdempotencyService(store, IdempotencyOptions{})
	count := 0
	op := func() (OperationResult, error) {
		count++
		return OperationResult{Status: 201, Body: `{"n":` + itoa(count) + `}`}, nil
	}
	resp1, _ := svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, op)
	resp2, _ := svc.Handle("client-b", "key-1", "POST", "/charges", `{"amount":100}`, op)
	if resp1.Status != 201 || resp1.Body != `{"n":1}` {
		t.Fatalf("unexpected response 1: %+v", resp1)
	}
	if resp2.Status != 201 || resp2.Body != `{"n":2}` {
		t.Fatalf("unexpected response 2: %+v", resp2)
	}
	if count != 2 {
		t.Fatalf("expected count 2, got %d", count)
	}
}

// IDEM-07
func TestExpiredKeyRunsOperationAgain(t *testing.T) {
	now := int64(1700000000)
	store := NewInMemoryStore()
	svc, _ := NewIdempotencyService(store, IdempotencyOptions{
		Clock: func() int64 { return now },
	})
	count := 0
	op := func() (OperationResult, error) {
		count++
		return OperationResult{Status: 201, Body: `{"n":` + itoa(count) + `}`}, nil
	}
	svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, op)
	now += 86400
	resp, _ := svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, op)
	if resp.Status != 201 || resp.Body != `{"n":2}` {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if count != 2 {
		t.Fatalf("expected count 2, got %d", count)
	}

	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (IDEM-07, amended): an in_progress record past
	// expires_at (a process killed mid-operation) is uncertain: 409 outcome_unknown, and it does not run.
	claimed, _ := store.TryClaim(IdempotencyRecord{Scope: "client-a", IdemKey: "key-crashed", RequestFingerprint: ComputeFingerprint("POST", "/charges", `{"amount":100}`),
		Status: "in_progress", CreatedAt: now - 90000, ExpiresAt: now - 3600}, now-90000)
	if !claimed {
		t.Fatal("could not plant the crashed in_progress record")
	}
	resp, _ = svc.Handle("client-a", "key-crashed", "POST", "/charges", `{"amount":100}`, op)
	if resp.Status != 409 || !strings.Contains(resp.Body, "outcome_unknown") || resp.ContentType != "application/problem+json" {
		t.Fatalf("stale in_progress: expected 409 outcome_unknown, got %+v", resp)
	}
	if count != 2 {
		t.Fatalf("a stale in_progress key must not run the operation; count %d", count)
	}
	if n, _ := svc.PurgeExpired(); n != 0 {
		t.Fatalf("purge must keep the stale in_progress record (and the unexpired completed one); purged %d", n)
	}
}

// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the amended IDEM-08 frees the key only for a
// DEFINITE failure, an error wrapping ErrOperationFailed; a plain error now leaves it uncertain (IDEM-10).
// IDEM-08
func TestRaisingOperationFreesTheKey(t *testing.T) {
	store := NewInMemoryStore()
	svc, _ := NewIdempotencyService(store, IdempotencyOptions{})
	count := 0
	boom := fmt.Errorf("card declined: %w", ErrOperationFailed)
	op := func() (OperationResult, error) {
		count++
		return OperationResult{}, boom
	}
	_, err := svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, op)
	if !errors.Is(err, boom) {
		t.Fatalf("expected boom error, got: %v", err)
	}
	count = 0
	op2 := func() (OperationResult, error) {
		count++
		return OperationResult{Status: 201, Body: `{"n":1}`}, nil
	}
	resp, _ := svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, op2)
	if resp.Status != 201 || resp.Body != `{"n":1}` {
		t.Fatalf("unexpected response: %+v", resp)
	}
	resp2, _ := svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, op2)
	if resp2.Status != 201 || resp2.Body != `{"n":1}` {
		t.Fatalf("unexpected replay response: %+v", resp2)
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}
}

// IDEM-09
func TestErrorResponsesAreProblemJson(t *testing.T) {
	store := NewInMemoryStore()
	svc, _ := NewIdempotencyService(store, IdempotencyOptions{})
	count := 0
	op := func() (OperationResult, error) {
		count++
		return OperationResult{Status: 201, Body: `{"n":1}`}, nil
	}
	resp400, _ := svc.Handle("client-a", "", "POST", "/charges", `{"amount":100}`, op)
	if resp400.Status != 400 || resp400.ContentType != "application/problem+json" {
		t.Fatalf("unexpected 400 response: %+v", resp400)
	}
	var innerResp HttpResponse
	opReentrant := func() (OperationResult, error) {
		count++
		innerResp, _ = svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, func() (OperationResult, error) {
			return OperationResult{Status: 201, Body: `{"n":2}`}, nil
		})
		return OperationResult{Status: 201, Body: `{"n":1}`}, nil
	}
	resp409, _ := svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, opReentrant)
	if resp409.Status != 201 {
		t.Fatalf("unexpected outer response: %+v", resp409)
	}
	if innerResp.Status != 409 || innerResp.ContentType != "application/problem+json" {
		t.Fatalf("unexpected 409 response: %+v", innerResp)
	}
	svc.Handle("client-a", "key-2", "POST", "/charges", `{"amount":100}`, op)
	resp422, _ := svc.Handle("client-a", "key-2", "POST", "/charges", `{"amount":200}`, op)
	if resp422.Status != 422 || resp422.ContentType != "application/problem+json" {
		t.Fatalf("unexpected 422 response: %+v", resp422)
	}
}

func TestFingerprintVectors(t *testing.T) {
	v1 := ComputeFingerprint("POST", "/charges", `{"amount":100}`)
	if v1 != "70cf65c7a3ff49d51f1453b276fad9d916ef23b88bcd6eaf7be5560757fbffac" {
		t.Fatalf("unexpected fingerprint 1: %s", v1)
	}
	v2 := ComputeFingerprint("post", "/charges", `{"amount":100}`)
	if v2 != v1 {
		t.Fatalf("fingerprints should match: %s vs %s", v1, v2)
	}
	v3 := ComputeFingerprint("POST", "/charges", `{"amount":200}`)
	if v3 != "bf84a34ee8f1f73a21d2ab06fa5bdbc2a44163460468db84a24cc19163a8dc19" {
		t.Fatalf("unexpected fingerprint 3: %s", v3)
	}
	v4 := ComputeFingerprint("POST", "/charges", "")
	if v4 != "aacec4b81fc95fe65af0e605dc76dc5705975f54fb2b55c1a3d36ff76f133334" {
		t.Fatalf("unexpected fingerprint 4: %s", v4)
	}
	v5 := ComputeFingerprint("POST", "/caf\u00e9", "\u20ac")
	if v5 != "514e90be1195bdd29a59a54bc13392840ae09b70da2fdbb3a30817f7028688ba" {
		t.Fatalf("unexpected fingerprint 5: %s", v5)
	}
	v6 := ComputeFingerprint("p\u00f6st", "/charges", "")
	if v6 != "3e0d88ec545d0bfa3805145243041df631292b351dae46b446b4c7f1b6dc54b3" {
		t.Fatalf("unexpected fingerprint 6: %s", v6)
	}
}

func TestInputValidationAndPassThrough(t *testing.T) {
	store := NewInMemoryStore()
	svc, _ := NewIdempotencyService(store, IdempotencyOptions{})
	count := 0
	op := func() (OperationResult, error) {
		count++
		return OperationResult{Status: 201, Body: `{"n":1}`}, nil
	}
	svc.Handle("client-a", "0", "POST", "/charges", `{"amount":100}`, op)
	svc.Handle("client-a", strings.Repeat("k", 255), "POST", "/charges", `{"amount":100}`, op)
	resp256, _ := svc.Handle("client-a", strings.Repeat("k", 256), "POST", "/charges", `{"amount":100}`, op)
	if resp256.Status != 400 || resp256.ContentType != "application/problem+json" {
		t.Fatalf("unexpected 256 response: %+v", resp256)
	}
	respBad, _ := svc.Handle("client-a", "bad\nkey", "POST", "/charges", `{"amount":100}`, op)
	if respBad.Status != 400 || respBad.ContentType != "application/problem+json" {
		t.Fatalf("unexpected bad key response: %+v", respBad)
	}
	_, err := svc.Handle("", "key-1", "POST", "/charges", `{"amount":100}`, op)
	if err == nil {
		t.Fatal("expected SCOPE_REQUIRED error")
	}
	var ie *IdempotencyError
	if !errors.As(err, &ie) || ie.Code != "SCOPE_REQUIRED" {
		t.Fatalf("unexpected error: %v", err)
	}
	svc.Handle("client-a", "key-1", "GET", "/charges", `{"amount":100}`, op)
	svc.Handle("client-a", "key-1", "GET", "/charges", `{"amount":100}`, op)
	if !svc.IsRequired("post", "/charges") {
		t.Fatal("expected POST to be required")
	}
	if !svc.IsRequired("PATCH", "/charges") {
		t.Fatal("expected PATCH to be required")
	}
	if svc.IsRequired("GET", "/charges") {
		t.Fatal("expected GET to not be required")
	}
	if svc.IsRequired("DELETE", "/charges") {
		t.Fatal("expected DELETE to not be required")
	}
	svcPut, _ := NewIdempotencyService(store, IdempotencyOptions{RequiredMethods: []string{"put"}})
	if !svcPut.IsRequired("PUT", "/charges") {
		t.Fatal("expected PUT to be required")
	}
	if svcPut.IsRequired("POST", "/charges") {
		t.Fatal("expected POST to not be required")
	}
	if count != 4 {
		t.Fatalf("expected count 4, got %d", count)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
// TestOtherErrorLeavesKeyUncertain proves IDEM-10: an error that is not ErrOperationFailed (a timeout
// after the provider may have charged) leaves the key 'uncertain'; a retry gets 409 outcome_unknown and
// does not run; ListUncertain lists it; after Release a retry runs, and a second Release returns false.
// A panic is treated the same way. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// IDEM-10
func TestOtherErrorLeavesKeyUncertain(t *testing.T) {
	store := NewInMemoryStore()
	svc, _ := NewIdempotencyService(store, IdempotencyOptions{})
	count := 0
	timeout := errors.New("provider timeout")
	failing := func() (OperationResult, error) {
		count++
		return OperationResult{}, timeout
	}
	working := func() (OperationResult, error) {
		count++
		return OperationResult{Status: 201, Body: `{"n":2}`}, nil
	}
	if _, err := svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, failing); !errors.Is(err, timeout) {
		t.Fatalf("the operation's error must be re-raised, got %v", err)
	}
	resp, _ := svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, working)
	if resp.Status != 409 || resp.ContentType != "application/problem+json" ||
		resp.Body != `{"type":"https://developer.example.com/problems/outcome_unknown","title":"Outcome unknown","detail":"The first request with this Idempotency-Key ended without a known outcome; it will not be run again until it is reconciled."}` {
		t.Fatalf("expected 409 outcome_unknown, got %+v", resp)
	}
	if count != 1 {
		t.Fatalf("an uncertain key must not run the operation again; count %d", count)
	}
	// A different body on the same key is still 422 (the fingerprint check comes first).
	if r, _ := svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":999}`, working); r.Status != 422 {
		t.Fatalf("different body on an uncertain key: expected 422, got %+v", r)
	}
	list, _ := svc.ListUncertain(10)
	if len(list) != 1 || list[0].Scope != "client-a" || list[0].IdemKey != "key-1" {
		t.Fatalf("ListUncertain: %+v", list)
	}
	if n, _ := svc.PurgeExpired(); n != 0 {
		t.Fatalf("purge must keep an uncertain record")
	}
	if ok, _ := svc.Release("client-a", "key-1"); !ok {
		t.Fatal("Release on an uncertain key should return true")
	}
	if ok, _ := svc.Release("client-a", "key-1"); ok {
		t.Fatal("a second Release should return false")
	}
	resp, _ = svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, working)
	if resp.Status != 201 || count != 2 {
		t.Fatalf("after Release the retry should run: %+v count %d", resp, count)
	}
	if ok, _ := svc.Release("client-a", "key-1"); ok {
		t.Fatal("Release on a completed key should return false")
	}

	// A panic is an unknown outcome too.
	func() {
		defer func() { _ = recover() }()
		_, _ = svc.Handle("client-a", "key-panic", "POST", "/charges", `{}`, func() (OperationResult, error) {
			count++
			panic("crash after the provider call")
		})
	}()
	if r, _ := svc.Handle("client-a", "key-panic", "POST", "/charges", `{}`, working); r.Status != 409 || !strings.Contains(r.Body, "outcome_unknown") {
		t.Fatalf("after a panic: expected 409 outcome_unknown, got %+v", r)
	}
}

// TestResolveStoresOutcome proves IDEM-11: Resolve on an uncertain key stores the response; a retry
// returns it without running; a second Resolve or Release returns false; the resolved record expires
// 24 h after the resolve. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
// IDEM-11
func TestResolveStoresOutcome(t *testing.T) {
	now := int64(1_700_000_000)
	store := NewInMemoryStore()
	svc, _ := NewIdempotencyService(store, IdempotencyOptions{Clock: func() int64 { return now }})
	count := 0
	_, _ = svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, func() (OperationResult, error) {
		count++
		return OperationResult{}, errors.New("connection reset")
	})
	if ok, _ := svc.Resolve("client-b", "key-1", 201, `{"charge":"ch_1"}`); ok {
		t.Fatal("Resolve under another scope must not touch client-a's key")
	}
	now += 3600
	if ok, err := svc.Resolve("client-a", "key-1", 201, `{"charge":"ch_1"}`); !ok || err != nil {
		t.Fatalf("Resolve on an uncertain key: %v %v", ok, err)
	}
	resp, _ := svc.Handle("client-a", "key-1", "POST", "/charges", `{"amount":100}`, func() (OperationResult, error) {
		count++
		return OperationResult{Status: 201, Body: `{"charge":"ch_2"}`}, nil
	})
	if resp.Status != 201 || resp.Body != `{"charge":"ch_1"}` || resp.ContentType != "application/json" || count != 1 {
		t.Fatalf("retry after Resolve: %+v count %d", resp, count)
	}
	if ok, _ := svc.Resolve("client-a", "key-1", 201, `{"charge":"ch_3"}`); ok {
		t.Fatal("a second Resolve should return false")
	}
	if ok, _ := svc.Release("client-a", "key-1"); ok {
		t.Fatal("Release on a resolved key should return false")
	}
	rec, _ := store.Get("client-a", "key-1")
	if rec.ExpiresAt != now+86400 {
		t.Fatalf("resolved record should expire 24h after the resolve: %d", rec.ExpiresAt-now)
	}
}

// TestReleaseAndResolveAreSingleConditionalWrites proves that of many concurrent Release (or Resolve)
// calls on one uncertain key exactly one returns true, on the in-memory and the SQL store, and that the
// SQL store follows IDEM-07/10/11 too. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
// Touches: memory and an in-memory SQLite database.
func TestReleaseAndResolveAreSingleConditionalWrites(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	sqlStore := NewSqlStore(db)
	if err := sqlStore.Migrate(); err != nil {
		t.Fatal(err)
	}
	for name, store := range map[string]Store{"memory": NewInMemoryStore(), "sql": sqlStore} {
		now := int64(1_700_000_000)
		svc, _ := NewIdempotencyService(store, IdempotencyOptions{Clock: func() int64 { return now }})
		count := 0
		fail := func() (OperationResult, error) { count++; return OperationResult{}, errors.New("timeout") }
		ok := func() (OperationResult, error) { count++; return OperationResult{Status: 200, Body: `{"ok":true}`}, nil }
		for _, key := range []string{"k-release", "k-resolve"} {
			_, _ = svc.Handle("s", key, "POST", "/p", "b", fail)
		}
		if r, _ := svc.Handle("s", "k-release", "POST", "/p", "b", ok); r.Status != 409 || count != 2 {
			t.Fatalf("%s: uncertain retry: %+v count %d", name, r, count)
		}
		var wins int
		var mu sync.Mutex
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				if won, _ := svc.Release("s", "k-release"); won {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
			go func(i int) {
				defer wg.Done()
				if won, _ := svc.Resolve("s", "k-resolve", 200, fmt.Sprintf(`{"i":%d}`, i)); won {
					mu.Lock()
					wins += 100
					mu.Unlock()
				}
			}(i)
		}
		wg.Wait()
		if wins != 101 {
			t.Fatalf("%s: expected exactly one Release and one Resolve to win, got %d", name, wins)
		}
		if r, _ := svc.Handle("s", "k-release", "POST", "/p", "b", ok); r.Status != 200 || count != 3 {
			t.Fatalf("%s: retry after Release: %+v count %d", name, r, count)
		}
		if r, _ := svc.Handle("s", "k-resolve", "POST", "/p", "b", ok); r.Status != 200 || count != 3 {
			t.Fatalf("%s: retry after Resolve must replay, not run: %+v count %d", name, r, count)
		}
		// Expiry applies to completed records only: a day later the completed key runs again.
		now += 86400 + 1
		if r, _ := svc.Handle("s", "k-release", "POST", "/p", "b", ok); r.Status != 200 || count != 4 {
			t.Fatalf("%s: expired completed key should run again: %+v count %d", name, r, count)
		}
	}
}
