package api_keys

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// newTestService returns a service on a fresh in-memory SQLite database with an in-memory rate
// limiter and a clock frozen at the current instant, so hourly windows cannot roll over mid-test.
// Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the tests needed a live PostgreSQL and
// Redis on localhost (no network in library tests). Touches: an in-memory database only.
func newTestService(t *testing.T) *Service {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1) // every new connection to :memory: would be a separate, empty database
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(APIKeysDDL)
	require.NoError(t, err)
	s := NewService(db, NewMemoryRateLimiter(), "test")
	frozen := time.Now()
	s.SetClock(func() time.Time { return frozen })
	return s
}

// TestAPIKeyService tests the API key service: the spec's nine checks as subtests.
func TestAPIKeyService(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	// KEYS-01
	t.Run("Create key with scopes", func(t *testing.T) {
		req := CreateAPIKeyRequest{
			Name:     "Test Key",
			Scopes:   []string{"read:deployments", "write:webhooks"},
			RateLimit: 1000,
		}
		res, err := s.CreateAPIKey(ctx, 1, req)
		require.NoError(t, err)
		require.NotEmpty(t, res.APIKeyID)
		require.NotEmpty(t, res.Key)
		require.Equal(t, "Test Key", res.Name)
		// The key works for an endpoint its scopes cover.
		apiKey, err := s.ValidateAPIKey(ctx, res.Key, "/deployments", "GET")
		require.NoError(t, err)
		require.NotNil(t, apiKey)
		require.Equal(t, res.APIKeyID, apiKey.ID)
	})

	// KEYS-02
	t.Run("Use key: request succeeds with Authorization header", func(t *testing.T) {
		req := CreateAPIKeyRequest{
			Name:     "Usage Test",
			Scopes:   []string{"read:users"},
			RateLimit: 5,
		}
		createRes, err := s.CreateAPIKey(ctx, 2, req)
		require.NoError(t, err)

		// Valid request
		apiKey, err := s.ValidateAPIKey(ctx, createRes.Key, "/users", "GET")
		require.NoError(t, err)
		require.NotNil(t, apiKey)

		// Invalid key
		_, err = s.ValidateAPIKey(ctx, "sk_test_invalid", "/users", "GET")
		require.Error(t, err)
	})

	// KEYS-03
	t.Run("Revoke key: subsequent requests return 401", func(t *testing.T) {
		req := CreateAPIKeyRequest{
			Name:     "Revoke Test",
			Scopes:   []string{"read:users"},
			RateLimit: 5,
		}
		createRes, err := s.CreateAPIKey(ctx, 3, req)
		require.NoError(t, err)

		// Verify key works
		apiKey, err := s.ValidateAPIKey(ctx, createRes.Key, "/users", "GET")
		require.NoError(t, err)
		require.NotNil(t, apiKey)

		// Revoke key
		revokeRes, err := s.RevokeAPIKey(ctx, 3, createRes.APIKeyID)
		require.NoError(t, err)
		require.True(t, revokeRes.Success)

		// Verify key no longer works: 401 (status asserted 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
		_, err = s.ValidateAPIKey(ctx, createRes.Key, "/users", "GET")
		requireStatus(t, err, 401)
	})

	// KEYS-04
	t.Run("Rate limit: 1001st request in hour returns 429", func(t *testing.T) {
		req := CreateAPIKeyRequest{
			Name:     "Rate Limit Test",
			Scopes:   []string{"read:users"},
			RateLimit: 2, // Very low for testing
		}
		createRes, err := s.CreateAPIKey(ctx, 4, req)
		require.NoError(t, err)

		// First two requests should succeed
		for i := 0; i < 2; i++ {
			_, err := s.ValidateAPIKey(ctx, createRes.Key, "/users", "GET")
			require.NoError(t, err)
		}

		// Third request should fail with 429. The limit is 2, not 1000: each request is a bcrypt
		// verify, and the rule (limit+1-th request in the hour) is the same.
		_, err = s.ValidateAPIKey(ctx, createRes.Key, "/users", "GET")
		requireStatus(t, err, 429)
	})

	// KEYS-05
	t.Run("Scope check: key with 'read:deployments' can't write deployments (403)", func(t *testing.T) {
		req := CreateAPIKeyRequest{
			Name:     "Scope Test",
			Scopes:   []string{"read:deployments"},
			RateLimit: 1000,
		}
		createRes, err := s.CreateAPIKey(ctx, 5, req)
		require.NoError(t, err)

		// Read should work
		_, err = s.ValidateAPIKey(ctx, createRes.Key, "/deployments", "GET")
		require.NoError(t, err)

		// Write should fail with 403
		_, err = s.ValidateAPIKey(ctx, createRes.Key, "/deployments", "POST")
		requireStatus(t, err, 403)
	})

	// KEYS-06
	t.Run("Rotate: new key works, old key stops after grace period", func(t *testing.T) {
		req := CreateAPIKeyRequest{
			Name:     "Rotate Test",
			Scopes:   []string{"read:users"},
			RateLimit: 1000,
		}
		createRes, err := s.CreateAPIKey(ctx, 6, req)
		require.NoError(t, err)

		// Verify original key works
		apiKey, err := s.ValidateAPIKey(ctx, createRes.Key, "/users", "GET")
		require.NoError(t, err)
		require.NotNil(t, apiKey)

		// Rotate key
		rotateRes, err := s.RotateAPIKey(ctx, 6, createRes.APIKeyID)
		require.NoError(t, err)
		require.NotEmpty(t, rotateRes.NewKey)

		// New key should work
		apiKey, err = s.ValidateAPIKey(ctx, rotateRes.NewKey, "/users", "GET")
		require.NoError(t, err)
		require.NotNil(t, apiKey)

		// Old key should still work (within grace period)
		apiKey, err = s.ValidateAPIKey(ctx, createRes.Key, "/users", "GET")
		require.NoError(t, err)
		require.NotNil(t, apiKey)

		// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the injectable clock now proves the second half
		// of KEYS-06 (the old key stops after the 24 h grace period), which was only assumed before.
		frozen := s.now()
		s.SetClock(func() time.Time { return frozen.Add(GracePeriod + time.Second) })
		defer s.SetClock(func() time.Time { return frozen })
		_, err = s.ValidateAPIKey(ctx, createRes.Key, "/users", "GET")
		requireStatus(t, err, 401)
		_, err = s.ValidateAPIKey(ctx, rotateRes.NewKey, "/users", "GET")
		require.NoError(t, err)
	})

	// KEYS-07
	t.Run("Expired key: after expires_at, request returns 401", func(t *testing.T) {
		past := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
		req := CreateAPIKeyRequest{
			Name:     "Expired Test",
			Scopes:   []string{"read:users"},
			ExpiresAt: &past, // Already expired
			RateLimit: 1000,
		}
		createRes, err := s.CreateAPIKey(ctx, 7, req)
		require.NoError(t, err)

		// Key should be invalid due to expiration: 401
		_, err = s.ValidateAPIKey(ctx, createRes.Key, "/users", "GET")
		requireStatus(t, err, 401)
	})

	// KEYS-08
	t.Run("Usage stats: requests counted per endpoint", func(t *testing.T) {
		req := CreateAPIKeyRequest{
			Name:     "Usage Stats Test",
			Scopes:   []string{"read:users", "read:deployments"},
			RateLimit: 1000,
		}
		createRes, err := s.CreateAPIKey(ctx, 8, req)
		require.NoError(t, err)

		// Make some requests
		_, err = s.ValidateAPIKey(ctx, createRes.Key, "/users", "GET")
		require.NoError(t, err)
		_, err = s.ValidateAPIKey(ctx, createRes.Key, "/users", "GET")
		require.NoError(t, err)
		_, err = s.ValidateAPIKey(ctx, createRes.Key, "/deployments", "GET")
		require.NoError(t, err)

		// Get stats
		from := time.Now().Add(-1 * time.Hour)
		to := time.Now().Add(1 * time.Hour)
		stats, err := s.GetAPIKeyUsageStats(ctx, 8, createRes.APIKeyID, from, to)
		require.NoError(t, err)
		require.Equal(t, int64(3), stats.TotalRequests)
		require.Equal(t, int64(2), stats.RequestsByEndpoint["/users GET"])
		require.Equal(t, int64(1), stats.RequestsByEndpoint["/deployments GET"])
		require.Equal(t, int64(0), stats.RateLimitHits)
	})

	// KEYS-09
	t.Run("Admin audit: all keys visible to admin", func(t *testing.T) {
		// A fresh store: the counts below are exact, and earlier subtests created keys of their own.
		s := newTestService(t)
		// Create keys for two users
		req1 := CreateAPIKeyRequest{Name: "User1 Key", Scopes: []string{"read:users"}, RateLimit: 1000}
		req2 := CreateAPIKeyRequest{Name: "User2 Key", Scopes: []string{"read:deployments"}, RateLimit: 1000}
		res1, err := s.CreateAPIKey(ctx, 10, req1)
		require.NoError(t, err)
		res2, err := s.CreateAPIKey(ctx, 20, req2)
		require.NoError(t, err)

		// Admin list all keys
		adminRes, err := s.ListAPIKeysForAdmin(ctx, nil, "")
		require.NoError(t, err)
		require.Len(t, adminRes.Keys, 2)
		require.Equal(t, int64(2), adminRes.Total)
		require.ElementsMatch(t, []string{res1.APIKeyID, res2.APIKeyID},
			[]string{adminRes.Keys[0].APIKeyID, adminRes.Keys[1].APIKeyID})

		// Admin list by user_id
		adminRes2, err := s.ListAPIKeysForAdmin(ctx, &[]int64{10}[0], "")
		require.NoError(t, err)
		require.Len(t, adminRes2.Keys, 1)
		require.Equal(t, int64(1), adminRes2.Total)
		require.Equal(t, res1.APIKeyID, adminRes2.Keys[0].APIKeyID)
	})
}
// requireStatus asserts err is an *APIError with the given HTTP status.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the KEYS rows name statuses (401, 403, 429), and
// the tests only checked that some error came back. Touches nothing.
func requireStatus(t *testing.T, err error, status int) {
	t.Helper()
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, status, apiErr.Status)
}

// TestKeyOwnershipEnforced proves a caller cannot revoke, rotate or read usage of another user's key:
// each answers 404 and the key keeps working. Why: Revoke/Rotate took only a key id (Phase B review);
// identity comes from the verified caller (spec README). Written 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: an in-memory SQLite database.
func TestKeyOwnershipEnforced(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	res, err := s.CreateAPIKey(ctx, 1, CreateAPIKeyRequest{Name: "Owner key", Scopes: []string{"read:users"}, RateLimit: 100})
	require.NoError(t, err)

	_, err = s.RevokeAPIKey(ctx, 2, res.APIKeyID)
	requireStatus(t, err, 404)
	_, err = s.RotateAPIKey(ctx, 2, res.APIKeyID)
	requireStatus(t, err, 404)
	_, err = s.GetAPIKeyUsageStats(ctx, 2, res.APIKeyID, s.now().Add(-time.Hour), s.now().Add(time.Hour))
	requireStatus(t, err, 404)

	_, err = s.ValidateAPIKey(ctx, res.Key, "/users", "GET")
	require.NoError(t, err, "the owner's key must still work after another user's attempts")

	_, err = s.RevokeAPIKey(ctx, 1, res.APIKeyID)
	require.NoError(t, err)
	_, err = s.ValidateAPIKey(ctx, res.Key, "/users", "GET")
	requireStatus(t, err, 401)
}
