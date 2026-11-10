import os
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import redis
import fakeredis

# Set test environment
os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["REDIS_URL"] = "redis://localhost:6379/1"

# Import the app and dependencies from the implementation
from api_keys_service_accounts_python import (
    app, Base, get_db, get_redis, ApiKey, ApiKeyUsage,
    generate_api_key, hash_key, verify_key, validate_api_key,
    log_api_key_usage, get_current_user, CurrentUser, scope_for_request
)

# [2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP] One in-memory database shared by the app and the
# test code (StaticPool keeps the single connection). The old override built a NEW empty in-memory database
# on every call, so a key created through the API could never be found again by the next request or by the
# test's own session ("total 0 vs 2"): no implementation could pass. Tables are reset before each test.
TEST_ENGINE = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=TEST_ENGINE)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

def override_get_redis():
    return fakeredis.FakeRedis()

app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[get_redis] = override_get_redis
# [2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP] The management routes now act for the authenticated
# user instead of a hard-coded user 1. The tests act as TEST_USER_ID (an admin, for the audit test).
app.dependency_overrides[get_current_user] = lambda: CurrentUser(id=1, is_admin=True)

client = TestClient(app)

# Test data
TEST_USER_ID = 1
TEST_NAME = "Test Integration"
TEST_SCOPES = ["read:deployments", "write:webhooks"]
TEST_EXPIRES_AT = datetime.utcnow() + timedelta(days=365)
TEST_RATE_LIMIT = 5

@pytest.fixture(autouse=True)
def fresh_tables():
    """Give every test empty tables (2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP)."""
    Base.metadata.drop_all(bind=TEST_ENGINE)
    Base.metadata.create_all(bind=TEST_ENGINE)
    yield

@pytest.fixture
def db_session():
    """Create a fresh database session for each test."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture
def redis_client():
    """Create a fresh Redis client for each test."""
    return fakeredis.FakeRedis()

# KEYS-01
def test_create_key_with_scopes():
    """Test creating an API key with scopes"""
    response = client.post(
        "/api-keys",
        json={
            "name": TEST_NAME,
            "scopes": TEST_SCOPES,
            "expires_at": TEST_EXPIRES_AT.isoformat(),
            "rate_limit": TEST_RATE_LIMIT
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "api_key_id" in data
    assert "key" in data
    assert data["key"].startswith("sk_test_")
    assert data["created_at"] is not None
    assert data["expires_at"] == TEST_EXPIRES_AT.isoformat()
    assert data["rate_limit"] == TEST_RATE_LIMIT
    
    # Verify key is stored hashed
    db = next(override_get_db())
    api_key = db.query(ApiKey).filter(ApiKey.id == data["api_key_id"]).first()
    assert api_key is not None
    assert api_key.name == TEST_NAME
    assert api_key.scopes == TEST_SCOPES
    assert verify_key(data["key"], api_key.key_secret_hash)
    assert api_key.rate_limit == TEST_RATE_LIMIT
    assert api_key.is_active == True

# KEYS-02
def test_use_key_request_succeeds():
    """Test using a valid API key succeeds"""
    # Create key
    create_resp = client.post(
        "/api-keys",
        json={"name": TEST_NAME, "scopes": TEST_SCOPES, "rate_limit": TEST_RATE_LIMIT}
    )
    assert create_resp.status_code == 200
    key_data = create_resp.json()
    api_key_id = key_data["api_key_id"]
    plaintext_key = key_data["key"]
    
    # Mock a request to a protected endpoint (we'll test validation directly)
    db = next(override_get_db())
    redis_client = override_get_redis()
    
    # Validate key for a scoped endpoint
    validated_key = validate_api_key(
        key=plaintext_key,
        required_scope="read:deployments",
        db=db,
        redis_client=redis_client
    )
    assert validated_key.id == api_key_id
    
    # Verify last_used_at updated
    db.refresh(validated_key)
    assert validated_key.last_used_at is not None

# KEYS-03
def test_revoke_key_subsequent_requests_401():
    """Test that revoked key returns 401"""
    # Create key
    create_resp = client.post(
        "/api-keys",
        json={"name": TEST_NAME, "scopes": TEST_SCOPES}
    )
    assert create_resp.status_code == 200
    key_data = create_resp.json()
    api_key_id = key_data["api_key_id"]
    plaintext_key = key_data["key"]
    
    # Revoke key
    revoke_resp = client.delete(f"/api-keys/{api_key_id}")
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["success"] == True
    
    # Try to use revoked key
    db = next(override_get_db())
    redis_client = override_get_redis()
    with pytest.raises(Exception) as exc_info:
        validate_api_key(
            key=plaintext_key,
            required_scope="read:deployments",
            db=db,
            redis_client=redis_client
        )
    assert exc_info.value.status_code == 401

# KEYS-04
def test_rate_limit_1001st_request_429():
    """Test rate limiting: 1001st request in hour returns 429"""
    # Create key with low rate limit for testing
    create_resp = client.post(
        "/api-keys",
        json={"name": TEST_NAME, "scopes": TEST_SCOPES, "rate_limit": 2}
    )
    assert create_resp.status_code == 200
    key_data = create_resp.json()
    plaintext_key = key_data["key"]
    api_key_id = key_data["api_key_id"]
    
    db = next(override_get_db())
    redis_client = override_get_redis()
    
    # First request: should succeed
    validated_key = validate_api_key(
        key=plaintext_key,
        required_scope="read:deployments",
        db=db,
        redis_client=redis_client
    )
    assert validated_key.id == api_key_id
    
    # Second request: should succeed
    validated_key = validate_api_key(
        key=plaintext_key,
        required_scope="read:deployments",
        db=db,
        redis_client=redis_client
    )
    assert validated_key.id == api_key_id
    
    # Third request: should fail with 429
    with pytest.raises(Exception) as exc_info:
        validate_api_key(
            key=plaintext_key,
            required_scope="read:deployments",
            db=db,
            redis_client=redis_client
        )
    assert exc_info.value.status_code == 429

# KEYS-05
def test_scope_check_key_cannot_write_deployments():
    """Test key with read:deployments cannot write deployments (403)"""
    # Create key with only read scope
    create_resp = client.post(
        "/api-keys",
        json={"name": TEST_NAME, "scopes": ["read:deployments"]}
    )
    assert create_resp.status_code == 200
    key_data = create_resp.json()
    plaintext_key = key_data["key"]
    
    db = next(override_get_db())
    redis_client = override_get_redis()
    
    # Validate for read scope: should succeed
    validated_key = validate_api_key(
        key=plaintext_key,
        required_scope="read:deployments",
        db=db,
        redis_client=redis_client
    )
    assert validated_key is not None
    
    # Validate for write scope: should fail with 403
    with pytest.raises(Exception) as exc_info:
        validate_api_key(
            key=plaintext_key,
            required_scope="write:deployments",
            db=db,
            redis_client=redis_client
        )
    assert exc_info.value.status_code == 403

# KEYS-06
def test_rotate_new_key_works_old_stops_after_grace():
    """Test rotation: new key works, old key stops after grace period"""
    # Create key
    create_resp = client.post(
        "/api-keys",
        json={"name": TEST_NAME, "scopes": TEST_SCOPES}
    )
    assert create_resp.status_code == 200
    key_data = create_resp.json()
    api_key_id = key_data["api_key_id"]
    old_key = key_data["key"]
    
    # Rotate key
    rotate_resp = client.post(f"/api-keys/{api_key_id}/rotate")
    assert rotate_resp.status_code == 200
    rotate_data = rotate_resp.json()
    new_key = rotate_data["new_key"]
    old_revoked_at = datetime.fromisoformat(rotate_data["old_key_revoked_at"])
    grace_ends_at = datetime.fromisoformat(rotate_data["grace_period_ends_at"])
    
    db = next(override_get_db())
    redis_client = override_get_redis()
    
    # Immediately after rotation:
    # Old key should still work (within grace period)
    validated_key = validate_api_key(
        key=old_key,
        required_scope="read:deployments",
        db=db,
        redis_client=redis_client
    )
    assert validated_key is not None
    assert validated_key.id == api_key_id  # Same key ID
    
    # New key should work
    validated_key = validate_api_key(
        key=new_key,
        required_scope="read:deployments",
        db=db,
        redis_client=redis_client
    )
    assert validated_key is not None
    assert validated_key.id != api_key_id  # New key ID
    
    # Simulate grace period expiration by moving the old key's grace period end into the past
    # (In reality, we'd wait, but we can manipulate the DB for test)
    # [2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP] was "created_at = revoked - 25h": that only worked
    # with an implementation that overwrote the key's creation date at rotation to track the grace period.
    assert grace_ends_at - old_revoked_at == timedelta(hours=24)
    api_key = db.query(ApiKey).filter(ApiKey.id == api_key_id).first()
    api_key.grace_period_ends_at = grace_ends_at - timedelta(hours=25)  # as if rotated 25 hours ago
    db.commit()
    
    # After grace period, old key should fail
    with pytest.raises(Exception) as exc_info:
        validate_api_key(
            key=old_key,
            required_scope="read:deployments",
            db=db,
            redis_client=redis_client
        )
    assert exc_info.value.status_code == 401

# KEYS-07
def test_expired_key_after_expires_at_returns_401():
    """Test expired key returns 401 after expires_at"""
    # Create key with short expiration
    expires_at = datetime.utcnow() - timedelta(seconds=1)  # Already expired
    create_resp = client.post(
        "/api-keys",
        json={
            "name": TEST_NAME,
            "scopes": TEST_SCOPES,
            "expires_at": expires_at.isoformat()
        }
    )
    assert create_resp.status_code == 200
    key_data = create_resp.json()
    plaintext_key = key_data["key"]
    
    db = next(override_get_db())
    redis_client = override_get_redis()
    
    # Try to use expired key
    with pytest.raises(Exception) as exc_info:
        validate_api_key(
            key=plaintext_key,
            required_scope="read:deployments",
            db=db,
            redis_client=redis_client
        )
    assert exc_info.value.status_code == 401

# KEYS-08
def test_usage_stats_requests_counted_per_endpoint():
    """Test usage stats: requests counted per endpoint"""
    # Create key
    create_resp = client.post(
        "/api-keys",
        json={"name": TEST_NAME, "scopes": TEST_SCOPES, "rate_limit": 100}
    )
    assert create_resp.status_code == 200
    key_data = create_resp.json()
    api_key_id = key_data["api_key_id"]
    plaintext_key = key_data["key"]
    
    db = next(override_get_db())
    redis_client = override_get_redis()
    
    # Make several requests
    endpoints = [
        ("GET", "/deployments"),
        ("GET", "/deployments"),
        ("POST", "/webhooks"),
        ("GET", "/deployments"),
        ("POST", "/webhooks"),
        ("POST", "/webhooks")
    ]
    
    for method, endpoint in endpoints:
        # Validate key (simulates middleware)
        validated_key = validate_api_key(
            key=plaintext_key,
            # [2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP] was f"{method.lower()}:..." ("get:deployments"),
            # which is not a scope (the spec's are read:/write:), so the key must have been refused with 403.
            required_scope=scope_for_request(method, endpoint),
            db=db,
            redis_client=redis_client
        )
        # Log usage (simulates after request processing)
        log_api_key_usage(
            api_key_id=validated_key.id,
            endpoint=endpoint,
            method=method,
            status_code=200,
            db=db
        )
    
    # Get usage stats
    response = client.get(f"/api-keys/{api_key_id}/usage")
    assert response.status_code == 200
    stats = response.json()
    assert stats["api_key_id"] == api_key_id
    assert stats["total_requests"] == 6
    assert stats["requests_by_endpoint"]["GET /deployments"] == 3
    assert stats["requests_by_endpoint"]["POST /webhooks"] == 3
    assert stats["rate_limit_hits"] == 0
    assert stats["errors"] == {}

# KEYS-09
def test_admin_audit_all_keys_visible():
    """Test admin can see all API keys"""
    # Create two keys for different users
    client.post(
        "/api-keys",
        json={"name": "Key 1", "scopes": ["read:users"]}
    )
    client.post(
        "/api-keys",
        json={"name": "Key 2", "scopes": ["write:users"]}
    )
    
    # Admin list all keys
    response = client.get("/admin/api-keys")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["keys"]) == 2
    
    # Filter by user_id (assuming both keys belong to user 1 in our test setup)
    response = client.get("/admin/api-keys?user_id=1")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    
    # Filter by status active
    response = client.get("/admin/api-keys?status=active")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    
    # Revoke one key
    key_id = data["keys"][0]["api_key_id"]
    client.delete(f"/api-keys/{key_id}")
    
    # Check inactive keys
    response = client.get("/admin/api-keys?status=inactive")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1

def test_management_routes_require_login_and_admin():
    """Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: no identity -> 401; non-admin -> 403 on the
    audit list; another user's key -> 404 (the template used to give every caller user 1 and the admin list)."""
    created = client.post("/api-keys", json={"name": "Mine", "scopes": ["read:users"]}).json()
    try:
        del app.dependency_overrides[get_current_user]
        # Each call is made before its assert, so the requests still happen under `python -O` (code scanning, PR 19).
        anonymous = client.get("/api-keys")
        assert anonymous.status_code == 401
        app.dependency_overrides[get_current_user] = lambda: CurrentUser(id=2, is_admin=False)
        audit_list = client.get("/admin/api-keys")
        assert audit_list.status_code == 403
        delete_other = client.delete(f"/api-keys/{created['api_key_id']}")
        assert delete_other.status_code == 404
        own_keys = client.get("/api-keys").json()["keys"]
        assert own_keys == []
    finally:
        app.dependency_overrides[get_current_user] = lambda: CurrentUser(id=1, is_admin=True)
    listed = client.get("/api-keys").json()["keys"]
    assert len(listed) == 1 and listed[0]["is_active"] is True
    assert "key" not in listed[0] and "key_secret_hash" not in listed[0]

# KEYS-02
def test_bearer_request_succeeds_and_is_logged():
    """Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: spec endpoint 5 over HTTP, with
    Authorization: Bearer; a missing scope is 403 and both calls land in the usage stats."""
    shared_redis = fakeredis.FakeRedis()
    app.dependency_overrides[get_redis] = lambda: shared_redis
    try:
        ok = client.post("/api-keys", json={"name": "Reader", "scopes": ["read:deployments"]}).json()
        resp = client.get("/api/deployments", headers={"Authorization": f"Bearer {ok['key']}"})
        assert resp.status_code == 200
        assert resp.json()["api_key_id"] == ok["api_key_id"]
        no_key = client.get("/api/deployments")
        assert no_key.status_code == 401
        other = client.post("/api-keys", json={"name": "Users only", "scopes": ["read:users"]}).json()
        wrong_scope = client.get("/api/deployments", headers={"Authorization": f"Bearer {other['key']}"})
        assert wrong_scope.status_code == 403
        stats = client.get(f"/api-keys/{other['api_key_id']}/usage").json()
        assert stats["errors"] == {"403": 1}
    finally:
        app.dependency_overrides[get_redis] = override_get_redis

if __name__ == "__main__":
    pytest.main([__file__, "-v"])