"""API keys and service accounts (TIER_2 spec, system 5) as a FastAPI app over SQLAlchemy and Redis.

What it does
    Users create scoped API keys (``sk_live_...`` / ``sk_test_...``), list them (never the secret),
    revoke and rotate them (the old key keeps working for a 24 h grace period), and read per-key usage
    stats. Admins list every key. ``validate_api_key`` is the per-request check: bcrypt-verify the key,
    reject revoked (401), expired (401), out-of-scope (403) and over-limit (429) requests, and stamp
    ``last_used_at``. ``api_key_auth(scope)`` wraps it as a FastAPI dependency that reads
    ``Authorization: Bearer <key>`` and logs every call to ``api_key_usage``.

Inputs / outputs
    JSON bodies and responses in the spec's shapes. Management routes act for the user returned by
    ``get_current_user``; admin routes also require ``is_admin``.

Why (repair 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP)
    8 of 9 tests failed: created keys were never listed (the tests' database lived for one request)
    and use/revoke failed. Repairing it also fixed what made it unsafe to copy:
    every key belonged to a hard-coded ``user_id=1`` and any caller could manage or list (admin) all
    keys, so management routes now need an authenticated user (``get_current_user``, which you
    wire to your login system; it refuses until you do) and admin routes need an admin; a key lookup
    bcrypt-checked every active key in turn, so keys now carry a public lookup id and only matching
    rows are verified; rotation overwrote the old key's ``created_at`` and stored the new hash on
    the old row, so it now records ``rotated_at`` / ``grace_period_ends_at`` instead; the ``status``
    query parameter shadowed ``fastapi.status`` (any admin filter crashed); usage of denied
    requests is logged so ``rate_limit_hits`` and ``errors`` are real.

What it touches
    The SQL database at ``DATABASE_URL`` (tables api_keys, api_key_usage), Redis at ``REDIS_URL``
    (hourly rate-limit counters; lazy, connects on first use). Secrets: only bcrypt hashes are
    stored; the plaintext key is returned once, at creation or rotation, and never logged. No money.
"""
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple

import bcrypt
import redis
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, create_engine
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker

# Database setup
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./api_keys.db")
_connect_args = {"check_same_thread": False} if SQLALCHEMY_DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Redis setup (redis.from_url does not connect until the first command)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
redis_client = redis.from_url(REDIS_URL)

KEY_PREFIXES = ("sk_live_", "sk_test_")
LOOKUP_ID_LENGTH = 12            # public part of the random string, indexed for lookup
GRACE_PERIOD = timedelta(hours=24)
DEFAULT_RATE_LIMIT = 1000        # requests per hour (spec)
BCRYPT_ROUNDS = int(os.getenv("API_KEY_BCRYPT_ROUNDS", "12"))
ALL_SCOPES = "*"

# DDL for database schema (PostgreSQL), matching the SQLAlchemy models below
API_KEYS_DDL = """
CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    name VARCHAR(255) NOT NULL,
    key_lookup VARCHAR(32) NOT NULL,
    key_secret_hash VARCHAR(255) NOT NULL,
    scopes JSONB NOT NULL,
    rate_limit INTEGER NOT NULL,
    expires_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    revoked_at TIMESTAMP,
    rotated_at TIMESTAMP,
    grace_period_ends_at TIMESTAMP,
    replaced_by_id INTEGER REFERENCES api_keys(id)
);
CREATE INDEX IF NOT EXISTS idx_api_keys_lookup ON api_keys(key_lookup);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);

CREATE TABLE IF NOT EXISTS api_key_usage (
    id SERIAL PRIMARY KEY,
    api_key_id INTEGER REFERENCES api_keys(id),
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    status INTEGER NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_key_usage_key_time ON api_key_usage(api_key_id, timestamp);
"""


def _utcnow() -> datetime:
    """Current UTC time as a naive datetime (the form stored in the DateTime columns).

    2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: replaces the deprecated ``datetime.utcnow``.
    Touches nothing.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _to_naive_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Convert an aware datetime to naive UTC; a naive one is taken to be UTC already.

    2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: an ``expires_at`` with an offset was compared
    with the clock as if it were UTC. Touches nothing.
    """
    if value is None or value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


# Database models
class ApiKey(Base):
    """One API key. ``key_lookup`` is a public, indexed slice of the key; ``key_secret_hash`` is bcrypt.

    After rotation the old row is inactive with ``rotated_at``/``grace_period_ends_at`` set and
    ``replaced_by_id`` pointing at the new row; until the grace period ends the old key still works.
    2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the api_keys table.
    """
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    key_lookup = Column(String(32), index=True, nullable=False)
    key_secret_hash = Column(String(255), nullable=False)
    scopes = Column(JSON, nullable=False)
    rate_limit = Column(Integer, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=_utcnow)
    last_used_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    revoked_at = Column(DateTime, nullable=True)
    rotated_at = Column(DateTime, nullable=True)
    grace_period_ends_at = Column(DateTime, nullable=True)
    replaced_by_id = Column(Integer, ForeignKey("api_keys.id"), nullable=True)

    usage = relationship("ApiKeyUsage", back_populates="api_key")


class ApiKeyUsage(Base):
    """One API call made with a key: endpoint, method, response status and time (spec "Audit").

    2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the api_key_usage table.
    """
    __tablename__ = "api_key_usage"

    id = Column(Integer, primary_key=True, index=True)
    api_key_id = Column(Integer, ForeignKey("api_keys.id"), nullable=True, index=True)
    endpoint = Column(String(255), nullable=False)
    method = Column(String(10), nullable=False)
    status = Column(Integer, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=_utcnow)

    api_key = relationship("ApiKey", back_populates="usage")


# Create tables
Base.metadata.create_all(bind=engine)


# Pydantic models
class ApiKeyCreate(BaseModel):
    """POST /api-keys body. Scopes must be a non-empty list of 'action:resource' strings or '*'.

    2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: validation added (an empty scope list or a
    zero rate limit used to be stored). Touches nothing.
    """
    name: str = Field(min_length=1, max_length=255)
    scopes: List[str] = Field(min_length=1)
    expires_at: Optional[datetime] = None
    rate_limit: Optional[int] = Field(default=DEFAULT_RATE_LIMIT, gt=0)

    @field_validator("scopes")
    @classmethod
    def _check_scopes(cls, scopes: List[str]) -> List[str]:
        for s in scopes:
            if s != ALL_SCOPES and (s.count(":") != 1 or not all(s.split(":"))):
                raise ValueError(f"invalid scope {s!r}: use 'action:resource' or '*'")
        return scopes


class ApiKeyResponse(BaseModel):
    """POST /api-keys response; ``key`` is the only time the plaintext is ever returned."""
    api_key_id: int
    key: str
    created_at: datetime
    expires_at: Optional[datetime]
    rate_limit: int


class ApiKeyListItem(BaseModel):
    """One masked key in GET /api-keys (no secret, no hash)."""
    api_key_id: int
    name: str
    scopes: List[str]
    created_at: datetime
    last_used_at: Optional[datetime]
    rate_limit: int
    is_active: bool


class ApiKeyList(BaseModel):
    """GET /api-keys response: ``{keys: [...]}`` as in the spec. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP."""
    keys: List[ApiKeyListItem]


class ApiKeyUsageStats(BaseModel):
    """GET /api-keys/{id}/usage response."""
    api_key_id: int
    total_requests: int
    requests_by_endpoint: Dict[str, int]
    rate_limit_hits: int
    errors: Dict[str, int]


@dataclass(frozen=True)
class CurrentUser:
    """The authenticated caller of the management routes. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP."""
    id: int
    is_admin: bool = False


# Dependencies
def get_db():
    """Yield a SQLAlchemy session and close it afterwards. Touches the database."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_redis():
    """Return the shared Redis client. Touches Redis (network) when used."""
    return redis_client


def get_current_user() -> CurrentUser:
    """Return the logged-in user for the management routes. Wire this to your auth system.

    Override it with ``app.dependency_overrides[get_current_user] = <your session/JWT check>``. Until
    then every management route answers 401: identity must never come from the request body or a
    hard-coded id. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: replaces ``user_id=1``.
    Touches nothing.
    """
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


def require_admin(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    """Allow only admins (403 otherwise). 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the admin
    audit listed every user's keys to anyone. Touches nothing."""
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")
    return user


# Helper functions
def generate_api_key() -> str:
    """Generate a new API key ``sk_live_<random>`` (production) or ``sk_test_<random>`` (otherwise).

    The random part is 32 bytes from ``secrets`` (43 URL-safe characters). Touches nothing.
    """
    prefix = "sk_live_" if os.getenv("ENVIRONMENT") == "production" else "sk_test_"
    return f"{prefix}{secrets.token_urlsafe(32)}"


def key_lookup_id(key: str) -> Optional[str]:
    """Return the public lookup id of a key (its first LOOKUP_ID_LENGTH random characters), or None.

    It is indexed so a request bcrypt-checks only the matching row(s), never every key. The rest of
    the random part (over 180 bits) stays secret. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
    Touches nothing.
    """
    if not isinstance(key, str) or not key.startswith(KEY_PREFIXES):
        return None
    random_part = key[len("sk_test_"):]
    if len(random_part) <= LOOKUP_ID_LENGTH:
        return None
    return random_part[:LOOKUP_ID_LENGTH]


def hash_key(key: str) -> str:
    """Hash a plaintext API key with bcrypt (cost BCRYPT_ROUNDS) and return the hash text. Touches nothing."""
    return bcrypt.hashpw(key.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("utf-8")


def verify_key(plaintext_key: str, hashed_key: str) -> bool:
    """Check a plaintext key against its bcrypt hash (bcrypt compares in constant time). Touches nothing."""
    try:
        return bcrypt.checkpw(plaintext_key.encode("utf-8"), hashed_key.encode("utf-8"))
    except ValueError:  # malformed hash or over-long input
        return False


def scope_for_request(method: str, path: str) -> Optional[str]:
    """Map an HTTP request to the scope it needs: GET/HEAD/OPTIONS -> ``read:<resource>``, else ``write:<resource>``.

    ``<resource>`` is the first path segment after an optional ``/api`` (``GET /api/deployments`` ->
    ``read:deployments``). Returns None for ``/``. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP:
    a middleware needs this to check scopes as the spec lists them. Touches nothing.
    """
    parts = [p for p in path.split("?")[0].split("/") if p]
    if parts and parts[0] == "api":
        parts = parts[1:]
    if not parts:
        return None
    action = "read" if method.upper() in ("GET", "HEAD", "OPTIONS") else "write"
    return f"{action}:{parts[0]}"


def _has_scope(granted: List[str], required: str) -> bool:
    """True if ``granted`` holds ``required`` or the all-actions scope '*'. Touches nothing."""
    return ALL_SCOPES in granted or required in granted


def _find_key(db: Session, key: str, now: datetime) -> Optional[ApiKey]:
    """Return the row whose bcrypt hash matches ``key`` and that may still authenticate, else None.

    Only rows with the key's lookup id are checked. A row may authenticate while active, or while
    inactive within a rotation grace period (``grace_period_ends_at`` in the future). 2026-11-10,
    session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (read).
    """
    lookup = key_lookup_id(key)
    if lookup is None:
        return None
    candidates = db.query(ApiKey).filter(ApiKey.key_lookup == lookup).order_by(ApiKey.id).all()
    for row in candidates:
        if verify_key(key, row.key_secret_hash):
            if row.is_active or (row.grace_period_ends_at is not None and now < row.grace_period_ends_at):
                return row
            return None  # matched but revoked / grace over
    return None


def log_api_key_usage(
    api_key_id: Optional[int],
    endpoint: str,
    method: str,
    status_code: int,
    db: Session = Depends(get_db),
):
    """Record one API call (endpoint, method, response status, time) in api_key_usage and commit.

    Touches the database (INSERT). Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
    """
    db.add(ApiKeyUsage(api_key_id=api_key_id, endpoint=endpoint, method=method.upper(), status=status_code))
    db.commit()


def validate_api_key(
    key: str,
    required_scope: Optional[str] = None,
    db: Session = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
    endpoint: Optional[str] = None,
    method: Optional[str] = None,
) -> ApiKey:
    """Authenticate one request made with ``key`` and return its ApiKey row; raise HTTPException otherwise.

    Order (spec endpoint 5): unknown/malformed/revoked key -> 401; expired -> 401; missing
    ``required_scope`` -> 403; more than ``rate_limit`` requests in the current UTC hour (Redis counter
    ``rate_limit:<id>:<YYYY-MM-DDTHH>``) -> 429. On success ``last_used_at`` is set and committed. When
    ``endpoint``/``method`` are given, a denial for a known key is logged to api_key_usage (so usage
    stats count 401/403/429). Inputs: key, required_scope, db, redis_client, endpoint, method.
    2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: indexed lookup instead of a bcrypt scan over
    every key, rotation grace support, last_used_at, denial logging. Touches the database and Redis.
    """
    now = _utcnow()

    def deny(row: Optional[ApiKey], code: int, detail: str):
        if row is not None and endpoint and method:
            log_api_key_usage(row.id, endpoint, method, code, db=db)
        raise HTTPException(status_code=code, detail=detail)

    api_key = _find_key(db, key, now)
    if api_key is None:
        deny(None, status.HTTP_401_UNAUTHORIZED, "Invalid or revoked API key")
    if api_key.expires_at is not None and api_key.expires_at <= now:
        deny(api_key, status.HTTP_401_UNAUTHORIZED, "API key has expired")
    if required_scope and not _has_scope(list(api_key.scopes or []), required_scope):
        deny(api_key, status.HTTP_403_FORBIDDEN, f"Insufficient scope. Required: {required_scope}")

    redis_key = f"rate_limit:{api_key.id}:{now.strftime('%Y-%m-%dT%H')}"
    pipe = redis_client.pipeline()
    pipe.incr(redis_key)
    pipe.expire(redis_key, 7200)
    current_count = pipe.execute()[0]
    if current_count > api_key.rate_limit:
        deny(api_key, status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")

    api_key.last_used_at = now
    db.commit()
    return api_key


def api_key_auth(required_scope: Optional[str] = None) -> Callable[..., ApiKey]:
    """Build a FastAPI dependency that authenticates ``Authorization: Bearer <key>`` for a route.

    The scope is ``required_scope`` or, if None, derived from the request (``scope_for_request``).
    Successful calls are logged as 200 (adjust in your handler if it answers otherwise); denials are
    logged by ``validate_api_key``. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the template
    had no way to use a key over HTTP. Touches the database and Redis.
    """
    def dependency(request: Request,
                   authorization: Optional[str] = Header(default=None),
                   db: Session = Depends(get_db),
                   rds: redis.Redis = Depends(get_redis)) -> ApiKey:
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer API key",
                                headers={"WWW-Authenticate": "Bearer"})
        path, method = request.url.path, request.method
        scope = required_scope or scope_for_request(method, path)
        row = validate_api_key(token.strip(), scope, db=db, redis_client=rds, endpoint=path, method=method)
        log_api_key_usage(row.id, path, method, 200, db=db)
        return row
    return dependency


def _owned_key(db: Session, api_key_id: int, user: CurrentUser) -> ApiKey:
    """Return the caller's key with this id, or 404 (also for another user's key, so ids cannot be probed).

    2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (read).
    """
    row = db.query(ApiKey).filter(ApiKey.id == api_key_id, ApiKey.user_id == user.id).first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    return row


def _new_key_row(user_id: int, name: str, scopes: List[str], rate_limit: int,
                 expires_at: Optional[datetime]) -> Tuple[ApiKey, str]:
    """Create (unsaved) an ApiKey row plus its plaintext key. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP.
    Touches nothing."""
    plaintext = generate_api_key()
    row = ApiKey(user_id=user_id, name=name, key_lookup=key_lookup_id(plaintext), key_secret_hash=hash_key(plaintext),
                 scopes=list(scopes), rate_limit=rate_limit, expires_at=expires_at, created_at=_utcnow(),
                 is_active=True)
    return row, plaintext


# FastAPI app
app = FastAPI(title="API Keys & Service Accounts")


@app.post("/api-keys", response_model=ApiKeyResponse)
def create_api_key(key_data: ApiKeyCreate, db: Session = Depends(get_db),
                   user: CurrentUser = Depends(get_current_user)):
    """POST /api-keys: create a key for the caller; the plaintext is in this response only.

    2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: owner is the authenticated user, not 1.
    Touches the database (INSERT).
    """
    row, plaintext = _new_key_row(user.id, key_data.name, key_data.scopes,
                                  key_data.rate_limit or DEFAULT_RATE_LIMIT, _to_naive_utc(key_data.expires_at))
    db.add(row)
    db.commit()
    db.refresh(row)
    return ApiKeyResponse(api_key_id=row.id, key=plaintext, created_at=row.created_at,
                          expires_at=row.expires_at, rate_limit=row.rate_limit)


@app.get("/api-keys", response_model=ApiKeyList)
def list_api_keys(db: Session = Depends(get_db), user: CurrentUser = Depends(get_current_user)):
    """GET /api-keys: the caller's keys, masked (never the key or its hash), oldest first.

    2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: returns ``{keys: [...]}`` (spec) for the
    authenticated user, including revoked keys with ``is_active`` false. Touches the database (read).
    """
    rows = db.query(ApiKey).filter(ApiKey.user_id == user.id).order_by(ApiKey.id).all()
    return ApiKeyList(keys=[ApiKeyListItem(api_key_id=k.id, name=k.name, scopes=k.scopes, created_at=k.created_at,
                                           last_used_at=k.last_used_at, rate_limit=k.rate_limit,
                                           is_active=k.is_active) for k in rows])


@app.delete("/api-keys/{api_key_id}")
def revoke_api_key(api_key_id: int, db: Session = Depends(get_db), user: CurrentUser = Depends(get_current_user)):
    """DELETE /api-keys/{id}: revoke the caller's key at once (also ends any rotation grace period).

    Returns ``{success, revoked_at}``. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: ownership
    check added. Touches the database (UPDATE).
    """
    row = _owned_key(db, api_key_id, user)
    now = _utcnow()
    row.is_active = False
    row.revoked_at = row.revoked_at or now
    row.grace_period_ends_at = None
    db.commit()
    return {"success": True, "revoked_at": row.revoked_at.isoformat()}


@app.post("/api-keys/{api_key_id}/rotate")
def rotate_api_key(api_key_id: int, db: Session = Depends(get_db), user: CurrentUser = Depends(get_current_user)):
    """POST /api-keys/{id}/rotate: issue a new key (new row, same name/scopes/limits) and retire the old one.

    The old key keeps working until ``grace_period_ends_at`` (24 h). A revoked or already-rotated key
    cannot be rotated (409). Returns ``{new_key, old_key_revoked_at, grace_period_ends_at}``.
    2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the old code wrote the new hash and the
    rotation time over the old row's hash and created_at. Touches the database.
    """
    old = _owned_key(db, api_key_id, user)
    if not old.is_active:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="API key is revoked or already rotated")
    now = _utcnow()
    new, plaintext = _new_key_row(old.user_id, old.name, old.scopes, old.rate_limit, old.expires_at)
    db.add(new)
    db.flush()
    old.is_active = False
    old.rotated_at = now
    old.grace_period_ends_at = now + GRACE_PERIOD
    old.replaced_by_id = new.id
    db.commit()
    return {"new_key": plaintext, "api_key_id": new.id, "old_key_revoked_at": now.isoformat(),
            "grace_period_ends_at": old.grace_period_ends_at.isoformat()}


@app.get("/api-keys/{api_key_id}/usage", response_model=ApiKeyUsageStats)
def get_api_key_usage(
    api_key_id: int,
    from_date: Optional[datetime] = Query(default=None, alias="from"),
    to_date: Optional[datetime] = Query(default=None, alias="to"),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """GET /api-keys/{id}/usage?from=&to=: totals, per 'METHOD /endpoint' counts, 429 hits, errors by status.

    2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: ownership check; the query names are the
    spec's ``from``/``to``. Touches the database (read).
    """
    _owned_key(db, api_key_id, user)
    query = db.query(ApiKeyUsage).filter(ApiKeyUsage.api_key_id == api_key_id)
    if from_date:
        query = query.filter(ApiKeyUsage.timestamp >= _to_naive_utc(from_date))
    if to_date:
        query = query.filter(ApiKeyUsage.timestamp <= _to_naive_utc(to_date))
    by_endpoint: Dict[str, int] = {}
    errors: Dict[str, int] = {}
    hits = total = 0
    for record in query.order_by(ApiKeyUsage.id).all():
        total += 1
        label = f"{record.method} {record.endpoint}"
        by_endpoint[label] = by_endpoint.get(label, 0) + 1
        if record.status == 429:
            hits += 1
        if record.status >= 400:
            errors[str(record.status)] = errors.get(str(record.status), 0) + 1
    return ApiKeyUsageStats(api_key_id=api_key_id, total_requests=total, requests_by_endpoint=by_endpoint,
                            rate_limit_hits=hits, errors=errors)


@app.get("/admin/api-keys")
def admin_list_api_keys(
    user_id: Optional[int] = None,
    status_filter: Optional[str] = Query(default=None, alias="status", pattern="^(active|inactive)$"),
    db: Session = Depends(get_db),
    admin: CurrentUser = Depends(require_admin),
):
    """GET /admin/api-keys?user_id=&status=active|inactive: every key for audit (admins only), oldest first.

    2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: admin check added; the ``status`` parameter
    no longer shadows ``fastapi.status``. Touches the database (read).
    """
    query = db.query(ApiKey)
    if user_id is not None:
        query = query.filter(ApiKey.user_id == user_id)
    if status_filter == "active":
        query = query.filter(ApiKey.is_active.is_(True))
    elif status_filter == "inactive":
        query = query.filter(ApiKey.is_active.is_(False))
    rows = query.order_by(ApiKey.id).all()
    return {
        "keys": [
            {"api_key_id": k.id, "user_id": k.user_id, "name": k.name, "scopes": k.scopes,
             "created_at": k.created_at, "last_used_at": k.last_used_at, "rate_limit": k.rate_limit,
             "expires_at": k.expires_at, "is_active": k.is_active, "revoked_at": k.revoked_at,
             "grace_period_ends_at": k.grace_period_ends_at}
            for k in rows
        ],
        "total": len(rows),
    }


@app.post("/admin/api-keys/expire")
def expire_api_keys(db: Session = Depends(get_db), admin: CurrentUser = Depends(require_admin)):
    """Cron job (spec "Expiry"): mark every active key past ``expires_at`` inactive; returns ``{expired}``.

    Expired keys are already refused at request time; this keeps ``is_active`` truthful for audits.
    2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the database (UPDATE).
    """
    now = _utcnow()
    rows = db.query(ApiKey).filter(ApiKey.is_active.is_(True), ApiKey.expires_at.isnot(None),
                                   ApiKey.expires_at <= now).all()
    for row in rows:
        row.is_active = False
        row.revoked_at = now
    db.commit()
    return {"expired": len(rows)}


@app.get("/api/deployments")
def example_list_deployments(api_key: ApiKey = Depends(api_key_auth("read:deployments"))):
    """Example protected route (spec endpoint 5): needs a key with ``read:deployments``.

    Replace the body with your data. 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches the
    database and Redis through ``api_key_auth``.
    """
    return {"deployments": [], "api_key_id": api_key.id}
