/**
 * Idempotency keys (docs/specs/idempotency_keys.md): the same POST/PATCH with the same Idempotency-Key runs its
 * operation ONCE, per scope (the authenticated client), and a retry gets the stored response.
 *
 * Exports: OperationFailed, IdempotencyService (store + clock injectable), InMemoryIdempotencyStore, and the
 * module-level handle / release / resolve / list_uncertain / is_required / purge_expired over one shared default
 * service.
 *
 * Rewritten 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, for the IDEM-07/08/10/11 amendments: records gain the
 * status 'uncertain'; OperationFailed frees the key and any other error marks it 'uncertain' (a retry gets 409
 * outcome_unknown and does not run); only 'completed' records expire, and an 'in_progress' record past expires_at
 * is treated as uncertain; release() / resolve() / list_uncertain() are operator functions, each release/resolve
 * one conditional write. The old build deleted the record on every error, so a timeout after the provider was
 * called let a retry charge twice. Touches: process memory only (the in-memory store); the operation passed in
 * touches whatever it touches (money, for a charge).
 */
import { createHash } from "crypto";

export type HttpResponse = {
  status: number;
  content_type: string;
  body: string;
};

export type OperationResult = {
  status: number;
  body: any;
};

export type Operation = () => OperationResult | Promise<OperationResult>;

export type RecordStatus = "in_progress" | "completed" | "uncertain";

export type IdempotencyRecord = {
  scope: string;
  idem_key: string;
  request_fingerprint: string;
  status: RecordStatus;
  response_status?: number;
  response_body?: string;
  created_at: Date;
  expires_at: Date;
};

/** How long a key lives: 24 hours. */
export const TTL_MS = 24 * 60 * 60 * 1000;

/**
 * Raised by an operation to report a DEFINITE failure: it did nothing (a validation error, a provider decline).
 * handle() then deletes the in_progress record and re-raises, so a retry with the same key runs again (IDEM-08).
 * Any other error marks the key 'uncertain' (IDEM-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 */
export class OperationFailed extends Error {
  constructor(message = "operation failed") {
    super(message);
    this.name = "OperationFailed";
  }
}

/**
 * The storage contract. Every method is one atomic step on one record, so two concurrent callers cannot both
 * claim a key, and of two concurrent release()/resolve() calls exactly one succeeds.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the backing store.
 */
export interface IdempotencyStore {
  /** The record for (scope, key), or undefined. */
  get(scope: string, idem_key: string): IdempotencyRecord | undefined;
  /** Inserts `record` if no record exists or the existing one is 'completed' and expired at `now`; true if inserted. */
  claim(record: IdempotencyRecord, now: Date): boolean;
  /** in_progress -> completed with the response (only if still in_progress with this fingerprint). */
  complete(scope: string, idem_key: string, fp: string, status: number, body: string): void;
  /** Deletes the record only if it is still in_progress with this fingerprint. */
  deleteInProgress(scope: string, idem_key: string, fp: string): void;
  /** in_progress -> uncertain (only if still in_progress with this fingerprint). */
  markUncertain(scope: string, idem_key: string, fp: string): void;
  /** Deletes the record if it is uncertain at `now` (status uncertain, or in_progress past expires_at). One conditional write. */
  releaseIfUncertain(scope: string, idem_key: string, now: Date): boolean;
  /** Stores the outcome as completed, expires_at = now + 24 h, if the record is uncertain at `now`. One conditional write. */
  resolveIfUncertain(scope: string, idem_key: string, status: number, body: string, now: Date): boolean;
  /** Uncertain records at `now`, oldest first (ties by insertion order), at most `limit`. */
  listUncertain(limit: number, now: Date): IdempotencyRecord[];
  /** Deletes completed records expired at `now`; never in_progress or uncertain ones. */
  purgeExpired(now: Date): void;
}

/**
 * Whether a record counts as 'uncertain' at `now`: stored as uncertain, or in_progress past its expires_at (a
 * killed process could not record its outcome). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function isUncertain(rec: IdempotencyRecord, now: Date): boolean {
  return rec.status === "uncertain" ||
    (rec.status === "in_progress" && rec.expires_at.getTime() <= now.getTime());
}

/** Whether a record is 'completed' and expired at `now` (it then counts as absent). Touches nothing. */
function isExpiredCompleted(rec: IdempotencyRecord, now: Date): boolean {
  return rec.status === "completed" && rec.expires_at.getTime() <= now.getTime();
}

/**
 * In-memory store. JavaScript runs each method to completion without interleaving, so each method is atomic;
 * a SQL store does the same with INSERT ... ON CONFLICT and UPDATE/DELETE ... WHERE status conditions.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: process memory.
 */
export class InMemoryIdempotencyStore implements IdempotencyStore {
  private map: Map<string, IdempotencyRecord> = new Map();
  private seq = 0;
  private order = new WeakMap<IdempotencyRecord, number>();

  private key(scope: string, idem_key: string): string {
    return JSON.stringify([scope, idem_key]);
  }

  get(scope: string, idem_key: string): IdempotencyRecord | undefined {
    return this.map.get(this.key(scope, idem_key));
  }

  /** Test helper: replace a record as-is. */
  set(record: IdempotencyRecord): void {
    this.order.set(record, this.seq++);
    this.map.set(this.key(record.scope, record.idem_key), record);
  }

  /** Test helper: drop a record whatever its status. */
  delete(scope: string, idem_key: string): void {
    this.map.delete(this.key(scope, idem_key));
  }

  claim(record: IdempotencyRecord, now: Date): boolean {
    const existing = this.get(record.scope, record.idem_key);
    if (existing && !isExpiredCompleted(existing, now)) return false;
    this.set(record);
    return true;
  }

  private current(scope: string, idem_key: string, fp: string): IdempotencyRecord | undefined {
    const rec = this.get(scope, idem_key);
    return rec && rec.status === "in_progress" && rec.request_fingerprint === fp ? rec : undefined;
  }

  complete(scope: string, idem_key: string, fp: string, status: number, body: string): void {
    const rec = this.current(scope, idem_key, fp);
    if (!rec) return;
    rec.status = "completed";
    rec.response_status = status;
    rec.response_body = body;
  }

  deleteInProgress(scope: string, idem_key: string, fp: string): void {
    if (this.current(scope, idem_key, fp)) this.delete(scope, idem_key);
  }

  markUncertain(scope: string, idem_key: string, fp: string): void {
    const rec = this.current(scope, idem_key, fp);
    if (rec) rec.status = "uncertain";
  }

  releaseIfUncertain(scope: string, idem_key: string, now: Date): boolean {
    const rec = this.get(scope, idem_key);
    if (!rec || !isUncertain(rec, now)) return false;
    this.delete(scope, idem_key);
    return true;
  }

  resolveIfUncertain(scope: string, idem_key: string, status: number, body: string, now: Date): boolean {
    const rec = this.get(scope, idem_key);
    if (!rec || !isUncertain(rec, now)) return false;
    rec.status = "completed";
    rec.response_status = status;
    rec.response_body = body;
    rec.expires_at = new Date(now.getTime() + TTL_MS);
    return true;
  }

  listUncertain(limit: number, now: Date): IdempotencyRecord[] {
    return [...this.map.values()]
      .filter((r) => isUncertain(r, now))
      .sort((a, b) =>
        a.created_at.getTime() - b.created_at.getTime() || (this.order.get(a) ?? 0) - (this.order.get(b) ?? 0))
      .slice(0, Math.max(0, limit));
  }

  purgeExpired(now: Date): void {
    for (const rec of [...this.map.values()]) {
      if (isExpiredCompleted(rec, now)) this.delete(rec.scope, rec.idem_key);
    }
  }
}

/* ---------- helpers ---------- */

/** SHA-256 hex of method + " " + path + "\n" + body (spec). Touches nothing. */
function fingerprint(method: string, path: string, body: string): string {
  const data = `${method} ${path}\n${body}`;
  return createHash("sha256").update(data).digest("hex");
}

/**
 * An RFC 7807 error response. In: status, title, detail and the problem type (default "about:blank").
 * Out: {status, content_type "application/problem+json", body {type, title, detail}}. Touches nothing.
 */
function problemResponse(status: number, title: string, detail: string, type = "about:blank"): HttpResponse {
  return {
    status,
    content_type: "application/problem+json",
    body: JSON.stringify({ type, title, detail }),
  };
}

/** Whether an idempotency key is required: POST and PATCH (spec default). Touches nothing. */
export function is_required(method: string, path: string): boolean {
  const m = method.toUpperCase();
  return m === "POST" || m === "PATCH";
}

/**
 * The idempotency service over an injectable store and clock.
 *
 * In: a store (default in-memory) and `now` (default the system clock). Why: the spec's storage-behind-an-
 * interface and injectable-clock rules; the old module used a hidden singleton and `new Date()`.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
 */
export class IdempotencyService {
  constructor(
    readonly store: IdempotencyStore = new InMemoryIdempotencyStore(),
    private readonly now: () => Date = () => new Date(),
  ) {}

  /**
   * Handles one request.
   *
   * In: scope (the authenticated client id, never request input), the Idempotency-Key value, method, path, the
   * raw body, and the operation (called at most once; returns {status, body}).
   * Out: {status, content_type, body}: the operation's response as application/json, the stored response for a
   * completed key, or a problem+json error: 400 missing key; 422 different fingerprint (checked first, even
   * while in progress or uncertain); 409 still in progress; 409 type "outcome_unknown" when the outcome is
   * uncertain. Errors from the operation are re-raised: OperationFailed frees the key, any other error marks it
   * 'uncertain'.
   * Why: IDEM-01..11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store, and whatever the
   * operation touches.
   */
  async handle(
    scope: string,
    idempotency_key: string | undefined,
    method: string,
    path: string,
    body: string,
    operation: Operation,
  ): Promise<HttpResponse> {
    if (!idempotency_key) {
      if (is_required(method, path)) {
        return problemResponse(400, "Missing Idempotency-Key", "The request requires an Idempotency-Key header.");
      }
      const result = await Promise.resolve(operation());
      return { status: result.status, content_type: "application/json", body: JSON.stringify(result.body) };
    }

    const fp = fingerprint(method, path, body);
    const now = this.now();

    for (;;) {
      const existing = this.store.get(scope, idempotency_key);
      if (existing && !isExpiredCompleted(existing, now)) {
        return this.answerExisting(existing, fp, now);
      }
      const record: IdempotencyRecord = {
        scope,
        idem_key: idempotency_key,
        request_fingerprint: fp,
        status: "in_progress",
        created_at: now,
        expires_at: new Date(now.getTime() + TTL_MS),
      };
      if (this.store.claim(record, now)) break;
      // Someone else claimed it between the read and the claim: answer from their record.
    }

    let result: OperationResult;
    try {
      result = await Promise.resolve(operation());
    } catch (e) {
      if (e instanceof OperationFailed) {
        this.store.deleteInProgress(scope, idempotency_key, fp);
      } else {
        this.store.markUncertain(scope, idempotency_key, fp);
      }
      throw e;
    }
    const responseBody = JSON.stringify(result.body);
    this.store.complete(scope, idempotency_key, fp, result.status, responseBody);
    return { status: result.status, content_type: "application/json", body: responseBody };
  }

  /** The answer for a key that already has a live record (see handle). Touches nothing. */
  private answerExisting(rec: IdempotencyRecord, fp: string, now: Date): HttpResponse {
    if (rec.request_fingerprint !== fp) {
      return problemResponse(422, "Payload Mismatch", "The request payload differs from the original request.");
    }
    if (isUncertain(rec, now)) {
      return problemResponse(
        409,
        "Outcome Unknown",
        "The first request with this Idempotency-Key ended without a known outcome; it must be reconciled before a retry.",
        "outcome_unknown",
      );
    }
    if (rec.status === "in_progress") {
      return problemResponse(409, "Request In Progress", "A request with this Idempotency-Key is still being processed.");
    }
    return { status: rec.response_status!, content_type: "application/json", body: rec.response_body! };
  }

  /**
   * Operator/reconciliation only, never a client route: frees an 'uncertain' key (reconciliation showed the first
   * attempt did nothing) so a retry runs. In: the stored record's scope and key. Out: true if freed; false, with
   * nothing changed, for any key that is not uncertain. One conditional write. Why: IDEM-10.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
   */
  release(scope: string, idempotency_key: string): boolean {
    return this.store.releaseIfUncertain(scope, idempotency_key, this.now());
  }

  /**
   * Operator/reconciliation only: records the outcome reconciliation found for an 'uncertain' key as 'completed'
   * with expires_at = now + 24 h, so a retry gets it. In: scope, key, status, body (stored as JSON). Out: true if
   * stored; false, with nothing changed, for a key that is not uncertain. One conditional write. Why: IDEM-11.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
   */
  resolve(scope: string, idempotency_key: string, status: number, body: any): boolean {
    return this.store.resolveIfUncertain(scope, idempotency_key, status, JSON.stringify(body), this.now());
  }

  /**
   * Operator/reconciliation only: the work list of uncertain keys, oldest first. In: limit. Out:
   * [{scope, idem_key, created_at}]. Why: spec list_uncertain. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: the store (read).
   */
  list_uncertain(limit = 100): { scope: string; idem_key: string; created_at: Date }[] {
    return this.store.listUncertain(limit, this.now())
      .map((r) => ({ scope: r.scope, idem_key: r.idem_key, created_at: r.created_at }));
  }

  /**
   * Deletes expired 'completed' records; in_progress and uncertain records are kept. Why: spec purge_expired
   * (an uncertain record never expires). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the store.
   */
  purge_expired(): void {
    this.store.purgeExpired(this.now());
  }
}

/* ---------- module-level API over one shared service (all callers share the same store) ---------- */

const _default = new IdempotencyService();

/** See IdempotencyService.handle. Uses the shared default service. */
export function handle(
  scope: string,
  idempotency_key: string | undefined,
  method: string,
  path: string,
  body: string,
  operation: Operation,
): Promise<HttpResponse> {
  return _default.handle(scope, idempotency_key, method, path, body, operation);
}

/** See IdempotencyService.release (operator only). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
export function release(scope: string, idempotency_key: string): boolean {
  return _default.release(scope, idempotency_key);
}

/** See IdempotencyService.resolve (operator only). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
export function resolve(scope: string, idempotency_key: string, status: number, body: any): boolean {
  return _default.resolve(scope, idempotency_key, status, body);
}

/** See IdempotencyService.list_uncertain (operator only). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
export function list_uncertain(limit = 100): { scope: string; idem_key: string; created_at: Date }[] {
  return _default.list_uncertain(limit);
}

/** See IdempotencyService.purge_expired. */
export function purge_expired(): void {
  _default.purge_expired();
}

/* Exported for test introspection only */
export const _test_store = _default.store as InMemoryIdempotencyStore;
