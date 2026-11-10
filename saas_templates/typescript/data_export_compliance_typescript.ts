/**
 * DATA EXPORT & COMPLIANCE (GDPR/CCPA) MODULE
 * 
 * This module provides a production-grade implementation for handling user data exports
 * and account deletions in compliance with GDPR and CCPA regulations.
 * 
 * It includes:
 * - Full database schema as executable DDL.
 * - In-memory database engine simulating SQL tables.
 * - S3 client mock for encrypted-at-rest storage and signed URL generation.
 * - Email service mock for sending download links and deletion confirmations.
 * - ComplianceService coordinating exports, grace periods, cascade deletes, and audit logging.
 *
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-05/12/13/14 amendments and the review note that the
 * caller's identity must come from the verified session): every caller id parameter is the VERIFIED caller from
 * the auth layer, never a body or query value; confirm, cancel and export status act only on the caller's own
 * request (anyone else's is 404); the deletion token is 32 random bytes stored only as its SHA-256, single-use,
 * valid 24 h and compared in constant time; statutory reasons get no grace period and are erased on confirm; the
 * cascade runs in one transaction and calls the injected audit eraser's erase_subject() last. Ids and tokens come
 * from crypto, not Math.random.
 */

import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'crypto';

// =============================================================================
// DATABASE SCHEMA (DDL)
// =============================================================================

export const COMPLIANCE_DDL = `
CREATE TABLE users (
    id VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    tier VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL
);

CREATE TABLE sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address VARCHAR(45) NOT NULL,
    device_info VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE activity_logs (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action VARCHAR(255) NOT NULL,
    details TEXT,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE files (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename VARCHAR(255) NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE preferences (
    user_id VARCHAR(255) PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    notification_settings TEXT NOT NULL,
    theme VARCHAR(50) NOT NULL,
    language VARCHAR(10) NOT NULL
);

CREATE TABLE transactions (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount DECIMAL(10, 2) NOT NULL,
    currency VARCHAR(3) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'invoice' | 'payment' | 'refund'
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE api_keys (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE audit_logs (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL, -- Keep even if user is deleted (compliance requirement)
    action VARCHAR(255) NOT NULL,
    reason VARCHAR(255),
    why_chain TEXT,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE export_requests (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    requested_at TIMESTAMP NOT NULL,
    status VARCHAR(50) NOT NULL, -- 'pending' | 'completed' | 'failed'
    format VARCHAR(10) NOT NULL, -- 'json' | 'csv'
    file_url TEXT,
    completed_at TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE TABLE deletion_requests (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NULL,                  -- set NULL when the deletion completes (EXPORT-13)
    requested_at TIMESTAMP NOT NULL,
    status VARCHAR(50) NOT NULL, -- 'pending' | 'approved' | 'completed' | 'cancelled'
    reason VARCHAR(255) NOT NULL,
    deleted_at TIMESTAMP,
    confirmation_token_hash CHAR(64) NULL,      -- SHA-256 hex of the emailed token; NULL once used (EXPORT-14)
    token_expires_at TIMESTAMP NOT NULL,        -- requested_at + 24 hours
    scheduled_for TIMESTAMP NOT NULL
);
`;

// =============================================================================
// TYPES & INTERFACES
// =============================================================================

export interface User {
  id: string;
  email: string;
  name: string;
  created_at: Date;
  tier: string;
  status: string;
}

export interface Session {
  id: string;
  user_id: string;
  ip_address: string;
  device_info: string;
  created_at: Date;
}

export interface ActivityLog {
  id: string;
  user_id: string;
  action: string;
  details: string;
  created_at: Date;
}

export interface FileMetadata {
  id: string;
  user_id: string;
  filename: string;
  size_bytes: number;
  created_at: Date;
}

export interface Preferences {
  user_id: string;
  notification_settings: string;
  theme: string;
  language: string;
}

export interface Transaction {
  id: string;
  user_id: string;
  amount: number;
  currency: string;
  type: 'invoice' | 'payment' | 'refund';
  created_at: Date;
}

export interface ApiKey {
  id: string;
  user_id: string;
  key_hash: string;
  created_at: Date;
}

export interface AuditLog {
  id: string;
  user_id: string;
  action: string;
  reason?: string;
  why_chain?: string;
  created_at: Date;
}

export interface ExportRequest {
  id: string;
  user_id: string;
  requested_at: Date;
  status: 'pending' | 'completed' | 'failed';
  format: 'json' | 'csv';
  file_url: string | null;
  completed_at: Date | null;
  expires_at: Date | null;
}

/**
 * A deletion request. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the raw confirmation token is no longer stored
 * (only its SHA-256, cleared once used), the token expires 24 h after the request, and user_id becomes null when the
 * deletion completes so the row cannot re-identify erased audit entries (EXPORT-13/14).
 */
export interface DeletionRequest {
  id: string;
  user_id: string | null;
  requested_at: Date;
  status: 'pending' | 'approved' | 'completed' | 'cancelled';
  reason: DeletionReason;
  deleted_at: Date | null;
  confirmation_token_hash: string | null;
  token_expires_at: Date;
  scheduled_for: Date;
}

export type DeletionReason = 'user_requested' | 'gdpr_request' | 'gdpr_right_to_be_forgotten' | 'other';

/** Statutory erasure reasons: no grace period, erased as soon as the request is confirmed (EXPORT-12). */
export const STATUTORY_REASONS: readonly DeletionReason[] = ['gdpr_request', 'gdpr_right_to_be_forgotten'];

/**
 * The audit system's eraser (audit_logging erase_subject), injected so the cascade can erase the user's personal
 * audit data last, and tests can pass a fake. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-13).
 */
export interface AuditEraser {
  erase_subject(userId: string): void | Promise<void>;
}

/**
 * An error with an HTTP status and a stable code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: confirm and cancel
 * answer 404 not_found for a request that is not the caller's, 400 invalid_confirmation_token for a wrong, reused
 * or expired token, 409 deletion_not_pending for a cancelled request and 404 for a completed one (EXPORT-15).
 * Touches nothing.
 */
export class ComplianceError extends Error {
  constructor(public readonly code: string, message: string, public readonly status: number) {
    super(message);
    this.name = 'ComplianceError';
  }
}

const DAY_MS = 24 * 60 * 60 * 1000;
const GRACE_DAYS = 30;
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

/** SHA-256 hex of a token. Touches nothing. */
function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export interface Clock {
  now(): Date;
}

export class SystemClock implements Clock {
  now(): Date {
    return new Date();
  }
}

// =============================================================================
// IN-MEMORY DATABASE ENGINE
// =============================================================================

export class InMemoryDatabase {
  public users: User[] = [];
  public sessions: Session[] = [];
  public activityLogs: ActivityLog[] = [];
  public files: FileMetadata[] = [];
  public preferences: Preferences[] = [];
  public transactions: Transaction[] = [];
  public apiKeys: ApiKey[] = [];
  public auditLogs: AuditLog[] = [];
  public exportRequests: ExportRequest[] = [];
  public deletionRequests: DeletionRequest[] = [];

  public clear(): void {
    this.users = [];
    this.sessions = [];
    this.activityLogs = [];
    this.files = [];
    this.preferences = [];
    this.transactions = [];
    this.apiKeys = [];
    this.auditLogs = [];
    this.exportRequests = [];
    this.deletionRequests = [];
  }
}

// =============================================================================
// S3 STORAGE CLIENT (MOCK)
// =============================================================================

export interface S3Client {
  upload(key: string, body: string, contentType: string): Promise<string>;
  getSignedUrl(key: string, expiresInSeconds: number): Promise<string>;
  /** Deletes one object (export files are erased with the user). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
  delete(key: string): Promise<void>;
}

export class MockS3Client implements S3Client {
  public storage = new Map<string, { body: string; contentType: string }>();

  public async upload(key: string, body: string, contentType: string): Promise<string> {
    this.storage.set(key, { body, contentType });
    return `s3://compliance-exports-bucket/${key}`;
  }

  public async getSignedUrl(key: string, expiresInSeconds: number): Promise<string> {
    if (!this.storage.has(key)) {
      throw new Error(`File not found in S3: ${key}`);
    }
    const expiresTimestamp = Date.now() + expiresInSeconds * 1000;
    return `https://compliance-exports-bucket.s3.amazonaws.com/${key}?signature=mock_signature&expires=${expiresTimestamp}`;
  }

  /** Removes one stored object. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the in-memory map. */
  public async delete(key: string): Promise<void> {
    this.storage.delete(key);
  }
}

// =============================================================================
// EMAIL SERVICE (MOCK)
// =============================================================================

export interface EmailService {
  sendEmail(to: string, subject: string, body: string): Promise<void>;
}

export class MockEmailService implements EmailService {
  public sentEmails: Array<{ to: string; subject: string; body: string }> = [];

  public async sendEmail(to: string, subject: string, body: string): Promise<void> {
    this.sentEmails.push({ to, subject, body });
  }

  public clear(): void {
    this.sentEmails = [];
  }
}

// =============================================================================
// COMPLIANCE SERVICE
// =============================================================================

export class ComplianceService {
  private db: InMemoryDatabase;
  private s3: S3Client;
  private email: EmailService;
  private clock: Clock;
  private auditEraser: AuditEraser;

  /**
   * In: the database, S3 client, email service, clock and the audit eraser (required: without it a deletion would
   * leave the user's personal audit data behind). Out: the service. Throws when no eraser is given.
   * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-13). Touches nothing.
   */
  constructor(db: InMemoryDatabase, s3: S3Client, email: EmailService, clock: Clock, auditEraser: AuditEraser) {
    if (!auditEraser || typeof auditEraser.erase_subject !== 'function') {
      throw new Error('audit_eraser_required: pass the audit system\'s erase_subject');
    }
    this.db = db;
    this.s3 = s3;
    this.email = email;
    this.clock = clock ?? new SystemClock();
    this.auditEraser = auditEraser;
  }

  // ---------------------------------------------------------------------------
  // 1. Request Data Export
  // ---------------------------------------------------------------------------
  public async requestExport(
    userId: string,
    format: 'json' | 'csv',
    whyChain?: string
  ): Promise<{ success: boolean; export_id: string; status: 'pending'; will_email_at: string }> {
    const user = this.db.users.find(u => u.id === userId);
    if (!user) {
      throw new Error(`User with ID ${userId} not found`);
    }

    const exportId = `exp_${randomUUID()}`;
    const now = this.clock.now();

    const request: ExportRequest = {
      id: exportId,
      user_id: userId,
      requested_at: now,
      status: 'pending',
      format,
      file_url: null,
      completed_at: null,
      expires_at: null,
    };

    this.db.exportRequests.push(request);

    // Log in audit trail
    this.logAudit(userId, 'data_export_requested', `Format: ${format}`, whyChain);

    // Trigger background processing (async, non-blocking)
    // In a real production system, this would be pushed to a message queue.
    // We run it asynchronously here but return immediately.
    this.processExportAsync(exportId).catch(err => {
      console.error(`Failed to process export ${exportId}:`, err);
    });

    // Estimate email delivery in 5 minutes
    const willEmailAt = new Date(now.getTime() + 5 * 60 * 1000).toISOString();

    return {
      success: true,
      export_id: exportId,
      status: 'pending',
      will_email_at: willEmailAt,
    };
  }

  // ---------------------------------------------------------------------------
  // 2. Check Export Status
  // ---------------------------------------------------------------------------
  /**
   * The caller's own export request. In: the verified caller id and the export id. Out: status, file_url, dates.
   * Throws ComplianceError 404 for an unknown id or one belonging to someone else (its file_url is a link to all
   * of that user's data). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the caller check is new.
   * Touches: reads export_requests.
   */
  public async getExportStatus(callerUserId: string, exportId: string): Promise<{
    export_id: string;
    status: 'pending' | 'completed' | 'failed';
    file_url: string | null;
    expires_at: string | null;
    requested_at: string;
  }> {
    const req = this.db.exportRequests.find(r => r.id === exportId);
    if (!req || req.user_id !== callerUserId) {
      throw new ComplianceError('not_found', `Export request ${exportId} not found`, 404);
    }

    return {
      export_id: req.id,
      status: req.status,
      file_url: req.file_url,
      expires_at: req.expires_at ? req.expires_at.toISOString() : null,
      requested_at: req.requested_at.toISOString(),
    };
  }

  // ---------------------------------------------------------------------------
  // 3. Request Account Deletion
  // ---------------------------------------------------------------------------
  /**
   * Starts an account deletion for the verified caller; nothing is deleted until it is confirmed.
   *
   * In: the verified caller id, the reason and an optional why_chain. Out: { success, deletion_id, status:
   * 'pending', will_delete_at }. user_requested / other: will_delete_at = requested_at + 30 days (a grace period
   * the user can cancel in); gdpr_request / gdpr_right_to_be_forgotten: will_delete_at = requested_at (no grace).
   * Emails a confirmation link carrying a fresh token: 32 random bytes, stored only as its SHA-256, valid 24 h.
   * Why: EXPORT-05/12/14 amendments 2026-11-10 (every reason got 30 days, and the raw Math.random token was stored).
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: deletion_requests, audit_logs, email.
   */
  public async requestDeletion(
    userId: string,
    reason: DeletionReason,
    whyChain?: string
  ): Promise<{ success: boolean; deletion_id: string; status: 'pending'; will_delete_at: string }> {
    const user = this.db.users.find(u => u.id === userId);
    if (!user) {
      throw new ComplianceError('not_found', `User with ID ${userId} not found`, 404);
    }

    const deletionId = `del_${randomUUID()}`;
    const now = this.clock.now();
    const confirmationToken = randomBytes(32).toString('base64url');

    const statutory = STATUTORY_REASONS.includes(reason);
    const scheduledFor = statutory ? new Date(now.getTime()) : new Date(now.getTime() + GRACE_DAYS * DAY_MS);

    const request: DeletionRequest = {
      id: deletionId,
      user_id: userId,
      requested_at: now,
      status: 'pending',
      reason,
      deleted_at: null,
      confirmation_token_hash: sha256Hex(confirmationToken),
      token_expires_at: new Date(now.getTime() + TOKEN_TTL_MS),
      scheduled_for: scheduledFor,
    };

    this.db.deletionRequests.push(request);

    // Log in audit trail
    this.logAudit(userId, 'deletion_requested', `Reason: ${reason}`, whyChain);

    // Send email confirmation link (phishing protection)
    const confirmUrl = `https://saas-platform.com/compliance/delete/${deletionId}/confirm?token=${confirmationToken}`;
    await this.email.sendEmail(
      user.email,
      'Confirm your account deletion request',
      `Hello ${user.name},\n\nWe received a request to delete your account. Please confirm this request by clicking the following link within 24 hours:\n\n${confirmUrl}\n\nIf you did not request this, please ignore this email.`
    );

    return {
      success: true,
      deletion_id: deletionId,
      status: 'pending',
      will_delete_at: scheduledFor.toISOString(),
    };
  }

  /**
   * The caller's own deletion request, or ComplianceError 404 {error: "not_found"}: unknown, someone else's, or
   * completed (its user_id is NULL once completed, EXPORT-13, so it has no owner and is 404 to every caller,
   * EXPORT-15 as clarified in spec commit 3abb340). In: caller id, deletion id. Out: the request.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads deletion_requests.
   */
  private ownDeletion(callerUserId: string, deletionId: string): DeletionRequest {
    const req = this.db.deletionRequests.find(r => r.id === deletionId);
    if (!req || req.user_id === null || req.user_id !== callerUserId) {
      throw new ComplianceError('not_found', `Deletion request ${deletionId} not found`, 404);
    }
    return req;
  }

  /**
   * Refuses a request that is no longer pending: cancelled -> ComplianceError 409 {error: "deletion_not_pending"}
   * (a completed one never gets here: ownDeletion answers 404, EXPORT-13/15; 'completed' is checked too as a guard).
   * Checked before the token, so a spent token on a closed request does not read as a wrong token. In: the request.
   * Out: nothing, or the throw.
   * Why: EXPORT-15 (Phase B.2: one answer in every language). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches nothing.
   */
  private refuseIfClosed(req: DeletionRequest): void {
    if (req.status === 'cancelled' || req.status === 'completed') {
      throw new ComplianceError('deletion_not_pending', `Deletion request is already ${req.status}`, 409);
    }
  }

  // ---------------------------------------------------------------------------
  // 4. Approve/Confirm Deletion
  // ---------------------------------------------------------------------------
  /**
   * Confirms the caller's own deletion with the emailed token.
   *
   * In: the verified caller id, the deletion id and the token. Out: { success, deletion_scheduled_for }.
   * Errors: 404 not_found (unknown, another user's or completed request); 409 deletion_not_pending (cancelled);
   * 400 invalid_confirmation_token for a wrong, reused (already approved, hash cleared) or expired
   * (over 24 h) token, one answer so the reply never says which (compared in constant time as SHA-256 digests).
   * The token is single-use: its hash is cleared on success. For a statutory reason the cascade runs before this
   * returns: status 'completed', deleted_at = deletion_scheduled_for = now.
   * Why: EXPORT-09/12/14 amendments 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP; Phase B.2 /
   * EXPORT-15 the same day: a reused token was 409 not_pending, an expired one 403 confirmation_token_expired and a
   * wrong one 403.
   * Touches: deletion_requests, audit_logs, and (statutory) every user table, S3 and the audit eraser.
   */
  public async confirmDeletion(
    callerUserId: string,
    deletionId: string,
    confirmationToken: string
  ): Promise<{ success: boolean; deletion_scheduled_for: string }> {
    const req = this.ownDeletion(callerUserId, deletionId);
    this.refuseIfClosed(req);

    const now = this.clock.now();
    const given = createHash('sha256').update(String(confirmationToken ?? ''), 'utf8').digest();
    const stored = Buffer.from(req.confirmation_token_hash ?? '', 'hex');
    const matches = req.status === 'pending' && stored.length === given.length && timingSafeEqual(given, stored);
    if (!matches || now.getTime() > req.token_expires_at.getTime()) {
      // Wrong, reused or expired: one answer (EXPORT-15).
      throw new ComplianceError('invalid_confirmation_token', 'Invalid confirmation token', 400);
    }

    req.confirmation_token_hash = null;   // single use
    req.status = 'approved';
    const userId = req.user_id!;
    this.logAudit(userId, 'deletion_confirmed', 'User confirmed deletion via email token');

    if (STATUTORY_REASONS.includes(req.reason)) {
      req.scheduled_for = now;
      await this.runCascade(req, now);
    }

    return {
      success: true,
      deletion_scheduled_for: req.scheduled_for.toISOString(),
    };
  }

  // ---------------------------------------------------------------------------
  // 5. Cancel Deletion (Within Grace Period)
  // ---------------------------------------------------------------------------
  /**
   * Cancels the caller's own pending or approved deletion before it runs.
   * In: the verified caller id and the deletion id. Out: { success, status: 'cancelled' }. Errors: 404 not_found
   * (unknown, another user's, or completed: no owner any more), 409 deletion_not_pending (already cancelled),
   * 409 grace_period_over
   * (will_delete_at has passed: now >= will_delete_at, the deletion is due but not yet run). Why: EXPORT-06/14.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the caller check is new; Phase B.2 / EXPORT-15 the same day: a
   * cancelled request was 409 not_cancellable (a completed one stays 404, EXPORT-13/15). Phase B.3 ruling the same
   * day: a cancel after will_delete_at is 409 grace_period_over whatever the request's status (it was
   * not_cancellable, and only for an approved request). Touches: deletion_requests, audit_logs.
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.4 ruling (af92d76, EXPORT-16): only a confirmed (approved)
   * request is scheduled, so only it gets 409 grace_period_over from will_delete_at on (exactly at it included) and
   * stays approved; a pending (unconfirmed) request can always be cancelled, even after will_delete_at (it was
   * refused like a confirmed one).
   */
  public async cancelDeletion(callerUserId: string, deletionId: string): Promise<{ success: boolean; status: 'cancelled' }> {
    const req = this.ownDeletion(callerUserId, deletionId);
    this.refuseIfClosed(req);
    // Phase B.4 (af92d76): the grace period binds only a confirmed request; a pending one is not scheduled.
    if (req.status === 'approved' && this.clock.now().getTime() >= req.scheduled_for.getTime()) {
      throw new ComplianceError('grace_period_over', 'The grace period is over', 409);
    }

    req.status = 'cancelled';
    req.confirmation_token_hash = null;

    // Log in audit trail
    this.logAudit(req.user_id!, 'deletion_cancelled', 'User cancelled deletion request');

    return {
      success: true,
      status: 'cancelled',
    };
  }

  // ---------------------------------------------------------------------------
  // 6. List Export Requests (Admin Only)
  // ---------------------------------------------------------------------------
  public async listExports(
    adminUserId: string,
    filter: { userId?: string; status?: 'pending' | 'completed' | 'failed' }
  ): Promise<{ exports: ExportRequest[]; total: number }> {
    this.verifyAdmin(adminUserId);

    let results = this.db.exportRequests;

    if (filter.userId) {
      results = results.filter(r => r.user_id === filter.userId);
    }
    if (filter.status) {
      results = results.filter(r => r.status === filter.status);
    }

    return {
      exports: results,
      total: results.length,
    };
  }

  // ---------------------------------------------------------------------------
  // 7. List Deletion Requests (Admin Only)
  // ---------------------------------------------------------------------------
  public async listDeletions(
    adminUserId: string,
    filter: { status?: 'pending' | 'approved' | 'completed' | 'cancelled' }
  ): Promise<{ deletions: DeletionRequest[]; total: number }> {
    this.verifyAdmin(adminUserId);

    let results = this.db.deletionRequests;

    if (filter.status) {
      results = results.filter(r => r.status === filter.status);
    }

    return {
      deletions: results,
      total: results.length,
    };
  }

  // =============================================================================
  // BACKGROUND WORKERS & HELPERS
  // =============================================================================

  /**
   * Generates the export file, uploads to S3, creates a signed URL, and emails the user.
   */
  public async processExportAsync(exportId: string): Promise<void> {
    const req = this.db.exportRequests.find(r => r.id === exportId);
    if (!req) return;

    try {
      const user = this.db.users.find(u => u.id === req.user_id);
      if (!user) {
        req.status = 'failed';
        return;
      }

      // Gather all user data categories
      const profile = user;
      const sessions = this.db.sessions.filter(s => s.user_id === user.id);
      const activity = this.db.activityLogs.filter(a => a.user_id === user.id);
      const files = this.db.files.filter(f => f.user_id === user.id);
      const preferences = this.db.preferences.find(p => p.user_id === user.id) || null;
      const transactions = this.db.transactions.filter(t => t.user_id === user.id);
      const auditTrail = this.db.auditLogs.filter(a => a.user_id === user.id);

      let payload = '';
      let contentType = '';
      const filename = `export_${user.id}_${req.id}`;

      if (req.format === 'json') {
        contentType = 'application/json';
        payload = JSON.stringify(
          {
            profile,
            sessions,
            activity,
            files,
            preferences,
            transactions,
            audit_trail: auditTrail,
          },
          null,
          2
        );
      } else {
        contentType = 'text/csv';
        payload = this.generateCSVPayload(profile, sessions, activity, files, preferences, transactions, auditTrail);
      }

      // Upload to S3
      const s3Key = `${filename}.${req.format}`;
      await this.s3.upload(s3Key, payload, contentType);

      // Create signed URL (expires in 7 days)
      const sevenDaysInSeconds = 7 * 24 * 60 * 60;
      const signedUrl = await this.s3.getSignedUrl(s3Key, sevenDaysInSeconds);

      const now = this.clock.now();
      req.status = 'completed';
      req.file_url = signedUrl;
      req.completed_at = now;
      req.expires_at = new Date(now.getTime() + sevenDaysInSeconds * 1000);

      // Send email with download link
      await this.email.sendEmail(
        user.email,
        'Your data export is ready',
        `Hello ${user.name},\n\nYour requested data export is ready for download. This link will expire in 7 days:\n\n${signedUrl}`
      );

      // Log in audit trail
      this.logAudit(user.id, 'data_export_completed', `Export ID: ${exportId}`);
    } catch (err) {
      req.status = 'failed';
      this.logAudit(req.user_id, 'data_export_failed', `Export ID: ${exportId}. Error: ${(err as Error).message}`);
    }
  }

  /**
   * Runs the cascade for every approved deletion whose grace period is over. In: nothing. Out: how many ran.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the cascade itself is runCascade (EXPORT-13 order).
   * Touches: every user table, S3, the audit eraser.
   */
  public async executeScheduledDeletions(): Promise<number> {
    const now = this.clock.now();
    const pendingDeletions = this.db.deletionRequests.filter(
      r => r.status === 'approved' && r.user_id !== null && r.scheduled_for <= now
    );

    let count = 0;
    for (const req of pendingDeletions) {
      await this.runCascade(req, now);
      count++;
    }
    return count;
  }

  /**
   * The deletion cascade, in one transaction and in this order (EXPORT-07/08/13):
   * (1) delete the user's rows from every table except the audit log (sessions, activity, files, preferences,
   *     transactions, API keys, export requests and their S3 files, the user);
   * (2) log 'user_deleted_cascade' with the user as subject;
   * (3) call the audit eraser's erase_subject(user_id) LAST; nothing logs this user afterwards;
   * then mark the request completed with deleted_at = now and user_id = NULL.
   * Any error restores every table (S3 deletions happen only after the eraser succeeded) and is rethrown.
   * In: the request and now. Out: nothing. Why: EXPORT-13 amendment 2026-11-10 (nothing erased the user's audit
   * personal data, and the request row kept the user id). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: every user table, S3, the audit eraser.
   */
  private async runCascade(req: DeletionRequest, now: Date): Promise<void> {
    const userId = req.user_id!;
    const db = this.db;
    const snapshot = {
      users: [...db.users], sessions: [...db.sessions], activityLogs: [...db.activityLogs], files: [...db.files],
      preferences: [...db.preferences], transactions: [...db.transactions], apiKeys: [...db.apiKeys],
      auditLogs: [...db.auditLogs], exportRequests: [...db.exportRequests],
    };
    const exportKeys = db.exportRequests
      .filter(e => e.user_id === userId)
      .map(e => `export_${userId}_${e.id}.${e.format}`);
    try {
      // (1) the user's rows, never the audit log
      db.sessions = db.sessions.filter(x => x.user_id !== userId);
      db.activityLogs = db.activityLogs.filter(x => x.user_id !== userId);
      db.files = db.files.filter(x => x.user_id !== userId);
      db.preferences = db.preferences.filter(x => x.user_id !== userId);
      db.transactions = db.transactions.filter(x => x.user_id !== userId);
      db.apiKeys = db.apiKeys.filter(x => x.user_id !== userId);
      db.exportRequests = db.exportRequests.filter(x => x.user_id !== userId);
      db.users = db.users.filter(x => x.id !== userId);
      // (2) the cascade is logged with the user as subject
      this.logAudit(userId, 'user_deleted_cascade', `Cascade delete completed for user ${userId}`);
      // (3) the audit system erases the user's personal audit data, last
      await this.auditEraser.erase_subject(userId);
    } catch (err) {
      Object.assign(db, snapshot);
      throw err;
    }
    for (const key of exportKeys) {
      await this.s3.delete(key);
    }
    req.status = 'completed';
    req.deleted_at = now;
    req.user_id = null;
  }

  private logAudit(userId: string, action: string, reason?: string, whyChain?: string): void {
    const audit: AuditLog = {
      id: `aud_${randomUUID()}`,
      user_id: userId,
      action,
      reason,
      why_chain: whyChain,
      created_at: this.clock.now(),
    };
    this.db.auditLogs.push(audit);
  }

  private verifyAdmin(adminUserId: string): void {
    const admin = this.db.users.find(u => u.id === adminUserId);
    if (!admin || admin.tier !== 'admin') {
      throw new Error('Unauthorized: Admin privileges required');
    }
  }

  private generateCSVPayload(
    profile: User,
    sessions: Session[],
    activity: ActivityLog[],
    files: FileMetadata[],
    preferences: Preferences | null,
    transactions: Transaction[],
    auditTrail: AuditLog[]
  ): string {
    const sections: string[] = [];

    // Helper to convert objects to CSV rows
    const toCSV = (headers: string[], rows: any[]): string => {
      const headerLine = headers.join(',');
      const rowLines = rows.map(row =>
        headers
          .map(header => {
            const val = row[header];
            if (val === undefined || val === null) return '';
            const str = val instanceof Date ? val.toISOString() : String(val);
            if (str.includes(',') || str.includes('"') || str.includes('\n')) {
              return `"${str.replace(/"/g, '""')}"`;
            }
            return str;
          })
          .join(',')
      );
      return [headerLine, ...rowLines].join('\n');
    };

    sections.push('=== PROFILE ===');
    sections.push(toCSV(['id', 'email', 'name', 'created_at', 'tier', 'status'], [profile]));

    sections.push('\n=== SESSIONS ===');
    sections.push(toCSV(['id', 'user_id', 'ip_address', 'device_info', 'created_at'], sessions));

    sections.push('\n=== ACTIVITY ===');
    sections.push(toCSV(['id', 'user_id', 'action', 'details', 'created_at'], activity));

    sections.push('\n=== FILES ===');
    sections.push(toCSV(['id', 'user_id', 'filename', 'size_bytes', 'created_at'], files));

    sections.push('\n=== PREFERENCES ===');
    if (preferences) {
      sections.push(toCSV(['user_id', 'notification_settings', 'theme', 'language'], [preferences]));
    } else {
      sections.push('No preferences found');
    }

    sections.push('\n=== TRANSACTIONS ===');
    sections.push(toCSV(['id', 'user_id', 'amount', 'currency', 'type', 'created_at'], transactions));

    sections.push('\n=== AUDIT TRAIL ===');
    sections.push(toCSV(['id', 'user_id', 'action', 'reason', 'why_chain', 'created_at'], auditTrail));

    return sections.join('\n');
  }
}
