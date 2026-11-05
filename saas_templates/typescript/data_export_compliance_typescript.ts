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
 */

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
    user_id VARCHAR(255) NOT NULL,
    requested_at TIMESTAMP NOT NULL,
    status VARCHAR(50) NOT NULL, -- 'pending' | 'approved' | 'completed' | 'cancelled'
    reason VARCHAR(255) NOT NULL,
    deleted_at TIMESTAMP,
    confirmation_token VARCHAR(255) NOT NULL,
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

export interface DeletionRequest {
  id: string;
  user_id: string;
  requested_at: Date;
  status: 'pending' | 'approved' | 'completed' | 'cancelled';
  reason: 'user_requested' | 'gdpr_request' | 'gdpr_right_to_be_forgotten' | 'other';
  deleted_at: Date | null;
  confirmation_token: string;
  scheduled_for: Date;
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

  constructor(db: InMemoryDatabase, s3: S3Client, email: EmailService, clock: Clock = new SystemClock()) {
    this.db = db;
    this.s3 = s3;
    this.email = email;
    this.clock = clock;
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

    const exportId = `exp_${Math.random().toString(36).substr(2, 9)}`;
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
  public async getExportStatus(exportId: string): Promise<{
    export_id: string;
    status: 'pending' | 'completed' | 'failed';
    file_url: string | null;
    expires_at: string | null;
    requested_at: string;
  }> {
    const req = this.db.exportRequests.find(r => r.id === exportId);
    if (!req) {
      throw new Error(`Export request ${exportId} not found`);
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
  public async requestDeletion(
    userId: string,
    reason: 'user_requested' | 'gdpr_request' | 'gdpr_right_to_be_forgotten' | 'other',
    whyChain?: string
  ): Promise<{ success: boolean; deletion_id: string; status: 'pending'; will_delete_at: string }> {
    const user = this.db.users.find(u => u.id === userId);
    if (!user) {
      throw new Error(`User with ID ${userId} not found`);
    }

    const deletionId = `del_${Math.random().toString(36).substr(2, 9)}`;
    const now = this.clock.now();
    const confirmationToken = `tok_${Math.random().toString(36).substr(2, 15)}`;

    // 30-day grace period
    const scheduledFor = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

    const request: DeletionRequest = {
      id: deletionId,
      user_id: userId,
      requested_at: now,
      status: 'pending',
      reason,
      deleted_at: null,
      confirmation_token: confirmationToken,
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
      `Hello ${user.name},\n\nWe received a request to delete your account. Please confirm this request by clicking the following link within 30 days:\n\n${confirmUrl}\n\nIf you did not request this, please ignore this email.`
    );

    return {
      success: true,
      deletion_id: deletionId,
      status: 'pending',
      will_delete_at: scheduledFor.toISOString(),
    };
  }

  // ---------------------------------------------------------------------------
  // 4. Approve/Confirm Deletion
  // ---------------------------------------------------------------------------
  public async confirmDeletion(
    deletionId: string,
    confirmationToken: string
  ): Promise<{ success: boolean; deletion_scheduled_for: string }> {
    const req = this.db.deletionRequests.find(r => r.id === deletionId);
    if (!req) {
      throw new Error(`Deletion request ${deletionId} not found`);
    }

    if (req.status !== 'pending') {
      throw new Error(`Deletion request is already ${req.status}`);
    }

    if (req.confirmation_token !== confirmationToken) {
      throw new Error('Invalid confirmation token');
    }

    req.status = 'approved';

    // Log in audit trail
    this.logAudit(req.user_id, 'deletion_confirmed', 'User confirmed deletion via email token');

    return {
      success: true,
      deletion_scheduled_for: req.scheduled_for.toISOString(),
    };
  }

  // ---------------------------------------------------------------------------
  // 5. Cancel Deletion (Within Grace Period)
  // ---------------------------------------------------------------------------
  public async cancelDeletion(deletionId: string): Promise<{ success: boolean; status: 'cancelled' }> {
    const req = this.db.deletionRequests.find(r => r.id === deletionId);
    if (!req) {
      throw new Error(`Deletion request ${deletionId} not found`);
    }

    if (req.status === 'completed') {
      throw new Error('Cannot cancel a completed deletion');
    }

    req.status = 'cancelled';

    // Log in audit trail
    this.logAudit(req.user_id, 'deletion_cancelled', 'User cancelled deletion request');

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
   * Executes cascade deletion for approved deletion requests that have passed their grace period.
   */
  public async executeScheduledDeletions(): Promise<number> {
    const now = this.clock.now();
    const pendingDeletions = this.db.deletionRequests.filter(
      r => r.status === 'approved' && r.scheduled_for <= now
    );

    let count = 0;
    for (const req of pendingDeletions) {
      const userId = req.user_id;

      // Cascade delete: Delete from all tables where user_id = X, except audit_log
      this.db.sessions = this.db.sessions.filter(s => s.user_id !== userId);
      this.db.activityLogs = this.db.activityLogs.filter(a => a.user_id !== userId);
      this.db.files = this.db.files.filter(f => f.user_id !== userId);
      this.db.preferences = this.db.preferences.filter(p => p.user_id !== userId);
      this.db.transactions = this.db.transactions.filter(t => t.user_id !== userId);
      this.db.apiKeys = this.db.apiKeys.filter(k => k.user_id !== userId);
      this.db.exportRequests = this.db.exportRequests.filter(e => e.user_id !== userId);
      this.db.users = this.db.users.filter(u => u.id !== userId);

      // Update deletion request status
      req.status = 'completed';
      req.deleted_at = now;

      // Log in audit trail (audit_logs are preserved for compliance)
      this.logAudit(userId, 'account_permanently_deleted', `Cascade delete completed for user ${userId}`);
      count++;
    }

    return count;
  }

  private logAudit(userId: string, action: string, reason?: string, whyChain?: string): void {
    const audit: AuditLog = {
      id: `aud_${Math.random().toString(36).substr(2, 9)}`,
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
