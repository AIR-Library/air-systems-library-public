/**
 * Data export & compliance tests.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: converted from a hand-written runner to node:test (every check kept),
 * and adapted to the EXPORT-05/12/13/14 amendments: the service takes the verified caller for confirm / cancel /
 * export status and an audit eraser; confirmation tokens are read from the email (only their hash is stored);
 * statutory reasons are erased on confirm. Each changed check carries a comment saying why. Touches: memory only.
 */
import { test } from 'node:test';
import {
  InMemoryDatabase,
  MockS3Client,
  MockEmailService,
  ComplianceService,
  Clock,
  User,
  Session,
  ActivityLog,
  FileMetadata,
  Preferences,
  Transaction,
  ApiKey,
  AuditLog,
  ExportRequest,
  DeletionRequest,
  AuditEraser,
  ComplianceError,
} from './data_export_compliance_typescript';

// Simple custom assertion framework to run tests standalone
function assert(condition: boolean, message: string) {
  if (!condition) {
    throw new Error(`Assertion Failed: ${message}`);
  }
}

function assertEquals<T>(actual: T, expected: T, message: string) {
  if (actual !== expected) {
    throw new Error(`Assertion Failed: ${message}\nExpected: ${expected}\nActual: ${actual}`);
  }
}


class MockClock implements Clock {
  private currentTime: Date;

  constructor(initialTime: Date) {
    this.currentTime = initialTime;
  }

  now(): Date {
    return new Date(this.currentTime.getTime());
  }

  advanceDays(days: number): void {
    this.currentTime = new Date(this.currentTime.getTime() + days * 24 * 60 * 60 * 1000);
  }

  advanceHours(hours: number): void {
    this.currentTime = new Date(this.currentTime.getTime() + hours * 60 * 60 * 1000);
  }

  /**
   * Sets the clock to an exact instant. In: epoch milliseconds. Out: none. Why: EXPORT-16 (Phase B.4, af92d76)
   * needs the clock at will_delete_at and one second either side of it. 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
   */
  setMs(ms: number): void {
    this.currentTime = new Date(ms);
  }
}

/**
 * A fake audit eraser that records each call and what the database looked like at that moment (EXPORT-13).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory.
 */
class FakeAuditEraser implements AuditEraser {
  public calls: Array<{ userId: string; userRowsLeft: number; lastAuditAction: string | undefined; auditCount: number }> = [];
  constructor(private db: InMemoryDatabase) {}
  erase_subject(userId: string): void {
    const mine = this.db.auditLogs.filter(a => a.user_id === userId);
    this.calls.push({
      userId,
      userRowsLeft: this.db.users.filter(u => u.id === userId).length + this.db.sessions.filter(x => x.user_id === userId).length,
      lastAuditAction: mine[mine.length - 1]?.action,
      auditCount: mine.length,
    });
  }
}

/** The raw token from the newest deletion-confirmation email to `to`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function tokenFromEmail(email: MockEmailService, to: string): string {
  const mails = email.sentEmails.filter(e => e.to === to && e.subject.includes('Confirm your account deletion'));
  const m = /token=([A-Za-z0-9_-]+)/.exec(mails[mails.length - 1]?.body ?? '');
  if (!m) throw new Error('no confirmation token emailed');
  return m[1];
}

/** Runs fn and returns the ComplianceError it throws (fails when it does not throw one). */
async function rejection(fn: () => Promise<unknown>): Promise<ComplianceError> {
  try {
    await fn();
  } catch (e) {
    if (e instanceof ComplianceError) return e;
    throw e;
  }
  throw new Error('expected a ComplianceError');
}

{
  const db = new InMemoryDatabase();
  const s3 = new MockS3Client();
  const email = new MockEmailService();
  const clock = new MockClock(new Date('2026-09-25T09:00:00Z'));
  const eraser = new FakeAuditEraser(db);
  const service = new ComplianceService(db, s3, email, clock, eraser);

  // Helper to seed a standard user and related data
  const seedUser = () => {
    db.clear();
    email.clear();
    s3.storage.clear();

    const user: User = {
      id: 'user_123',
      email: 'alice@example.com',
      name: 'Alice Smith',
      created_at: new Date('2025-01-01T00:00:00Z'),
      tier: 'premium',
      status: 'active',
    };

    const admin: User = {
      id: 'admin_999',
      email: 'admin@example.com',
      name: 'System Admin',
      created_at: new Date('2024-01-01T00:00:00Z'),
      tier: 'admin',
      status: 'active',
    };

    const session: Session = {
      id: 'sess_1',
      user_id: 'user_123',
      ip_address: '192.168.1.1',
      device_info: 'Chrome / macOS',
      created_at: new Date('2026-09-24T10:00:00Z'),
    };

    const activity: ActivityLog = {
      id: 'act_1',
      user_id: 'user_123',
      action: 'login',
      details: 'Successful login from Chrome',
      created_at: new Date('2026-09-24T10:00:00Z'),
    };

    const file: FileMetadata = {
      id: 'file_1',
      user_id: 'user_123',
      filename: 'tax_return_2025.pdf',
      size_bytes: 1048576,
      created_at: new Date('2026-02-15T14:30:00Z'),
    };

    const prefs: Preferences = {
      user_id: 'user_123',
      notification_settings: 'email_only',
      theme: 'dark',
      language: 'en-US',
    };

    const tx: Transaction = {
      id: 'tx_1',
      user_id: 'user_123',
      amount: 49.99,
      currency: 'USD',
      type: 'payment',
      created_at: new Date('2026-09-01T12:00:00Z'),
    };

    const apiKey: ApiKey = {
      id: 'key_1',
      user_id: 'user_123',
      key_hash: 'sha256_hash_value',
      created_at: new Date('2026-05-01T08:00:00Z'),
    };

    db.users.push(user, admin);
    db.sessions.push(session);
    db.activityLogs.push(activity);
    db.files.push(file);
    db.preferences.push(prefs);
    db.transactions.push(tx);
    db.apiKeys.push(apiKey);
  };


  // ---------------------------------------------------------------------------
  // TEST 1: Export JSON and CSV formats both work
  // ---------------------------------------------------------------------------
  // EXPORT-01
  test('Export: JSON and CSV formats both work', async () => {
    seedUser();
    const resJson = await service.requestExport('user_123', 'json', 'gdpr_portal_request');
    assertEquals(resJson.success, true, 'JSON export request should succeed');
    assertEquals(resJson.status, 'pending', 'JSON export status should start as pending');

    // Process background job synchronously for testing
    await service.processExportAsync(resJson.export_id);

    const statusJson = await service.getExportStatus('user_123', resJson.export_id);
    assertEquals(statusJson.status, 'completed', 'JSON export status should be completed');
    assert(statusJson.file_url !== null, 'JSON export file URL should be populated');

    // Verify CSV format
    const resCsv = await service.requestExport('user_123', 'csv', 'ccpa_portal_request');
    await service.processExportAsync(resCsv.export_id);
    const statusCsv = await service.getExportStatus('user_123', resCsv.export_id);
    assertEquals(statusCsv.status, 'completed', 'CSV export status should be completed');
    assert(statusCsv.file_url !== null, 'CSV export file URL should be populated');
  });

  // ---------------------------------------------------------------------------
  // TEST 2: Export: All data categories included
  // ---------------------------------------------------------------------------
  // EXPORT-02
  test('Export: All data categories included', async () => {
    seedUser();
    const res = await service.requestExport('user_123', 'json');
    await service.processExportAsync(res.export_id);

    const s3Key = `export_user_123_${res.export_id}.json`;
    const fileData = s3.storage.get(s3Key);
    assert(fileData !== undefined, 'Export file must exist in S3 storage');

    const parsed = JSON.parse(fileData!.body);
    assertEquals(parsed.profile.id, 'user_123', 'Profile category must be included');
    assertEquals(parsed.sessions.length, 1, 'Sessions category must be included');
    assertEquals(parsed.activity.length, 1, 'Activity category must be included');
    assertEquals(parsed.files.length, 1, 'Files category must be included');
    assertEquals(parsed.preferences.theme, 'dark', 'Preferences category must be included');
    assertEquals(parsed.transactions.length, 1, 'Transactions category must be included');
    assertEquals(parsed.audit_trail.length, 1, 'Audit trail category must be included');
  });

  // ---------------------------------------------------------------------------
  // TEST 3: Export: Email sent with download link
  // ---------------------------------------------------------------------------
  // EXPORT-03
  test('Export: Email sent with download link', async () => {
    seedUser();
    const res = await service.requestExport('user_123', 'json');
    await service.processExportAsync(res.export_id);

    const status = await service.getExportStatus('user_123', res.export_id);
    const sentEmail = email.sentEmails.find(e => e.to === 'alice@example.com');
    assert(sentEmail !== undefined, 'Email should be sent to the user');
    assert(sentEmail!.subject.includes('export is ready'), 'Email subject should match');
    assert(sentEmail!.body.includes(status.file_url!), 'Email body must contain the download link');
  });

  // ---------------------------------------------------------------------------
  // TEST 4: Export: Signed URL works, expires after 7 days
  // ---------------------------------------------------------------------------
  // EXPORT-04
  test('Export: Signed URL works, expires after 7 days', async () => {
    seedUser();
    const res = await service.requestExport('user_123', 'json');
    await service.processExportAsync(res.export_id);

    const status = await service.getExportStatus('user_123', res.export_id);
    assert(status.expires_at !== null, 'Expiry date must be set');

    const requestedTime = new Date(status.requested_at).getTime();
    const expiresTime = new Date(status.expires_at!).getTime();
    const diffDays = (expiresTime - requestedTime) / (1000 * 60 * 60 * 24);
    assertEquals(Math.round(diffDays), 7, 'Signed URL must expire in exactly 7 days');
  });

  // ---------------------------------------------------------------------------
  // TEST 5: Deletion: 30-day grace period enforced
  // ---------------------------------------------------------------------------
  // EXPORT-05
  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the request reason is now user_requested. The EXPORT-05/12 amendment
  // gives statutory reasons (gdpr_right_to_be_forgotten, used here before) no grace period; the 30 days apply to
  // user_requested / other, and will_delete_at must be requested_at + 30 days. The token comes from the email.
  test('Deletion: 30-day grace period enforced', async () => {
    seedUser();
    const res = await service.requestDeletion('user_123', 'user_requested');
    assertEquals(res.status, 'pending', 'Deletion request should start as pending');
    assertEquals(res.will_delete_at, new Date(clock.now().getTime() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      'will_delete_at must be requested_at + 30 days');

    // Confirm deletion to move it to approved status
    await service.confirmDeletion('user_123', res.deletion_id, tokenFromEmail(email, 'alice@example.com'));

    // Try to execute scheduled deletions immediately (0 days advanced)
    let deletedCount = await service.executeScheduledDeletions();
    assertEquals(deletedCount, 0, 'No deletions should occur before the 30-day grace period');

    // Advance clock by 29 days
    clock.advanceDays(29);
    deletedCount = await service.executeScheduledDeletions();
    assertEquals(deletedCount, 0, 'No deletions should occur at 29 days');

    // Advance clock to 31 days
    clock.advanceDays(2);
    deletedCount = await service.executeScheduledDeletions();
    assertEquals(deletedCount, 1, 'Deletion should execute after 30 days have passed');
  });

  // ---------------------------------------------------------------------------
  // TEST 6: Deletion: User can cancel within grace period
  // ---------------------------------------------------------------------------
  // EXPORT-06
  test('Deletion: User can cancel within grace period', async () => {
    seedUser();
    const res = await service.requestDeletion('user_123', 'user_requested');
    const cancelRes = await service.cancelDeletion('user_123', res.deletion_id);
    assertEquals(cancelRes.status, 'cancelled', 'Cancellation should return cancelled status');

    // Advance clock past grace period and verify no deletion occurs
    clock.advanceDays(35);
    const deletedCount = await service.executeScheduledDeletions();
    assertEquals(deletedCount, 0, 'Cancelled deletion requests must not be executed');
  });

  // ---------------------------------------------------------------------------
  // TEST 7: Deletion: Cascade delete works
  // ---------------------------------------------------------------------------
  // EXPORT-07
  test('Deletion: Cascade delete works', async () => {
    seedUser();
    const res = await service.requestDeletion('user_123', 'user_requested');
    await service.confirmDeletion('user_123', res.deletion_id, tokenFromEmail(email, 'alice@example.com'));

    // Advance past grace period
    clock.advanceDays(31);
    await service.executeScheduledDeletions();

    // Verify all user data is deleted
    assertEquals(db.users.find(u => u.id === 'user_123'), undefined, 'User should be deleted');
    assertEquals(db.sessions.filter(s => s.user_id === 'user_123').length, 0, 'Sessions should be deleted');
    assertEquals(db.activityLogs.filter(a => a.user_id === 'user_123').length, 0, 'Activity logs should be deleted');
    assertEquals(db.files.filter(f => f.user_id === 'user_123').length, 0, 'Files should be deleted');
    assertEquals(db.preferences.filter(p => p.user_id === 'user_123').length, 0, 'Preferences should be deleted');
    assertEquals(db.transactions.filter(t => t.user_id === 'user_123').length, 0, 'Transactions should be deleted');
    assertEquals(db.apiKeys.filter(k => k.user_id === 'user_123').length, 0, 'API keys should be deleted');
    assertEquals(db.exportRequests.filter(e => e.user_id === 'user_123').length, 0, 'Export requests should be deleted');

    // Verify deletion request is marked completed
    const delReq = db.deletionRequests.find(r => r.id === res.deletion_id)!;
    assertEquals(delReq.status, 'completed', 'Deletion request should be marked completed');
    assert(delReq.deleted_at !== null, 'Deleted timestamp should be set');
  });

  // ---------------------------------------------------------------------------
  // TEST 8: Deletion: Audit log preserved (not deleted with user)
  // ---------------------------------------------------------------------------
  // EXPORT-08
  test('Deletion: Audit log preserved (not deleted with user)', async () => {
    seedUser();
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: a gdpr_request is now erased on confirm (EXPORT-12), so no
    // clock advance is needed; the final log is 'user_deleted_cascade' (EXPORT-13), which replaced
    // 'account_permanently_deleted' because nothing may log the user after the audit eraser runs.
    const res = await service.requestDeletion('user_123', 'gdpr_request');
    await service.confirmDeletion('user_123', res.deletion_id, tokenFromEmail(email, 'alice@example.com'));

    // Audit logs for this user should still exist
    const userAuditLogs = db.auditLogs.filter(a => a.user_id === 'user_123');
    assert(userAuditLogs.length > 0, 'Audit logs must be preserved for compliance');

    // Should contain at least: deletion_requested, deletion_confirmed, user_deleted_cascade
    const actions = userAuditLogs.map(a => a.action);
    assert(actions.includes('deletion_requested'), 'Audit log should contain deletion_requested');
    assert(actions.includes('deletion_confirmed'), 'Audit log should contain deletion_confirmed');
    assert(actions.includes('user_deleted_cascade'), 'Audit log should contain user_deleted_cascade');
  });

  // ---------------------------------------------------------------------------
  // TEST 9: Deletion: User confirmed via email token
  // ---------------------------------------------------------------------------
  // EXPORT-09
  test('Deletion: User confirmed via email token', async () => {
    seedUser();
    const res = await service.requestDeletion('user_123', 'user_requested');
    
    // Get the confirmation token from the email (2026-11-10: only its SHA-256 is stored now)
    const req = db.deletionRequests.find(r => r.id === res.deletion_id)!;
    const token = tokenFromEmail(email, 'alice@example.com');
    assert(!JSON.stringify(req).includes(token), 'The raw token must not be stored');
    
    // Confirm with valid token
    const confirmRes = await service.confirmDeletion('user_123', res.deletion_id, token);
    assertEquals(confirmRes.success, true, 'Confirmation should succeed with valid token');
    
    const updatedReq = db.deletionRequests.find(r => r.id === res.deletion_id)!;
    assertEquals(updatedReq.status, 'approved', 'Status should be approved after confirmation');
    
    // Try to confirm again with same token - should fail
    try {
      await service.confirmDeletion('user_123', res.deletion_id, token);
      assert(false, 'Second confirmation should fail');
    } catch (e) {
      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 / EXPORT-15): the reply was "already approved"; a
      // reused token now gets the same 400 invalid_confirmation_token as a wrong one, so the reply never says which.
      assert(e instanceof ComplianceError && e.code === 'invalid_confirmation_token' && e.status === 400, 'Should reject duplicate confirmation');
    }
    
    // Try with invalid token
    seedUser(); // Reset with new user
    const res2 = await service.requestDeletion('user_123', 'user_requested');
    try {
      await service.confirmDeletion('user_123', res2.deletion_id, 'invalid_token');
      assert(false, 'Invalid token should be rejected');
    } catch (e) {
      assert((e as Error).message.includes('Invalid confirmation token'), 'Should reject invalid token');
    }
  });

  // ---------------------------------------------------------------------------
  // TEST 10: Admin: Can see all export/deletion requests
  // ---------------------------------------------------------------------------
  // EXPORT-10
  test('Admin: Can see all export/deletion requests', async () => {
    seedUser();
    
    // Create multiple export requests
    const exp1 = await service.requestExport('user_123', 'json');
    await service.processExportAsync(exp1.export_id);
    const exp2 = await service.requestExport('user_123', 'csv');
    await service.processExportAsync(exp2.export_id);
    
    // Create deletion requests
    await service.requestDeletion('user_123', 'user_requested');
    await service.requestDeletion('user_123', 'gdpr_request');
    
    // Admin lists exports
    const exportsList = await service.listExports('admin_999', {});
    assertEquals(exportsList.total, 2, 'Admin should see all 2 export requests');
    
    // Admin filters exports by status
    const completedExports = await service.listExports('admin_999', { status: 'completed' });
    assertEquals(completedExports.total, 2, 'Admin should see 2 completed exports');
    
    // Admin filters exports by user_id
    const userExports = await service.listExports('admin_999', { userId: 'user_123' });
    assertEquals(userExports.total, 2, 'Admin should see 2 exports for user_123');
    
    // Admin lists deletions
    const deletionsList = await service.listDeletions('admin_999', {});
    assertEquals(deletionsList.total, 2, 'Admin should see all 2 deletion requests');
    
    // Admin filters deletions by status
    const pendingDeletions = await service.listDeletions('admin_999', { status: 'pending' });
    assertEquals(pendingDeletions.total, 2, 'Admin should see 2 pending deletions');
    
    // Non-admin should be rejected
    try {
      await service.listExports('user_123', {});
      assert(false, 'Non-admin should be rejected');
    } catch (e) {
      assert((e as Error).message.includes('Admin privileges required'), 'Should require admin tier');
    }
  });

  // ---------------------------------------------------------------------------
  // TEST 11: Audit: All requests logged with why_chain support
  // ---------------------------------------------------------------------------
  // EXPORT-11
  test('Audit: All requests logged with why_chain support', async () => {
    seedUser();
    
    // Request export with why_chain
    const whyChainExport = 'user_initiated_via_gdpr_portal|session_abc123|ip_192.168.1.1';
    await service.requestExport('user_123', 'json', whyChainExport);
    
    // Request deletion with why_chain
    const whyChainDeletion = 'gdpr_article_17_request|legal_team_approved|case_456';
    await service.requestDeletion('user_123', 'gdpr_right_to_be_forgotten', whyChainDeletion);
    
    // Check audit logs
    const auditLogs = db.auditLogs.filter(a => a.user_id === 'user_123');
    assert(auditLogs.length >= 2, 'Should have at least 2 audit log entries');
    
    // Find export request log
    const exportLog = auditLogs.find(a => a.action === 'data_export_requested');
    assert(exportLog !== undefined, 'Should have data_export_requested audit log');
    assertEquals(exportLog!.why_chain, whyChainExport, 'Export audit log should contain why_chain');
    assertEquals(exportLog!.reason, 'Format: json', 'Export audit log should contain format reason');
    
    // Find deletion request log
    const deletionLog = auditLogs.find(a => a.action === 'deletion_requested');
    assert(deletionLog !== undefined, 'Should have deletion_requested audit log');
    assertEquals(deletionLog!.why_chain, whyChainDeletion, 'Deletion audit log should contain why_chain');
    assertEquals(deletionLog!.reason, 'Reason: gdpr_right_to_be_forgotten', 'Deletion audit log should contain reason');
    
    // Confirm deletion and check audit log
    const delReq = db.deletionRequests.find(r => r.user_id === 'user_123')!;
    await service.confirmDeletion('user_123', delReq.id, tokenFromEmail(email, 'alice@example.com'));
    
    const confirmLog = db.auditLogs.find(a => a.action === 'deletion_confirmed' && a.user_id === 'user_123');
    assert(confirmLog !== undefined, 'Should have deletion_confirmed audit log');
    assertEquals(confirmLog!.reason, 'User confirmed deletion via email token', 'Confirm log should have reason');
  });

  /**
   * EXPORT-12: gdpr_request and gdpr_right_to_be_forgotten get no grace period: will_delete_at = requested_at, and
   * confirm() runs the cascade before returning (status completed, deleted_at = deletion_scheduled_for = now).
   * In: the shared service on its mock clock. Out: throws on failure. Why: EXPORT-12 amendment 2026-11-10.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
   */
  // EXPORT-12
  test('Deletion: statutory reasons are not held for 30 days and are erased on confirm', async () => {
    for (const reason of ['gdpr_request', 'gdpr_right_to_be_forgotten'] as const) {
      seedUser();
      const now = clock.now();
      const res = await service.requestDeletion('user_123', reason);
      assertEquals(res.will_delete_at, now.toISOString(), `${reason}: will_delete_at must equal requested_at`);
      assertEquals(db.users.some(u => u.id === 'user_123'), true, 'nothing is deleted before confirm');
      const confirmed = await service.confirmDeletion('user_123', res.deletion_id, tokenFromEmail(email, 'alice@example.com'));
      assertEquals(confirmed.deletion_scheduled_for, now.toISOString(), 'scheduled for now');
      const req = db.deletionRequests.find(r => r.id === res.deletion_id)!;
      assertEquals(req.status, 'completed', 'statutory deletion completes on confirm');
      assertEquals(req.deleted_at?.toISOString(), now.toISOString(), 'deleted_at = now');
      assertEquals(db.users.some(u => u.id === 'user_123'), false, 'the user is gone');
    }
  });

  /**
   * EXPORT-13: the cascade order. When erase_subject(user_id) is called the user's rows are already gone and the
   * last audit entry for the user is 'user_deleted_cascade'; nothing is logged for the user after it; the eraser is
   * called exactly once; deletion_requests.user_id is NULL; the user's export file is deleted from S3. A failing
   * eraser rolls every table back. In: the shared service with the fake eraser. Out: throws on failure.
   * Why: EXPORT-13 amendment 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
   */
  // EXPORT-13
  test('Deletion cascade order: rows deleted, user_deleted_cascade logged, erase_subject last', async () => {
    seedUser();
    eraser.calls = [];
    const exp = await service.requestExport('user_123', 'json');
    await service.processExportAsync(exp.export_id);
    const s3Key = `export_user_123_${exp.export_id}.json`;
    assert(s3.storage.has(s3Key), 'export file exists before deletion');
    const res = await service.requestDeletion('user_123', 'gdpr_right_to_be_forgotten');
    await service.confirmDeletion('user_123', res.deletion_id, tokenFromEmail(email, 'alice@example.com'));

    assertEquals(eraser.calls.length, 1, 'erase_subject called once');
    assertEquals(eraser.calls[0].userId, 'user_123', 'erase_subject called with the user id');
    assertEquals(eraser.calls[0].userRowsLeft, 0, "the user's rows were deleted before erase_subject");
    assertEquals(eraser.calls[0].lastAuditAction, 'user_deleted_cascade', "'user_deleted_cascade' was logged before erase_subject");
    assertEquals(db.auditLogs.filter(a => a.user_id === 'user_123').length, eraser.calls[0].auditCount, 'nothing logged for the user after erase_subject');
    assertEquals(db.deletionRequests.find(r => r.id === res.deletion_id)!.user_id, null, 'deletion_requests.user_id is NULL');
    assert(!s3.storage.has(s3Key), 'the export file is deleted with the user');

    // A failing eraser rolls the whole cascade back.
    seedUser();
    const failing = new ComplianceService(db, s3, email, clock, { erase_subject: () => { throw new Error('audit store down'); } });
    const res2 = await failing.requestDeletion('user_123', 'gdpr_request');
    let threw = false;
    try {
      await failing.confirmDeletion('user_123', res2.deletion_id, tokenFromEmail(email, 'alice@example.com'));
    } catch (e) {
      threw = (e as Error).message === 'audit store down';
    }
    assert(threw, 'the eraser error is rethrown');
    assertEquals(db.users.some(u => u.id === 'user_123'), true, 'user restored');
    assertEquals(db.sessions.length, 1, 'sessions restored');
    assert(!db.auditLogs.some(a => a.action === 'user_deleted_cascade'), 'the cascade log entry is rolled back');
  });

  /**
   * EXPORT-14: nothing is deleted before confirm; a wrong token, a reused token and a token over 24 h old are
   * refused; another user's deletion request is 404 for confirm and cancel (and their export status is 404 too).
   * In: the shared service. Out: throws on failure. Why: EXPORT-14 amendment 2026-11-10.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
   */
  // EXPORT-14
  test('Deletion confirmation: wrong, reused and expired tokens refused; other users get 404', async () => {
    seedUser();
    const res = await service.requestDeletion('user_123', 'user_requested');
    const token = tokenFromEmail(email, 'alice@example.com');
    assertEquals(db.users.some(u => u.id === 'user_123'), true, 'nothing deleted before confirm');
    assertEquals(db.sessions.length, 1, 'sessions intact before confirm');

    assertEquals((await rejection(() => service.confirmDeletion('admin_999', res.deletion_id, token))).status, 404, "another user's confirm is 404");
    assertEquals((await rejection(() => service.cancelDeletion('admin_999', res.deletion_id))).status, 404, "another user's cancel is 404");
    assertEquals((await rejection(() => service.confirmDeletion('user_123', 'del_unknown', token))).status, 404, 'unknown id is 404');
    const wrong = await rejection(() => service.confirmDeletion('user_123', res.deletion_id, token.slice(0, -1) + (token.endsWith('A') ? 'B' : 'A')));
    assertEquals(wrong.code, 'invalid_confirmation_token', 'a wrong token is refused');
    assertEquals(db.deletionRequests.find(r => r.id === res.deletion_id)!.status, 'pending', 'still pending');

    await service.confirmDeletion('user_123', res.deletion_id, token);
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 / EXPORT-15): a reused token was 409 not_pending; the
    // spec now gives a wrong, reused or expired token the one answer 400 invalid_confirmation_token.
    assertEquals((await rejection(() => service.confirmDeletion('user_123', res.deletion_id, token))).code, 'invalid_confirmation_token', 'a reused token is refused');

    seedUser();
    const late = await service.requestDeletion('user_123', 'user_requested');
    const lateToken = tokenFromEmail(email, 'alice@example.com');
    clock.advanceHours(24);
    clock.advanceHours(0.001);
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 / EXPORT-15): was 403 confirmation_token_expired, which
    // told the caller which case it was; now the same 400 invalid_confirmation_token as a wrong token.
    assertEquals((await rejection(() => service.confirmDeletion('user_123', late.deletion_id, lateToken))).code, 'invalid_confirmation_token', 'a token over 24 h old is refused');

    const exp = await service.requestExport('user_123', 'json');
    assertEquals((await rejection(() => service.getExportStatus('admin_999', exp.export_id))).status, 404, "another user's export status is 404");
  });

  /**
   * EXPORT-15: a wrong, a reused and an expired (over 24 h) token all get the same 400
   * {error: "invalid_confirmation_token"} and change nothing; confirm and cancel of a cancelled request are 409
   * {error: "deletion_not_pending"}; of a completed one (a statutory reason completes on confirm; its user_id is NULL,
   * EXPORT-13) 404 {error: "not_found"}, even for the user who asked; another user's request is 404 too
   * (spec clarification 3abb340, 2026-11-10).
   * In: the shared service. Out: throws on failure. Why: EXPORT-15 (Phase B.2, spec amended 2026-11-10).
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
   */
  // EXPORT-15
  test('Deletion confirmation: one 400 for wrong, reused or expired tokens; 409 once cancelled, 404 once completed', async () => {
    seedUser();
    const res = await service.requestDeletion('user_123', 'user_requested');
    const token = tokenFromEmail(email, 'alice@example.com');

    const other = await rejection(() => service.confirmDeletion('admin_999', res.deletion_id, token));
    assertEquals(other.status, 404, "another user's confirm is 404");
    assertEquals(other.code, 'not_found', "another user's confirm is not_found");
    const otherCancel = await rejection(() => service.cancelDeletion('admin_999', res.deletion_id));
    assertEquals(otherCancel.status, 404, "another user's cancel is 404");
    assertEquals(otherCancel.code, 'not_found', "another user's cancel is not_found");

    const wrong = await rejection(() => service.confirmDeletion('user_123', res.deletion_id, token.slice(0, -1) + (token.endsWith('A') ? 'B' : 'A')));
    assertEquals(wrong.status, 400, 'a wrong token is 400');
    assertEquals(wrong.code, 'invalid_confirmation_token', 'a wrong token is invalid_confirmation_token');
    assertEquals(db.deletionRequests.find(r => r.id === res.deletion_id)!.status, 'pending', 'a wrong token changes nothing');

    await service.confirmDeletion('user_123', res.deletion_id, token);
    const reused = await rejection(() => service.confirmDeletion('user_123', res.deletion_id, token));
    assertEquals(reused.status, 400, 'a reused token is 400');
    assertEquals(reused.code, 'invalid_confirmation_token', 'a reused token gets the same answer');
    assertEquals(db.deletionRequests.find(r => r.id === res.deletion_id)!.status, 'approved', 'a reused token changes nothing');

    seedUser();
    const late = await service.requestDeletion('user_123', 'user_requested');
    const lateToken = tokenFromEmail(email, 'alice@example.com');
    clock.advanceHours(24.001);
    const expired = await rejection(() => service.confirmDeletion('user_123', late.deletion_id, lateToken));
    assertEquals(expired.status, 400, 'an expired token is 400');
    assertEquals(expired.code, 'invalid_confirmation_token', 'an expired token gets the same answer');
    assertEquals(wrong.message, expired.message, 'the message does not say which case it was');
    assertEquals(db.deletionRequests.find(r => r.id === late.deletion_id)!.status, 'pending', 'an expired token changes nothing');

    // cancelled: confirm and cancel are both 409 deletion_not_pending
    await service.cancelDeletion('user_123', late.deletion_id);
    const confirmCancelled = await rejection(() => service.confirmDeletion('user_123', late.deletion_id, lateToken));
    assertEquals(confirmCancelled.status, 409, 'confirm of a cancelled request is 409');
    assertEquals(confirmCancelled.code, 'deletion_not_pending', 'confirm of a cancelled request is deletion_not_pending');
    const cancelCancelled = await rejection(() => service.cancelDeletion('user_123', late.deletion_id));
    assertEquals(cancelCancelled.status, 409, 'cancel of a cancelled request is 409');
    assertEquals(cancelCancelled.code, 'deletion_not_pending', 'cancel of a cancelled request is deletion_not_pending');

    // completed: a statutory reason runs the cascade at confirm; the request has no owner any more, so it is 404
    seedUser();
    const gdpr = await service.requestDeletion('user_123', 'gdpr_request');
    const gdprToken = tokenFromEmail(email, 'alice@example.com');
    await service.confirmDeletion('user_123', gdpr.deletion_id, gdprToken);
    assertEquals(db.deletionRequests.find(r => r.id === gdpr.deletion_id)!.status, 'completed', 'the statutory request completed');
    assertEquals(db.deletionRequests.find(r => r.id === gdpr.deletion_id)!.user_id, null, 'the completed request has no owner');
    const confirmCompleted = await rejection(() => service.confirmDeletion('user_123', gdpr.deletion_id, gdprToken));
    assertEquals(confirmCompleted.status, 404, 'confirm of a completed request is 404');
    assertEquals(confirmCompleted.code, 'not_found', 'confirm of a completed request is not_found');
    const cancelCompleted = await rejection(() => service.cancelDeletion('user_123', gdpr.deletion_id));
    assertEquals(cancelCompleted.status, 404, 'cancel of a completed request is 404');
    assertEquals(cancelCompleted.code, 'not_found', 'cancel of a completed request is not_found');
    assertEquals((await rejection(() => service.cancelDeletion('admin_999', gdpr.deletion_id))).status, 404, 'and 404 to anyone else');
  });

  /**
   * EXPORT-06 (Phase B.3 ruling): a deletion can be cancelled until will_delete_at; once will_delete_at has passed
   * (the deletion is due but the worker has not run it yet) cancel is 409 {error: "grace_period_over"} and the
   * request is unchanged, confirmed or not. One second before will_delete_at the cancel still succeeds.
   * In: the shared service and its mock clock. Out: throws on failure. Why: Phase D wave 1, owner request 2026-11-10
   * (B.3 rulings). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
   * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.4 ruling af92d76, EXPORT-16): an unconfirmed
   * (pending) request past will_delete_at is now cancelled; this test asserted 409 grace_period_over for it, which
   * af92d76 overturns (a pending request is not scheduled, so it can always be cancelled).
   */
  // EXPORT-06
  test('Deletion: cancelling after will_delete_at is 409 grace_period_over', async () => {
    seedUser();
    const due = await service.requestDeletion('user_123', 'user_requested');
    await service.confirmDeletion('user_123', due.deletion_id, tokenFromEmail(email, 'alice@example.com'));
    clock.advanceDays(30);
    assertEquals(clock.now().toISOString(), due.will_delete_at, 'the clock is exactly at will_delete_at');
    const over = await rejection(() => service.cancelDeletion('user_123', due.deletion_id));
    assertEquals(over.status, 409, 'cancel after will_delete_at is 409');
    assertEquals(over.code, 'grace_period_over', 'cancel after will_delete_at is grace_period_over');
    assertEquals(db.deletionRequests.find(r => r.id === due.deletion_id)!.status, 'approved', 'the refused cancel changes nothing');

    seedUser();
    const unconfirmed = await service.requestDeletion('user_123', 'user_requested');
    clock.advanceDays(31);
    // Phase B.4 (af92d76, 2026-11-10): was 409 grace_period_over; a pending request can always be cancelled.
    const late = await service.cancelDeletion('user_123', unconfirmed.deletion_id);
    assertEquals(late.status, 'cancelled', 'an unconfirmed request past will_delete_at is still cancelled');

    seedUser();
    const inTime = await service.requestDeletion('user_123', 'user_requested');
    clock.advanceHours(30 * 24 - 1 / 3600);
    const cancelled = await service.cancelDeletion('user_123', inTime.deletion_id);
    assertEquals(cancelled.status, 'cancelled', 'one second before will_delete_at the cancel succeeds');
  });

  /**
   * EXPORT-16 (Phase B.4 ruling af92d76): cancel follows the request's state. A pending (unconfirmed) request is
   * cancelled a day after will_delete_at; a confirmed one is cancelled one second before will_delete_at, and gets
   * 409 {error: "grace_period_over"} exactly at will_delete_at and one second after it, staying approved.
   * In: the shared service and its mock clock. Out: throws on failure. Why: EXPORT-16 (af92d76).
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
   */
  // EXPORT-16
  test('Deletion: a pending request is always cancellable; a confirmed one is refused from will_delete_at on', async () => {
    const statusOf = (id: string) => db.deletionRequests.find(r => r.id === id)!.status;
    const start = clock.now().getTime();
    const confirmedAt = async (offsetSeconds: number) => {
      seedUser();
      clock.setMs(start);
      const d = await service.requestDeletion('user_123', 'user_requested');
      await service.confirmDeletion('user_123', d.deletion_id, tokenFromEmail(email, 'alice@example.com'));
      clock.setMs(Date.parse(d.will_delete_at) + offsetSeconds * 1000);
      return d;
    };

    seedUser();
    clock.setMs(start);
    const pending = await service.requestDeletion('user_123', 'user_requested');
    clock.setMs(Date.parse(pending.will_delete_at) + 24 * 3600 * 1000);
    assertEquals((await service.cancelDeletion('user_123', pending.deletion_id)).status, 'cancelled',
      'a pending request a day after will_delete_at is cancelled');
    assertEquals(statusOf(pending.deletion_id), 'cancelled', 'and stored as cancelled');

    const before = await confirmedAt(-1);
    assertEquals((await service.cancelDeletion('user_123', before.deletion_id)).status, 'cancelled',
      'a confirmed request one second before will_delete_at is cancelled');

    for (const offset of [0, 1]) {
      const d = await confirmedAt(offset);
      const refused = await rejection(() => service.cancelDeletion('user_123', d.deletion_id));
      assertEquals(refused.status, 409, `a confirmed request ${offset}s after will_delete_at is 409`);
      assertEquals(refused.code, 'grace_period_over', `a confirmed request ${offset}s after will_delete_at is grace_period_over`);
      assertEquals(statusOf(d.deletion_id), 'approved', 'the refused cancel leaves it confirmed');
    }
  });
}
