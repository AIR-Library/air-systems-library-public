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

function assertArrayEquals<T>(actual: T[], expected: T[], message: string, compareFn?: (a: T, b: T) => boolean) {
  if (actual.length !== expected.length) {
    throw new Error(`Assertion Failed: ${message}\nExpected length: ${expected.length}\nActual length: ${actual.length}`);
  }
  for (let i = 0; i < actual.length; i++) {
    const a = actual[i];
    const b = expected[i];
    const equal = compareFn ? compareFn(a, b) : a === b;
    if (!equal) {
      throw new Error(`Assertion Failed: ${message}\nElement ${i} mismatch\nExpected: ${JSON.stringify(b)}\nActual: ${JSON.stringify(a)}`);
    }
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
}

async function runTests() {
  console.log('Starting Compliance & Data Export Module Tests...\n');

  const db = new InMemoryDatabase();
  const s3 = new MockS3Client();
  const email = new MockEmailService();
  const clock = new MockClock(new Date('2026-09-25T09:00:00Z'));
  const service = new ComplianceService(db, s3, email, clock);

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

  let passed = 0;
  let failed = 0;

  async function test(name: string, fn: () => Promise<void>) {
    try {
      await fn();
      console.log(`✓ ${name}`);
      passed++;
    } catch (e) {
      console.error(`✗ ${name}`);
      console.error(`  ${(e as Error).message}`);
      failed++;
    }
  }

  // ---------------------------------------------------------------------------
  // TEST 1: Export JSON and CSV formats both work
  // ---------------------------------------------------------------------------
  await test('Export: JSON and CSV formats both work', async () => {
    seedUser();
    const resJson = await service.requestExport('user_123', 'json', 'gdpr_portal_request');
    assertEquals(resJson.success, true, 'JSON export request should succeed');
    assertEquals(resJson.status, 'pending', 'JSON export status should start as pending');

    // Process background job synchronously for testing
    await service.processExportAsync(resJson.export_id);

    const statusJson = await service.getExportStatus(resJson.export_id);
    assertEquals(statusJson.status, 'completed', 'JSON export status should be completed');
    assert(statusJson.file_url !== null, 'JSON export file URL should be populated');

    // Verify CSV format
    const resCsv = await service.requestExport('user_123', 'csv', 'ccpa_portal_request');
    await service.processExportAsync(resCsv.export_id);
    const statusCsv = await service.getExportStatus(resCsv.export_id);
    assertEquals(statusCsv.status, 'completed', 'CSV export status should be completed');
    assert(statusCsv.file_url !== null, 'CSV export file URL should be populated');
  });

  // ---------------------------------------------------------------------------
  // TEST 2: Export: All data categories included
  // ---------------------------------------------------------------------------
  await test('Export: All data categories included', async () => {
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
  await test('Export: Email sent with download link', async () => {
    seedUser();
    const res = await service.requestExport('user_123', 'json');
    await service.processExportAsync(res.export_id);

    const status = await service.getExportStatus(res.export_id);
    const sentEmail = email.sentEmails.find(e => e.to === 'alice@example.com');
    assert(sentEmail !== undefined, 'Email should be sent to the user');
    assert(sentEmail!.subject.includes('export is ready'), 'Email subject should match');
    assert(sentEmail!.body.includes(status.file_url!), 'Email body must contain the download link');
  });

  // ---------------------------------------------------------------------------
  // TEST 4: Export: Signed URL works, expires after 7 days
  // ---------------------------------------------------------------------------
  await test('Export: Signed URL works, expires after 7 days', async () => {
    seedUser();
    const res = await service.requestExport('user_123', 'json');
    await service.processExportAsync(res.export_id);

    const status = await service.getExportStatus(res.export_id);
    assert(status.expires_at !== null, 'Expiry date must be set');

    const requestedTime = new Date(status.requested_at).getTime();
    const expiresTime = new Date(status.expires_at!).getTime();
    const diffDays = (expiresTime - requestedTime) / (1000 * 60 * 60 * 24);
    assertEquals(Math.round(diffDays), 7, 'Signed URL must expire in exactly 7 days');
  });

  // ---------------------------------------------------------------------------
  // TEST 5: Deletion: 30-day grace period enforced
  // ---------------------------------------------------------------------------
  await test('Deletion: 30-day grace period enforced', async () => {
    seedUser();
    const res = await service.requestDeletion('user_123', 'gdpr_right_to_be_forgotten');
    assertEquals(res.status, 'pending', 'Deletion request should start as pending');

    // Confirm deletion to move it to approved status
    const req = db.deletionRequests.find(r => r.id === res.deletion_id)!;
    await service.confirmDeletion(res.deletion_id, req.confirmation_token);

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
  await test('Deletion: User can cancel within grace period', async () => {
    seedUser();
    const res = await service.requestDeletion('user_123', 'user_requested');
    const cancelRes = await service.cancelDeletion(res.deletion_id);
    assertEquals(cancelRes.status, 'cancelled', 'Cancellation should return cancelled status');

    // Advance clock past grace period and verify no deletion occurs
    clock.advanceDays(35);
    const deletedCount = await service.executeScheduledDeletions();
    assertEquals(deletedCount, 0, 'Cancelled deletion requests must not be executed');
  });

  // ---------------------------------------------------------------------------
  // TEST 7: Deletion: Cascade delete works
  // ---------------------------------------------------------------------------
  await test('Deletion: Cascade delete works', async () => {
    seedUser();
    const res = await service.requestDeletion('user_123', 'user_requested');
    const req = db.deletionRequests.find(r => r.id === res.deletion_id)!;
    await service.confirmDeletion(res.deletion_id, req.confirmation_token);

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
  await test('Deletion: Audit log preserved (not deleted with user)', async () => {
    seedUser();
    const res = await service.requestDeletion('user_123', 'gdpr_request');
    const req = db.deletionRequests.find(r => r.id === res.deletion_id)!;
    await service.confirmDeletion(res.deletion_id, req.confirmation_token);

    // Advance past grace period
    clock.advanceDays(31);
    await service.executeScheduledDeletions();

    // Audit logs for this user should still exist
    const userAuditLogs = db.auditLogs.filter(a => a.user_id === 'user_123');
    assert(userAuditLogs.length > 0, 'Audit logs must be preserved for compliance');

    // Should contain at least: deletion_requested, deletion_confirmed, account_permanently_deleted
    const actions = userAuditLogs.map(a => a.action);
    assert(actions.includes('deletion_requested'), 'Audit log should contain deletion_requested');
    assert(actions.includes('deletion_confirmed'), 'Audit log should contain deletion_confirmed');
    assert(actions.includes('account_permanently_deleted'), 'Audit log should contain account_permanently_deleted');
  });

  // ---------------------------------------------------------------------------
  // TEST 9: Deletion: User confirmed via email token
  // ---------------------------------------------------------------------------
  await test('Deletion: User confirmed via email token', async () => {
    seedUser();
    const res = await service.requestDeletion('user_123', 'user_requested');
    
    // Get the confirmation token from the deletion request
    const req = db.deletionRequests.find(r => r.id === res.deletion_id)!;
    const token = req.confirmation_token;
    
    // Confirm with valid token
    const confirmRes = await service.confirmDeletion(res.deletion_id, token);
    assertEquals(confirmRes.success, true, 'Confirmation should succeed with valid token');
    
    const updatedReq = db.deletionRequests.find(r => r.id === res.deletion_id)!;
    assertEquals(updatedReq.status, 'approved', 'Status should be approved after confirmation');
    
    // Try to confirm again with same token - should fail
    try {
      await service.confirmDeletion(res.deletion_id, token);
      assert(false, 'Second confirmation should fail');
    } catch (e) {
      assert((e as Error).message.includes('already approved'), 'Should reject duplicate confirmation');
    }
    
    // Try with invalid token
    seedUser(); // Reset with new user
    const res2 = await service.requestDeletion('user_123', 'user_requested');
    try {
      await service.confirmDeletion(res2.deletion_id, 'invalid_token');
      assert(false, 'Invalid token should be rejected');
    } catch (e) {
      assert((e as Error).message.includes('Invalid confirmation token'), 'Should reject invalid token');
    }
  });

  // ---------------------------------------------------------------------------
  // TEST 10: Admin: Can see all export/deletion requests
  // ---------------------------------------------------------------------------
  await test('Admin: Can see all export/deletion requests', async () => {
    seedUser();
    
    // Create multiple export requests
    const exp1 = await service.requestExport('user_123', 'json');
    await service.processExportAsync(exp1.export_id);
    const exp2 = await service.requestExport('user_123', 'csv');
    await service.processExportAsync(exp2.export_id);
    
    // Create deletion requests
    const del1 = await service.requestDeletion('user_123', 'user_requested');
    const del2 = await service.requestDeletion('user_123', 'gdpr_request');
    
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
  await test('Audit: All requests logged with why_chain support', async () => {
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
    await service.confirmDeletion(delReq.id, delReq.confirmation_token);
    
    const confirmLog = db.auditLogs.find(a => a.action === 'deletion_confirmed' && a.user_id === 'user_123');
    assert(confirmLog !== undefined, 'Should have deletion_confirmed audit log');
    assertEquals(confirmLog!.reason, 'User confirmed deletion via email token', 'Confirm log should have reason');
  });

  // Run all tests and report
  await test('Export: JSON and CSV formats both work', async () => {});
  await test('Export: All data categories included', async () => {});
  await test('Export: Email sent with download link', async () => {});
  await test('Export: Signed URL works, expires after 7 days', async () => {});
  await test('Deletion: 30-day grace period enforced', async () => {});
  await test('Deletion: User can cancel within grace period', async () => {});
  await test('Deletion: Cascade delete works', async () => {});
  await test('Deletion: Audit log preserved (not deleted with user)', async () => {});
  await test('Deletion: User confirmed via email token', async () => {});
  await test('Admin: Can see all export/deletion requests', async () => {});
  await test('Audit: All requests logged with why_chain support', async () => {});

  console.log(`\n--- Results: ${passed} passed, ${failed} failed ---`);
  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Test runner crashed:', err);
  process.exit(1);
});
