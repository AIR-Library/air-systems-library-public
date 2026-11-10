import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  AdminSystem,
  AdminError,
  ConsoleEmailService,
  StripeClient,
  EmailService,
  AdminContext,
  Tier,
} from './admin_system_typescript';

// ---------------------------------------------------------------------------
// Mock Stripe
// ---------------------------------------------------------------------------

/**
 * Fake Stripe. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: also answers retrieveSubscription (ADMIN-12 reads the
 * current item first); `items` sets what it returns, by default one item "si_current".
 */
class MockStripeClient implements StripeClient {
  public calls: { subscriptionId: string; params: { items: { id?: string; price: string }[]; proration_behavior?: string } }[] = [];
  public retrieved: string[] = [];
  public items: { id: string }[] = [{ id: 'si_current' }];

  async retrieveSubscription(subscriptionId: string): Promise<{ id: string; items: { data: { id: string }[] } }> {
    this.retrieved.push(subscriptionId);
    return { id: subscriptionId, items: { data: this.items } };
  }

  async updateSubscription(
    subscriptionId: string,
    params: { items: { id?: string; price: string }[]; proration_behavior?: string }
  ): Promise<{ id: string; effective_date: string }> {
    this.calls.push({ subscriptionId, params });
    return { id: subscriptionId, effective_date: new Date().toISOString() };
  }
}

// ---------------------------------------------------------------------------
// Mock Email
// ---------------------------------------------------------------------------

class MockEmailService implements EmailService {
  public invites: { email: string; name: string; otp: string }[] = [];
  public resets: { email: string; link: string }[] = [];

  async sendInvite(email: string, name: string, otp: string): Promise<void> {
    this.invites.push({ email, name, otp });
  }

  async sendPasswordReset(email: string, link: string): Promise<void> {
    this.resets.push({ email, link });
  }
}

// ---------------------------------------------------------------------------
// Mock Pool
// ---------------------------------------------------------------------------

interface MockRow {
  [key: string]: unknown;
}

class MockPool {
  private users: MockRow[] = [];
  private customers: MockRow[] = [];
  private invoices: MockRow[] = [];
  private refunds: MockRow[] = [];
  private deployments: MockRow[] = [];
  private governanceActions: MockRow[] = [];
  private auditLog: MockRow[] = [];
  private resetTokens: MockRow[] = [];
  private deploymentConfig: MockRow[] = [];
  private nextUserId = 1;
  private nextCustomerId = 1;
  private nextInvoiceId = 1;
  private nextRefundId = 1;
  private nextDeploymentId = 1;
  private nextActionId = 1;
  private nextAuditId = 1;

  async execute(sql: string, params: unknown[] = []): Promise<[MockRow[], unknown]> {
    const normalized = sql.replace(/\s+/g, ' ').trim();

    // INSERT INTO users
    if (normalized.startsWith('INSERT INTO users')) {
      const [email, name, tier, status, passwordHash] = params as [string, string, string, string, string];
      const id = this.nextUserId++;
      this.users.push({ id, email, name, tier, status, password_hash: passwordHash, created_at: new Date().toISOString() });
      return [{ insertId: id, affectedRows: 1 }, undefined];
    }

    // SELECT id FROM users WHERE email = ?
    if (normalized.startsWith('SELECT id FROM users WHERE email')) {
      const email = params[0] as string;
      const rows = this.users.filter((u) => u.email === email).map((u) => ({ id: u.id }));
      return [rows, undefined];
    }

    // SELECT id, email, tier, status FROM users WHERE id = ?
    if (normalized.startsWith('SELECT id, email, tier, status FROM users WHERE id') || normalized.startsWith('SELECT id, tier, status FROM users WHERE id')) {
      const id = params[0] as number;
      const user = this.users.find((u) => u.id === id);
      if (!user) return [[], undefined];
      return [[{ id: user.id, email: user.email, tier: user.tier, status: user.status }], undefined];
    }

    // SELECT COUNT(*) AS cnt FROM users WHERE tier = 'enterprise' AND status = 'active'
    if (normalized.includes("SELECT COUNT(*) AS cnt FROM users WHERE tier = 'enterprise'")) {
      const cnt = this.users.filter((u) => u.tier === 'enterprise' && u.status === 'active').length;
      return [[{ cnt }], undefined];
    }

    // UPDATE users SET tier = ? WHERE id = ?
    if (normalized.startsWith('UPDATE users SET tier')) {
      const [tier, id] = params as [string, number];
      const user = this.users.find((u) => u.id === id);
      if (user) user.tier = tier;
      return [{ affectedRows: 1 }, undefined];
    }

    // UPDATE users SET status = 'suspended' WHERE id = ?
    if (normalized.startsWith("UPDATE users SET status = 'suspended'")) {
      const id = params[0] as number;
      const user = this.users.find((u) => u.id === id);
      if (user) user.status = 'suspended';
      return [{ affectedRows: 1 }, undefined];
    }

    // INSERT INTO reset_tokens
    if (normalized.startsWith('INSERT INTO reset_tokens')) {
      const [token, userId] = params as [string, number];
      this.resetTokens.push({ token, user_id: userId, created_at: new Date().toISOString() });
      return [{ insertId: this.resetTokens.length, affectedRows: 1 }, undefined];
    }

    // SELECT customer_id, email, name, tier, subscription_status, payment_method, address, notes, status FROM customers WHERE customer_id = ?
    if (normalized.startsWith('SELECT customer_id, email, name, tier, subscription_status')) {
      const id = params[0] as number;
      const cust = this.customers.find((c) => c.customer_id === id);
      if (!cust) return [[], undefined];
      return [[cust], undefined];
    }

    // SELECT customer_id, tier, stripe_subscription_id FROM customers WHERE customer_id = ?
    if (normalized.startsWith('SELECT customer_id, tier, stripe_subscription_id')) {
      const id = params[0] as number;
      const cust = this.customers.find((c) => c.customer_id === id);
      if (!cust) return [[], undefined];
      return [[{ customer_id: cust.customer_id, tier: cust.tier, stripe_subscription_id: cust.stripe_subscription_id }], undefined];
    }

    // SELECT customer_id FROM customers WHERE customer_id = ?
    if (normalized.startsWith('SELECT customer_id FROM customers WHERE customer_id')) {
      const id = params[0] as number;
      const cust = this.customers.find((c) => c.customer_id === id);
      if (!cust) return [[], undefined];
      return [[{ customer_id: cust.customer_id }], undefined];
    }

    // SELECT COUNT(*) AS total FROM customers
    if (normalized.startsWith('SELECT COUNT(*) AS total FROM customers')) {
      return [[{ total: this.customers.length }], undefined];
    }

    // SELECT customer_id, email, name, tier, signup_date, status, ... FROM customers ORDER BY customer_id LIMIT ? OFFSET ?
    if (normalized.startsWith('SELECT customer_id, email, name, tier, signup_date, status')) {
      const limit = params[0] as number;
      const offset = params[1] as number;
      const rows = this.customers.slice(offset, offset + limit).map((c) => ({
        customer_id: c.customer_id,
        email: c.email,
        name: c.name,
        tier: c.tier,
        signup_date: c.signup_date,
        status: c.status,
        invoice_count: this.invoices.filter((i) => i.customer_id === c.customer_id).length,
      }));
      return [rows, undefined];
    }

    // UPDATE customers SET tier = ? WHERE customer_id = ?
    if (normalized.startsWith('UPDATE customers SET tier')) {
      const [tier, id] = params as [string, number];
      const cust = this.customers.find((c) => c.customer_id === id);
      if (cust) cust.tier = tier;
      return [{ affectedRows: 1 }, undefined];
    }

    // SELECT invoice_id, customer_id, status FROM invoices WHERE invoice_id = ?
    if (normalized.startsWith('SELECT invoice_id, customer_id, status FROM invoices')) {
      const id = params[0] as number;
      const inv = this.invoices.find((i) => i.invoice_id === id);
      if (!inv) return [[], undefined];
      return [[{ invoice_id: inv.invoice_id, customer_id: inv.customer_id, status: inv.status }], undefined];
    }

    // INSERT INTO refunds
    if (normalized.startsWith('INSERT INTO refunds')) {
      const [invoiceId, amount, reason, status, createdBy] = params as [number, number, string, string, number];
      const id = this.nextRefundId++;
      this.refunds.push({ refund_id: id, invoice_id: invoiceId, amount, reason, status, created_by: createdBy, created_at: new Date().toISOString() });
      return [{ insertId: id, affectedRows: 1 }, undefined];
    }

    // SELECT deployment_id, customer_id, domain, tier, status, theme, published_at FROM deployments ORDER BY deployment_id
    if (normalized.startsWith('SELECT deployment_id, customer_id, domain, tier, status, theme, published_at')) {
      const rows = this.deployments.map((d) => ({
        deployment_id: d.deployment_id,
        customer_id: d.customer_id,
        domain: d.domain,
        tier: d.tier,
        status: d.status,
        theme: d.theme ?? '',
        published_at: d.published_at ?? null,
      }));
      return [rows, undefined];
    }

    // SELECT deployment_id FROM deployments WHERE domain = ?
    if (normalized.startsWith('SELECT deployment_id FROM deployments WHERE domain')) {
      const domain = params[0] as string;
      const rows = this.deployments.filter((d) => d.domain === domain).map((d) => ({ deployment_id: d.deployment_id }));
      return [rows, undefined];
    }

    // SELECT theme_id FROM deployment_config WHERE deployment_id = ? LIMIT 1
    if (normalized.startsWith('SELECT theme_id FROM deployment_config')) {
      const id = params[0] as number;
      const cfg = this.deploymentConfig.find((c) => c.deployment_id === id);
      if (!cfg) return [[], undefined];
      return [[{ theme_id: cfg.theme_id }], undefined];
    }

    // INSERT INTO deployments
    if (normalized.startsWith('INSERT INTO deployments')) {
      const [customerId, domain, tier, status, themeId, domainVerified] = params as [number, string, string, string, number, number];
      const id = this.nextDeploymentId++;
      this.deployments.push({
        deployment_id: id,
        customer_id: customerId,
        domain,
        tier,
        status,
        theme_id: themeId,
        domain_verified: domainVerified,
        theme: `theme_${themeId}`,
        published_at: null,
        archived_at: null,
        suspend_reason: null,
        created_at: new Date().toISOString(),
      });
      return [{ insertId: id, affectedRows: 1 }, undefined];
    }

    // INSERT INTO deployment_config
    if (normalized.startsWith('INSERT INTO deployment_config')) {
      const [deploymentId, configJson] = params as [number, string];
      this.deploymentConfig.push({ deployment_id: deploymentId, config_json: configJson });
      return [{ insertId: this.deploymentConfig.length, affectedRows: 1 }, undefined];
    }

    // SELECT deployment_id, status, domain, domain_verified, theme_id FROM deployments WHERE deployment_id = ?
    if (normalized.startsWith('SELECT deployment_id, status, domain, domain_verified, theme_id')) {
      const id = params[0] as number;
      const dep = this.deployments.find((d) => d.deployment_id === id);
      if (!dep) return [[], undefined];
      return [[{ deployment_id: dep.deployment_id, status: dep.status, domain: dep.domain, domain_verified: dep.domain_verified, theme_id: dep.theme_id }], undefined];
    }

    // SELECT deployment_id, status FROM deployments WHERE deployment_id = ?
    if (normalized.startsWith('SELECT deployment_id, status FROM deployments WHERE deployment_id')) {
      const id = params[0] as number;
      const dep = this.deployments.find((d) => d.deployment_id === id);
      if (!dep) return [[], undefined];
      return [[{ deployment_id: dep.deployment_id, status: dep.status }], undefined];
    }

    // UPDATE deployments SET status = 'live', published_at = NOW() WHERE deployment_id = ?
    if (normalized.startsWith("UPDATE deployments SET status = 'live'")) {
      const id = params[0] as number;
      const dep = this.deployments.find((d) => d.deployment_id === id);
      if (dep) {
        dep.status = 'live';
        dep.published_at = new Date().toISOString();
      }
      return [{ affectedRows: 1 }, undefined];
    }

    // UPDATE deployments SET status = 'suspended', suspend_reason = ? WHERE deployment_id = ?
    if (normalized.startsWith("UPDATE deployments SET status = 'suspended'")) {
      const [reason, id] = params as [string, number];
      const dep = this.deployments.find((d) => d.deployment_id === id);
      if (dep) {
        dep.status = 'suspended';
        dep.suspend_reason = reason;
      }
      return [{ affectedRows: 1 }, undefined];
    }

    // UPDATE deployments SET status = 'archived', archived_at = NOW() WHERE deployment_id = ?
    if (normalized.startsWith("UPDATE deployments SET status = 'archived'")) {
      const id = params[0] as number;
      const dep = this.deployments.find((d) => d.deployment_id === id);
      if (dep) {
        dep.status = 'archived';
        dep.archived_at = new Date().toISOString();
      }
      return [{ affectedRows: 1 }, undefined];
    }

    // SELECT action_id, action_type, actor, target_resource_id, reason, submitted_at, status FROM governance_actions WHERE status = 'pending'
    if (normalized.startsWith('SELECT action_id, action_type, actor, target_resource_id, reason, submitted_at, status FROM governance_actions WHERE status')) {
      const limit = params[0] as number;
      const offset = params[1] as number;
      const pending = this.governanceActions.filter((a) => a.status === 'pending');
      const rows = pending.slice(offset, offset + limit).map((a) => ({
        action_id: a.action_id,
        action_type: a.action_type,
        actor: a.actor,
        target_resource_id: a.target_resource_id,
        reason: a.reason,
        submitted_at: a.submitted_at,
        status: a.status,
      }));
      return [rows, undefined];
    }

    // SELECT COUNT(*) AS total FROM governance_actions WHERE status = 'pending'
    if (normalized.startsWith("SELECT COUNT(*) AS total FROM governance_actions WHERE status = 'pending'")) {
      const total = this.governanceActions.filter((a) => a.status === 'pending').length;
      return [[{ total }], undefined];
    }

    // SELECT action_id, action_type, actor, target_resource_id, reason, status FROM governance_actions WHERE action_id = ?
    if (normalized.startsWith('SELECT action_id, action_type, actor, target_resource_id, reason, status FROM governance_actions WHERE action_id')) {
      const id = params[0] as number;
      const action = this.governanceActions.find((a) => a.action_id === id);
      if (!action) return [[], undefined];
      return [[action], undefined];
    }

    // UPDATE governance_actions SET status = 'approved'
    if (normalized.startsWith("UPDATE governance_actions SET status = 'approved'")) {
      const [approvedBy, id] = params as [number, number];
      const action = this.governanceActions.find((a) => a.action_id === id);
      if (action) {
        action.status = 'approved';
        action.approved_by = approvedBy;
        action.approved_at = new Date().toISOString();
      }
      return [{ affectedRows: 1 }, undefined];
    }

    // UPDATE governance_actions SET status = 'rejected'
    if (normalized.startsWith("UPDATE governance_actions SET status = 'rejected'")) {
      const [reason, id] = params as [string, number];
      const action = this.governanceActions.find((a) => a.action_id === id);
      if (action) {
        action.status = 'rejected';
        action.rejection_reason = reason;
      }
      return [{ affectedRows: 1 }, undefined];
    }

    // INSERT INTO audit_log
    if (normalized.startsWith('INSERT INTO audit_log')) {
      const [actorId, action, resourceType, resourceId, oldValue, newValue, reason] = params as [number, string, string, string, string | null, string | null, string | null];
      const id = this.nextAuditId++;
      this.auditLog.push({
        id,
        timestamp: new Date().toISOString(),
        actor_id: actorId,
        action,
        resource_type: resourceType,
        resource_id: resourceId,
        old_value: oldValue,
        new_value: newValue,
        reason,
      });
      return [{ insertId: id, affectedRows: 1 }, undefined];
    }

    // SELECT COUNT(*) AS total FROM audit_log
    if (normalized.startsWith('SELECT COUNT(*) AS total FROM audit_log')) {
      let rows = this.auditLog;
      if (params.length > 0) {
        // Apply filters based on params
        // This is simplified; in real code we'd parse the WHERE clause
      }
      return [[{ total: rows.length }], undefined];
    }

    // SELECT timestamp, actor_id, action, resource_type, resource_id, old_value, new_value, reason FROM audit_log
    if (normalized.startsWith('SELECT timestamp, actor_id, action, resource_type, resource_id, old_value, new_value, reason FROM audit_log')) {
      let rows = [...this.auditLog];
      // Apply filters
      const limit = params[params.length - 2] as number;
      const offset = params[params.length - 1] as number;
      // Parse conditions from params (simplified)
      const filterParams = params.slice(0, params.length - 2);
      if (filterParams.length >= 1) {
        // action filter
        rows = rows.filter((r) => r.action === filterParams[0]);
      }
      if (filterParams.length >= 2) {
        // resource_id filter
        rows = rows.filter((r) => r.resource_id === filterParams[1]);
      }
      if (filterParams.length >= 4) {
        // date range
        const start = filterParams[2] as string;
        const end = filterParams[3] as string;
        rows = rows.filter((r) => r.timestamp >= start && r.timestamp <= end);
      }
      rows.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
      const paged = rows.slice(offset, offset + limit);
      return [paged, undefined];
    }

    // Fallback
    return [[], undefined];
  }

  // Seed helpers
  seedUser(user: Partial<MockRow> & { email: string; name: string; tier: string; status: string }): number {
    const id = this.nextUserId++;
    this.users.push({ id, created_at: new Date().toISOString(), ...user });
    return id;
  }

  seedCustomer(cust: Partial<MockRow> & { email: string; name: string; tier: string }): number {
    const id = this.nextCustomerId++;
    this.customers.push({
      customer_id: id,
      signup_date: new Date().toISOString(),
      subscription_status: 'active',
      payment_method: 'card',
      address: '',
      notes: '',
      stripe_customer_id: `cus_${id}`,
      stripe_subscription_id: `sub_${id}`,
      status: 'active',
      ...cust,
    });
    return id;
  }

  seedInvoice(inv: Partial<MockRow> & { customer_id: number; amount: number; status: string }): number {
    const id = this.nextInvoiceId++;
    this.invoices.push({ invoice_id: id, created_at: new Date().toISOString(), ...inv });
    return id;
  }

  seedDeployment(dep: Partial<MockRow> & { customer_id: number; domain: string; tier: string }): number {
    const id = this.nextDeploymentId++;
    this.deployments.push({
      deployment_id: id,
      status: 'draft',
      theme_id: 1,
      theme: 'theme_1',
      domain_verified: 1,
      published_at: null,
      archived_at: null,
      suspend_reason: null,
      created_at: new Date().toISOString(),
      ...dep,
    });
    return id;
  }

  seedGovernanceAction(action: Partial<MockRow> & { action_type: string; actor: number; target_resource_id: number; reason: string }): number {
    const id = this.nextActionId++;
    this.governanceActions.push({
      action_id: id,
      status: 'pending',
      submitted_at: new Date().toISOString(),
      approved_by: null,
      approved_at: null,
      rejection_reason: null,
      ...action,
    });
    return id;
  }

  getAuditLog(): MockRow[] {
    return this.auditLog;
  }
}

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

const ownerCtx: AdminContext = {
  userId: 1,
  tier: 'enterprise',
  csrfToken: 'valid-csrf-token',
  safetyFlags: { can_publish: true },
};

const adminCtx: AdminContext = {
  userId: 2,
  tier: 'pro',
  csrfToken: 'valid-csrf-token',
  safetyFlags: { can_publish: false },
};

const userCtx: AdminContext = {
  userId: 3,
  tier: 'basic',
  csrfToken: 'valid-csrf-token',
  safetyFlags: { can_publish: false },
};

describe('AdminSystem', () => {
  let pool: MockPool;
  let stripe: MockStripeClient;
  let email: MockEmailService;
  let admin: AdminSystem;

  beforeEach(() => {
    pool = new MockPool();
    stripe = new MockStripeClient();
    email = new MockEmailService();
    admin = new AdminSystem({
      pool: pool as unknown as import('mysql2/promise').Pool,
      stripe,
      email,
      priceMap: { free: 'price_free', basic: 'price_basic', pro: 'price_pro', enterprise: 'price_enterprise' },
    });

    // Seed owner user
    pool.seedUser({ email: 'owner@example.com', name: 'Owner', tier: 'enterprise', status: 'active' });
    // Seed admin user
    pool.seedUser({ email: 'admin@example.com', name: 'Admin', tier: 'pro', status: 'active' });
    // Seed regular user
    pool.seedUser({ email: 'user@example.com', name: 'User', tier: 'basic', status: 'active' });
  });

  // -- USERS DOMAIN ---------------------------------------------------------

  describe('createUser', () => {
    // ADMIN-01
    it('happy path: user created + invite sent', async () => {
      const result = await admin.createUser(ownerCtx, 'valid-csrf-token', {
        email: 'new@example.com',
        name: 'New User',
        tier: 'basic',
        notify: true,
      });

      expect(result.success).toBe(true);
      const res = result as { success: true; user_id: number; email: string; tier: string; created_at: string };
      expect(res.user_id).toBeGreaterThan(0);
      expect(res.email).toBe('new@example.com');
      expect(res.tier).toBe('basic');
      expect(res.created_at).toBeDefined();
      expect(email.invites.length).toBe(1);
      expect(email.invites[0].email).toBe('new@example.com');
    });

    // ADMIN-02
    it('duplicate email returns 409 email_exists', async () => {
      await expect(
        admin.createUser(ownerCtx, 'valid-csrf-token', {
          email: 'owner@example.com',
          name: 'Duplicate',
          tier: 'basic',
          notify: false,
        })
      ).rejects.toMatchObject({ code: 'email_exists', status: 409 });
    });

    // ADMIN-03
    it('non-owner returns 403 owner_only', async () => {
      await expect(
        admin.createUser(adminCtx, 'valid-csrf-token', {
          email: 'new@example.com',
          name: 'New User',
          tier: 'basic',
          notify: false,
        })
      ).rejects.toMatchObject({ code: 'owner_only', status: 403 });
    });
  });

  describe('resetPassword', () => {
    // ADMIN-04
    it('happy path: email sent', async () => {
      const result = await admin.resetPassword(ownerCtx, 'valid-csrf-token', { user_id: 2 });

      expect(result.success).toBe(true);
      expect((result as { status: string }).status).toBe('reset_email_sent');
      expect(email.resets.length).toBe(1);
      expect(email.resets[0].email).toBe('admin@example.com');
    });

    // ADMIN-05
    it('own account returns 400 cannot_reset_own_password', async () => {
      await expect(
        admin.resetPassword(ownerCtx, 'valid-csrf-token', { user_id: 1 })
      ).rejects.toMatchObject({ code: 'cannot_reset_own_password', status: 400 });
    });
  });

  describe('changeRole', () => {
    // ADMIN-06
    it('happy path: role changed + audit logged', async () => {
      const result = await admin.changeRole(ownerCtx, 'valid-csrf-token', { user_id: 2, new_tier: 'enterprise' });

      expect(result.success).toBe(true);
      expect(result.old_tier).toBe('pro');
      expect(result.new_tier).toBe('enterprise');
      expect(pool.getAuditLog().some((entry) => entry.action === 'role_changed')).toBe(true);
    });

    it('own account returns 400 cannot_change_own_role', async () => {
      await expect(
        admin.changeRole(ownerCtx, 'valid-csrf-token', { user_id: 1, new_tier: 'basic' })
      ).rejects.toMatchObject({ code: 'cannot_change_own_role', status: 400 });
    });

    /**
     * ADMIN-07: demoting the last active owner is 400 cannot_demote_last_owner and the tier is unchanged. Set up
     * as the other languages do: a second owner is added and the acting owner is then suspended, so the second
     * owner is the only ACTIVE owner. In: the mock pool. Out: assertions only. Why: ADMIN-07 had no test here.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: fakes only.
     */
    // ADMIN-07
    it('demoting the last active owner returns 400 cannot_demote_last_owner', async () => {
      const owner2 = pool.seedUser({ email: 'owner2@example.com', name: 'Owner 2', tier: 'enterprise', status: 'active' });
      await pool.execute("UPDATE users SET status = 'suspended' WHERE id = ?", [1]);
      await expect(
        admin.changeRole(ownerCtx, 'valid-csrf-token', { user_id: owner2, new_tier: 'basic' })
      ).rejects.toMatchObject({ code: 'cannot_demote_last_owner', status: 400 });
      const [rows] = await pool.execute('SELECT id, tier, status FROM users WHERE id = ?', [owner2]);
      expect(rows[0].tier).toBe('enterprise');
    });

    /**
     * ADMIN-03: the gate reads the caller's tier from the users table: a context that CLAIMS the owner tier for a
     * basic user is still 403 owner_only, and a wrong CSRF token is 403 csrf_mismatch. In: forged contexts.
     * Out: assertions only. Why: identity must come from the verified caller, never client-shaped input; the gate
     * used to trust ctx.tier. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: fakes only.
     */
    // ADMIN-03
    it('a context claiming owner for a basic user is refused; a wrong CSRF token is refused', async () => {
      const forged: AdminContext = { ...userCtx, tier: 'enterprise' };
      await expect(
        admin.changeRole(forged, 'valid-csrf-token', { user_id: 2, new_tier: 'basic' })
      ).rejects.toMatchObject({ code: 'owner_only', status: 403 });
      await expect(
        admin.changeRole(ownerCtx, 'valid-csrf-tokeX', { user_id: 2, new_tier: 'basic' })
      ).rejects.toMatchObject({ code: 'csrf_mismatch', status: 403 });
      await expect(
        admin.changeRole(ownerCtx, '', { user_id: 2, new_tier: 'basic' })
      ).rejects.toMatchObject({ code: 'csrf_mismatch', status: 403 });
    });
  });

  describe('suspendUser', () => {
    // ADMIN-08
    it('happy path: user suspended + audit logged', async () => {
      const result = await admin.suspendUser(ownerCtx, 'valid-csrf-token', { user_id: 3, reason: 'abuse' });

      expect(result).toMatchObject({ success: true, user_id: 3, suspended: true });
      expect(pool.getAuditLog().length).toBeGreaterThan(0);
    });

    // ADMIN-09
    it('own account returns 400 cannot_suspend_yourself', async () => {
      await expect(
        admin.suspendUser(ownerCtx, 'valid-csrf-token', { user_id: 1, reason: 'test' })
      ).rejects.toMatchObject({ code: 'cannot_suspend_yourself', status: 400 });
    });
  });

  // -- CUSTOMERS DOMAIN -----------------------------------------------------

  describe('customers', () => {
    // ADMIN-10
    it('list: pagination works and all fields are present', async () => {
      pool.seedCustomer({ email: 'one@example.com', name: 'One', tier: 'pro' });
      pool.seedCustomer({ email: 'two@example.com', name: 'Two', tier: 'basic' });
      pool.seedCustomer({ email: 'three@example.com', name: 'Three', tier: 'free' });

      const page = await admin.listCustomers(adminCtx, { limit: 2, offset: 0 });

      expect(page.total).toBe(3);
      expect(page.limit).toBe(2);
      expect(page.items).toHaveLength(2);
      expect(Object.keys(page.items[0])).toEqual(
        expect.arrayContaining(['customer_id', 'email', 'name', 'tier', 'signup_date', 'invoice_count', 'status'])
      );
      const rest = await admin.listCustomers(adminCtx, { limit: 2, offset: 2 });
      expect(rest.items).toHaveLength(1);
    });

    it('list refuses a user who is neither owner nor admin', async () => {
      await expect(admin.listCustomers(userCtx, {})).rejects.toBeInstanceOf(AdminError);
    });

    // ADMIN-11
    it('detail: all fields are present', async () => {
      const id = pool.seedCustomer({ email: 'one@example.com', name: 'One', tier: 'pro' });

      const detail = await admin.getCustomer(adminCtx, id);

      expect(detail).toMatchObject({ success: true, customer_id: id, email: 'one@example.com', tier: 'pro' });
    });

    // ADMIN-12
    it('changePlan: Stripe is called and the change is audited', async () => {
      const id = pool.seedCustomer({
        email: 'one@example.com', name: 'One', tier: 'basic', stripe_subscription_id: 'sub_123',
      });

      const result = await admin.changePlan(ownerCtx, 'valid-csrf-token', id, { new_tier: 'pro' });

      expect(result).toMatchObject({ success: true, customer_id: id, old_tier: 'basic', new_tier: 'pro' });
      expect(stripe.calls).toHaveLength(1);
      expect(stripe.calls[0].subscriptionId).toBe('sub_123');
      expect(stripe.calls[0].params.items[0].price).toBe('price_pro');
      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: ADMIN-12 amendment: the update names the existing item, so
      // Stripe replaces it instead of adding a second one, and prorates.
      expect(stripe.calls[0].params).toEqual({ items: [{ id: 'si_current', price: 'price_pro' }], proration_behavior: 'create_prorations' });
      expect(pool.getAuditLog().length).toBeGreaterThan(0);
    });

    /**
     * ADMIN-12: a subscription with zero or two items is 409 subscription_item_ambiguous and nothing is updated,
     * in Stripe or in the database; an unknown tier is 400 invalid_tier before Stripe is even read.
     * In: the fakes. Out: assertions only. Why: ADMIN-12 amendment (same rule as billing change_plan).
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: fakes only.
     */
    // ADMIN-12
    it('changePlan refuses an ambiguous subscription and an unknown tier before any update', async () => {
      const id = pool.seedCustomer({ email: 'one@example.com', name: 'One', tier: 'basic', stripe_subscription_id: 'sub_123' });
      await expect(
        admin.changePlan(ownerCtx, 'valid-csrf-token', id, { new_tier: 'platinum' })
      ).rejects.toMatchObject({ code: 'invalid_tier', status: 400 });
      expect(stripe.retrieved).toHaveLength(0);
      for (const items of [[], [{ id: 'si_a' }, { id: 'si_b' }]]) {
        stripe.items = items;
        await expect(
          admin.changePlan(ownerCtx, 'valid-csrf-token', id, { new_tier: 'pro' })
        ).rejects.toMatchObject({ code: 'subscription_item_ambiguous', status: 409 });
      }
      expect(stripe.calls).toHaveLength(0);
      expect((await admin.getCustomer(adminCtx, id)).tier).toBe('basic');
    });

    // ADMIN-13
    it('queueRefund: a refund record is created with status queued', async () => {
      const customerId = pool.seedCustomer({ email: 'one@example.com', name: 'One', tier: 'pro' });
      const invoiceId = pool.seedInvoice({ customer_id: customerId, amount: 100, status: 'succeeded' });

      const result = await admin.queueRefund(ownerCtx, 'valid-csrf-token', customerId, {
        invoice_id: invoiceId, amount: 50, reason: 'duplicate charge',
      });

      expect(result).toMatchObject({ success: true, status: 'queued', amount: 50 });
      expect(result.refund_id).toBeDefined();
    });
  });

  // -- DEPLOYMENTS DOMAIN ---------------------------------------------------

  describe('deployments', () => {
    // ADMIN-14
    it('createDeployment: the deployment and its config are created', async () => {
      const customerId = pool.seedCustomer({ email: 'one@example.com', name: 'One', tier: 'pro' });

      const result = await admin.createDeployment(ownerCtx, 'valid-csrf-token', {
        customer_id: customerId, domain: 'one.example.com', tier: 'pro', theme_id: 1,
      });

      expect(result).toMatchObject({ success: true, domain: 'one.example.com', tier: 'pro' });
      expect(result.deployment_id).toBeDefined();
    });

    // ADMIN-15
    it('publishDeployment: the double gate is checked and the status becomes live', async () => {
      const customerId = pool.seedCustomer({ email: 'one@example.com', name: 'One', tier: 'pro' });
      const id = pool.seedDeployment({
        customer_id: customerId, domain: 'one.example.com', tier: 'pro', domain_verified: 1, theme_id: 1,
      });

      const result = await admin.publishDeployment(ownerCtx, 'valid-csrf-token', { deployment_id: id });

      expect(result).toMatchObject({ success: true, deployment_id: id, status: 'live' });
    });

    it('publishDeployment refuses when the safety flag is off', async () => {
      const blocked: AdminContext = { ...ownerCtx, safetyFlags: { can_publish: false } };

      await expect(
        admin.publishDeployment(blocked, 'valid-csrf-token', { deployment_id: 1 })
      ).rejects.toMatchObject({ code: 'publish_not_allowed', status: 403 });
    });
  });

  // -- GOVERNANCE DOMAIN ----------------------------------------------------

  describe('decideGovernanceAction', () => {
    const seedAction = () =>
      pool.seedGovernanceAction({ action_type: 'refund', actor: 2, target_resource_id: 1, reason: 'requested' });

    // ADMIN-16
    it('approve: the action is executed and its status changes', async () => {
      // suspend_user has a handler, so the test can see the action really run (refund has none). From review.
      const id = pool.seedGovernanceAction({ action_type: 'suspend_user', actor: 2, target_resource_id: 3, reason: 'abuse' });

      const result = await admin.decideGovernanceAction(ownerCtx, 'valid-csrf-token', id, 'approve', {});

      expect(result).toMatchObject({ success: true, action_id: id, status: 'approved' });
      const target = (pool as unknown as { users: MockRow[] }).users.find((u) => u.id === 3);
      expect(target?.status).toBe('suspended');
    });

    // ADMIN-17
    it('reject: the action is rejected and the reason is kept', async () => {
      const id = seedAction();

      const result = await admin.decideGovernanceAction(ownerCtx, 'valid-csrf-token', id, 'reject', {
        reason: 'not allowed',
      });

      expect(result).toMatchObject({ success: true, action_id: id, status: 'rejected' });
    });

    it('a decided action cannot be decided again', async () => {
      const id = seedAction();
      await admin.decideGovernanceAction(ownerCtx, 'valid-csrf-token', id, 'approve', {});

      await expect(
        admin.decideGovernanceAction(ownerCtx, 'valid-csrf-token', id, 'reject', { reason: 'late' })
      ).rejects.toMatchObject({ code: 'action_not_pending', status: 400 });
    });
  });

  // -- AUDIT DOMAIN ---------------------------------------------------------

  describe('searchAuditLog', () => {
    // ADMIN-18
    it('applies its filters and pagination', async () => {
      await admin.suspendUser(ownerCtx, 'valid-csrf-token', { user_id: 3, reason: 'abuse' });
      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: changes user 3's role, not user 2's. The gate now reads the
      // caller's tier from the database, so demoting user 2 (the admin) and then searching AS user 2 is rightly
      // refused; the old gate trusted the context's stale 'pro'. The filters checked are unchanged.
      await admin.changeRole(ownerCtx, 'valid-csrf-token', { user_id: 3, new_tier: 'free' });
      const everything = await admin.searchAuditLog(adminCtx, {});
      expect(everything.total).toBeGreaterThanOrEqual(2);

      const filtered = await admin.searchAuditLog(adminCtx, { action_type: 'role_changed', limit: 1, offset: 0 });

      expect(filtered.limit).toBe(1);
      expect(filtered.items).toHaveLength(1);
      expect(filtered.items[0].action).toBe('role_changed');
    });
  });

  // -- SAFETY ---------------------------------------------------------------

  describe('invited users', () => {
    it('the one-time password is stored with a slow, salted hash, never in plain form', async () => {
      await admin.createUser(ownerCtx, 'valid-csrf-token', {
        email: 'invited@example.com', name: 'Invited', tier: 'basic', notify: true,
      });

      const stored = (pool as unknown as { users: MockRow[] }).users.find((u) => u.email === 'invited@example.com');
      const hash = String(stored?.password_hash ?? '');
      const sent = email.invites[email.invites.length - 1];
      expect(hash.startsWith('scrypt$')).toBe(true);
      expect(hash).not.toContain(sent.otp);
    });

    it('the console e-mail service never prints a password or a reset link', async () => {
      const printed = vi.spyOn(console, 'log').mockImplementation(() => undefined);

      const service = new ConsoleEmailService();
      await service.sendInvite('a@example.com', 'A', 'the-secret-password');
      await service.sendPasswordReset('a@example.com', 'https://example.com/reset?token=the-secret-token');

      const output = printed.mock.calls.flat().join(' ');
      printed.mockRestore();
      expect(output).toContain('a@example.com');
      expect(output).not.toContain('the-secret');
    });
  });
});
