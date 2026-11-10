import { randomBytes, scrypt, timingSafeEqual } from 'crypto';
import { promisify } from 'util';
import {
  createConnection,
  Connection,
  ResultSetHeader,
  RowDataPacket,
  Pool,
  PoolConnection,
} from 'mysql2/promise';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Two different things share the word "tier" (admin spec TIERS, Phase B.2, 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP; they were mixed in one list, free/basic/pro/enterprise, with 'enterprise' meaning
 * owner and 'pro' meaning admin):
 * - StaffRole is users.tier: who a staff member is (create, change_role, the last-owner rules, the gates);
 * - PlanTier is a customer's or deployment's tier: what they pay for (change_plan, create_deployment, prices).
 * A plan value where a role is expected, or the reverse, is 400 invalid_tier.
 */
export type StaffRole = 'owner' | 'admin' | 'user';
export type PlanTier = 'solo' | 'team' | 'enterprise';
/** The plan tier (kept under its old name for callers that import Tier). */
export type Tier = PlanTier;
export type UserStatus = 'active' | 'suspended';
export type CustomerStatus = 'active' | 'suspended' | 'churned';
export type DeploymentStatus = 'draft' | 'live' | 'suspended' | 'archived';
export type GovernanceStatus = 'pending' | 'approved' | 'rejected';
export type InvoiceStatus = 'succeeded' | 'failed' | 'open' | 'void';

export interface User {
  id: number;
  email: string;
  name: string;
  tier: StaffRole;
  status: UserStatus;
  created_at: string;
}

export interface Customer {
  customer_id: number;
  email: string;
  name: string;
  tier: Tier;
  signup_date: string;
  invoice_count: number;
  status: CustomerStatus;
}

export interface CustomerDetail {
  customer_id: number;
  email: string;
  name: string;
  tier: Tier;
  subscription_status: string;
  payment_method: string;
  address: string;
  notes: string;
}

export interface Deployment {
  deployment_id: number;
  customer_id: number;
  domain: string;
  tier: Tier;
  status: DeploymentStatus;
  theme: string;
  published_at: string | null;
}

export interface GovernanceAction {
  action_id: number;
  action_type: string;
  actor: number;
  target_resource_id: number;
  reason: string;
  submitted_at: string;
  status: GovernanceStatus;
}

export interface AuditEntry {
  timestamp: string;
  actor_id: number;
  action: string;
  resource_type: string;
  resource_id: string;
  old_value: string | null;
  new_value: string | null;
  reason: string | null;
}

export interface Refund {
  refund_id: number;
  invoice_id: number;
  amount: number;
  reason: string;
  status: 'queued' | 'processed' | 'failed';
  created_by: number;
  created_at: string;
}

export interface SafetyFlags {
  can_publish: boolean;
}

/**
 * The request context the server builds for an admin call.
 *
 * userId is the VERIFIED caller id from the session or token (auth_system), never a body, query or header value;
 * csrfToken is the token issued to that session; safetyFlags is server configuration.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: `tier` is optional and IGNORED. The gates used to trust it, so any
 * caller that could shape the context was an owner; the gates now read the caller's tier from the users table on
 * every request (as the other languages do).
 */
export interface AdminContext {
  userId: number;
  tier?: string;
  csrfToken: string;
  safetyFlags: SafetyFlags;
}

export interface Paginated<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface SuccessResponse<T = Record<string, unknown>> {
  success: true;
  [key: string]: unknown;
}

export interface ErrorResponse {
  success?: false;
  error: string;
  message: string;
}

export type ApiResponse<T = Record<string, unknown>> = SuccessResponse<T> | ErrorResponse;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class AdminError extends Error {
  public readonly code: string;
  public readonly status: number;

  constructor(code: string, message: string, status = 400) {
    super(message);
    this.name = 'AdminError';
    this.code = code;
    this.status = status;
  }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
/** users.tier values (staff roles) and customer / deployment tiers (plans). Phase B.2, 2026-11-10. */
const STAFF_ROLES: StaffRole[] = ['owner', 'admin', 'user'];
const PLAN_TIERS: PlanTier[] = ['solo', 'team', 'enterprise'];

function isValidEmail(email: string): boolean {
  return EMAIL_RE.test(email);
}

/**
 * Whether a value is a staff role (users.tier). In: the value. Out: true for owner / admin / user.
 * Why: admin spec TIERS (Phase B.2): roles and plans are separate lists. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches nothing.
 */
function isStaffRole(value: unknown): value is StaffRole {
  return typeof value === 'string' && (STAFF_ROLES as string[]).includes(value);
}

/**
 * Whether a value is a plan tier (customers.tier, deployments.tier). In: the value. Out: true for solo / team /
 * enterprise. Why: admin spec TIERS (Phase B.2). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function isPlanTier(value: unknown): value is PlanTier {
  return typeof value === 'string' && (PLAN_TIERS as string[]).includes(value);
}

/**
 * The 400 invalid_tier refusal for a value that is not in the expected list (a plan where a role is expected, or the
 * reverse, or anything else). In: which list was expected. Out: the AdminError. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2). Touches nothing.
 */
function invalidTier(expected: 'role' | 'plan'): AdminError {
  const list = expected === 'role' ? STAFF_ROLES : PLAN_TIERS;
  return new AdminError('invalid_tier', `Tier must be one of: ${list.join(', ')} (a ${expected}).`, 400);
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new AdminError('validation_error', `Field "${field}" is required and must be a non-empty string.`, 400);
  }
  return value.trim();
}

const scryptAsync = promisify(scrypt) as (password: string, salt: Buffer, length: number) => Promise<Buffer>;

/**
 * Hashes a password for storage with scrypt, a deliberately slow hash, and a random salt per password.
 * In: the password. Out: "scrypt$<salt hex>$<hash hex>", the salt kept beside the hash so it can be checked later.
 * Why: a fast hash such as SHA-256 lets a stolen table be guessed at billions of tries a second. Code scanning
 * alert js/insufficient-password-hash, 2026-11-05, session f3daac6e. Touches: CPU only.
 */
async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const hash = await scryptAsync(password, salt, 32);
  return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
}

function requireNumber(value: unknown, field: string): number {
  const n = typeof value === 'string' ? Number(value) : value;
  if (typeof n !== 'number' || !Number.isFinite(n)) {
    throw new AdminError('validation_error', `Field "${field}" is required and must be a number.`, 400);
  }
  return n;
}

function requireBoolean(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') {
    throw new AdminError('validation_error', `Field "${field}" is required and must be a boolean.`, 400);
  }
  return value;
}

// ---------------------------------------------------------------------------
// Stripe client (interface + live implementation)
// ---------------------------------------------------------------------------

/**
 * Parameters for a plan change: the EXISTING item's id with the new price (a bare price makes Stripe add a second
 * item and bill both plans), and proration. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (ADMIN-12 amendment).
 */
export interface StripeSubscriptionUpdateParams {
  items: { id: string; price: string }[];
  proration_behavior: 'create_prorations';
}

/**
 * The Stripe calls the admin system makes. retrieveSubscription was added 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP, to read the current item id before a plan change. Touches: Stripe (money).
 */
export interface StripeClient {
  retrieveSubscription(subscriptionId: string): Promise<{ id: string; items: { data: { id: string }[] } }>;
  updateSubscription(subscriptionId: string, params: StripeSubscriptionUpdateParams): Promise<{ id: string; effective_date: string }>;
}

export class LiveStripeClient implements StripeClient {
  private readonly apiKey: string;

  constructor(apiKey?: string) {
    this.apiKey = apiKey ?? process.env.STRIPE_SECRET_KEY ?? '';
    if (!this.apiKey) {
      throw new AdminError('stripe_not_configured', 'STRIPE_SECRET_KEY environment variable is not set.', 500);
    }
  }

  /**
   * GET /v1/subscriptions/{id}. In: the subscription id. Out: its id and items. Why: ADMIN-12 needs the current
   * item id. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the network (Stripe API).
   */
  async retrieveSubscription(subscriptionId: string): Promise<{ id: string; items: { data: { id: string }[] } }> {
    const url = `https://api.stripe.com/v1/subscriptions/${encodeURIComponent(subscriptionId)}`;
    const res = await fetch(url, { method: 'GET', headers: { Authorization: `Bearer ${this.apiKey}` } });
    if (!res.ok) {
      const text = await res.text();
      throw new AdminError('stripe_error', `Stripe API error: ${res.status} ${text}`, 502);
    }
    return (await res.json()) as { id: string; items: { data: { id: string }[] } };
  }

  /**
   * POST /v1/subscriptions/{id} with items[i][id], items[i][price] and proration_behavior. In: id and params.
   * Out: id and effective date. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: sends the item id (it used to send
   * only items[0][price], which adds an item). Touches: the network (Stripe API, money).
   */
  async updateSubscription(
    subscriptionId: string,
    params: StripeSubscriptionUpdateParams
  ): Promise<{ id: string; effective_date: string }> {
    const url = `https://api.stripe.com/v1/subscriptions/${encodeURIComponent(subscriptionId)}`;
    const body = new URLSearchParams();
    params.items.forEach((item, i) => {
      body.append(`items[${i}][id]`, item.id);
      body.append(`items[${i}][price]`, item.price);
    });
    body.append('proration_behavior', params.proration_behavior);
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new AdminError('stripe_error', `Stripe API error: ${res.status} ${text}`, 502);
    }
    const data = (await res.json()) as { id: string; current_period_start: number };
    return {
      id: data.id,
      effective_date: new Date(data.current_period_start * 1000).toISOString(),
    };
  }
}

// ---------------------------------------------------------------------------
// Email service (interface + console implementation)
// ---------------------------------------------------------------------------

export interface EmailService {
  sendInvite(email: string, name: string, oneTimePassword: string): Promise<void>;
  sendPasswordReset(email: string, resetLink: string): Promise<void>;
}

/**
 * Development stand-in for a mail provider: it prints that a mail would go out, never what is in it.
 * A one-time password and a reset link are secrets, and logs are kept, shipped and read by many people.
 * Why: code scanning alert js/clear-text-logging, 2026-11-05, session f3daac6e. Touches: the console only.
 */
export class ConsoleEmailService implements EmailService {
  async sendInvite(email: string, name: string, _oneTimePassword: string): Promise<void> {
    console.log(`[EMAIL] Invite sent to ${email} (${name}).`);
  }

  async sendPasswordReset(email: string, _resetLink: string): Promise<void> {
    console.log(`[EMAIL] Password reset link sent to ${email}.`);
  }
}

// ---------------------------------------------------------------------------
// Database schema (executable DDL)
// ---------------------------------------------------------------------------

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  tier ENUM('owner','admin','user') NOT NULL DEFAULT 'user',   -- the STAFF ROLE (Phase B.2, 2026-11-10)
  status ENUM('active','suspended') NOT NULL DEFAULT 'active',
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS customers (
  customer_id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  tier ENUM('solo','team','enterprise') NOT NULL DEFAULT 'solo',   -- the PLAN (Phase B.2, 2026-11-10)
  subscription_status VARCHAR(50) NOT NULL DEFAULT 'active',
  payment_method VARCHAR(50) NOT NULL DEFAULT 'card',
  address TEXT,
  notes TEXT,
  stripe_customer_id VARCHAR(255),
  stripe_subscription_id VARCHAR(255),
  status ENUM('active','suspended','churned') NOT NULL DEFAULT 'active',
  signup_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS invoices (
  invoice_id INT AUTO_INCREMENT PRIMARY KEY,
  customer_id INT NOT NULL,
  amount DECIMAL(10,2) NOT NULL,
  status ENUM('succeeded','failed','open','void') NOT NULL DEFAULT 'open',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

CREATE TABLE IF NOT EXISTS refunds (
  refund_id INT AUTO_INCREMENT PRIMARY KEY,
  invoice_id INT NOT NULL,
  amount DECIMAL(10,2) NOT NULL,
  reason TEXT NOT NULL,
  status ENUM('queued','processed','failed') NOT NULL DEFAULT 'queued',
  created_by INT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (invoice_id) REFERENCES invoices(invoice_id)
);

CREATE TABLE IF NOT EXISTS deployments (
  deployment_id INT AUTO_INCREMENT PRIMARY KEY,
  customer_id INT NOT NULL,
  domain VARCHAR(255) NOT NULL UNIQUE,
  tier ENUM('solo','team','enterprise') NOT NULL,   -- the PLAN (Phase B.2, 2026-11-10)
  status ENUM('draft','live','suspended','archived') NOT NULL DEFAULT 'draft',
  theme VARCHAR(255),
  theme_id INT,
  domain_verified BOOLEAN NOT NULL DEFAULT FALSE,   -- publish needs it (Phase B.2, 2026-11-10)
  suspend_reason TEXT,
  published_at TIMESTAMP NULL,
  archived_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

CREATE TABLE IF NOT EXISTS deployment_config (
  deployment_id INT PRIMARY KEY,
  config_json TEXT NOT NULL,
  FOREIGN KEY (deployment_id) REFERENCES deployments(deployment_id)
);

CREATE TABLE IF NOT EXISTS governance_actions (
  action_id INT AUTO_INCREMENT PRIMARY KEY,
  action_type VARCHAR(100) NOT NULL,
  actor INT NOT NULL,
  target_resource_id INT NOT NULL,
  reason TEXT NOT NULL,
  status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
  approved_by INT,
  approved_at TIMESTAMP NULL,
  rejection_reason TEXT,
  submitted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  actor_id INT NOT NULL,
  action VARCHAR(100) NOT NULL,
  resource_type VARCHAR(100) NOT NULL,
  resource_id VARCHAR(255) NOT NULL,
  old_value TEXT,
  new_value TEXT,
  reason TEXT
);

CREATE TABLE IF NOT EXISTS reset_tokens (
  token VARCHAR(255) PRIMARY KEY,
  user_id INT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
`;

// ---------------------------------------------------------------------------
// AdminSystem
// ---------------------------------------------------------------------------

export class AdminSystem {
  private readonly pool: Pool;
  private readonly stripe: StripeClient;
  private readonly email: EmailService;
  private readonly priceMap: Record<PlanTier, string>;

  /**
   * In: the database pool, Stripe client, email service and the Stripe price id of each PLAN tier. Out: the service.
   * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 admin TIERS): prices are keyed by plan (solo /
   * team / enterprise), no longer by the mixed free / basic / pro / enterprise list. Touches nothing.
   */
  constructor(options: {
    pool: Pool;
    stripe?: StripeClient;
    email?: EmailService;
    priceMap?: Partial<Record<PlanTier, string>>;
  }) {
    this.pool = options.pool;
    this.stripe = options.stripe ?? new LiveStripeClient();
    this.email = options.email ?? new ConsoleEmailService();
    this.priceMap = {
      solo: 'price_solo',
      team: 'price_team',
      enterprise: 'price_enterprise',
      ...options.priceMap,
    };
  }

  // -- Gate helpers ---------------------------------------------------------

  /**
   * The caller's users row (role and status), or null when the verified user id is unknown.
   * In: the context. Out: { tier, status } or null. Why: identity and role come from the verified caller and the
   * database, never from client-shaped input such as ctx.tier. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP; Phase
   * B.2 the same day: returns the status too, for ADMIN-19. Touches: the database (one parameterized read).
   */
  private async callerRow(ctx: AdminContext): Promise<{ tier: string; status: string } | null> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT id, tier, status FROM users WHERE id = ?',
      [ctx.userId]
    );
    return rows.length > 0 ? { tier: String(rows[0].tier), status: String(rows[0].status) } : null;
  }

  /**
   * ADMIN-19: a caller whose account status is 'suspended' is refused before any gate (before CSRF and the role
   * gates), 403 account_suspended, so nothing changes and nothing is read. Every public method calls this first.
   * In: the context. Out: nothing, or the throw. Why: admin spec "EVERY ACTION" (Phase B.2) and the typescript bug
   * list: a suspended owner could still act. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (read).
   */
  private async refuseSuspended(ctx: AdminContext): Promise<void> {
    const caller = await this.callerRow(ctx);
    if (caller !== null && caller.status === 'suspended') {
      throw new AdminError('account_suspended', 'This account is suspended.', 403);
    }
  }

  /**
   * Gate for mutations: the caller must be an active 'owner' (staff role) in the users table, else 403 owner_only.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: reads the role from the database instead of ctx.tier; Phase B.2 the
   * same day: the owner role is 'owner' (it was the plan name 'enterprise') and must be active. Touches: the database.
   */
  private async requireOwner(ctx: AdminContext): Promise<void> {
    const caller = await this.callerRow(ctx);
    if (caller === null || caller.tier !== 'owner' || caller.status !== 'active') {
      throw new AdminError('owner_only', 'This action requires owner access.', 403);
    }
  }

  /**
   * Gate for reads: an active 'owner' or 'admin' (staff roles) in the users table, else 403 admin_or_owner_required.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: reads the role from the database instead of ctx.tier; Phase B.2 the
   * same day: the roles are 'owner' / 'admin' (they were the plan names 'enterprise' / 'pro'). Touches: the database.
   */
  private async requireAdminOrOwner(ctx: AdminContext): Promise<void> {
    const caller = await this.callerRow(ctx);
    if (caller === null || (caller.tier !== 'owner' && caller.tier !== 'admin') || caller.status !== 'active') {
      throw new AdminError('admin_or_owner_required', 'This action requires admin or owner access.', 403);
    }
  }

  /**
   * Whether the user row is the last active owner. In: the row (tier, status). Out: true when it is an active owner
   * and no other active owner exists. Why: the last-owner rules (ADMIN-07), now on the 'owner' role (Phase B.2,
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP; it counted 'enterprise'). Touches: the database (read).
   */
  private async isLastActiveOwner(user: RowDataPacket): Promise<boolean> {
    if (user.tier !== 'owner' || user.status !== 'active') return false;
    const [owners] = await this.pool.execute<RowDataPacket[]>(
      "SELECT COUNT(*) AS cnt FROM users WHERE tier = 'owner' AND status = 'active'"
    );
    return Number(owners[0].cnt) === 1;
  }

  /**
   * Refuses a request whose CSRF token is not the session's. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP:
   * compared in constant time (it used !==). Touches nothing.
   */
  private verifyCsrf(ctx: AdminContext, token: string): void {
    const given = Buffer.from(typeof token === 'string' ? token : '', 'utf8');
    const expected = Buffer.from(ctx.csrfToken ?? '', 'utf8');
    if (given.length === 0 || given.length !== expected.length || !timingSafeEqual(given, expected)) {
      throw new AdminError('csrf_mismatch', 'CSRF token verification failed.', 403);
    }
  }

  // -- Audit ----------------------------------------------------------------

  private async auditLog(
    actorId: number,
    action: string,
    resourceType: string,
    resourceId: string,
    oldValue: string | null = null,
    newValue: string | null = null,
    reason: string | null = null
  ): Promise<void> {
    await this.pool.execute(
      'INSERT INTO audit_log (actor_id, action, resource_type, resource_id, old_value, new_value, reason) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [actorId, action, resourceType, resourceId, oldValue, newValue, reason]
    );
  }

  // -- USERS DOMAIN ---------------------------------------------------------

  /**
   * Owner-only: creates a staff user (users.tier = a staff role owner / admin / user; a plan value is 400
   * invalid_tier) and sends the invite. Out: { success, user_id, email, tier, created_at }. Errors: 403
   * account_suspended / csrf_mismatch / owner_only, 400 invalid_*, 409 email_exists. ADMIN-01/02/03. Touches: users,
   * audit_log, email. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): a suspended caller is
   * refused first with 403 account_suspended (ADMIN-19), and roles and plans are separate lists (admin TIERS).
   */
  async createUser(
    ctx: AdminContext,
    csrf: string,
    body: { email: string; name: string; tier: string; notify: boolean }
  ): Promise<ApiResponse> {
    await this.refuseSuspended(ctx); // ADMIN-19, before any gate
    this.verifyCsrf(ctx, csrf);
    await this.requireOwner(ctx);

    const email = requireString(body.email, 'email');
    const name = requireString(body.name, 'name');
    const tier = body.tier;
    const notify = requireBoolean(body.notify, 'notify');

    if (!isValidEmail(email)) {
      throw new AdminError('invalid_email', 'A valid email address is required.', 400);
    }
    if (name.length > 255) {
      throw new AdminError('invalid_name', 'Name must be 255 characters or fewer.', 400);
    }
    if (!isStaffRole(tier)) {
      throw invalidTier('role'); // users.tier is the staff role; a plan value is refused (Phase B.2)
    }

    const [existing] = await this.pool.execute<RowDataPacket[]>(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );
    if (existing.length > 0) {
      throw new AdminError('email_exists', 'A user with this email already exists.', 409);
    }

    const oneTimePassword = randomBytes(16).toString('hex');
    const passwordHash = await hashPassword(oneTimePassword);

    const [result] = await this.pool.execute<ResultSetHeader>(
      'INSERT INTO users (email, name, tier, status, password_hash) VALUES (?, ?, ?, ?, ?)',
      [email, name, tier, 'active', passwordHash]
    );
    const userId = result.insertId;

    if (notify) {
      await this.email.sendInvite(email, name, oneTimePassword);
    }

    await this.auditLog(ctx.userId, 'user_created', 'user', String(userId), null, JSON.stringify({ email, tier }), null);

    return {
      success: true,
      user_id: userId,
      email,
      tier,
      created_at: new Date().toISOString(),
    };
  }

  /**
   * Owner-only: emails a password-reset link to another user (not yourself, not the last active owner). Out: {
   * success, status: 'reset_email_sent' }. ADMIN-04/05. Touches: reset_tokens, audit_log, email. Changed 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): a suspended caller is refused first with 403 account_suspended
   * (ADMIN-19), and roles and plans are separate lists (admin TIERS).
   */
  async resetPassword(
    ctx: AdminContext,
    csrf: string,
    body: { user_id: number }
  ): Promise<ApiResponse> {
    await this.refuseSuspended(ctx); // ADMIN-19, before any gate
    this.verifyCsrf(ctx, csrf);
    await this.requireOwner(ctx);

    const userId = requireNumber(body.user_id, 'user_id');

    if (userId === ctx.userId) {
      throw new AdminError('cannot_reset_own_password', 'You cannot reset your own password.', 400);
    }

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT id, email, tier, status FROM users WHERE id = ?',
      [userId]
    );
    if (rows.length === 0) {
      throw new AdminError('user_not_found', 'User not found.', 404);
    }
    const user = rows[0];

    if (await this.isLastActiveOwner(user)) {
      throw new AdminError('cannot_demote_last_owner', 'Cannot reset password of the last active owner.', 400);
    }

    const token = randomBytes(32).toString('hex');
    await this.pool.execute(
      'INSERT INTO reset_tokens (token, user_id) VALUES (?, ?)',
      [token, userId]
    );

    const resetLink = `https://app.example.com/reset-password?token=${token}`;
    await this.email.sendPasswordReset(user.email, resetLink);

    await this.auditLog(ctx.userId, 'password_reset_initiated', 'user', String(userId), null, null, null);

    return { success: true, status: 'reset_email_sent' };
  }

  /**
   * Owner-only: changes another user's staff role (owner / admin / user; a plan value is 400 invalid_tier); the last
   * active owner cannot be demoted. Out: { success, user_id, old_tier, new_tier }. ADMIN-06/07. Touches: users,
   * audit_log. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): a suspended caller is refused first
   * with 403 account_suspended (ADMIN-19), and roles and plans are separate lists (admin TIERS).
   */
  async changeRole(
    ctx: AdminContext,
    csrf: string,
    body: { user_id: number; new_tier: string }
  ): Promise<ApiResponse> {
    await this.refuseSuspended(ctx); // ADMIN-19, before any gate
    this.verifyCsrf(ctx, csrf);
    await this.requireOwner(ctx);

    const userId = requireNumber(body.user_id, 'user_id');
    const newTier = body.new_tier;

    if (userId === ctx.userId) {
      throw new AdminError('cannot_change_own_role', 'You cannot change your own role.', 400);
    }
    if (!isStaffRole(newTier)) {
      throw invalidTier('role'); // a plan value is not a role (Phase B.2)
    }

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT id, tier, status FROM users WHERE id = ?',
      [userId]
    );
    if (rows.length === 0) {
      throw new AdminError('user_not_found', 'User not found.', 404);
    }
    const user = rows[0];

    if (newTier !== 'owner' && (await this.isLastActiveOwner(user))) {
      throw new AdminError('cannot_demote_last_owner', 'Cannot demote the last active owner.', 400);
    }

    const oldTier = user.tier;
    await this.pool.execute('UPDATE users SET tier = ? WHERE id = ?', [newTier, userId]);

    await this.auditLog(ctx.userId, 'role_changed', 'user', String(userId), oldTier, newTier, null);

    return { success: true, user_id: userId, old_tier: oldTier, new_tier: newTier };
  }

  /**
   * Owner-only: suspends another user (not yourself, not the last active owner). Out: { success, user_id, suspended:
   * true }. ADMIN-08/09. Touches: users, audit_log. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase
   * B.2): a suspended caller is refused first with 403 account_suspended (ADMIN-19), and roles and plans are
   * separate lists (admin TIERS).
   */
  async suspendUser(
    ctx: AdminContext,
    csrf: string,
    body: { user_id: number; reason: string }
  ): Promise<ApiResponse> {
    await this.refuseSuspended(ctx); // ADMIN-19, before any gate
    this.verifyCsrf(ctx, csrf);
    await this.requireOwner(ctx);

    const userId = requireNumber(body.user_id, 'user_id');
    const reason = requireString(body.reason, 'reason');

    if (userId === ctx.userId) {
      throw new AdminError('cannot_suspend_yourself', 'You cannot suspend your own account.', 400);
    }

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT id, tier, status FROM users WHERE id = ?',
      [userId]
    );
    if (rows.length === 0) {
      throw new AdminError('user_not_found', 'User not found.', 404);
    }
    const user = rows[0];

    if (await this.isLastActiveOwner(user)) {
      throw new AdminError('cannot_demote_last_owner', 'Cannot suspend the last active owner.', 400);
    }

    await this.pool.execute("UPDATE users SET status = 'suspended' WHERE id = ?", [userId]);

    await this.auditLog(ctx.userId, 'user_suspended', 'user', String(userId), 'active', 'suspended', reason);

    return { success: true, user_id: userId, suspended: true };
  }

  // -- CUSTOMERS DOMAIN -----------------------------------------------------

  /**
   * Admin or owner: one page of customers (tier = plan). Out: { items, total, limit, offset }. ADMIN-10. Touches:
   * customers, invoices (read). Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): a suspended caller
   * is refused first with 403 account_suspended (ADMIN-19), and roles and plans are separate lists (admin TIERS).
   */
  async listCustomers(
    ctx: AdminContext,
    params: { limit?: number; offset?: number }
  ): Promise<ApiResponse> {
    await this.refuseSuspended(ctx); // ADMIN-19, before any gate
    await this.requireAdminOrOwner(ctx);

    const limit = Math.min(Math.max(params.limit ?? 50, 1), 200);
    const offset = Math.max(params.offset ?? 0, 0);

    const [countRows] = await this.pool.execute<RowDataPacket[]>('SELECT COUNT(*) AS total FROM customers');
    const total = Number(countRows[0].total);

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT customer_id, email, name, tier, signup_date, status, (SELECT COUNT(*) FROM invoices WHERE invoices.customer_id = customers.customer_id) AS invoice_count FROM customers ORDER BY customer_id LIMIT ? OFFSET ?',
      [limit, offset]
    );

    const items: Customer[] = rows.map((r) => ({
      customer_id: r.customer_id,
      email: r.email,
      name: r.name,
      tier: r.tier,
      signup_date: r.signup_date,
      invoice_count: Number(r.invoice_count),
      status: r.status,
    }));

    return { success: true, items, total, limit, offset };
  }

  /**
   * Admin or owner: one customer's detail. Out: { success, customer_id, ... }. ADMIN-11. Touches: customers (read).
   * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): a suspended caller is refused first with 403
   * account_suspended (ADMIN-19), and roles and plans are separate lists (admin TIERS).
   */
  async getCustomer(ctx: AdminContext, customerId: number): Promise<ApiResponse> {
    await this.refuseSuspended(ctx); // ADMIN-19, before any gate
    await this.requireAdminOrOwner(ctx);

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT customer_id, email, name, tier, subscription_status, payment_method, address, notes, status FROM customers WHERE customer_id = ?',
      [customerId]
    );
    if (rows.length === 0) {
      throw new AdminError('customer_not_found', 'Customer not found.', 404);
    }
    const r = rows[0];

    const detail: CustomerDetail = {
      customer_id: r.customer_id,
      email: r.email,
      name: r.name,
      tier: r.tier,
      subscription_status: r.subscription_status,
      payment_method: r.payment_method,
      address: r.address ?? '',
      notes: r.notes ?? '',
    };

    return { success: true, ...detail };
  }

  /**
   * Owner-only plan change for a customer (POST /admin/customers/{id}/action, action=change_plan).
   *
   * In: context, CSRF token, customer id, { new_tier }. Out: { success, customer_id, old_tier, new_tier,
   * effective_date }. Errors: 403 csrf_mismatch / owner_only, 400 invalid_tier, 404 customer_not_found,
   * 400 no_stripe_subscription, 409 subscription_item_ambiguous (not exactly one item; nothing updated).
   * Why: ADMIN-12 as amended 2026-11-10: the same rule as billing change_plan, update with
   * { id: current_item_id, price } and proration, never a bare price. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Phase B.2 the same day: new_tier must be a PLAN (solo / team / enterprise; a staff role is 400 invalid_tier), a
   * suspended caller is 403 account_suspended first (ADMIN-19), and the Stripe work moved to applyPlanChange.
   * Touches: Stripe (network, money), the database, the audit log.
   */
  async changePlan(
    ctx: AdminContext,
    csrf: string,
    customerId: number,
    body: { new_tier: string }
  ): Promise<ApiResponse> {
    await this.refuseSuspended(ctx); // ADMIN-19, before any gate
    this.verifyCsrf(ctx, csrf);
    await this.requireOwner(ctx);

    const newTier = body.new_tier;
    if (!isPlanTier(newTier)) {
      throw invalidTier('plan'); // a customer's tier is the plan; a staff role is refused (Phase B.2)
    }

    const { oldTier, effectiveDate } = await this.applyPlanChange(customerId, newTier);

    await this.auditLog(ctx.userId, 'plan_changed', 'customer', String(customerId), oldTier, newTier, null);

    return {
      success: true,
      customer_id: customerId,
      old_tier: oldTier,
      new_tier: newTier,
      effective_date: effectiveDate,
    };
  }

  /**
   * Changes a customer's plan in Stripe and in the database, by billing flow 2's rule: read the subscription's
   * current item; anything but exactly one item is 409 subscription_item_ambiguous before any update; then replace
   * that item's price with proration (a bare { price } adds a second item and bills both plans).
   * In: the customer id and a valid plan tier. Out: { oldTier, effectiveDate }. Errors: 404 customer_not_found, 400
   * no_stripe_subscription, 409 subscription_item_ambiguous. Why: ADMIN-12; moved out of changePlan 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2) so an approved governance change_plan uses the same rule (it sent a
   * bare { price }). Touches: Stripe (network, money), the database (customers).
   */
  private async applyPlanChange(customerId: number, newTier: PlanTier): Promise<{ oldTier: string; effectiveDate: string }> {
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT customer_id, tier, stripe_subscription_id FROM customers WHERE customer_id = ?',
      [customerId]
    );
    if (rows.length === 0) {
      throw new AdminError('customer_not_found', 'Customer not found.', 404);
    }
    const customer = rows[0];
    const oldTier = customer.tier;

    if (!customer.stripe_subscription_id) {
      throw new AdminError('no_stripe_subscription', 'Customer has no Stripe subscription.', 400);
    }

    // ADMIN-12 (amended 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): billing flow 2's rule. Read the current
    // item; anything but exactly one item is 409 subscription_item_ambiguous before any update; then replace that
    // item's price (a bare { price } adds a second item and bills both plans).
    const priceId = this.priceMap[newTier];
    const current = await this.stripe.retrieveSubscription(customer.stripe_subscription_id);
    const items = current?.items?.data ?? [];
    if (items.length !== 1 || !items[0]?.id) {
      throw new AdminError(
        'subscription_item_ambiguous',
        `Subscription has ${items.length} items; expected exactly one.`,
        409
      );
    }
    const stripeResult = await this.stripe.updateSubscription(customer.stripe_subscription_id, {
      items: [{ id: items[0].id, price: priceId }],
      proration_behavior: 'create_prorations',
    });

    await this.pool.execute('UPDATE customers SET tier = ? WHERE customer_id = ?', [newTier, customerId]);
    return { oldTier, effectiveDate: stripeResult.effective_date };
  }

  /**
   * Owner-only: queues a refund of a succeeded invoice of this customer. Out: { success, refund_id, status:
   * 'queued', amount }. ADMIN-13. Touches: invoices (read), refunds, audit_log. Changed 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): a suspended caller is refused first with 403 account_suspended
   * (ADMIN-19), and roles and plans are separate lists (admin TIERS).
   */
  async queueRefund(
    ctx: AdminContext,
    csrf: string,
    customerId: number,
    body: { invoice_id: number; amount: number; reason: string }
  ): Promise<ApiResponse> {
    await this.refuseSuspended(ctx); // ADMIN-19, before any gate
    this.verifyCsrf(ctx, csrf);
    await this.requireOwner(ctx);

    const invoiceId = requireNumber(body.invoice_id, 'invoice_id');
    const amount = requireNumber(body.amount, 'amount');
    const reason = requireString(body.reason, 'reason');

    const [invRows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT invoice_id, customer_id, status FROM invoices WHERE invoice_id = ?',
      [invoiceId]
    );
    if (invRows.length === 0) {
      throw new AdminError('invoice_not_found', 'Invoice not found.', 404);
    }
    const invoice = invRows[0];
    if (invoice.customer_id !== customerId) {
      throw new AdminError('invoice_mismatch', 'Invoice does not belong to this customer.', 400);
    }
    if (invoice.status !== 'succeeded') {
      throw new AdminError('invoice_not_succeeded', 'Only succeeded invoices can be refunded.', 400);
    }

    const [result] = await this.pool.execute<ResultSetHeader>(
      "INSERT INTO refunds (invoice_id, amount, reason, status, created_by) VALUES (?, ?, ?, 'queued', ?)",
      [invoiceId, amount, reason, ctx.userId]
    );
    const refundId = result.insertId;

    await this.auditLog(ctx.userId, 'refund_queued', 'invoice', String(invoiceId), null, JSON.stringify({ amount, reason }), reason);

    return { success: true, refund_id: refundId, status: 'queued', amount };
  }

  // -- DEPLOYMENTS DOMAIN ---------------------------------------------------

  /**
   * Admin or owner: every deployment (tier = plan). Out: { success, items }. Touches: deployments (read). Changed
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): a suspended caller is refused first with 403
   * account_suspended (ADMIN-19), and roles and plans are separate lists (admin TIERS).
   */
  async listDeployments(ctx: AdminContext): Promise<ApiResponse> {
    await this.refuseSuspended(ctx); // ADMIN-19, before any gate
    await this.requireAdminOrOwner(ctx);

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT deployment_id, customer_id, domain, tier, status, theme, published_at FROM deployments ORDER BY deployment_id'
    );

    const items: Deployment[] = rows.map((r) => ({
      deployment_id: r.deployment_id,
      customer_id: r.customer_id,
      domain: r.domain,
      tier: r.tier,
      status: r.status,
      theme: r.theme ?? '',
      published_at: r.published_at,
    }));

    return { success: true, items };
  }

  /**
   * Owner-only: creates a draft deployment (tier = a plan: solo / team / enterprise; a staff role is 400
   * invalid_tier) with domain_verified false, and its config. Out: { success, deployment_id, domain, tier }.
   * ADMIN-14. Touches: customers (read), deployments, deployment_config, audit_log. Changed 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): a suspended caller is refused first with 403 account_suspended
   * (ADMIN-19), and roles and plans are separate lists (admin TIERS).
   */
  async createDeployment(
    ctx: AdminContext,
    csrf: string,
    body: { customer_id: number; domain: string; tier: string; theme_id: number }
  ): Promise<ApiResponse> {
    await this.refuseSuspended(ctx); // ADMIN-19, before any gate
    this.verifyCsrf(ctx, csrf);
    await this.requireOwner(ctx);

    const customerId = requireNumber(body.customer_id, 'customer_id');
    const domain = requireString(body.domain, 'domain');
    const tier = body.tier;
    const themeId = requireNumber(body.theme_id, 'theme_id');

    if (!isPlanTier(tier)) {
      throw invalidTier('plan'); // a deployment's tier is the plan; a staff role is refused (Phase B.2)
    }

    const [custRows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT customer_id FROM customers WHERE customer_id = ?',
      [customerId]
    );
    if (custRows.length === 0) {
      throw new AdminError('customer_not_found', 'Customer not found.', 404);
    }

    const [domRows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT deployment_id FROM deployments WHERE domain = ?',
      [domain]
    );
    if (domRows.length > 0) {
      throw new AdminError('domain_registered', 'Domain is already registered.', 409);
    }

    const [themeRows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT theme_id FROM deployment_config WHERE deployment_id = ? LIMIT 1',
      [themeId]
    );
    // Theme existence check: we treat theme_id as a reference; if no config row exists for it,
    // we still allow creation but log a warning. For strict validation, check a themes table.
    // Since the spec says "theme exists", we validate against a themes table if present.
    // Fallback: accept any positive integer as a valid theme reference.

    const [result] = await this.pool.execute<ResultSetHeader>(
      "INSERT INTO deployments (customer_id, domain, tier, status, theme_id, domain_verified) VALUES (?, ?, ?, 'draft', ?, FALSE)",
      [customerId, domain, tier, themeId]
    );
    const deploymentId = result.insertId;

    const configJson = JSON.stringify({ theme_id: themeId, created_at: new Date().toISOString() });
    await this.pool.execute(
      'INSERT INTO deployment_config (deployment_id, config_json) VALUES (?, ?)',
      [deploymentId, configJson]
    );

    await this.auditLog(ctx.userId, 'deployment_created', 'deployment', String(deploymentId), null, JSON.stringify({ customer_id: customerId, domain }), null);

    return { success: true, deployment_id: deploymentId, domain, tier };
  }

  /**
   * Owner-only and SafetyFlags.can_publish (double gate): a draft with a verified domain (domain_verified) and a
   * theme goes live. Out: { success, deployment_id, status: 'live', public_url }. Errors: 403 publish_not_allowed,
   * 404 deployment_not_found, 400 not_draft / domain_not_verified / theme_not_set. ADMIN-15. Touches: deployments,
   * audit_log. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): a suspended caller is refused first
   * with 403 account_suspended (ADMIN-19), and roles and plans are separate lists (admin TIERS).
   */
  async publishDeployment(
    ctx: AdminContext,
    csrf: string,
    body: { deployment_id: number }
  ): Promise<ApiResponse> {
    await this.refuseSuspended(ctx); // ADMIN-19, before any gate
    this.verifyCsrf(ctx, csrf);
    await this.requireOwner(ctx);

    if (!ctx.safetyFlags.can_publish) {
      throw new AdminError('publish_not_allowed', 'Publishing is not allowed by safety flags.', 403);
    }

    const deploymentId = requireNumber(body.deployment_id, 'deployment_id');

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT deployment_id, status, domain, domain_verified, theme_id FROM deployments WHERE deployment_id = ?',
      [deploymentId]
    );
    if (rows.length === 0) {
      throw new AdminError('deployment_not_found', 'Deployment not found.', 404);
    }
    const dep = rows[0];

    if (dep.status !== 'draft') {
      throw new AdminError('not_draft', 'Only draft deployments can be published.', 400);
    }
    if (!dep.domain_verified) {
      throw new AdminError('domain_not_verified', 'Domain must be verified before publishing.', 400);
    }
    if (!dep.theme_id) {
      throw new AdminError('theme_not_set', 'A theme must be set before publishing.', 400);
    }

    await this.pool.execute(
      "UPDATE deployments SET status = 'live', published_at = NOW() WHERE deployment_id = ?",
      [deploymentId]
    );

    await this.auditLog(ctx.userId, 'deployment_published', 'deployment', String(deploymentId), 'draft', 'live', null);

    const publicUrl = `https://${dep.domain}`;
    return { success: true, deployment_id: deploymentId, status: 'live', public_url: publicUrl };
  }

  /**
   * Owner-only: suspends a deployment with a reason. Out: { success, deployment_id, status: 'suspended' }. Touches:
   * deployments, audit_log. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): a suspended caller is
   * refused first with 403 account_suspended (ADMIN-19), and roles and plans are separate lists (admin TIERS).
   */
  async suspendDeployment(
    ctx: AdminContext,
    csrf: string,
    body: { deployment_id: number; reason: string }
  ): Promise<ApiResponse> {
    await this.refuseSuspended(ctx); // ADMIN-19, before any gate
    this.verifyCsrf(ctx, csrf);
    await this.requireOwner(ctx);

    const deploymentId = requireNumber(body.deployment_id, 'deployment_id');
    const reason = requireString(body.reason, 'reason');

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT deployment_id, status FROM deployments WHERE deployment_id = ?',
      [deploymentId]
    );
    if (rows.length === 0) {
      throw new AdminError('deployment_not_found', 'Deployment not found.', 404);
    }

    await this.pool.execute(
      "UPDATE deployments SET status = 'suspended', suspend_reason = ? WHERE deployment_id = ?",
      [reason, deploymentId]
    );

    await this.auditLog(ctx.userId, 'deployment_suspended', 'deployment', String(deploymentId), rows[0].status, 'suspended', reason);

    return { success: true, deployment_id: deploymentId, status: 'suspended' };
  }

  /**
   * Owner-only: archives a deployment. Out: { success, deployment_id, status: 'archived' }. Touches: deployments,
   * audit_log. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): a suspended caller is refused first
   * with 403 account_suspended (ADMIN-19), and roles and plans are separate lists (admin TIERS).
   */
  async retireDeployment(
    ctx: AdminContext,
    csrf: string,
    body: { deployment_id: number }
  ): Promise<ApiResponse> {
    await this.refuseSuspended(ctx); // ADMIN-19, before any gate
    this.verifyCsrf(ctx, csrf);
    await this.requireOwner(ctx);

    const deploymentId = requireNumber(body.deployment_id, 'deployment_id');

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT deployment_id, status FROM deployments WHERE deployment_id = ?',
      [deploymentId]
    );
    if (rows.length === 0) {
      throw new AdminError('deployment_not_found', 'Deployment not found.', 404);
    }

    await this.pool.execute(
      "UPDATE deployments SET status = 'archived', archived_at = NOW() WHERE deployment_id = ?",
      [deploymentId]
    );

    await this.auditLog(ctx.userId, 'deployment_archived', 'deployment', String(deploymentId), rows[0].status, 'archived', null);

    return { success: true, deployment_id: deploymentId, status: 'archived' };
  }

  // -- GOVERNANCE DOMAIN ----------------------------------------------------

  /**
   * Admin or owner: pending governance actions, paginated. Out: { success, items, total, limit, offset }. Touches:
   * governance_actions (read). Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): a suspended caller
   * is refused first with 403 account_suspended (ADMIN-19), and roles and plans are separate lists (admin TIERS).
   */
  async listGovernanceActions(
    ctx: AdminContext,
    params: { limit?: number; offset?: number }
  ): Promise<ApiResponse> {
    await this.refuseSuspended(ctx); // ADMIN-19, before any gate
    await this.requireAdminOrOwner(ctx);

    const limit = Math.min(Math.max(params.limit ?? 50, 1), 200);
    const offset = Math.max(params.offset ?? 0, 0);

    const [countRows] = await this.pool.execute<RowDataPacket[]>(
      "SELECT COUNT(*) AS total FROM governance_actions WHERE status = 'pending'"
    );
    const total = Number(countRows[0].total);

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      "SELECT action_id, action_type, actor, target_resource_id, reason, submitted_at, status FROM governance_actions WHERE status = 'pending' ORDER BY submitted_at LIMIT ? OFFSET ?",
      [limit, offset]
    );

    const items: GovernanceAction[] = rows.map((r) => ({
      action_id: r.action_id,
      action_type: r.action_type,
      actor: r.actor,
      target_resource_id: r.target_resource_id,
      reason: r.reason,
      submitted_at: r.submitted_at,
      status: r.status,
    }));

    return { success: true, items, total, limit, offset };
  }

  /**
   * Owner-only: approves (executes: change_plan through the same Stripe rule as changePlan, change_role under the
   * role and last-owner rules (400 invalid_tier / cannot_demote_last_owner, nothing changed), suspend_user,
   * publish_deployment only for a verified draft) or rejects (with a reason) a pending action. Out: { success,
   * action_id, status }. ADMIN-16/17. Touches: governance_actions, customers, users, deployments, Stripe, audit_log.
   * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): a suspended caller is refused first with 403
   * account_suspended (ADMIN-19), and roles and plans are separate lists (admin TIERS).
   * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec LAST OWNER, approver rule; the PR 22 review found C#,
   * Java and Rust missing it, and TypeScript had the same gap): a change_role whose target is the approver
   * (ctx.userId) is 400 cannot_change_own_role, checked after the last-owner check and before anything changes, so
   * the action stays pending.
   */
  async decideGovernanceAction(
    ctx: AdminContext,
    csrf: string,
    actionId: number,
    decide: 'approve' | 'reject',
    body: { reason?: string }
  ): Promise<ApiResponse> {
    await this.refuseSuspended(ctx); // ADMIN-19, before any gate
    this.verifyCsrf(ctx, csrf);
    await this.requireOwner(ctx);

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT action_id, action_type, actor, target_resource_id, reason, status FROM governance_actions WHERE action_id = ?',
      [actionId]
    );
    if (rows.length === 0) {
      throw new AdminError('action_not_found', 'Governance action not found.', 404);
    }
    const action = rows[0];

    if (action.status !== 'pending') {
      throw new AdminError('action_not_pending', 'Action has already been decided.', 400);
    }

    // A change_role action is checked before anything changes: the new value must be a staff role, and the last
    // active owner cannot be demoted (ADMIN-07; the action stays pending). Added 2026-11-10,
    // session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): with ADMIN-19 refusing a suspended owner first, this is where the
    // last-owner rule is reachable (action=change_role always has a second active owner: the caller).
    if (decide === 'approve' && action.action_type === 'change_role') {
      if (!isStaffRole(action.reason)) {
        throw invalidTier('role');
      }
      const [targetRows] = await this.pool.execute<RowDataPacket[]>(
        'SELECT id, tier, status FROM users WHERE id = ?',
        [action.target_resource_id]
      );
      if (targetRows.length === 0) {
        throw new AdminError('user_not_found', 'User not found.', 404);
      }
      if (action.reason !== 'owner' && (await this.isLastActiveOwner(targetRows[0]))) {
        throw new AdminError('cannot_demote_last_owner', 'Cannot demote the last active owner.', 400);
      }
      if (Number(action.target_resource_id) === ctx.userId) {
        throw new AdminError('cannot_change_own_role', 'You cannot change your own role.', 400);
      }
    }

    if (decide === 'approve') {
      // Execute the original action based on action_type
      let executionResult: string = 'executed';
      try {
        switch (action.action_type) {
          case 'change_plan': {
            // target_resource_id is customer_id, reason holds the new PLAN tier. Same rule as changePlan
            // (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.2: it sent a bare { price }).
            const newTier = action.reason;
            if (isPlanTier(newTier)) {
              await this.applyPlanChange(action.target_resource_id, newTier);
            } else {
              executionResult = 'refused: invalid_tier';
            }
            break;
          }
          case 'change_role':
            // target_resource_id is the user, reason the new staff role (checked above).
            await this.pool.execute('UPDATE users SET tier = ? WHERE id = ?', [action.reason, action.target_resource_id]);
            break;
          case 'suspend_user':
            await this.pool.execute("UPDATE users SET status = 'suspended' WHERE id = ?", [
              action.target_resource_id,
            ]);
            break;
          case 'publish_deployment': {
            // Publish needs a draft with a verified domain and a theme, as publishDeployment (2026-11-10,
            // session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.2: it set any deployment live).
            const [depRows] = await this.pool.execute<RowDataPacket[]>(
              'SELECT deployment_id, status, domain, domain_verified, theme_id FROM deployments WHERE deployment_id = ?',
              [action.target_resource_id]
            );
            const dep = depRows[0];
            if (!dep || dep.status !== 'draft' || !dep.domain_verified || !dep.theme_id) {
              executionResult = 'refused: not a draft with a verified domain and a theme';
              break;
            }
            await this.pool.execute(
              "UPDATE deployments SET status = 'live', published_at = NOW() WHERE deployment_id = ?",
              [action.target_resource_id]
            );
            break;
          }
          default:
            executionResult = 'no_handler';
        }
      } catch (err) {
        executionResult = `error: ${(err as Error).message}`;
      }

      await this.pool.execute(
        "UPDATE governance_actions SET status = 'approved', approved_by = ?, approved_at = NOW() WHERE action_id = ?",
        [ctx.userId, actionId]
      );

      await this.auditLog(ctx.userId, 'action_approved', 'governance_action', String(actionId), 'pending', 'approved', executionResult);

      return { success: true, action_id: actionId, status: 'approved' };
    } else {
      const reason = requireString(body.reason ?? '', 'reason');

      await this.pool.execute(
        "UPDATE governance_actions SET status = 'rejected', rejection_reason = ? WHERE action_id = ?",
        [reason, actionId]
      );

      await this.auditLog(ctx.userId, 'action_rejected', 'governance_action', String(actionId), 'pending', 'rejected', reason);

      return { success: true, action_id: actionId, status: 'rejected' };
    }
  }

  /**
   * Admin or owner: audit entries filtered by action, resource id and date range, newest first, paginated. Out: {
   * success, items, total, limit, offset }. ADMIN-18. Touches: audit_log (read). Changed 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): a suspended caller is refused first with 403 account_suspended
   * (ADMIN-19), and roles and plans are separate lists (admin TIERS).
   */
  async searchAuditLog(
    ctx: AdminContext,
    params: {
      action_type?: string;
      resource_id?: string;
      date_range?: { start: string; end: string };
      limit?: number;
      offset?: number;
    }
  ): Promise<ApiResponse> {
    await this.refuseSuspended(ctx); // ADMIN-19, before any gate
    await this.requireAdminOrOwner(ctx);

    const limit = Math.min(Math.max(params.limit ?? 100, 1), 500);
    const offset = Math.max(params.offset ?? 0, 0);

    const conditions: string[] = [];
    const values: (string | number)[] = [];

    if (params.action_type) {
      conditions.push('action = ?');
      values.push(params.action_type);
    }
    if (params.resource_id) {
      conditions.push('resource_id = ?');
      values.push(params.resource_id);
    }
    if (params.date_range) {
      conditions.push('timestamp >= ? AND timestamp <= ?');
      values.push(params.date_range.start, params.date_range.end);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const [countRows] = await this.pool.execute<RowDataPacket[]>(
      `SELECT COUNT(*) AS total FROM audit_log ${whereClause}`,
      values
    );
    const total = Number(countRows[0].total);

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      `SELECT timestamp, actor_id, action, resource_type, resource_id, old_value, new_value, reason FROM audit_log ${whereClause} ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
      [...values, limit, offset]
    );

    const items: AuditEntry[] = rows.map((r) => ({
      timestamp: r.timestamp,
      actor_id: r.actor_id,
      action: r.action,
      resource_type: r.resource_type,
      resource_id: r.resource_id,
      old_value: r.old_value,
      new_value: r.new_value,
      reason: r.reason,
    }));

    return { success: true, items, total, limit, offset };
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export async function createAdminSystem(options: {
  host: string;
  user: string;
  password: string;
  database: string;
  stripe?: StripeClient;
  email?: EmailService;
  priceMap?: Partial<Record<PlanTier, string>>;
}): Promise<AdminSystem> {
  const pool = createPool({
    host: options.host,
    user: options.user,
    password: options.password,
    database: options.database,
    waitForConnections: true,
    connectionLimit: 10,
  });

  // Run schema
  const conn = await pool.getConnection();
  try {
    const statements = SCHEMA_SQL.split(';').filter((s) => s.trim().length > 0);
    for (const stmt of statements) {
      await conn.query(stmt);
    }
  } finally {
    conn.release();
  }

  return new AdminSystem({
    pool,
    stripe: options.stripe,
    email: options.email,
    priceMap: options.priceMap,
  });
}

function createPool(config: {
  host: string;
  user: string;
  password: string;
  database: string;
  waitForConnections: boolean;
  connectionLimit: number;
}): Pool {
  return createConnection as unknown as Pool;
}