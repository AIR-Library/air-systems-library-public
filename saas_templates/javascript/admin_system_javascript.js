'use strict';

/**
 * Admin system (owner/admin back office): users, customers, deployments and governance, with an audit log row for
 * every mutation.
 *
 * Contract: GEMINI_DISPATCH_MASTER_SPEC.txt, TEMPLATE #2 ADMIN SYSTEM, and docs/SPEC_auth_admin_trial_abuse.md.
 *
 * Who the caller is: an access token issued by the auth system (auth_system_javascript.js signs
 * `{ user_id, tier }` with HS256 and JWT_SECRET), sent as `Authorization: Bearer <token>`. The token only says WHICH
 * user is calling. Their tier and status are read from the users table on every request, so a token minted before a
 * demotion or a suspension stops granting owner rights at once, and no header the client controls can raise a role.
 *
 * CSRF: every state-changing request carries `X-CSRF-Token`, an HMAC of the caller's user id under a server secret
 * (GET /admin/csrf-token hands it to the signed-in page). It is compared in constant time.
 *
 * Outside services sit behind small interfaces so the template runs with no network: `stripe` (anything with
 * `subscriptions.retrieve` and `subscriptions.update`, normally the stripe package's client) and `mailer` (anything with `send({to, subject, text})`;
 * InMemoryMailer is the fake the tests use).
 *
 * Repair, 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Fifteen of eighteen tests answered 403 because a global
 * `csurf({ cookie: true })` refused every POST before any route ran (the tests never had a csurf cookie), and the
 * owner gate trusted `X-User-Id`/`X-User-Role` headers that any client can set. Also fixed: a hard-coded CSRF secret
 * and Stripe key, password-reset links written to the console, governance approval that never executed the action,
 * refunds queued against invoices that were never checked.
 *
 * Touches: the database given (SQLite through knex by default), Stripe (money: plan changes) through the injected
 * client, e-mail through the injected mailer. Nothing secret is logged.
 */

const crypto = require('crypto');
const express = require('express');
const knexLib = require('knex');
const jwt = require('jsonwebtoken');
const { rateLimit } = require('express-rate-limit');

// Two different things share the word "tier" (admin spec TIERS, Phase B.2, 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP): users.tier is the STAFF ROLE, a customer's or deployment's tier is the PLAN.
// A value from one list given where the other is expected is 400 invalid_tier.
const VALID_TIERS = ['owner', 'admin', 'user'];
const PLAN_TIERS = ['solo', 'team', 'enterprise'];
const RESET_TOKEN_TTL_MS = 60 * 60 * 1000; // one hour
const MAX_PAGE_SIZE = 100;

/**
 * In-memory mailer: keeps every message in `outbox` instead of sending it. Use a real provider (SMTP, SES, ...) with
 * the same `send` shape in production.
 * In: send({ to, subject, text }). Out: a promise of `{ accepted: [to] }`.
 * Why: reset and invite links must reach the user without being written to logs (2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: memory only.
 */
class InMemoryMailer {
  constructor() {
    this.outbox = [];
  }

  async send(message) {
    this.outbox.push({ ...message });
    return { accepted: [message.to] };
  }
}

/**
 * Opens the admin database (SQLite through knex).
 * In: filename, default ':memory:'. Out: a knex instance; call `.destroy()` when done.
 * Why: lets each test or server own its connection instead of sharing a module-level one (2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: the database file named.
 */
function createDatabase(filename = ':memory:') {
  return knexLib({ client: 'sqlite3', connection: { filename }, useNullAsDefault: true });
}

/**
 * Creates every admin table that does not exist yet; with `{ reset: true }` drops them all first.
 * In: a knex instance, options `{ reset }` (default false). Out: a promise that resolves when the schema exists.
 * Why: the schema the routes need. 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP) added `invoices` (refunds must be
 * checked against a succeeded invoice, as the spec says), `password_resets` (reset and invite tokens are stored only
 * as hashes) and `governance_actions.payload` (approval executes the original action, which needs its parameters),
 * and stopped dropping every table on each start, which would have wiped a real database when run as a server.
 * Phase B.2 (2026-11-10): deployments.domain_verified (boolean, default false), added to an older table as well.
 * Touches: database (creates tables, adds a column; drops them only with reset).
 */
async function runMigrations(knex, { reset = false } = {}) {
  if (reset) {
    for (const t of ['password_resets', 'audit_logs', 'refunds', 'invoices', 'governance_actions', 'deployments',
      'customers', 'users']) {
      await knex.schema.dropTableIfExists(t);
    }
  }
  const schema = {
    async createTable(name, build) {
      if (!(await knex.schema.hasTable(name))) await knex.schema.createTable(name, build);
    },
  };

  await schema.createTable('users', (t) => {
    t.increments('id').primary();
    t.string('email').unique().notNullable();
    t.string('name').notNullable();
    t.string('tier').notNullable(); // owner, admin, user
    t.string('status').defaultTo('active'); // active, suspended
    t.timestamps(true, true);
  });

  await schema.createTable('customers', (t) => {
    t.increments('id').primary();
    t.string('email').notNullable();
    t.string('name').notNullable();
    t.string('tier').notNullable(); // the PLAN: solo, team, enterprise
    t.date('signup_date').notNullable();
    t.integer('invoice_count').defaultTo(0);
    t.string('status').defaultTo('active');
    t.string('subscription_status').defaultTo('active');
    t.string('payment_method').notNullable();
    t.string('address').notNullable();
    t.text('notes');
    t.string('stripe_subscription_id').notNullable();
  });

  await schema.createTable('invoices', (t) => {
    t.increments('id').primary();
    t.integer('customer_id').unsigned().notNullable().references('id').inTable('customers');
    t.decimal('amount', 10, 2).notNullable();
    t.string('status').notNullable(); // succeeded, failed, open
    t.timestamp('created_at').defaultTo(knex.fn.now());
  });

  await schema.createTable('deployments', (t) => {
    t.increments('id').primary();
    t.integer('customer_id').unsigned().references('id').inTable('customers');
    t.string('domain').notNullable();
    t.string('tier').notNullable(); // the PLAN: solo, team, enterprise
    t.string('status').defaultTo('draft'); // draft, live, suspended, archived
    t.string('theme').notNullable();
    // Publishing needs a verified domain (admin spec, Phase B.2, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
    t.boolean('domain_verified').notNullable().defaultTo(false);
    t.timestamp('published_at');
    t.string('suspend_reason');
    t.timestamp('archived_at');
  });

  await schema.createTable('audit_logs', (t) => {
    t.increments('id').primary();
    t.timestamp('timestamp').defaultTo(knex.fn.now());
    t.integer('actor_id').unsigned();
    t.string('action').notNullable();
    t.string('resource_type');
    t.integer('resource_id');
    t.json('old_value');
    t.json('new_value');
    t.string('reason');
  });

  await schema.createTable('refunds', (t) => {
    t.increments('id').primary();
    t.integer('customer_id').unsigned().notNullable();
    t.integer('invoice_id').notNullable();
    t.decimal('amount', 10, 2).notNullable();
    t.string('reason').notNullable();
    t.integer('created_by').unsigned();
    t.timestamp('created_at').defaultTo(knex.fn.now());
    t.string('status').defaultTo('queued');
  });

  await schema.createTable('governance_actions', (t) => {
    t.increments('id').primary();
    t.string('action_type').notNullable();
    t.integer('actor_id').unsigned();
    t.integer('target_resource_id');
    t.json('payload');
    t.string('reason');
    t.timestamp('submitted_at').defaultTo(knex.fn.now());
    t.string('status').defaultTo('pending'); // pending, approved, rejected
    t.integer('approved_by').unsigned();
    t.timestamp('approved_at');
    t.string('rejection_reason');
    t.text('execution_result');
  });

  await schema.createTable('password_resets', (t) => {
    t.increments('id').primary();
    t.integer('user_id').unsigned().notNullable();
    t.string('purpose').notNullable(); // reset, invite
    t.string('token_hash').notNullable().unique();
    t.bigInteger('expires_at_ms').notNullable();
    t.timestamp('used_at');
  });

  // A deployments table made before Phase B.2 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP) has no domain_verified;
  // add it, false for every row, so publish can require it.
  if (!(await knex.schema.hasColumn('deployments', 'domain_verified'))) {
    await knex.schema.alterTable('deployments', (t) => {
      t.boolean('domain_verified').notNullable().defaultTo(false);
    });
  }
}

/**
 * Checks the shape of an e-mail address: one @, something before it, and a domain with a dot inside it.
 * In: any value. Out: true or false.
 * Why: the regular expression this replaces took polynomial time on a long crafted address (code scanning alert
 * js/polynomial-redos), so a request could tie up the server. This walks the text a fixed number of times and
 * refuses anything over the 254 characters an address can have. 2026-11-05, session f3daac6e. Touches: nothing.
 */
function validateEmail(email) {
  if (typeof email !== 'string' || email.length > 254 || /\s/.test(email)) return false;
  const at = email.indexOf('@');
  if (at < 1 || at !== email.lastIndexOf('@')) return false;
  const domain = email.slice(at + 1);
  const dot = domain.lastIndexOf('.');
  return dot > 0 && dot < domain.length - 1;
}

/**
 * Checks a display name: a string of 3 to 50 characters. In: any value. Out: true or false.
 * Why: spec "Validation: ... name length". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (documented only).
 * Touches: nothing.
 */
function validateName(name) {
  return typeof name === 'string' && name.length >= 3 && name.length <= 50;
}

/**
 * Checks a STAFF ROLE (users.tier) against the allowed list (owner, admin, user). In: any value. Out: true or false.
 * A plan value ('solo', 'team', 'enterprise') is not a role and fails.
 * Why: spec "role in allowed_roles"; TIERS (Phase B.2). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function validateTier(tier) {
  return VALID_TIERS.includes(tier);
}

/**
 * Checks a PLAN (a customer's or deployment's tier) against solo, team, enterprise. In: any value. Out: true or false.
 * A staff role ('owner', 'admin', 'user') is not a plan and fails.
 * Why: admin spec TIERS (Phase B.2): change_plan and create_deployment checked plans against the role list, so a
 * customer could be put on the "admin" plan. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function validatePlan(tier) {
  return PLAN_TIERS.includes(tier);
}

/**
 * Reads a positive integer id from a request value ("3" or 3).
 * In: any value. Out: the integer, or null when it is not a positive integer.
 * Why: the self-action guards compared `"1" === 1` and so let an owner suspend or reset themselves by sending the id
 * as a string (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
 */
function toId(value) {
  const n = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value;
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

/**
 * Compares two strings in constant time.
 * In: two values. Out: true only when both are strings of the same length with the same bytes.
 * Why: CSRF tokens must not leak through response timing (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
 * Touches: nothing.
 */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

/**
 * Hashes a one-time token for storage (SHA-256, hex). In: the token. Out: its hash.
 * Why: a database leak must not hand out working reset links (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
 * Touches: nothing.
 */
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Error with an HTTP status and a spec error code, thrown inside a route and turned into `{error, message}`.
 * Why: one exit path for refusals, so a transaction is rolled back whenever a check fails after it began (2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
 */
class AdminError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/**
 * Builds the admin application.
 *
 * In (all optional):
 *   knex        database (default: a new in-memory SQLite; run `runMigrations()` before use)
 *   jwtSecret   secret the auth system signs access tokens with (default env JWT_SECRET, else a random one per process,
 *               which accepts no token from anywhere else)
 *   csrfSecret  secret CSRF tokens are derived from (default env ADMIN_CSRF_SECRET, else random per process)
 *   stripe      Stripe client (default: `require('stripe')(STRIPE_SECRET_KEY)` when that env var is set, else none, and
 *               plan changes answer 503 billing_not_configured)
 *   mailer      `{ send({to, subject, text}) }` (default InMemoryMailer)
 *   priceIds    plan (solo, team, enterprise) -> Stripe price id (default env STRIPE_PRICE_<PLAN>, else price_<plan>;
 *               keyed by plan, not by role, since Phase B.2 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
 *   safetyFlags `{ can_publish }`, the second gate on publishing (default `{ can_publish: true }`)
 *   themes      the theme ids a deployment may be created with (default `['default']`); themes have no table of their
 *               own in this template, so this list is the catalogue. Added 2026-11-10, session
 *               session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19: a theme used to "exist" only once some
 *               deployment used it, so a fresh database could never create its first deployment).
 *   baseUrl     origin used in e-mailed links (default env APP_BASE_URL or https://example.com)
 *   now         clock in ms (default Date.now)
 * Out: `{ app, knex, runMigrations, csrfTokenFor, mailer, safetyFlags }`.
 *
 * Why: replaces the module-level app whose global csurf middleware refused every POST and whose gates trusted
 * client-supplied role headers (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
 * Touches: database, Stripe (money), e-mail, as configured.
 */
function createAdminSystem(options = {}) {
  const knex = options.knex || createDatabase();
  const jwtSecret = options.jwtSecret || process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
  const csrfSecret = options.csrfSecret || process.env.ADMIN_CSRF_SECRET || crypto.randomBytes(32).toString('hex');
  const mailer = options.mailer || new InMemoryMailer();
  const safetyFlags = options.safetyFlags || { can_publish: true };
  const themes = new Set(options.themes || ['default']);
  const baseUrl = options.baseUrl || process.env.APP_BASE_URL || 'https://example.com';
  const now = options.now || Date.now;
  const priceIds = options.priceIds || Object.fromEntries(
    PLAN_TIERS.map((t) => [t, process.env[`STRIPE_PRICE_${t.toUpperCase()}`] || `price_${t}`]),
  );
  let stripe = options.stripe || null;
  if (!stripe && process.env.STRIPE_SECRET_KEY) {
    stripe = require('stripe')(process.env.STRIPE_SECRET_KEY); // eslint-disable-line global-require
  }

  /**
   * The CSRF token for one user: HMAC-SHA256 of their id under the server's CSRF secret.
   * In: user id. Out: hex string. Why: per-user token, so one user's token cannot forge another's requests
   * (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
   */
  function csrfTokenFor(userId) {
    return crypto.createHmac('sha256', csrfSecret).update(`admin-csrf:${userId}`).digest('hex');
  }

  /**
   * Writes one audit row. In: the fields of the spec's audit_log plus the transaction (or knex) to write with.
   * Out: a promise. Why: "Every mutation: audit_log write before commit" (spec). 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP (now written inside the mutation's transaction). Touches: database.
   */
  async function auditLog(db, { actor_id, action, resource_type, resource_id, old_value, new_value, reason }) {
    await db('audit_logs').insert({
      actor_id,
      action,
      resource_type,
      resource_id,
      old_value: old_value ? JSON.stringify(old_value) : null,
      new_value: new_value ? JSON.stringify(new_value) : null,
      reason: reason || null,
    });
  }

  /**
   * Counts active owners. In: db or transaction. Out: a number. Why: the last-owner safety invariant (spec).
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database (read).
   */
  async function activeOwnerCount(db) {
    const row = await db('users').where({ tier: 'owner', status: 'active' }).count('id as cnt').first();
    return Number(row.cnt);
  }

  /**
   * Issues a one-time link token (reset or invite), stores only its hash, and e-mails the link.
   * In: db, the user row, purpose ('reset' | 'invite'). Out: a promise. Why: the reset link used to be printed to the
   * console, where anyone reading logs could take over the account (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
   * Touches: database, e-mail.
   */
  async function sendLinkEmail(db, user, purpose) {
    const token = crypto.randomBytes(32).toString('hex');
    await db('password_resets').insert({
      user_id: user.id,
      purpose,
      token_hash: hashToken(token),
      expires_at_ms: now() + RESET_TOKEN_TTL_MS,
    });
    const path = purpose === 'invite' ? 'accept-invite' : 'reset-password';
    await mailer.send({
      to: user.email,
      subject: purpose === 'invite' ? 'You have been invited' : 'Reset your password',
      text: `Use this link within one hour: ${baseUrl}/${path}?token=${token}`,
    });
  }

  /**
   * Express middleware: identifies the caller from `Authorization: Bearer <access token>`, then loads their tier and
   * status from the database. Sets `req.user = { id, tier, email }`. It runs before every other gate (CSRF, owner,
   * admin), so a suspended caller is refused first: 403 account_suspended (ADMIN-19); any other non-active status is
   * 403 account_inactive.
   * Out: 401 authentication_required / invalid_token, 403 account_suspended / account_inactive, or next().
   * Why: the gate trusted `X-User-Id`/`X-User-Role` headers, so any client could call itself owner (2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP); account_suspended added the same day (Phase B.2, ADMIN-19).
   * Touches: database (read).
   */
  async function authenticate(req, res, next) {
    try {
      const match = /^Bearer ([A-Za-z0-9_.-]+)$/.exec(req.get('authorization') || '');
      if (!match) {
        return res.status(401).json({ error: 'authentication_required', message: 'Bearer access token required' });
      }
      let payload;
      try {
        payload = jwt.verify(match[1], jwtSecret, { algorithms: ['HS256'] });
      } catch (e) {
        return res.status(401).json({ error: 'invalid_token', message: 'Access token is invalid or expired' });
      }
      const id = toId(payload && payload.user_id);
      const user = id ? await knex('users').where({ id }).first() : null;
      if (!user) {
        return res.status(401).json({ error: 'invalid_token', message: 'Access token is invalid or expired' });
      }
      if (user.status === 'suspended') {
        return res.status(403).json({ error: 'account_suspended', message: 'Account is suspended' });
      }
      if (user.status !== 'active') {
        return res.status(403).json({ error: 'account_inactive', message: 'Account is not active' });
      }
      req.user = { id: user.id, tier: user.tier, email: user.email };
      return next();
    } catch (err) {
      return next(err);
    }
  }

  /**
   * Express middleware: on POST, PUT, PATCH and DELETE, requires `X-CSRF-Token` to equal the caller's CSRF token.
   * Out: 403 csrf_token_invalid, or next(). Why: spec "Every POST: verify_csrf() first"; replaces a global csurf whose
   * cookie the clients never had, and a CSRF secret hard-coded in the source (2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
   */
  function verifyCsrf(req, res, next) {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    if (!safeEqual(req.get('x-csrf-token'), csrfTokenFor(req.user.id))) {
      return res.status(403).json({ error: 'csrf_token_invalid', message: 'Invalid CSRF token' });
    }
    return next();
  }

  /**
   * Express middleware: owner-only gate, on the tier read from the database. Out: 403 owner_only, or next().
   * Why: spec require_owner(current_user). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
   */
  function requireOwner(req, res, next) {
    if (req.user.tier !== 'owner') {
      return res.status(403).json({ error: 'owner_only', message: 'Owner role required' });
    }
    return next();
  }

  /**
   * Express middleware: owner-or-admin gate for read-only routes. Out: 403 admin_only, or next().
   * Why: spec require_admin (error "admin_only"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
   */
  function requireAdminOrOwner(req, res, next) {
    if (req.user.tier !== 'owner' && req.user.tier !== 'admin') {
      return res.status(403).json({ error: 'admin_only', message: 'Admin or Owner role required' });
    }
    return next();
  }

  /**
   * Wraps an async route so every refusal and error ends in one JSON answer.
   * In: async (req, res) => body. Out: an Express handler that sends `{...body}` or `{error, message}`.
   * Why: unhandled rejections in GET routes used to leave requests hanging (2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: whatever the route touches.
   */
  function route(fn) {
    return async (req, res) => {
      try {
        const body = await fn(req, res);
        if (!res.headersSent) res.json(body);
      } catch (err) {
        if (err instanceof AdminError) {
          res.status(err.status).json({ error: err.code, message: err.message });
        } else {
          console.error('admin route failed:', err && err.message);
          res.status(500).json({ error: 'internal_error', message: 'Internal server error' });
        }
      }
    };
  }

  /**
   * Suspends a user after the safety checks (not yourself, not the last active owner), with an audit row.
   * In: transaction, actor id, target id, reason, audit action name. Out: `{ user_id, suspended: true }`.
   * Why: shared by the suspend action and by approving a governance `suspend_user` action, which the old code marked
   * approved without doing (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: database.
   */
  async function suspendUser(trx, actorId, userId, reason, auditAction = 'user_suspended') {
    if (userId === actorId) throw new AdminError(400, 'cannot_suspend_yourself', 'Cannot suspend yourself');
    const user = await trx('users').where({ id: userId }).first();
    if (!user) throw new AdminError(404, 'user_not_found', 'User not found');
    if (user.tier === 'owner' && user.status === 'active' && (await activeOwnerCount(trx)) <= 1) {
      throw new AdminError(400, 'cannot_suspend_last_owner', 'Cannot suspend last active owner');
    }
    await trx('users').where({ id: userId }).update({ status: 'suspended' });
    await auditLog(trx, {
      actor_id: actorId,
      action: auditAction,
      resource_type: 'user',
      resource_id: userId,
      old_value: { status: user.status },
      new_value: { status: 'suspended' },
      reason,
    });
    return { user_id: userId, suspended: true };
  }

  /**
   * Changes a user's tier after the safety checks (valid tier, not the last active owner, not yourself).
   * In: transaction, actor id, target id, new tier. Out: `{ user_id, old_tier, new_tier }`.
   * Why: shared by change_role and by approving a governance `change_role` action (2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP). The last-owner check runs before the self check: an active owner acting on
   * another active owner always leaves two, so the last owner can only be the caller, and "cannot demote the last
   * owner" is then the reason that matters (spec test "change_role last_owner"). Touches: database.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.3): the direct route now applies the self gate before
   * calling this, so the last-owner answer is reached only by approving a governance change_role (ADMIN-07); a
   * refusal here throws, which rolls the approval's transaction back and leaves the action pending.
   */
  async function changeRole(trx, actorId, userId, newTier) {
    if (!validateTier(newTier)) throw new AdminError(400, 'invalid_tier', 'Invalid tier');
    const user = await trx('users').where({ id: userId }).first();
    if (!user) throw new AdminError(404, 'user_not_found', 'User not found');
    if (user.tier === 'owner' && newTier !== 'owner' && user.status === 'active'
      && (await activeOwnerCount(trx)) <= 1) {
      throw new AdminError(400, 'cannot_demote_last_owner', 'Cannot demote last active owner');
    }
    if (userId === actorId) throw new AdminError(400, 'cannot_change_own_role', 'Cannot change own role');
    await trx('users').where({ id: userId }).update({ tier: newTier });
    await auditLog(trx, {
      actor_id: actorId,
      action: 'role_changed',
      resource_type: 'user',
      resource_id: userId,
      old_value: { tier: user.tier },
      new_value: { tier: newTier },
    });
    return { user_id: userId, old_tier: user.tier, new_tier: newTier };
  }

  const app = express();
  /**
   * Limits how often one address can call the admin API, before any other work is done for the request. Admin routes
   * read and write the database, so without this one client could flood them. Change the limit with ADMIN_RATE_LIMIT.
   * Why: nine code scanning alerts js/missing-rate-limiting, 2026-11-05, session f3daac6e. Touches: memory only, one
   * counter per address. With more than one server, give it a shared store such as Redis.
   */
  const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: Number(process.env.ADMIN_RATE_LIMIT) || 300,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
  });
  // Behind a reverse proxy, req.ip is the proxy's address unless Express is told how many proxies to trust, and then
  // every client shares one limit. Set TRUST_PROXY to the number of proxies in front of the app, for example 1
  // (2026-11-08, session f3daac6e, from review).
  if (process.env.TRUST_PROXY) {
    app.set('trust proxy', Number(process.env.TRUST_PROXY) || process.env.TRUST_PROXY);
  }
  app.use(adminLimiter);
  app.use(express.json({ limit: '100kb' }));
  app.use('/admin', authenticate, verifyCsrf);

  // The page asks for its CSRF token once it is signed in.
  /**
   * GET /admin/csrf-token: the signed-in user's CSRF token. Out: { csrf_token }.
   * Why: replaces the shared hard-coded token (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
   */
  app.get('/admin/csrf-token', (req, res) => res.json({ csrf_token: csrfTokenFor(req.user.id) }));

  // ---------------------------------------------------------------- USERS DOMAIN
  /**
   * POST /admin/users/action (owner): create | reset_password | change_role | suspend.
   * In: { action, ... } per spec. Out: { success: true, ... } or { error, message }.
   * change_role refuses the caller's own account (400 cannot_change_own_role) before any check, as the spec's gate
   * order says (Phase B.3, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
   * Why: spec endpoint; rebuilt 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP behind the token gate (see module header). Touches: database, e-mail.
   */
  app.post('/admin/users/action', requireOwner, route(async (req) => {
    const { action } = req.body;
    const actorId = req.user.id;
    if (action === 'create') {
      const { email, name, tier, notify } = req.body;
      if (!email || !name || !tier) throw new AdminError(400, 'missing_params', 'email, name, tier required');
      if (!validateEmail(email)) throw new AdminError(400, 'invalid_email', 'Invalid email format');
      if (!validateName(name)) throw new AdminError(400, 'invalid_name', 'Name must be 3-50 chars');
      if (!validateTier(tier)) throw new AdminError(400, 'invalid_tier', 'Invalid tier');
      return knex.transaction(async (trx) => {
        if (await trx('users').where({ email }).first()) {
          throw new AdminError(409, 'email_exists', 'Email already exists');
        }
        const [userId] = await trx('users').insert({ email, name, tier, status: 'active' });
        await auditLog(trx, {
          actor_id: actorId,
          action: 'user_created',
          resource_type: 'user',
          resource_id: userId,
          new_value: { email, tier },
        });
        if (notify) await sendLinkEmail(trx, { id: userId, email }, 'invite');
        return { success: true, user_id: userId, email, tier, created_at: new Date(now()).toISOString() };
      });
    }
    if (action === 'reset_password') {
      const userId = toId(req.body.user_id);
      if (!userId) throw new AdminError(400, 'missing_params', 'user_id required');
      if (userId === actorId) {
        throw new AdminError(400, 'cannot_reset_own_password', 'Cannot reset own password');
      }
      return knex.transaction(async (trx) => {
        const user = await trx('users').where({ id: userId }).first();
        if (!user) throw new AdminError(404, 'user_not_found', 'User not found');
        if (user.tier === 'owner' && user.status === 'active' && (await activeOwnerCount(trx)) <= 1) {
          throw new AdminError(400, 'cannot_reset_last_owner', 'Cannot reset the last active owner');
        }
        await auditLog(trx, {
          actor_id: actorId, action: 'password_reset_initiated', resource_type: 'user', resource_id: userId,
        });
        await sendLinkEmail(trx, user, 'reset');
        return { success: true, status: 'reset_email_sent' };
      });
    }
    if (action === 'change_role') {
      const userId = toId(req.body.user_id);
      if (!userId || !req.body.new_tier) throw new AdminError(400, 'missing_params', 'user_id, new_tier required');
      // Gate user_id != current_user_id runs before the checks (spec change_role), so a direct change_role never
      // reaches the last active owner; only a governance approval can (ADMIN-07, Phase B.3, 2026-11-10,
      // session_012zDydZCZ4AChqhEZ4oVtaP).
      if (userId === actorId) throw new AdminError(400, 'cannot_change_own_role', 'Cannot change own role');
      const out = await knex.transaction((trx) => changeRole(trx, actorId, userId, req.body.new_tier));
      return { success: true, ...out };
    }
    if (action === 'suspend') {
      const userId = toId(req.body.user_id);
      const { reason } = req.body;
      if (!userId || !reason) throw new AdminError(400, 'missing_params', 'user_id, reason required');
      const out = await knex.transaction((trx) => suspendUser(trx, actorId, userId, reason));
      return { success: true, ...out };
    }
    throw new AdminError(400, 'unknown_action', 'Unknown action');
  }));

  // ------------------------------------------------------------ CUSTOMERS DOMAIN
  /**
   * GET /admin/customers (admin or owner): page (default 1), limit (1-100, default 10).
   * Out: [{ customer_id, email, name, tier, signup_date, invoice_count, status }].
   * Why: spec endpoint; rebuilt 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP behind the token gate (see module header). Touches: database (read).
   */
  app.get('/admin/customers', requireAdminOrOwner, route(async (req) => {
    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 10, 1), MAX_PAGE_SIZE);
    return knex('customers')
      .select('id as customer_id', 'email', 'name', 'tier', 'signup_date', 'invoice_count', 'status')
      .orderBy('id')
      .limit(limit)
      .offset((page - 1) * limit);
  }));

  /**
   * GET /admin/customers/:id (admin or owner). Out: the spec's detail object, or 404.
   * Why: spec endpoint; rebuilt 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP behind the token gate (see module header). Touches: database (read).
   */
  app.get('/admin/customers/:id', requireAdminOrOwner, route(async (req) => {
    const id = toId(req.params.id);
    const customer = id ? await knex('customers').where({ id }).first() : null;
    if (!customer) throw new AdminError(404, 'customer_not_found', 'Customer not found');
    return {
      customer_id: customer.id,
      email: customer.email,
      name: customer.name,
      tier: customer.tier,
      subscription_status: customer.subscription_status,
      payment_method: customer.payment_method,
      address: customer.address,
      notes: customer.notes,
    };
  }));

  /**
   * POST /admin/customers/:id/action (owner): change_plan (Stripe subscription update) | queue_refund (against
   * a succeeded invoice of this customer, never more than its amount). Out: { success: true, ... } or { error, message }.
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] change_plan follows billing flow 2 (ADMIN-12 amended): 400 invalid_tier
   * unless new_tier is a PLAN (solo, team, enterprise; a staff role is refused, Phase B.2),
   * then stripe.subscriptions.retrieve and 409 subscription_item_ambiguous unless exactly one item, then
   * update({items: [{id: current_item_id, price}], proration_behavior: 'create_prorations'}).
   * Why: spec endpoint; rebuilt 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP behind the token gate (see module header). Touches: database, Stripe (money).
   */
  app.post('/admin/customers/:id/action', requireOwner, route(async (req) => {
    const { action } = req.body;
    const actorId = req.user.id;
    const customerId = toId(req.params.id);
    const customer = customerId ? await knex('customers').where({ id: customerId }).first() : null;
    if (!customer) throw new AdminError(404, 'customer_not_found', 'Customer not found');

    if (action === 'change_plan') {
      const newTier = req.body.new_tier;
      if (!newTier) throw new AdminError(400, 'missing_params', 'new_tier required');
      if (!validatePlan(newTier)) throw new AdminError(400, 'invalid_tier', 'new_tier must be solo, team or enterprise');
      if (!stripe) throw new AdminError(503, 'billing_not_configured', 'Billing provider is not configured');
      // [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] ADMIN-12 / billing flow 2: read the subscription's one item and
      // update THAT item to the new price. A bare {price} makes Stripe add a second item and bill both plans. Zero or
      // several items -> 409 subscription_item_ambiguous, before any update.
      const current = await stripe.subscriptions.retrieve(customer.stripe_subscription_id);
      const items = current && current.items && Array.isArray(current.items.data) ? current.items.data : [];
      if (items.length !== 1 || !items[0] || !items[0].id) {
        throw new AdminError(409, 'subscription_item_ambiguous', 'The subscription must have exactly one item');
      }
      await stripe.subscriptions.update(customer.stripe_subscription_id, {
        items: [{ id: items[0].id, price: priceIds[newTier] }],
        proration_behavior: 'create_prorations',
      });
      await knex.transaction(async (trx) => {
        await trx('customers').where({ id: customerId }).update({ tier: newTier });
        await auditLog(trx, {
          actor_id: actorId,
          action: 'plan_changed',
          resource_type: 'customer',
          resource_id: customerId,
          old_value: { tier: customer.tier },
          new_value: { tier: newTier },
        });
      });
      return {
        success: true,
        customer_id: customerId,
        old_tier: customer.tier,
        new_tier: newTier,
        effective_date: new Date(now()).toISOString(),
      };
    }
    if (action === 'queue_refund') {
      const invoiceId = toId(req.body.invoice_id);
      const amount = Number(req.body.amount);
      const { reason } = req.body;
      if (!invoiceId || !reason || !(amount > 0)) {
        throw new AdminError(400, 'missing_params', 'invoice_id, amount (> 0), reason required');
      }
      return knex.transaction(async (trx) => {
        const invoice = await trx('invoices').where({ id: invoiceId, customer_id: customerId }).first();
        if (!invoice) throw new AdminError(404, 'invoice_not_found', 'Invoice not found for this customer');
        if (invoice.status !== 'succeeded') {
          throw new AdminError(400, 'invoice_not_refundable', 'Only succeeded invoices can be refunded');
        }
        const already = await trx('refunds').where({ invoice_id: invoiceId }).whereNot({ status: 'cancelled' })
          .sum('amount as total').first();
        if (Math.round((Number(already.total || 0) + amount) * 100) > Math.round(Number(invoice.amount) * 100)) {
          throw new AdminError(400, 'refund_exceeds_invoice', 'Refunds would exceed the invoice amount');
        }
        const [refundId] = await trx('refunds').insert({
          customer_id: customerId, invoice_id: invoiceId, amount, reason, created_by: actorId, status: 'queued',
        });
        await auditLog(trx, {
          actor_id: actorId,
          action: 'refund_queued',
          resource_type: 'refund',
          resource_id: refundId,
          new_value: { invoice_id: invoiceId, amount },
          reason,
        });
        return { success: true, refund_id: refundId, status: 'queued', amount };
      });
    }
    throw new AdminError(400, 'unknown_action', 'Unknown action');
  }));

  // ---------------------------------------------------------- DEPLOYMENTS DOMAIN
  /**
   * GET /admin/deployments (admin or owner). Out: [{ deployment_id, customer_id, domain, tier, status, theme, published_at }].
   * Why: spec endpoint; rebuilt 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP behind the token gate (see module header). Touches: database (read).
   */
  app.get('/admin/deployments', requireAdminOrOwner, route(async () => knex('deployments')
    .select('id as deployment_id', 'customer_id', 'domain', 'tier', 'status', 'theme', 'published_at')
    .orderBy('id')));

  /**
   * POST /admin/deployments/action (owner): create | publish (also needs safetyFlags.can_publish) | suspend | retire.
   * In: { action, ... }; create takes { customer_id, domain, tier, theme_id }: tier is the PLAN (solo, team,
   * enterprise; a staff role is 400 invalid_tier), and theme_id must be one of the configured `themes`
   * (createAdminSystem option, default ['default']), else 404 theme_not_found. A new deployment has
   * domain_verified false; publish needs status 'draft', domain_verified (else 400 domain_not_verified) and a theme.
   * Out: { success: true, ... } or { error, message }.
   * Why: spec endpoint; rebuilt 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP behind the token gate (see module header).
   * Changed the same day (CodeRabbit review on PR 19): create checks theme_id against the configured theme list
   * instead of requiring an existing deployment to use it, so a fresh database can create its first deployment.
   * Phase B.2 the same day: the tier is checked as a plan, and publish requires domain_verified.
   * Touches: database.
   */
  app.post('/admin/deployments/action', requireOwner, route(async (req) => {
    const { action } = req.body;
    const actorId = req.user.id;
    if (action === 'create') {
      const customerId = toId(req.body.customer_id);
      const { domain, tier, theme_id: themeId } = req.body;
      if (!customerId || !domain || !tier || !themeId) {
        throw new AdminError(400, 'missing_params', 'customer_id, domain, tier, theme_id required');
      }
      if (!validatePlan(tier)) throw new AdminError(400, 'invalid_tier', 'tier must be solo, team or enterprise');
      return knex.transaction(async (trx) => {
        if (!(await trx('customers').where({ id: customerId }).first())) {
          throw new AdminError(404, 'customer_not_found', 'Customer not found');
        }
        if (await trx('deployments').where({ domain }).first()) {
          throw new AdminError(400, 'domain_taken', 'Domain already registered');
        }
        // Themes have no table of their own in this template: the configured `themes` list is the catalogue.
        if (!themes.has(themeId)) {
          throw new AdminError(404, 'theme_not_found', 'Theme not found');
        }
        const [deploymentId] = await trx('deployments').insert({
          customer_id: customerId, domain, tier, status: 'draft', theme: themeId,
        });
        await auditLog(trx, {
          actor_id: actorId,
          action: 'deployment_created',
          resource_type: 'deployment',
          resource_id: deploymentId,
          new_value: { customer_id: customerId, domain, tier, theme: themeId },
        });
        return { success: true, deployment_id: deploymentId, domain, tier };
      });
    }

    const deploymentId = toId(req.body.deployment_id);
    if (!deploymentId) throw new AdminError(400, 'missing_params', 'deployment_id required');
    return knex.transaction(async (trx) => {
      const deployment = await trx('deployments').where({ id: deploymentId }).first();
      if (!deployment) throw new AdminError(404, 'deployment_not_found', 'Deployment not found');
      if (action === 'publish') {
        if (!safetyFlags.can_publish) {
          throw new AdminError(403, 'publish_not_allowed', 'Publishing is switched off by the safety flag');
        }
        if (deployment.status !== 'draft') {
          throw new AdminError(400, 'invalid_status', 'Only draft deployments can be published');
        }
        if (!deployment.domain_verified) {
          throw new AdminError(400, 'domain_not_verified', 'The deployment\'s domain is not verified');
        }
        if (!deployment.theme) throw new AdminError(400, 'theme_not_set', 'Theme must be set before publishing');
        await trx('deployments').where({ id: deploymentId })
          .update({ status: 'live', published_at: new Date(now()).toISOString() });
        await auditLog(trx, {
          actor_id: actorId, action: 'deployment_published', resource_type: 'deployment', resource_id: deploymentId,
          old_value: { status: deployment.status }, new_value: { status: 'live' },
        });
        return { success: true, deployment_id: deploymentId, status: 'live', public_url: `https://${deployment.domain}` };
      }
      if (action === 'suspend') {
        const { reason } = req.body;
        if (!reason) throw new AdminError(400, 'missing_params', 'deployment_id, reason required');
        await trx('deployments').where({ id: deploymentId }).update({ status: 'suspended', suspend_reason: reason });
        await auditLog(trx, {
          actor_id: actorId, action: 'deployment_suspended', resource_type: 'deployment', resource_id: deploymentId,
          old_value: { status: deployment.status }, new_value: { status: 'suspended' }, reason,
        });
        return { success: true, deployment_id: deploymentId, status: 'suspended' };
      }
      if (action === 'retire') {
        await trx('deployments').where({ id: deploymentId })
          .update({ status: 'archived', archived_at: new Date(now()).toISOString() });
        await auditLog(trx, {
          actor_id: actorId, action: 'deployment_archived', resource_type: 'deployment', resource_id: deploymentId,
          old_value: { status: deployment.status }, new_value: { status: 'archived' },
        });
        return { success: true, deployment_id: deploymentId, status: 'archived' };
      }
      throw new AdminError(400, 'unknown_action', 'Unknown action');
    });
  }));

  // ----------------------------------------------------------- GOVERNANCE DOMAIN
  /**
   * GET /admin/governance/actions (admin or owner): pending approvals, paginated (limit 1-100, offset).
   * Why: spec endpoint; rebuilt 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP behind the token gate (see module header). Touches: database (read).
   */
  app.get('/admin/governance/actions', requireAdminOrOwner, route(async (req) => {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), MAX_PAGE_SIZE);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
    return knex('governance_actions')
      .select('id as action_id', 'action_type', 'actor_id as actor', 'target_resource_id', 'reason', 'submitted_at',
        'status')
      .where({ status: 'pending' })
      .orderBy('id')
      .limit(limit)
      .offset(offset);
  }));

  /**
   * Runs the action a governance request asked for, inside the approval's transaction.
   * In: transaction, approver id, the governance_actions row. Out: a short result object for the audit log.
   * Why: spec "decide=approve → execute the original action"; the old code only marked it approved (2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: database.
   */
  async function executeGovernanceAction(trx, approverId, action) {
    const payload = action.payload ? JSON.parse(action.payload) : {};
    const target = toId(action.target_resource_id);
    switch (action.action_type) {
      case 'suspend_user':
        return suspendUser(trx, approverId, target, action.reason || 'governance approval');
      case 'change_role':
        return changeRole(trx, approverId, target, payload.new_tier);
      case 'suspend_deployment': {
        const changed = await trx('deployments').where({ id: target })
          .update({ status: 'suspended', suspend_reason: action.reason || 'governance approval' });
        if (!changed) throw new AdminError(404, 'deployment_not_found', 'Deployment not found');
        return { deployment_id: target, status: 'suspended' };
      }
      default:
        throw new AdminError(400, 'unsupported_action_type', `Cannot execute ${action.action_type}`);
    }
  }

  /**
   * POST /admin/governance/actions/:id/decide (owner): approve (executes the action; not by its submitter) |
   * reject (needs reason). Out: { success: true, action_id, status }.
   * Why: spec endpoint; rebuilt 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP behind the token gate (see module header). Touches: database.
   */
  app.post('/admin/governance/actions/:id/decide', requireOwner, route(async (req) => {
    const actionId = toId(req.params.id);
    const { decide, reason } = req.body;
    if (!actionId) throw new AdminError(404, 'action_not_found', 'Action not found');
    if (decide !== 'approve' && decide !== 'reject') {
      throw new AdminError(400, 'unknown_decide', 'decide must be approve or reject');
    }
    if (decide === 'reject' && !reason) {
      throw new AdminError(400, 'missing_reason', 'Reason required for rejection');
    }
    return knex.transaction(async (trx) => {
      const action = await trx('governance_actions').where({ id: actionId }).first();
      if (!action) throw new AdminError(404, 'action_not_found', 'Action not found');
      if (action.status !== 'pending') throw new AdminError(400, 'already_decided', 'Action already decided');
      if (decide === 'approve') {
        if (action.actor_id === req.user.id) {
          throw new AdminError(403, 'cannot_approve_own_action', 'Another owner must approve this action');
        }
        const result = await executeGovernanceAction(trx, req.user.id, action);
        await trx('governance_actions').where({ id: actionId }).update({
          status: 'approved',
          approved_by: req.user.id,
          approved_at: new Date(now()).toISOString(),
          execution_result: JSON.stringify(result),
        });
        await auditLog(trx, {
          actor_id: req.user.id,
          action: 'action_approved',
          resource_type: 'governance_action',
          resource_id: actionId,
          old_value: { status: 'pending' },
          new_value: { status: 'approved', execution_result: result },
        });
        return { success: true, action_id: actionId, status: 'approved' };
      }
      await trx('governance_actions').where({ id: actionId }).update({ status: 'rejected', rejection_reason: reason });
      await auditLog(trx, {
        actor_id: req.user.id,
        action: 'action_rejected',
        resource_type: 'governance_action',
        resource_id: actionId,
        old_value: { status: 'pending' },
        new_value: { status: 'rejected' },
        reason,
      });
      return { success: true, action_id: actionId, status: 'rejected' };
    });
  }));

  /**
   * GET /admin/governance/audit-log (admin or owner): filters action_type, resource_id, date_from, date_to;
   * limit (1-100, default 100), offset. Out: audit rows in the spec's shape.
   * Why: spec endpoint; rebuilt 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP behind the token gate (see module header). Touches: database (read).
   */
  app.get('/admin/governance/audit-log', requireAdminOrOwner, route(async (req) => {
    const { action_type: actionType, resource_id: resourceId, date_from: dateFrom, date_to: dateTo } = req.query;
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), MAX_PAGE_SIZE);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
    let query = knex('audit_logs')
      .select('timestamp', 'actor_id', 'action', 'resource_type', 'resource_id', 'old_value', 'new_value', 'reason');
    if (actionType) query = query.where({ action: String(actionType) });
    if (resourceId && toId(resourceId)) query = query.where({ resource_id: toId(resourceId) });
    if (dateFrom) query = query.where('timestamp', '>=', String(dateFrom));
    if (dateTo) query = query.where('timestamp', '<=', String(dateTo));
    return query.orderBy('id').limit(limit).offset(offset);
  }));

  // Body that is not JSON, or any error a middleware passed on: one JSON answer, no stack trace.
  app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
    if (err && err.type === 'entity.parse.failed') {
      return res.status(400).json({ error: 'invalid_json', message: 'Request body is not valid JSON' });
    }
    console.error('admin request failed:', err && err.message);
    return res.status(500).json({ error: 'internal_error', message: 'Internal server error' });
  });

  return { app, knex, runMigrations: (opts) => runMigrations(knex, opts), csrfTokenFor, mailer, safetyFlags };
}

// Run as a server: `JWT_SECRET=... ADMIN_CSRF_SECRET=... STRIPE_SECRET_KEY=... node admin_system_javascript.js`
if (require.main === module) {
  const system = createAdminSystem({ knex: createDatabase(process.env.ADMIN_DB_FILE || 'admin.sqlite3') });
  system.runMigrations().then(() => {
    const port = Number(process.env.PORT) || 3000;
    system.app.listen(port, () => console.log(`Admin system listening on ${port}`));
  });
}

module.exports = {
  createAdminSystem,
  createDatabase,
  runMigrations,
  InMemoryMailer,
  validateEmail,
  VALID_TIERS,
  PLAN_TIERS,
};
