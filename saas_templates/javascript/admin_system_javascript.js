const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const knexLib = require('knex');
const stripeLib = require('stripe');
const { v4: uuidv4 } = require('uuid');
const moment = require('moment');
const { rateLimit } = require('express-rate-limit');

// ---------- Configuration ----------
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || 'sk_test_123';
const stripe = stripeLib(STRIPE_SECRET_KEY);
const CSRF_SECRET = 'csrf_secret';
const SAFETY_FLAGS = { can_publish: true };

// ---------- Database ----------
const knex = knexLib({
  client: 'sqlite3',
  connection: { filename: ':memory:' },
  useNullAsDefault: true,
});

async function runMigrations() {
  await knex.schema.dropTableIfExists('audit_logs');
  await knex.schema.dropTableIfExists('refunds');
  await knex.schema.dropTableIfExists('governance_actions');
  await knex.schema.dropTableIfExists('deployments');
  await knex.schema.dropTableIfExists('customers');
  await knex.schema.dropTableIfExists('users');

  await knex.schema.createTable('users', (t) => {
    t.increments('id').primary();
    t.string('email').unique().notNullable();
    t.string('name').notNullable();
    t.string('tier').notNullable(); // owner, admin, user
    t.string('status').defaultTo('active'); // active, suspended
    t.timestamps(true, true);
  });

  await knex.schema.createTable('customers', (t) => {
    t.increments('id').primary();
    t.string('email').notNullable();
    t.string('name').notNullable();
    t.string('tier').notNullable();
    t.date('signup_date').notNullable();
    t.integer('invoice_count').defaultTo(0);
    t.string('status').defaultTo('active');
    t.string('subscription_status').defaultTo('active');
    t.string('payment_method').notNullable();
    t.string('address').notNullable();
    t.text('notes');
    t.string('stripe_subscription_id').notNullable();
  });

  await knex.schema.createTable('deployments', (t) => {
    t.increments('id').primary();
    t.integer('customer_id').unsigned().references('id').inTable('customers');
    t.string('domain').notNullable();
    t.string('tier').notNullable();
    t.string('status').defaultTo('draft'); // draft, live, suspended, archived
    t.string('theme').notNullable();
    t.timestamp('published_at');
    t.string('suspend_reason');
    t.timestamp('archived_at');
  });

  await knex.schema.createTable('audit_logs', (t) => {
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

  await knex.schema.createTable('refunds', (t) => {
    t.increments('id').primary();
    t.integer('invoice_id').notNullable();
    t.decimal('amount', 10, 2).notNullable();
    t.string('reason').notNullable();
    t.integer('created_by').unsigned();
    t.timestamp('created_at').defaultTo(knex.fn.now());
    t.string('status').defaultTo('queued');
  });

  await knex.schema.createTable('governance_actions', (t) => {
    t.increments('id').primary();
    t.string('action_type').notNullable();
    t.integer('actor_id').unsigned();
    t.integer('target_resource_id');
    t.string('reason');
    t.timestamp('submitted_at').defaultTo(knex.fn.now());
    t.string('status').defaultTo('pending'); // pending, approved, rejected
    t.integer('approved_by').unsigned();
    t.timestamp('approved_at');
    t.string('rejection_reason');
  });
}

// ---------- Middleware ----------
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
app.use(adminLimiter);
app.use(bodyParser.json());
app.use(cookieParser());
app.use(csrf({ cookie: true }));

function verifyCsrf(req, res, next) {
  // CSRF token is expected in header X-CSRF-Token
  const token = req.headers['x-csrf-token'];
  if (!token || token !== CSRF_SECRET) {
    return res.status(403).json({ error: 'csrf_token_invalid', message: 'Invalid CSRF token' });
  }
  next();
}

function mockAuth(req, res, next) {
  // For simplicity, use headers X-User-Id and X-User-Role
  const id = parseInt(req.headers['x-user-id'], 10);
  const role = req.headers['x-user-role'];
  if (!id || !role) {
    return res.status(401).json({ error: 'unauthenticated', message: 'Missing auth headers' });
  }
  req.user = { id, role };
  next();
}

function requireOwner(req, res, next) {
  if (req.user.role !== 'owner') {
    return res.status(403).json({ error: 'owner_only', message: 'Owner role required' });
  }
  next();
}

function requireAdminOrOwner(req, res, next) {
  if (req.user.role !== 'owner' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'admin_or_owner', message: 'Admin or Owner role required' });
  }
  next();
}

async function auditLog({ actor_id, action, resource_type, resource_id, old_value, new_value, reason }) {
  await knex('audit_logs').insert({
    actor_id,
    action,
    resource_type,
    resource_id,
    old_value: old_value ? JSON.stringify(old_value) : null,
    new_value: new_value ? JSON.stringify(new_value) : null,
    reason,
  });
}

// ---------- Helpers ----------
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

function validateName(name) {
  return typeof name === 'string' && name.length >= 3 && name.length <= 50;
}

const VALID_TIERS = ['owner', 'admin', 'user'];

function validateTier(tier) {
  return VALID_TIERS.includes(tier);
}

// ---------- Routes ----------
app.use('/admin', mockAuth, verifyCsrf);

// USERS DOMAIN
app.post('/admin/users/action', requireOwner, async (req, res) => {
  const { action } = req.body;
  try {
    if (action === 'create') {
      const { email, name, tier, notify } = req.body;
      if (!email || !name || !tier) {
        return res.status(400).json({ error: 'missing_params', message: 'email, name, tier required' });
      }
      if (!validateEmail(email)) {
        return res.status(400).json({ error: 'invalid_email', message: 'Invalid email format' });
      }
      if (!validateName(name)) {
        return res.status(400).json({ error: 'invalid_name', message: 'Name must be 3-50 chars' });
      }
      if (!validateTier(tier)) {
        return res.status(400).json({ error: 'invalid_tier', message: 'Invalid tier' });
      }
      const existing = await knex('users').where({ email }).first();
      if (existing) {
        return res.status(409).json({ error: 'email_exists', message: 'Email already exists' });
      }
      const [user_id] = await knex('users').insert({ email, name, tier, status: 'active' });
      await auditLog({
        actor_id: req.user.id,
        action: 'user_created',
        resource_type: 'user',
        resource_id: user_id,
        new_value: { email, tier },
      });
      // Simulate invite email
      if (notify) {
        console.log(`Invite sent to ${email}`);
      }
      const created_at = new Date().toISOString();
      return res.json({ success: true, user_id, email, tier, created_at });
    } else if (action === 'reset_password') {
      const { user_id } = req.body;
      if (!user_id) {
        return res.status(400).json({ error: 'missing_params', message: 'user_id required' });
      }
      if (user_id === req.user.id) {
        return res.status(400).json({ error: 'cannot_reset_own_password', message: 'Cannot reset own password' });
      }
      const user = await knex('users').where({ id: user_id }).first();
      if (!user) {
        return res.status(404).json({ error: 'user_not_found', message: 'User not found' });
      }
      const lastOwner = await knex('users').where({ tier: 'owner', status: 'active' }).count('id as cnt').first();
      if (lastOwner.cnt === 1 && user.tier === 'owner') {
        return res.status(400).json({ error: 'cannot_demote_last_owner', message: 'Cannot demote last active owner' });
      }
      const resetToken = uuidv4();
      // Simulate email
      console.log(`Password reset link for user ${user.email}: https://example.com/reset?token=${resetToken}`);
      await auditLog({
        actor_id: req.user.id,
        action: 'password_reset_initiated',
        resource_type: 'user',
        resource_id: user_id,
      });
      return res.json({ success: true, status: 'reset_email_sent' });
    } else if (action === 'change_role') {
      const { user_id, new_tier } = req.body;
      if (!user_id || !new_tier) {
        return res.status(400).json({ error: 'missing_params', message: 'user_id, new_tier required' });
      }
      if (user_id === req.user.id) {
        return res.status(400).json({ error: 'cannot_change_own_role', message: 'Cannot change own role' });
      }
      if (!validateTier(new_tier)) {
        return res.status(400).json({ error: 'invalid_tier', message: 'Invalid tier' });
      }
      const user = await knex('users').where({ id: user_id }).first();
      if (!user) {
        return res.status(404).json({ error: 'user_not_found', message: 'User not found' });
      }
      if (user.tier === 'owner' && new_tier !== 'owner') {
        const ownerCount = await knex('users').where({ tier: 'owner', status: 'active' }).count('id as cnt').first();
        if (ownerCount.cnt <= 1) {
          return res.status(400).json({ error: 'cannot_demote_last_owner', message: 'Cannot demote last active owner' });
        }
      }
      const old_tier = user.tier;
      await knex('users').where({ id: user_id }).update({ tier: new_tier });
      await auditLog({
        actor_id: req.user.id,
        action: 'role_changed',
        resource_type: 'user',
        resource_id: user_id,
        old_value: { tier: old_tier },
        new_value: { tier: new_tier },
      });
      return res.json({ success: true, user_id, old_tier, new_tier });
    } else if (action === 'suspend') {
      const { user_id, reason } = req.body;
      if (!user_id || !reason) {
        return res.status(400).json({ error: 'missing_params', message: 'user_id, reason required' });
      }
      if (user_id === req.user.id) {
        return res.status(400).json({ error: 'cannot_suspend_yourself', message: 'Cannot suspend yourself' });
      }
      const user = await knex('users').where({ id: user_id }).first();
      if (!user) {
        return res.status(404).json({ error: 'user_not_found', message: 'User not found' });
      }
      if (user.tier === 'owner') {
        const ownerCount = await knex('users').where({ tier: 'owner', status: 'active' }).count('id as cnt').first();
        if (ownerCount.cnt <= 1) {
          return res.status(400).json({ error: 'cannot_suspend_last_owner', message: 'Cannot suspend last active owner' });
        }
      }
      await knex('users').where({ id: user_id }).update({ status: 'suspended' });
      await auditLog({
        actor_id: req.user.id,
        action: 'user_suspended',
        resource_type: 'user',
        resource_id: user_id,
        reason,
      });
      return res.json({ success: true, user_id, suspended: true });
    } else {
      return res.status(400).json({ error: 'unknown_action', message: 'Unknown action' });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal_error', message: 'Internal server error' });
  }
});

// CUSTOMERS DOMAIN
app.get('/admin/customers', requireAdminOrOwner, async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 10;
  const offset = (page - 1) * limit;
  const customers = await knex('customers')
    .select('id as customer_id', 'email', 'name', 'tier', 'signup_date', 'invoice_count', 'status')
    .limit(limit)
    .offset(offset);
  res.json(customers);
});

app.get('/admin/customers/:id', requireAdminOrOwner, async (req, res) => {
  const customer = await knex('customers').where({ id: req.params.id }).first();
  if (!customer) {
    return res.status(404).json({ error: 'customer_not_found', message: 'Customer not found' });
  }
  res.json({
    customer_id: customer.id,
    email: customer.email,
    name: customer.name,
    tier: customer.tier,
    subscription_status: customer.subscription_status,
    payment_method: customer.payment_method,
    address: customer.address,
    notes: customer.notes,
  });
});

app.post('/admin/customers/:id/action', requireOwner, async (req, res) => {
  const { action } = req.body;
  const customer_id = parseInt(req.params.id, 10);
  try {
    if (action === 'change_plan') {
      const { new_tier } = req.body;
      if (!new_tier) {
        return res.status(400).json({ error: 'missing_params', message: 'new_tier required' });
      }
      if (!validateTier(new_tier)) {
        return res.status(400).json({ error: 'invalid_tier', message: 'Invalid tier' });
      }
      const customer = await knex('customers').where({ id: customer_id }).first();
      if (!customer) {
        return res.status(404).json({ error: 'customer_not_found', message: 'Customer not found' });
      }
      const old_tier = customer.tier;
      const price_id_map = { owner: 'price_owner', admin: 'price_admin', user: 'price_user' };
      await stripe.subscriptions.update(customer.stripe_subscription_id, {
        items: [{ price: price_id_map[new_tier] }],
      });
      await knex('customers').where({ id: customer_id }).update({ tier: new_tier });
      await auditLog({
        actor_id: req.user.id,
        action: 'plan_changed',
        resource_type: 'customer',
        resource_id: customer_id,
        old_value: { tier: old_tier },
        new_value: { tier: new_tier },
      });
      return res.json({ success: true, customer_id, old_tier, new_tier, effective_date: new Date().toISOString() });
    } else if (action === 'queue_refund') {
      const { invoice_id, amount, reason } = req.body;
      if (!invoice_id || !amount || !reason) {
        return res.status(400).json({ error: 'missing_params', message: 'invoice_id, amount, reason required' });
      }
      // For simplicity, assume invoice exists and succeeded
      const [refund_id] = await knex('refunds').insert({
        invoice_id,
        amount,
        reason,
        created_by: req.user.id,
        status: 'queued',
      });
      await auditLog({
        actor_id: req.user.id,
        action: 'refund_queued',
        resource_type: 'refund',
        resource_id: refund_id,
        new_value: { invoice_id, amount, reason },
      });
      return res.json({ success: true, refund_id, status: 'queued', amount });
    } else {
      return res.status(400).json({ error: 'unknown_action', message: 'Unknown action' });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal_error', message: 'Internal server error' });
  }
});

// DEPLOYMENTS DOMAIN
app.get('/admin/deployments', requireAdminOrOwner, async (req, res) => {
  const deployments = await knex('deployments')
    .select('id as deployment_id', 'customer_id', 'domain', 'tier', 'status', 'theme', 'published_at');
  res.json(deployments);
});

app.post('/admin/deployments/action', requireOwner, async (req, res) => {
  const { action } = req.body;
  try {
    if (action === 'create') {
      const { customer_id, domain, tier, theme_id } = req.body;
      if (!customer_id || !domain || !tier || !theme_id) {
        return res.status(400).json({ error: 'missing_params', message: 'customer_id, domain, tier, theme_id required' });
      }
      const customer = await knex('customers').where({ id: customer_id }).first();
      if (!customer) {
        return res.status(404).json({ error: 'customer_not_found', message: 'Customer not found' });
      }
      const domainExists = await knex('deployments').where({ domain }).first();
      if (domainExists) {
        return res.status(400).json({ error: 'domain_taken', message: 'Domain already registered' });
      }
      const themeExists = await knex('deployments').where({ theme: theme_id }).first(); // Simplified
      if (!themeExists) {
        return res.status(404).json({ error: 'theme_not_found', message: 'Theme not found' });
      }
      const [deployment_id] = await knex('deployments').insert({
        customer_id,
        domain,
        tier,
        status: 'draft',
        theme: theme_id,
      });
      await auditLog({
        actor_id: req.user.id,
        action: 'deployment_created',
        resource_type: 'deployment',
        resource_id: deployment_id,
        new_value: { customer_id, domain, tier, theme: theme_id },
      });
      return res.json({ success: true, deployment_id, domain, tier });
    } else if (action === 'publish') {
      const { deployment_id } = req.body;
      if (!deployment_id) {
        return res.status(400).json({ error: 'missing_params', message: 'deployment_id required' });
      }
      const deployment = await knex('deployments').where({ id: deployment_id }).first();
      if (!deployment) {
        return res.status(404).json({ error: 'deployment_not_found', message: 'Deployment not found' });
      }
      if (deployment.status !== 'draft') {
        return res.status(400).json({ error: 'invalid_status', message: 'Only draft deployments can be published' });
      }
      if (!SAFETY_FLAGS.can_publish) {
        return res.status(403).json({ error: 'publish_not_allowed', message: 'Publish not allowed' });
      }
      // Simplified checks: domain_verified, theme_set
      await knex('deployments').where({ id: deployment_id }).update({ status: 'live', published_at: knex.fn.now() });
      await auditLog({
        actor_id: req.user.id,
        action: 'deployment_published',
        resource_type: 'deployment',
        resource_id: deployment_id,
      });
      return res.json({ success: true, deployment_id, status: 'live', public_url: `https://${deployment.domain}` });
    } else if (action === 'suspend') {
      const { deployment_id, reason } = req.body;
      if (!deployment_id || !reason) {
        return res.status(400).json({ error: 'missing_params', message: 'deployment_id, reason required' });
      }
      const deployment = await knex('deployments').where({ id: deployment_id }).first();
      if (!deployment) {
        return res.status(404).json({ error: 'deployment_not_found', message: 'Deployment not found' });
      }
      await knex('deployments').where({ id: deployment_id }).update({ status: 'suspended', suspend_reason: reason });
      await auditLog({
        actor_id: req.user.id,
        action: 'deployment_suspended',
        resource_type: 'deployment',
        resource_id: deployment_id,
        reason,
      });
      return res.json({ success: true, deployment_id, status: 'suspended' });
    } else if (action === 'retire') {
      const { deployment_id } = req.body;
      if (!deployment_id) {
        return res.status(400).json({ error: 'missing_params', message: 'deployment_id required' });
      }
      const deployment = await knex('deployments').where({ id: deployment_id }).first();
      if (!deployment) {
        return res.status(404).json({ error: 'deployment_not_found', message: 'Deployment not found' });
      }
      await knex('deployments').where({ id: deployment_id }).update({ status: 'archived', archived_at: knex.fn.now() });
      await auditLog({
        actor_id: req.user.id,
        action: 'deployment_archived',
        resource_type: 'deployment',
        resource_id: deployment_id,
      });
      return res.json({ success: true, deployment_id, status: 'archived' });
    } else {
      return res.status(400).json({ error: 'unknown_action', message: 'Unknown action' });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal_error', message: 'Internal server error' });
  }
});

// GOVERNANCE DOMAIN
app.get('/admin/governance/actions', requireAdminOrOwner, async (req, res) => {
  const actions = await knex('governance_actions')
    .select('id as action_id', 'action_type', 'actor_id', 'target_resource_id', 'reason', 'submitted_at', 'status');
  res.json(actions);
});

app.post('/admin/governance/actions/:id/decide', requireOwner, async (req, res) => {
  const action_id = parseInt(req.params.id, 10);
  const { decide, reason } = req.body;
  try {
    const action = await knex('governance_actions').where({ id: action_id }).first();
    if (!action) {
      return res.status(404).json({ error: 'action_not_found', message: 'Action not found' });
    }
    if (action.status !== 'pending') {
      return res.status(400).json({ error: 'already_decided', message: 'Action already decided' });
    }
    if (decide === 'approve') {
      // Execute original action (simplified)
      // For demo, just mark approved
      await knex('governance_actions')
        .where({ id: action_id })
        .update({ status: 'approved', approved_by: req.user.id, approved_at: knex.fn.now() });
      await auditLog({
        actor_id: req.user.id,
        action: 'action_approved',
        resource_type: 'governance_action',
        resource_id: action_id,
        new_value: { status: 'approved' },
      });
      return res.json({ success: true, action_id, status: 'approved' });
    } else if (decide === 'reject') {
      if (!reason) {
        return res.status(400).json({ error: 'missing_reason', message: 'Reason required for rejection' });
      }
      await knex('governance_actions')
        .where({ id: action_id })
        .update({ status: 'rejected', rejection_reason: reason });
      await auditLog({
        actor_id: req.user.id,
        action: 'action_rejected',
        resource_type: 'governance_action',
        resource_id: action_id,
        reason,
      });
      return res.json({ success: true, action_id, status: 'rejected' });
    } else {
      return res.status(400).json({ error: 'unknown_decide', message: 'Unknown decide value' });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal_error', message: 'Internal server error' });
  }
});

app.get('/admin/governance/audit-log', requireAdminOrOwner, async (req, res) => {
  const { action_type, resource_id, date_from, date_to, limit = 100, offset = 0 } = req.query;
  let query = knex('audit_logs').select('*');
  if (action_type) query = query.where({ action: action_type });
  if (resource_id) query = query.where({ resource_id: parseInt(resource_id, 10) });
  if (date_from) query = query.where('timestamp', '>=', date_from);
  if (date_to) query = query.where('timestamp', '<=', date_to);
  const logs = await query.limit(parseInt(limit, 10)).offset(parseInt(offset, 10));
  res.json(logs);
});

// ---------- Export ----------
module.exports = { app, knex, runMigrations, CSRF_SECRET, SAFETY_FLAGS };