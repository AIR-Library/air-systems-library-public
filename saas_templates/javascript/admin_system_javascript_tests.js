const crypto = require('crypto');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const { createAdminSystem, InMemoryMailer } = require('./admin_system_javascript');

// Identity: an access token as the auth system issues it ({ user_id, tier }, HS256), signed with a secret made for
// this run. The admin system reads the caller's tier from the database, never from the token or a header.
// Stripe and e-mail are in-memory fakes, so nothing leaves the machine.
// (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: replaces X-User-Id/X-User-Role headers, which any client can set,
// and jest.mock('stripe'), whose automock has no `subscriptions` property, so the change_plan test could not run.)
const JWT_SECRET = crypto.randomBytes(32).toString('hex');
const stripe = { subscriptions: { update: jest.fn() } };
const mailer = new InMemoryMailer();
const { app, knex, runMigrations, csrfTokenFor } = createAdminSystem({
  jwtSecret: JWT_SECRET,
  csrfSecret: crypto.randomBytes(32).toString('hex'),
  stripe,
  mailer,
  priceIds: { owner: 'price_owner', admin: 'price_admin', user: 'price_user' },
});

describe('Admin System Tests', () => {
  beforeAll(async () => {
    await runMigrations();
    // Seed data
    await knex('users').insert([
      { id: 1, email: 'owner@example.com', name: 'Owner', tier: 'owner', status: 'active' },
      { id: 2, email: 'admin@example.com', name: 'Admin', tier: 'admin', status: 'active' },
      { id: 3, email: 'user@example.com', name: 'User', tier: 'user', status: 'active' },
    ]);
    await knex('customers').insert([
      {
        id: 1,
        email: 'cust@example.com',
        name: 'Customer',
        tier: 'user',
        signup_date: '2023-01-01',
        invoice_count: 5,
        status: 'active',
        subscription_status: 'active',
        payment_method: 'pm_123',
        address: '123 Main St',
        notes: 'Test customer',
        stripe_subscription_id: 'sub_123',
      },
    ]);
    await knex('invoices').insert([{ id: 10, customer_id: 1, amount: 100.0, status: 'succeeded' }]);
    await knex('deployments').insert([
      {
        id: 1,
        customer_id: 1,
        domain: 'example.com',
        tier: 'user',
        status: 'draft',
        theme: 'theme1',
      },
    ]);
    await knex('governance_actions').insert([
      {
        id: 1,
        action_type: 'suspend_user',
        actor_id: 2,
        target_resource_id: 3,
        reason: 'Violation',
        status: 'pending',
      },
    ]);
  });

  afterAll(async () => {
    await knex.destroy();
  });

  const agent = request.agent(app);

  const authHeaders = (userId, role) => ({
    Authorization: `Bearer ${jwt.sign({ user_id: userId, tier: role }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '15m' })}`,
    'X-CSRF-Token': csrfTokenFor(userId),
  });

  test('create user happy path → user created + invite sent', async () => {
    const res = await agent
      .post('/admin/users/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'create', email: 'new@example.com', name: 'New User', tier: 'user', notify: true });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    const user = await knex('users').where({ email: 'new@example.com' }).first();
    expect(user).toBeDefined();
    expect(user.tier).toBe('user');
    const invite = mailer.outbox.find((m) => m.to === 'new@example.com');
    expect(invite).toBeDefined();
    expect(invite.text).toMatch(/token=[a-f0-9]{64}/);
  });

  test('create user duplicate email → 409 {error: "email_exists"}', async () => {
    const res = await agent
      .post('/admin/users/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'create', email: 'user@example.com', name: 'Dup', tier: 'user' });
    expect(res.status).toBe(409);
    expect(res.body.error).toBe('email_exists');
  });

  test('create user non-owner → 403 {error: "owner_only"}', async () => {
    const res = await agent
      .post('/admin/users/action')
      .set(authHeaders(2, 'admin'))
      .send({ action: 'create', email: 'another@example.com', name: 'Another', tier: 'user' });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('owner_only');
  });

  test('reset_password happy path → email sent', async () => {
    const res = await agent
      .post('/admin/users/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'reset_password', user_id: 3 });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.status).toBe('reset_email_sent');
    const mail = mailer.outbox.find((m) => m.to === 'user@example.com');
    expect(mail).toBeDefined();
    const token = mail.text.match(/token=([a-f0-9]{64})/)[1];
    const stored = await knex('password_resets').where({ user_id: 3, purpose: 'reset' }).first();
    expect(stored.token_hash).toBe(crypto.createHash('sha256').update(token).digest('hex'));
  });

  test('reset_password own account → 400 {error: "cannot_reset_own_password"}', async () => {
    const res = await agent
      .post('/admin/users/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'reset_password', user_id: 1 });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('cannot_reset_own_password');
  });

  test('change_role happy path → role changed + audit logged', async () => {
    const res = await agent
      .post('/admin/users/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'change_role', user_id: 3, new_tier: 'admin' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    const user = await knex('users').where({ id: 3 }).first();
    expect(user.tier).toBe('admin');
  });

  test('change_role last_owner → 400 {error: "cannot_demote_last_owner"}', async () => {
    const res = await agent
      .post('/admin/users/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'change_role', user_id: 1, new_tier: 'admin' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('cannot_demote_last_owner');
  });

  test('suspend_user happy path → status changed', async () => {
    const res = await agent
      .post('/admin/users/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'suspend', user_id: 3, reason: 'Violation' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    const user = await knex('users').where({ id: 3 }).first();
    expect(user.status).toBe('suspended');
  });

  test('suspend_own_account → 400 {error: "cannot_suspend_yourself"}', async () => {
    const res = await agent
      .post('/admin/users/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'suspend', user_id: 1, reason: 'Self' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('cannot_suspend_yourself');
  });

  test('customers list → pagination works, all fields present', async () => {
    const res = await agent
      .get('/admin/customers')
      .set(authHeaders(2, 'admin'))
      .query({ page: 1, limit: 10 });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    const cust = res.body[0];
    expect(cust).toHaveProperty('customer_id');
    expect(cust).toHaveProperty('email');
    expect(cust).toHaveProperty('name');
    expect(cust).toHaveProperty('tier');
    expect(cust).toHaveProperty('signup_date');
    expect(cust).toHaveProperty('invoice_count');
    expect(cust).toHaveProperty('status');
  });

  test('customers detail → all fields present', async () => {
    const res = await agent
      .get('/admin/customers/1')
      .set(authHeaders(2, 'admin'));
    expect(res.status).toBe(200);
    const cust = res.body;
    expect(cust).toHaveProperty('customer_id');
    expect(cust).toHaveProperty('email');
    expect(cust).toHaveProperty('name');
    expect(cust).toHaveProperty('tier');
    expect(cust).toHaveProperty('subscription_status');
    expect(cust).toHaveProperty('payment_method');
    expect(cust).toHaveProperty('address');
    expect(cust).toHaveProperty('notes');
  });

  test('change_plan → stripe.subscriptions.update called, audit logged', async () => {
    stripe.subscriptions.update.mockResolvedValue({ id: 'sub_123' });
    const res = await agent
      .post('/admin/customers/1/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'change_plan', new_tier: 'admin' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    const customer = await knex('customers').where({ id: 1 }).first();
    expect(customer.tier).toBe('admin');
    expect(stripe.subscriptions.update).toHaveBeenCalled();
    expect(stripe.subscriptions.update).toHaveBeenCalledWith('sub_123', { items: [{ price: 'price_admin' }] });
    const audit = await knex('audit_logs').where({ action: 'plan_changed', resource_id: 1 }).first();
    expect(audit).toBeDefined();
  });

  test('queue_refund → refund record created with status=\'queued\'', async () => {
    const res = await agent
      .post('/admin/customers/1/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'queue_refund', invoice_id: 10, amount: 50.0, reason: 'Refund' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    const refund = await knex('refunds').where({ id: res.body.refund_id }).first();
    expect(refund).toBeDefined();
    expect(refund.status).toBe('queued');
  });

  test('create_deployment → deployment created + config initialized', async () => {
    const res = await agent
      .post('/admin/deployments/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'create', customer_id: 1, domain: 'newdomain.com', tier: 'user', theme_id: 'theme1' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    const deployment = await knex('deployments').where({ id: res.body.deployment_id }).first();
    expect(deployment).toBeDefined();
    expect(deployment.domain).toBe('newdomain.com');
  });

  test('publish_deployment → double-gate checked, status changed to \'live\'', async () => {
    const res = await agent
      .post('/admin/deployments/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'publish', deployment_id: 1 });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    const deployment = await knex('deployments').where({ id: 1 }).first();
    expect(deployment.status).toBe('live');
  });

  test('governance approve → action executed + status changed', async () => {
    const res = await agent
      .post('/admin/governance/actions/1/decide')
      .set(authHeaders(1, 'owner'))
      .send({ decide: 'approve' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    const action = await knex('governance_actions').where({ id: 1 }).first();
    expect(action.status).toBe('approved');
    const target = await knex('users').where({ id: 3 }).first();
    expect(target.status).toBe('suspended');
    expect(JSON.parse(action.execution_result)).toEqual({ user_id: 3, suspended: true });
  });

  test('governance reject → action rejected + reason logged', async () => {
    // Insert a new pending action
    await knex('governance_actions').insert({
      id: 2,
      action_type: 'suspend_user',
      actor_id: 2,
      target_resource_id: 3,
      reason: 'Violation',
      status: 'pending',
    });
    const res = await agent
      .post('/admin/governance/actions/2/decide')
      .set(authHeaders(1, 'owner'))
      .send({ decide: 'reject', reason: 'Not valid' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    const action = await knex('governance_actions').where({ id: 2 }).first();
    expect(action.status).toBe('rejected');
    expect(action.rejection_reason).toBe('Not valid');
  });

  test('audit_log search → correct filters applied, pagination works', async () => {
    const res = await agent
      .get('/admin/governance/audit-log')
      .set(authHeaders(2, 'admin'))
      .query({ limit: 10, offset: 0 });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeLessThanOrEqual(10);
  });

  // Added 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the gate must not be opened by anything the client controls.
  test('owner gate reads the tier from the database, not from the token or headers', async () => {
    const res = await agent
      .post('/admin/users/action')
      .set(authHeaders(2, 'owner'))
      .set('X-User-Role', 'owner')
      .send({ action: 'create', email: 'forged@example.com', name: 'Forged', tier: 'owner' });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('owner_only');
    expect(await knex('users').where({ email: 'forged@example.com' }).first()).toBeUndefined();
  });

  test('missing or forged access token → 401, wrong CSRF token → 403', async () => {
    const noToken = await agent.get('/admin/customers').set('X-User-Id', '1').set('X-User-Role', 'owner');
    expect(noToken.status).toBe(401);
    const forged = jwt.sign({ user_id: 1, tier: 'owner' }, 'not-the-server-secret', { algorithm: 'HS256' });
    const badSig = await agent.get('/admin/customers').set('Authorization', `Bearer ${forged}`);
    expect(badSig.status).toBe(401);
    const badCsrf = await agent
      .post('/admin/users/action')
      .set({ ...authHeaders(1, 'owner'), 'X-CSRF-Token': csrfTokenFor(2) })
      .send({ action: 'create', email: 'csrf@example.com', name: 'Csrf User', tier: 'user' });
    expect(badCsrf.status).toBe(403);
    expect(badCsrf.body.error).toBe('csrf_token_invalid');
  });
});