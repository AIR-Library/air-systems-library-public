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
const stripe = { subscriptions: { retrieve: jest.fn(), update: jest.fn() } };
const mailer = new InMemoryMailer();
const { app, knex, runMigrations, csrfTokenFor } = createAdminSystem({
  jwtSecret: JWT_SECRET,
  csrfSecret: crypto.randomBytes(32).toString('hex'),
  stripe,
  mailer,
  // Prices are keyed by PLAN (solo, team, enterprise), not by staff role (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP,
  // Phase B.2 admin spec TIERS: the two are never mixed).
  priceIds: { solo: 'price_solo', team: 'price_team', enterprise: 'price_enterprise' },
  // The seeded deployment and the create test use theme1, so it is configured (2026-11-10, session
  // session_012zDydZCZ4AChqhEZ4oVtaP: themes are now a configured list, CodeRabbit review on PR 19).
  themes: ['default', 'theme1'],
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
        tier: 'solo', // a customer's tier is the PLAN (was 'user', a staff role; Phase B.2, 2026-11-10)
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
        tier: 'solo', // the PLAN (was 'user'; Phase B.2, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
        status: 'draft',
        theme: 'theme1',
        domain_verified: true, // publish now needs a verified domain (Phase B.2); ADMIN-15 publishes this one
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

  // ADMIN-01
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

  // ADMIN-02
  test('create user duplicate email → 409 {error: "email_exists"}', async () => {
    const res = await agent
      .post('/admin/users/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'create', email: 'user@example.com', name: 'Dup', tier: 'user' });
    expect(res.status).toBe(409);
    expect(res.body.error).toBe('email_exists');
  });

  // ADMIN-03
  test('create user non-owner → 403 {error: "owner_only"}', async () => {
    const res = await agent
      .post('/admin/users/action')
      .set(authHeaders(2, 'admin'))
      .send({ action: 'create', email: 'another@example.com', name: 'Another', tier: 'user' });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('owner_only');
  });

  // ADMIN-04
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

  // ADMIN-05
  test('reset_password own account → 400 {error: "cannot_reset_own_password"}', async () => {
    const res = await agent
      .post('/admin/users/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'reset_password', user_id: 1 });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('cannot_reset_own_password');
  });

  // ADMIN-06
  test('change_role happy path → role changed + audit logged', async () => {
    const res = await agent
      .post('/admin/users/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'change_role', user_id: 3, new_tier: 'admin' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    const user = await knex('users').where({ id: 3 }).first();
    expect(user.tier).toBe('admin');
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: ADMIN-06 also requires the audit row; it was not checked.
    const audit = await knex('audit_logs').where({ action: 'role_changed', resource_id: 3 }).first();
    expect(audit).toBeDefined();
  });

  /**
   * change_role on the caller's own account is refused by the gate user_id != current_user_id (400
   * cannot_change_own_role), even for the last active owner: the spec runs the gate before the last-owner check, so a
   * direct change_role never reaches that check (Phase B.3; ADMIN-07 is proven through governance below).
   * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (it expected cannot_demote_last_owner, the answer of the
   * old check order). Touches the test database.
   */
  test('change_role own role → 400 {error: "cannot_change_own_role"}, role unchanged', async () => {
    const res = await agent
      .post('/admin/users/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'change_role', user_id: 1, new_tier: 'admin' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('cannot_change_own_role');
    expect((await knex('users').where({ id: 1 }).first()).tier).toBe('owner');
  });

  /**
   * ADMIN-07 (Phase B.3): the last active owner is reached only through a governance-approved change_role. The
   * owner approving a change_role (submitted by an admin) that would demote the last active owner gets 400
   * cannot_demote_last_owner; the action stays pending, the owner keeps the role, and no audit row is written.
   * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the test database.
   */
  // ADMIN-07
  test('governance-approved change_role demoting the last active owner → 400 {error: "cannot_demote_last_owner"}, still pending', async () => {
    await knex('governance_actions').insert({
      id: 70, action_type: 'change_role', actor_id: 2, target_resource_id: 1, reason: 'Rotate ownership',
      status: 'pending', payload: JSON.stringify({ new_tier: 'admin' }),
    });
    const auditBefore = (await knex('audit_logs').count('id as n').first()).n;
    const res = await agent
      .post('/admin/governance/actions/70/decide')
      .set(authHeaders(1, 'owner'))
      .send({ decide: 'approve' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('cannot_demote_last_owner');
    const action = await knex('governance_actions').where({ id: 70 }).first();
    expect(action.status).toBe('pending');
    expect(action.approved_by).toBeNull();
    expect((await knex('users').where({ id: 1 }).first()).tier).toBe('owner');
    expect((await knex('audit_logs').count('id as n').first()).n).toBe(auditBefore);
  });

  // ADMIN-08
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

  // ADMIN-09
  test('suspend_own_account → 400 {error: "cannot_suspend_yourself"}', async () => {
    const res = await agent
      .post('/admin/users/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'suspend', user_id: 1, reason: 'Self' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('cannot_suspend_yourself');
  });

  // ADMIN-10
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

  // ADMIN-11
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

  // ADMIN-12
  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the update now names the existing item (spec amended); a bare
  // {price} adds a second item and bills both plans, so the expected call changed. Phase B.2, same day: the new tier
  // is a PLAN ('team'; it was 'admin', a staff role, which is now 400 invalid_tier).
  test('change_plan → stripe.subscriptions.update called with the existing item id, audit logged', async () => {
    stripe.subscriptions.retrieve.mockResolvedValue({ id: 'sub_123', items: { data: [{ id: 'si_current', price: { id: 'price_solo' } }] } });
    stripe.subscriptions.update.mockResolvedValue({ id: 'sub_123' });
    const res = await agent
      .post('/admin/customers/1/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'change_plan', new_tier: 'team' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.old_tier).toBe('solo');
    expect(res.body.new_tier).toBe('team');
    const customer = await knex('customers').where({ id: 1 }).first();
    expect(customer.tier).toBe('team');
    expect(stripe.subscriptions.update).toHaveBeenCalled();
    expect(stripe.subscriptions.retrieve).toHaveBeenCalledWith('sub_123');
    expect(stripe.subscriptions.update).toHaveBeenCalledTimes(1);
    expect(stripe.subscriptions.update).toHaveBeenCalledWith('sub_123', {
      items: [{ id: 'si_current', price: 'price_team' }],
      proration_behavior: 'create_prorations',
    });
    const audit = await knex('audit_logs').where({ action: 'plan_changed', resource_id: 1 }).first();
    expect(audit).toBeDefined();
  });

  /**
   * ADMIN-12: a subscription with two items is 409 subscription_item_ambiguous and Stripe is never updated; the tier
   * stays as it was. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the test database and the Stripe fake.
   */
  // ADMIN-12
  test('change_plan on a subscription with two items → 409 subscription_item_ambiguous, no update', async () => {
    stripe.subscriptions.retrieve.mockResolvedValue({ id: 'sub_123', items: { data: [{ id: 'si_a' }, { id: 'si_b' }] } });
    stripe.subscriptions.update.mockClear();
    const before = await knex('customers').where({ id: 1 }).first();
    const res = await agent
      .post('/admin/customers/1/action')
      .set(authHeaders(1, 'owner'))
      .send({ action: 'change_plan', new_tier: 'enterprise' }); // a PLAN (was 'owner'; Phase B.2, 2026-11-10)
    expect(res.status).toBe(409);
    expect(res.body.error).toBe('subscription_item_ambiguous');
    expect(stripe.subscriptions.update).not.toHaveBeenCalled();
    const after = await knex('customers').where({ id: 1 }).first();
    expect(after.tier).toBe(before.tier);
  });

  // ADMIN-13
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

  // ADMIN-14
  test('create_deployment → deployment created + config initialized', async () => {
    const res = await agent
      .post('/admin/deployments/action')
      .set(authHeaders(1, 'owner'))
      // tier is the PLAN (was 'user', a staff role; Phase B.2, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
      .send({ action: 'create', customer_id: 1, domain: 'newdomain.com', tier: 'team', theme_id: 'theme1' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    const deployment = await knex('deployments').where({ id: res.body.deployment_id }).first();
    expect(deployment).toBeDefined();
    expect(deployment.domain).toBe('newdomain.com');
    expect(deployment.tier).toBe('team');
    expect(Boolean(deployment.domain_verified)).toBe(false); // a new deployment's domain is not verified yet
  });

  // ADMIN-15
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

  // ADMIN-16
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

  // ADMIN-17
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

  // ADMIN-18
  test('audit_log search → correct filters applied, pagination works', async () => {
    const res = await agent
      .get('/admin/governance/audit-log')
      .set(authHeaders(2, 'admin'))
      .query({ limit: 10, offset: 0 });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeLessThanOrEqual(10);
  });

  /**
   * A fresh system, with no deployment yet, can create its first deployment with a configured theme, and an unknown
   * theme gets 404 theme_not_found. In: a new in-memory system. Out: assertions only.
   * Why 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): CodeRabbit review on PR 19 (a theme only "existed"
   * once a deployment used it, so no first deployment could ever be created). Touches: an in-memory SQLite only.
   */
  test('create_deployment on a fresh database → configured theme accepted, unknown theme 404', async () => {
    const fresh = createAdminSystem({
      jwtSecret: JWT_SECRET,
      csrfSecret: crypto.randomBytes(32).toString('hex'),
      stripe,
      mailer: new InMemoryMailer(),
    });
    try {
      await fresh.runMigrations();
      await fresh.knex('users').insert([{ id: 1, email: 'owner@example.com', name: 'Owner', tier: 'owner', status: 'active' }]);
      await fresh.knex('customers').insert([{
        id: 1, email: 'cust@example.com', name: 'Customer', tier: 'solo', signup_date: '2023-01-01', status: 'active',
        payment_method: 'pm_123', address: '123 Main St', stripe_subscription_id: 'sub_123',
      }]);
      expect(await fresh.knex('deployments').first()).toBeUndefined();
      const headers = {
        Authorization: `Bearer ${jwt.sign({ user_id: 1, tier: 'owner' }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '15m' })}`,
        'X-CSRF-Token': fresh.csrfTokenFor(1),
      };

      const unknown = await request(fresh.app)
        .post('/admin/deployments/action')
        .set(headers)
        // tier is the PLAN (was 'user'; Phase B.2, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP)
        .send({ action: 'create', customer_id: 1, domain: 'nope.example.com', tier: 'solo', theme_id: 'no-such-theme' });
      expect(unknown.status).toBe(404);
      expect(unknown.body.error).toBe('theme_not_found');
      expect(await fresh.knex('deployments').first()).toBeUndefined();

      const first = await request(fresh.app)
        .post('/admin/deployments/action')
        .set(headers)
        .send({ action: 'create', customer_id: 1, domain: 'first.example.com', tier: 'solo', theme_id: 'default' });
      expect(first.status).toBe(200);
      expect(first.body.success).toBe(true);
      const deployment = await fresh.knex('deployments').where({ id: first.body.deployment_id }).first();
      expect(deployment.domain).toBe('first.example.com');
      expect(deployment.theme).toBe('default');
    } finally {
      await fresh.knex.destroy();
    }
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

  /**
   * ADMIN-15 (Phase B.2): publish needs domain_verified. A draft deployment whose domain is not verified is 400
   * domain_not_verified and stays a draft; once verified it publishes. In: the shared test system. Out: assertions.
   * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the test database.
   */
  // ADMIN-15
  test('publish_deployment with an unverified domain → 400 domain_not_verified, still draft', async () => {
    const [id] = await knex('deployments').insert({ customer_id: 1, domain: 'unverified.example.com', tier: 'team',
      status: 'draft', theme: 'theme1' });
    const refused = await agent.post('/admin/deployments/action').set(authHeaders(1, 'owner'))
      .send({ action: 'publish', deployment_id: id });
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe('domain_not_verified');
    expect((await knex('deployments').where({ id }).first()).status).toBe('draft');
    await knex('deployments').where({ id }).update({ domain_verified: true });
    const ok = await agent.post('/admin/deployments/action').set(authHeaders(1, 'owner'))
      .send({ action: 'publish', deployment_id: id });
    expect(ok.status).toBe(200);
    expect(ok.body.status).toBe('live');
  });

  /**
   * TIERS (Phase B.2): users.tier is the staff role and a customer's or deployment's tier is the plan; a value from
   * the wrong list is 400 invalid_tier and changes nothing (user create and change_role refuse a plan; change_plan and
   * deployment create refuse a role). In: the shared test system. Out: assertions.
   * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the test database and the Stripe fake.
   */
  // ADMIN-06 ADMIN-12 ADMIN-14
  test('a plan where a role is expected, or a role where a plan is expected → 400 invalid_tier', async () => {
    stripe.subscriptions.update.mockClear();
    const post = (path, body) => agent.post(path).set(authHeaders(1, 'owner')).send(body);
    const cases = [
      ['/admin/users/action', { action: 'create', email: 'plan@example.com', name: 'Plan User', tier: 'team' }],
      ['/admin/users/action', { action: 'change_role', user_id: 2, new_tier: 'enterprise' }],
      ['/admin/customers/1/action', { action: 'change_plan', new_tier: 'admin' }],
      ['/admin/deployments/action', { action: 'create', customer_id: 1, domain: 'role.example.com', tier: 'owner', theme_id: 'theme1' }],
    ];
    const customerBefore = await knex('customers').where({ id: 1 }).first();
    for (const [path, body] of cases) {
      const res = await post(path, body);
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('invalid_tier');
    }
    expect(await knex('users').where({ email: 'plan@example.com' }).first()).toBeUndefined();
    expect((await knex('users').where({ id: 2 }).first()).tier).toBe('admin');
    expect((await knex('customers').where({ id: 1 }).first()).tier).toBe(customerBefore.tier);
    expect(await knex('deployments').where({ domain: 'role.example.com' }).first()).toBeUndefined();
    expect(stripe.subscriptions.update).not.toHaveBeenCalled();
  });

  /**
   * ADMIN-19: a suspended owner is refused before any gate (authentication runs first, then CSRF, then the role
   * gates) with 403 account_suspended on reads and mutations, even with a wrong CSRF token, and nothing changes.
   * In: the shared test system with a suspended owner (id 9). Out: assertions.
   * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the test database.
   */
  // ADMIN-19
  test('a suspended owner calling any admin action → 403 account_suspended, nothing changed', async () => {
    await knex('users').insert({ id: 9, email: 'suspended-owner@example.com', name: 'Suspended Owner', tier: 'owner',
      status: 'suspended' });
    const auditBefore = (await knex('audit_logs').count('id as n').first()).n;
    const usersBefore = (await knex('users').count('id as n').first()).n;
    const calls = [
      agent.get('/admin/customers').set(authHeaders(9, 'owner')),
      agent.get('/admin/governance/audit-log').set(authHeaders(9, 'owner')),
      agent.post('/admin/users/action').set(authHeaders(9, 'owner'))
        .send({ action: 'create', email: 'by-suspended@example.com', name: 'By Suspended', tier: 'user' }),
      agent.post('/admin/users/action').set({ ...authHeaders(9, 'owner'), 'X-CSRF-Token': 'wrong' })
        .send({ action: 'suspend', user_id: 2, reason: 'x' }),
      // Phase B.3 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): no CSRF header at all is still account_suspended,
      // never csrf_token_invalid: the suspended check runs before the CSRF check.
      agent.post('/admin/users/action').set({ Authorization: authHeaders(9, 'owner').Authorization })
        .send({ action: 'suspend', user_id: 2, reason: 'x' }),
      agent.post('/admin/customers/1/action').set(authHeaders(9, 'owner')).send({ action: 'change_plan', new_tier: 'team' }),
      agent.post('/admin/deployments/action').set(authHeaders(9, 'owner')).send({ action: 'retire', deployment_id: 1 }),
    ];
    for (const res of await Promise.all(calls)) {
      expect(res.status).toBe(403);
      expect(res.body.error).toBe('account_suspended');
    }
    expect(await knex('users').where({ email: 'by-suspended@example.com' }).first()).toBeUndefined();
    expect((await knex('users').where({ id: 2 }).first()).status).toBe('active');
    expect((await knex('deployments').where({ id: 1 }).first()).status).not.toBe('archived');
    expect((await knex('users').count('id as n').first()).n).toBe(usersBefore);
    expect((await knex('audit_logs').count('id as n').first()).n).toBe(auditBefore);
  });
});
