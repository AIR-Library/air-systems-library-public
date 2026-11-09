const { db,
        check_email_trial_history,
        check_payment_method_history,
        check_ip_signup_rate_limit,
        check_device_fingerprint,
        check_trial_payment_timing,
        check_chargeback_history } = require('./trial_abuse_prevention_javascript');

beforeEach(() => {
  db.exec('DELETE FROM trial_abuse_ledger');
  db.exec('DELETE FROM device_fingerprints');
  db.exec('DELETE FROM gate_decisions');
  db.exec('DELETE FROM signups');
  db.exec('DELETE FROM users');
  db.exec('DELETE FROM stripe_events');
  db.exec('DELETE FROM refunds');
});

test('email_trial_history PASS → new email allowed', async () => {
  const res = await check_email_trial_history('new@example.com');
  expect(res.success).toBe(true);
});

test('email_trial_history CHALLENGE → same email after 1 trial, flagged', async () => {
  db.prepare(`
    INSERT INTO trial_abuse_ledger (email, subscription_status)
    VALUES (?, 'completed')
  `).run('repeat@example.com');
  const res = await check_email_trial_history('repeat@example.com');
  expect(res.success).toBe(true);
  expect(res.challenge).toBe('email_confirm');
  expect(res.flags).toContain('email_trial_attempt_2+');
});

test('email_trial_history FAIL → same email after 2 trials, rejected', async () => {
  db.prepare(`
    INSERT INTO trial_abuse_ledger (email, subscription_status)
    VALUES (?, 'completed'), (?, 'completed')
  `).run('fail@example.com', 'fail@example.com');
  const res = await check_email_trial_history('fail@example.com');
  expect(res.error).toBe('email_has_trial_history');
  expect(res.code).toBe(409);
});

test('payment_method_history PASS → new card allowed', async () => {
  const res = await check_payment_method_history('pm_new');
  expect(res.success).toBe(true);
});

test('payment_method_history FAIL → same card after 3 trials, rejected', async () => {
  db.prepare(`
    INSERT INTO trial_abuse_ledger (stripe_payment_method_id, subscription_status)
    VALUES (?, 'completed'), (?, 'completed'), (?, 'completed')
  `).run('pm_fail', 'pm_fail', 'pm_fail');
  const res = await check_payment_method_history('pm_fail');
  expect(res.error).toBe('payment_method_used_for_multiple_trials');
  expect(res.code).toBe(403);
});

test('ip_signup_rate_limit PASS → < 5 signups from IP, allowed', async () => {
  const ip = '192.168.1.1';
  const insert = db.prepare('INSERT INTO signups (ip, created_at) VALUES (?, ?)');
  for (let i = 0; i < 4; i++) insert.run(ip, new Date(Date.now() - 1000 * 60 * 60).toISOString());
  const res = await check_ip_signup_rate_limit(ip);
  expect(res.success).toBe(true);
});

test('ip_signup_rate_limit FAIL → 10+ signups from IP, rejected 429', async () => {
  const ip = '10.0.0.1';
  const insert = db.prepare('INSERT INTO signups (ip, created_at) VALUES (?, ?)');
  for (let i = 0; i < 10; i++) insert.run(ip, new Date(Date.now() - 1000 * 60 * 60).toISOString());
  const res = await check_ip_signup_rate_limit(ip);
  expect(res.error).toBe('too_many_signups_from_ip');
  expect(res.code).toBe(429);
});

test('device_fingerprint PASS → device < 2 users, allowed', async () => {
  const device = { user_agent: 'UA', screen_resolution: '1920x1080', timezone: 'UTC', browser_language: 'en' };
  const res = await check_device_fingerprint(device);
  expect(res.success).toBe(true);
});

test('device_fingerprint FAIL → device > 5 users, rejected', async () => {
  const device = { user_agent: 'UA', screen_resolution: '1920x1080', timezone: 'UTC', browser_language: 'en' };
  const device_hash = require('crypto').createHash('sha256').update(JSON.stringify(device)).digest('hex');
  const insert = db.prepare(`
    INSERT INTO device_fingerprints (user_id, device_hash, user_agent, screen_resolution, timezone)
    VALUES (?, ?, ?, ?, ?)
  `);
  for (let i = 0; i < 6; i++) insert.run(i, device_hash, 'UA', '1920x1080', 'UTC');
  const res = await check_device_fingerprint(device);
  expect(res.error).toBe('device_suspected_fraud');
  expect(res.code).toBe(403);
});

test('trial_payment_timing PASS → payment within trial window, allowed', async () => {
  const insertUser = db.prepare('INSERT INTO users (email, created_at) VALUES (?, ?)');
  const userInfo = insertUser.run('user@example.com', new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString());
  const user_id = userInfo.lastInsertRowid;

  const insertLedger = db.prepare(`
    INSERT INTO trial_abuse_ledger (user_id, trial_started_at, payment_added_date, subscription_status)
    VALUES (?, ?, ?, 'completed')
  `);
  insertLedger.run(
    user_id,
    new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(),
    new Date(Date.now() - 1000 * 60 * 60 * 12).toISOString()
  );

  const res = await check_trial_payment_timing(user_id);
  expect(res.success).toBe(true);
});

test('trial_payment_timing FAIL → trial ended, no payment, trying to re-add, rejected', async () => {
  const insertUser = db.prepare('INSERT INTO users (email, created_at) VALUES (?, ?)');
  const userInfo = insertUser.run('user2@example.com', new Date(Date.now() - 1000 * 60 * 60 * 24 * 120).toISOString());
  const user_id = userInfo.lastInsertRowid;

  const insertLedger = db.prepare(`
    INSERT INTO trial_abuse_ledger (user_id, trial_started_at, subscription_status)
    VALUES (?, ?, 'completed')
  `);
  insertLedger.run(
    user_id,
    new Date(Date.now() - 1000 * 60 * 60 * 24 * 120).toISOString()
  );

  const res = await check_trial_payment_timing(user_id);
  expect(res.error).toBe('trial_ended_no_payment_cannot_retry');
  expect(res.code).toBe(403);
});

test('chargeback_history PASS → no chargebacks, allowed', async () => {
  const insertUser = db.prepare('INSERT INTO users (email, created_at) VALUES (?, ?)');
  const userInfo = insertUser.run('user3@example.com', new Date().toISOString());
  const user_id = userInfo.lastInsertRowid;

  // Create ledger entry with stripe_customer_id for chargeback lookup
  db.prepare(`
    INSERT INTO trial_abuse_ledger (user_id, stripe_customer_id)
    VALUES (?, ?)
  `).run(user_id, `cust_${user_id}`);

  const res = await check_chargeback_history(user_id);
  expect(res.success).toBe(true);
});

test('chargeback_history FAIL → 2+ chargebacks, requires prepayment', async () => {
  const insertUser = db.prepare('INSERT INTO users (email, created_at) VALUES (?, ?)');
  const userInfo = insertUser.run('user4@example.com', new Date().toISOString());
  const user_id = userInfo.lastInsertRowid;

  // Create ledger entry with stripe_customer_id matching the stripe_events
  db.prepare(`
    INSERT INTO trial_abuse_ledger (user_id, stripe_customer_id)
    VALUES (?, ?)
  `).run(user_id, `cust_${user_id}`);

  db.prepare(`
    INSERT INTO stripe_events (customer, type)
    VALUES (?, 'chargeback'), (?, 'chargeback')
  `).run(`cust_${user_id}`, `cust_${user_id}`);

  const res = await check_chargeback_history(user_id);
  expect(res.error).toBe('chargeback_history_requires_prepayment');
  expect(res.code).toBe(403);
});

test('chargeback_history checks the customer supplied at subscription time, before the ledger has it', async () => {
  const insertUser = db.prepare('INSERT INTO users (email, created_at) VALUES (?, ?)');
  const user_id = insertUser.run('user_supplied@example.com', new Date().toISOString()).lastInsertRowid;
  db.prepare(`INSERT INTO trial_abuse_ledger (user_id) VALUES (?)`).run(user_id);   // no customer stored yet
  db.prepare(`INSERT INTO stripe_events (customer, type) VALUES (?, 'chargeback'), (?, 'chargeback')`)
    .run('cus_supplied', 'cus_supplied');

  expect((await check_chargeback_history(user_id)).success).toBe(true);   // nothing stored, nothing found
  const res = await check_chargeback_history(user_id, 'cus_supplied');
  expect(res.error).toBe('chargeback_history_requires_prepayment');
  expect(res.code).toBe(403);
});
