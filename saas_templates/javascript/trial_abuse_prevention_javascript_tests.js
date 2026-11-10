const { db,
        configure,
        signup,
        subscription_created,
        check_email_trial_history,
        check_payment_method_history,
        check_ip_signup_rate_limit,
        check_device_fingerprint,
        check_trial_payment_timing,
        check_chargeback_history } = require('./trial_abuse_prevention_javascript');

// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: a fixed clock, so no result depends on the day the suite runs.
const NOW = Date.parse('2026-06-01T12:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;
const DEVICE = { user_agent: 'UA', screen_resolution: '1920x1080', timezone: 'UTC', browser_language: 'en' };
const DEVICE_HASH = require('crypto').createHash('sha256').update(JSON.stringify(DEVICE)).digest('hex');

/** Gives `n` other users (ids 1001..) a row for DEVICE. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function seedDeviceUsers(n) {
  const insert = db.prepare(`
    INSERT INTO device_fingerprints (user_id, device_hash, user_agent, screen_resolution, timezone)
    VALUES (?, ?, ?, ?, ?)
  `);
  for (let i = 0; i < n; i++) insert.run(1001 + i, DEVICE_HASH, 'UA', '1920x1080', 'UTC');
}

/**
 * Creates a user whose trial (14 days) ended `daysAfterTrial` days before NOW, with an optional earlier payment on
 * the ledger. Out: the user id. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 */
function userTrialEnded(daysAfterTrial, earlierPaymentIso = null) {
  const created = new Date(NOW - (14 + daysAfterTrial) * DAY).toISOString();
  const id = db.prepare('INSERT INTO users (email, created_at) VALUES (?, ?)').run(`u${daysAfterTrial}@x.test`, created).lastInsertRowid;
  db.prepare(`INSERT INTO trial_abuse_ledger (user_id, trial_started_at, payment_added_date) VALUES (?, ?, ?)`)
    .run(id, created, earlierPaymentIso);
  return id;
}

beforeEach(() => {
  configure({ now: () => NOW, trialDays: 14 });
  db.exec('DELETE FROM trial_abuse_ledger');
  db.exec('DELETE FROM device_fingerprints');
  db.exec('DELETE FROM gate_decisions');
  db.exec('DELETE FROM signups');
  db.exec('DELETE FROM users');
  db.exec('DELETE FROM stripe_events');
  db.exec('DELETE FROM refunds');
});

// TRIAL-01
test('email_trial_history PASS → new email allowed', async () => {
  const res = await check_email_trial_history('new@example.com');
  expect(res.success).toBe(true);
});

// TRIAL-02
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

// TRIAL-03
test('email_trial_history FAIL → same email after 2 trials, rejected', async () => {
  db.prepare(`
    INSERT INTO trial_abuse_ledger (email, subscription_status)
    VALUES (?, 'completed'), (?, 'completed')
  `).run('fail@example.com', 'fail@example.com');
  const res = await check_email_trial_history('fail@example.com');
  expect(res.error).toBe('email_has_trial_history');
  expect(res.code).toBe(409);
});

// TRIAL-04
test('payment_method_history PASS → new card allowed', async () => {
  const res = await check_payment_method_history('pm_new');
  expect(res.success).toBe(true);
});

// TRIAL-05
test('payment_method_history FAIL → same card after 3 trials, rejected', async () => {
  db.prepare(`
    INSERT INTO trial_abuse_ledger (stripe_payment_method_id, subscription_status)
    VALUES (?, 'completed'), (?, 'completed'), (?, 'completed')
  `).run('pm_fail', 'pm_fail', 'pm_fail');
  const res = await check_payment_method_history('pm_fail');
  expect(res.error).toBe('payment_method_used_for_multiple_trials');
  expect(res.code).toBe(403);
});

// TRIAL-06
test('ip_signup_rate_limit PASS → < 5 signups from IP, allowed', async () => {
  const ip = '192.168.1.1';
  const insert = db.prepare('INSERT INTO signups (ip, created_at) VALUES (?, ?)');
  for (let i = 0; i < 4; i++) insert.run(ip, new Date(NOW - 1000 * 60 * 60).toISOString());
  const res = await check_ip_signup_rate_limit(ip);
  expect(res.success).toBe(true);
});

// TRIAL-07
test('ip_signup_rate_limit FAIL → 10+ signups from IP, rejected 429', async () => {
  const ip = '10.0.0.1';
  const insert = db.prepare('INSERT INTO signups (ip, created_at) VALUES (?, ?)');
  for (let i = 0; i < 10; i++) insert.run(ip, new Date(NOW - 1000 * 60 * 60).toISOString());
  const res = await check_ip_signup_rate_limit(ip);
  expect(res.error).toBe('too_many_signups_from_ip');
  expect(res.code).toBe(429);
});

// TRIAL-08
test('device_fingerprint PASS → device < 2 users, allowed', async () => {
  const device = { user_agent: 'UA', screen_resolution: '1920x1080', timezone: 'UTC', browser_language: 'en' };
  const res = await check_device_fingerprint(device);
  expect(res.success).toBe(true);
});

// TRIAL-09
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the amended row is "5 or more OTHER users" (was "> 5 users"), so the
// test now uses exactly 5 other users and checks the device is rejected for a known user as well.
test('device_fingerprint FAIL → device used by 5 or more other users, rejected', async () => {
  seedDeviceUsers(5);
  const res = await check_device_fingerprint(DEVICE);
  expect(res.error).toBe('device_suspected_fraud');
  expect(res.code).toBe(403);
  expect(res.decision).toBe('FAIL');
  const known = await check_device_fingerprint(DEVICE, 1003);
  expect(known.matching_users).toBe(4); // user 1003 is not counted against itself
  expect(known.decision).toBe('PASS'); // fewer than 5 others, and the device is already this user's
});

/**
 * TRIAL-14: device boundaries. 4 other users -> CHALLENGE (and the device row is written after the decision);
 * exactly 5 other users -> FAIL, even when this user already has the device, and a FAIL writes no device row.
 * 2 other users and a known device -> PASS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the test database.
 */
// TRIAL-14
test('device_fingerprint boundaries: 4 others CHALLENGE, 5 others FAIL even for a known device, FAIL records nothing', async () => {
  seedDeviceUsers(4);
  const challenge = await check_device_fingerprint(DEVICE, 7);
  expect(challenge.decision).toBe('CHALLENGE');
  expect(challenge.matching_users).toBe(4);
  expect(db.prepare('SELECT COUNT(*) AS n FROM device_fingerprints WHERE user_id = 7').get().n).toBe(1);

  seedDeviceUsers(5); // users 1001..1005 now (1001..1004 already had rows)
  db.exec('DELETE FROM device_fingerprints WHERE user_id = 1005');
  db.prepare(`INSERT INTO device_fingerprints (user_id, device_hash) VALUES (1005, ?)`).run(DEVICE_HASH);
  // user 7 already has the device and 5 OTHER users have it: FAIL wins over "known device"
  const fail = await check_device_fingerprint(DEVICE, 7);
  expect(fail.matching_users).toBe(5);
  expect(fail.decision).toBe('FAIL');
  expect(fail.error).toBe('device_suspected_fraud');

  const before = db.prepare('SELECT COUNT(*) AS n FROM device_fingerprints').get().n;
  const failNew = await check_device_fingerprint(DEVICE, 8);
  expect(failNew.decision).toBe('FAIL');
  expect(db.prepare('SELECT COUNT(*) AS n FROM device_fingerprints').get().n).toBe(before);
  expect(db.prepare('SELECT COUNT(*) AS n FROM device_fingerprints WHERE user_id = 8').get().n).toBe(0);

  db.exec('DELETE FROM device_fingerprints');
  seedDeviceUsers(2);
  db.prepare(`INSERT INTO device_fingerprints (user_id, device_hash) VALUES (9, ?)`).run(DEVICE_HASH);
  expect((await check_device_fingerprint(DEVICE, 9)).decision).toBe('PASS');
  expect((await check_device_fingerprint(DEVICE, 10)).decision).toBe('CHALLENGE');
});

/**
 * TRIAL-09 / TRIAL-14 through signup: the gate runs before the device is recorded, so a device farm is stopped at the
 * sixth account (five accounts already on the device) and the rejected signup creates no user and no device row.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the test database.
 */
// TRIAL-09
test('signup runs the device gate before recording: the 6th account on one device is rejected', async () => {
  const results = [];
  for (let i = 0; i < 6; i++) {
    results.push(await signup(`farm${i}@x.test`, 'correct horse battery staple', `198.51.100.${i}`, DEVICE));
  }
  expect(results.slice(0, 5).every(r => r.success === true)).toBe(true);
  expect(results[2].flags).toContain('new_device_login_detected');
  expect(results[5].error).toBe('device_suspected_fraud');
  expect(results[5].code).toBe(403);
  expect(db.prepare('SELECT COUNT(*) AS n FROM users').get().n).toBe(5);
  expect(db.prepare('SELECT COUNT(*) AS n FROM device_fingerprints').get().n).toBe(5);
});

// TRIAL-10
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: rewritten for the amended rule (days after the trial END, judged as
// the payment is added); the old test judged a stored payment date against the trial start.
test('trial_payment_timing PASS → first payment 4 days after the trial ended, and one during the trial, allowed', async () => {
  const late = userTrialEnded(4);
  const res = await check_trial_payment_timing(late);
  expect(res.success).toBe(true);
  expect(res.decision).toBe('PASS');
  expect(res.days_after_trial).toBe(4);
  expect(res.earlier_payment).toBe(false);

  const during = userTrialEnded(-10); // 4 days into a 14-day trial
  const res2 = await check_trial_payment_timing(during);
  expect(res2.decision).toBe('PASS');
  expect(res2.days_after_trial).toBe(-10);

  // floor rounds toward negative infinity: half a day before the trial ends is day -1, not 0
  const almost = db.prepare('INSERT INTO users (email, created_at) VALUES (?, ?)')
    .run('half@x.test', new Date(NOW - 14 * DAY + DAY / 2).toISOString()).lastInsertRowid;
  expect((await check_trial_payment_timing(almost)).days_after_trial).toBe(-1);
});

// TRIAL-11
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: rewritten for the amended rule (90 days after the trial END).
test('trial_payment_timing FAIL → first payment 90 days after the trial ended, no earlier payment, rejected', async () => {
  const user_id = userTrialEnded(90);
  const res = await check_trial_payment_timing(user_id);
  expect(res.error).toBe('trial_ended_no_payment_cannot_retry');
  expect(res.code).toBe(403);
  expect(res.decision).toBe('FAIL');
  expect(res.days_after_trial).toBe(90);
});

/**
 * TRIAL-15: payment timing boundaries. 5 and 89 days after the trial -> CHALLENGE; 90 days with an earlier payment ->
 * CHALLENGE (not FAIL); trial_days is configuration (a 30-day trial moves the boundary).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the test database.
 */
// TRIAL-15
test('trial_payment_timing boundaries: 5 and 89 days CHALLENGE; 90 days with an earlier payment CHALLENGE', async () => {
  for (const days of [5, 89]) {
    const res = await check_trial_payment_timing(userTrialEnded(days));
    expect(res.decision).toBe('CHALLENGE');
    expect(res.flags).toContain('late_payment_entry');
  }
  const paidBefore = userTrialEnded(90, new Date(NOW - 100 * DAY).toISOString());
  const res = await check_trial_payment_timing(paidBefore);
  expect(res.decision).toBe('CHALLENGE');
  expect(res.earlier_payment).toBe(true);

  configure({ trialDays: 30 });
  const longTrial = userTrialEnded(4); // created 18 days ago: still inside a 30-day trial
  expect((await check_trial_payment_timing(longTrial)).days_after_trial).toBe(-12);
});

/**
 * Phase B.2 amendment to gate 5: a user with no users row is FAIL { error: 'user_not_found' } (fail closed, and
 * subscription_created refuses it without touching the ledger); a user with a users row but no ledger row is judged
 * from users.created_at with no earlier payment. In: the test database. Out: assertions.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the test database.
 */
// TRIAL-11
test('trial_payment_timing: no users row FAILs closed with user_not_found; no ledger row is judged from created_at', async () => {
  const unknown = await check_trial_payment_timing(987654);
  expect(unknown.decision).toBe('FAIL');
  expect(unknown.error).toBe('user_not_found');
  expect(unknown.code).toBe(403);
  const refused = await subscription_created(987654, 'pm_unknown_user', 'cus_unknown_user');
  expect(refused.error).toBe('user_not_found');
  expect(db.prepare('SELECT COUNT(*) AS n FROM trial_abuse_ledger').get().n).toBe(0);

  const noLedger = (daysAfterTrial) => db.prepare('INSERT INTO users (email, created_at) VALUES (?, ?)')
    .run(`noledger${daysAfterTrial}@x.test`, new Date(NOW - (14 + daysAfterTrial) * DAY).toISOString()).lastInsertRowid;
  const early = await check_trial_payment_timing(noLedger(2));
  expect(early).toMatchObject({ decision: 'PASS', days_after_trial: 2, earlier_payment: false });
  const late = await check_trial_payment_timing(noLedger(90));
  expect(late).toMatchObject({ decision: 'FAIL', error: 'trial_ended_no_payment_cannot_retry', earlier_payment: false });
});

/**
 * subscription_created records the gate decisions on the ledger (they were missing) and the payment date from the
 * clock. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the test database.
 */
// TRIAL-10
test('subscription_created stores each gate decision and the payment date', async () => {
  const user_id = userTrialEnded(2);
  const res = await subscription_created(user_id, 'pm_ok', 'cus_ok');
  expect(res.success).toBe(true);
  const row = db.prepare('SELECT payment_added_date, gate_flags FROM trial_abuse_ledger WHERE user_id = ?').get(user_id);
  expect(row.payment_added_date).toBe(new Date(NOW).toISOString());
  expect(JSON.parse(row.gate_flags)).toEqual({ payment: 'PASS', timing: 'PASS', chargeback: 'PASS' });
});

// TRIAL-12
test('chargeback_history PASS → no chargebacks, allowed', async () => {
  const insertUser = db.prepare('INSERT INTO users (email, created_at) VALUES (?, ?)');
  const userInfo = insertUser.run('user3@example.com', new Date(NOW).toISOString());
  const user_id = userInfo.lastInsertRowid;

  // Create ledger entry with stripe_customer_id for chargeback lookup
  db.prepare(`
    INSERT INTO trial_abuse_ledger (user_id, stripe_customer_id)
    VALUES (?, ?)
  `).run(user_id, `cust_${user_id}`);

  const res = await check_chargeback_history(user_id);
  expect(res.success).toBe(true);
});

// TRIAL-13
test('chargeback_history FAIL → 2+ chargebacks, requires prepayment', async () => {
  const insertUser = db.prepare('INSERT INTO users (email, created_at) VALUES (?, ?)');
  const userInfo = insertUser.run('user4@example.com', new Date(NOW).toISOString());
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
  const user_id = insertUser.run('user_supplied@example.com', new Date(NOW).toISOString()).lastInsertRowid;
  db.prepare(`INSERT INTO trial_abuse_ledger (user_id) VALUES (?)`).run(user_id);   // no customer stored yet
  db.prepare(`INSERT INTO stripe_events (customer, type) VALUES (?, 'chargeback'), (?, 'chargeback')`)
    .run('cus_supplied', 'cus_supplied');

  expect((await check_chargeback_history(user_id)).success).toBe(true);   // nothing stored, nothing found
  const res = await check_chargeback_history(user_id, 'cus_supplied');
  expect(res.error).toBe('chargeback_history_requires_prepayment');
  expect(res.code).toBe(403);
});
