import { db, signup, subscription_created, check_email_trial_history, check_payment_method_history, check_ip_signup_rate_limit, check_device_fingerprint, check_trial_payment_timing, check_chargeback_history, record_device_fingerprint, device_fingerprint_gate, set_clock } from './trial_abuse_prevention_typescript';
import { createHash } from 'crypto';

afterEach(() => set_clock());

beforeEach(() => {
  // Reset DB
  db.exec('PRAGMA foreign_keys = OFF;');
  db.exec('DROP TABLE IF EXISTS trial_abuse_ledger;');
  db.exec('DROP TABLE IF EXISTS device_fingerprints;');
  db.exec('DROP TABLE IF EXISTS gate_decisions;');
  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): the users table is reset too; payment timing reads
  // users.created_at.
  db.exec('DROP TABLE IF EXISTS users;');
  db.exec(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY,
      email TEXT NOT NULL,
      created_at DATETIME NOT NULL,
      abuse_flags TEXT NOT NULL DEFAULT '[]'
    );
    CREATE TABLE trial_abuse_ledger (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      email TEXT NOT NULL,
      stripe_payment_method_id TEXT,
      ip TEXT NOT NULL,
      device_fingerprint TEXT,
      signup_date DATETIME NOT NULL,
      trial_started_at DATETIME NOT NULL,
      payment_added_date DATETIME,
      subscription_status TEXT,
      chargeback_count INTEGER DEFAULT 0,
      refund_count INTEGER DEFAULT 0,
      gate_flags TEXT NOT NULL,
      alert_reason TEXT,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE device_fingerprints (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      device_hash TEXT NOT NULL,
      user_agent TEXT,
      screen_resolution TEXT,
      timezone TEXT,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE gate_decisions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      gate_name TEXT NOT NULL,
      decision TEXT NOT NULL,
      rule_inputs TEXT,
      rule_outputs TEXT,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);
});

/**
 * Inserts a users row (id, email t<id>@example.com, created_at). In: the user id and when the account was created.
 * Out: nothing. Why: Phase B.2 trial spec amendment: payment timing is judged from users.created_at.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
 */
function addUser(userId: number, createdAt: Date) {
  db.prepare(`INSERT INTO users (id, email, created_at) VALUES (?, ?, ?)`).run(userId, `t${userId}@example.com`, createdAt.toISOString());
}

// TRIAL-01
test('email_trial_history PASS → new email allowed', () => {
  const result = signup({
    email: 'new@example.com',
    password: 'pwd',
    ip: '1.2.3.4',
    user_agent: 'ua',
    screen_resolution: '1920x1080',
    timezone: 'UTC',
    browser_language: 'en'
  });
  expect(result.success).toBe(true);
  expect(result.error).toBeUndefined();
});

// TRIAL-02
test('email_trial_history CHALLENGE → same email after 1 trial, flagged', () => {
  // Insert prior completed trial
  db.prepare(`
    INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, gate_flags, subscription_status)
    VALUES (100, 'repeat@example.com', '1.2.3.4', datetime('now'), datetime('now'), '{}', 'completed')
  `).run();

  const result = signup({
    email: 'repeat@example.com',
    password: 'pwd',
    ip: '5.6.7.8',
    user_agent: 'ua',
    screen_resolution: '1920x1080',
    timezone: 'UTC',
    browser_language: 'en'
  });
  expect(result.success).toBe(true);
  expect(result.user?.abuse_flags).toContain('email_trial_attempt_2+');
});

// TRIAL-03
test('email_trial_history FAIL → same email after 2 trials, rejected', () => {
  // Two prior trials
  db.prepare(`
    INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, gate_flags, subscription_status)
    VALUES (101, 'blocked@example.com', '1.2.3.4', datetime('now'), datetime('now'), '{}', 'completed')
  `).run();
  db.prepare(`
    INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, gate_flags, subscription_status)
    VALUES (102, 'blocked@example.com', '5.6.7.8', datetime('now'), datetime('now'), '{}', 'completed')
  `).run();

  const result = signup({
    email: 'blocked@example.com',
    password: 'pwd',
    ip: '9.10.11.12',
    user_agent: 'ua',
    screen_resolution: '1920x1080',
    timezone: 'UTC',
    browser_language: 'en'
  });
  expect(result.success).toBe(false);
  expect(result.error?.error).toBe('email_has_trial_history');
  expect(result.error?.code).toBe(409);
});

// TRIAL-04
test('payment_method_history PASS → new card allowed', () => {
  const decision = check_payment_method_history('pm_new', 200);
  expect(decision.decision).toBe('PASS');
});

// TRIAL-05
test('payment_method_history FAIL → same card after 3 trials, rejected', () => {
  // Insert three prior trials with same payment method
  for (let i = 0; i < 3; i++) {
    db.prepare(`
      INSERT INTO trial_abuse_ledger (user_id, email, ip, stripe_payment_method_id, signup_date, trial_started_at, gate_flags, subscription_status)
      VALUES (?, ?, ?, ?, datetime('now'), datetime('now'), '{}', 'completed')
    `).run(300 + i, `u${i}@example.com`, `1.2.3.${i}`, 'pm_reused');
  }
  const decision = check_payment_method_history('pm_reused', 400);
  expect(decision.decision).toBe('FAIL');
});

// TRIAL-06
test('ip_signup_rate_limit PASS → < 5 signups from IP, allowed', () => {
  // 3 prior signups
  for (let i = 0; i < 3; i++) {
    db.prepare(`
      INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, gate_flags)
      VALUES (?, ?, ?, datetime('now'), datetime('now'), '{}')
    `).run(500 + i, `ip${i}@example.com`, '8.8.8.8');
  }
  const decision = check_ip_signup_rate_limit('8.8.8.8', 600);
  expect(decision.decision).toBe('PASS');
});

// TRIAL-07
test('ip_signup_rate_limit FAIL → 10+ signups from IP, rejected', () => {
  for (let i = 0; i < 10; i++) {
    db.prepare(`
      INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, gate_flags)
      VALUES (?, ?, ?, datetime('now'), datetime('now'), '{}')
    `).run(700 + i, `ip${i}@example.com`, '9.9.9.9');
  }
  const decision = check_ip_signup_rate_limit('9.9.9.9', 800);
  expect(decision.decision).toBe('FAIL');
});

// TRIAL-08
test('device_fingerprint PASS → device < 2 users, allowed', () => {
  const device = {
    user_agent: 'ua1',
    screen_resolution: '1920x1080',
    timezone: 'UTC',
    browser_language: 'en'
  };
  const decision = check_device_fingerprint(device, 900);
  expect(decision.decision).toBe('PASS');
});

// TRIAL-09
test('device_fingerprint FAIL → device > 5 users, rejected', () => {
  const device = {
    user_agent: 'ua_shared',
    screen_resolution: '1280x720',
    timezone: 'UTC',
    browser_language: 'en'
  };
  const deviceString = `${device.user_agent}|${device.screen_resolution}|${device.timezone}|${device.browser_language}`;
  const deviceHash = createHash('sha256').update(deviceString).digest('hex');

  // Insert 6 distinct users with same device hash
  for (let i = 0; i < 6; i++) {
    db.prepare(`
      INSERT INTO device_fingerprints (user_id, device_hash, user_agent, screen_resolution, timezone)
      VALUES (?, ?, ?, ?, ?)
    `).run(1000 + i, deviceHash, device.user_agent, device.screen_resolution, device.timezone);
  }

  const decision = check_device_fingerprint(device, 1100);
  expect(decision.decision).toBe('FAIL');
});

// TRIAL-10
test('trial_payment_timing PASS → payment within trial window, allowed', () => {
  // Create a user with trial started 5 days ago
  const now = new Date();
  const fiveDaysAgo = new Date(now.getTime() - 5 * 24 * 60 * 60 * 1000);
  db.prepare(`
    INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, gate_flags)
    VALUES (1200, 'timing@example.com', '1.1.1.1', ?, ?, '{}')
  `).run(fiveDaysAgo.toISOString(), fiveDaysAgo.toISOString());
  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): the trial starts at users.created_at now, so the user
  // needs a users row (signup writes one).
  addUser(1200, fiveDaysAgo);

  const decision = check_trial_payment_timing(1200, 14);
  expect(decision.decision).toBe('PASS');
});

// TRIAL-11
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the TRIAL-11 amendment counts days AFTER the trial ended (FAIL at 90
// with no earlier payment). A trial that started 100 days ago ended 86 days ago (CHALLENGE now), so the trial here
// starts 104 days ago (14-day trial + 90 days) on a pinned clock.
test('trial_payment_timing FAIL → trial ended, no payment, trying to re-add, rejected', () => {
  const now = new Date('2026-06-15T12:00:00.000Z');
  set_clock(() => now);
  const hundredDaysAgo = new Date(now.getTime() - 104 * 24 * 60 * 60 * 1000);
  db.prepare(`
    INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, gate_flags)
    VALUES (1300, 'ended@example.com', '2.2.2.2', ?, ?, '{}')
  `).run(hundredDaysAgo.toISOString(), hundredDaysAgo.toISOString());
  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2): the trial starts at users.created_at now.
  addUser(1300, hundredDaysAgo);

  const decision = check_trial_payment_timing(1300, 14);
  expect(decision.decision).toBe('FAIL');
});

// TRIAL-12
test('chargeback_history PASS → no chargebacks, allowed', () => {
  const decision = check_chargeback_history('cust_no_cb', 1400);
  expect(decision.decision).toBe('PASS');
});

// TRIAL-13
test('chargeback_history FAIL → 2+ chargebacks, requires prepayment', () => {
  // Insert two chargeback events
  db.exec(`
    CREATE TABLE stripe_events (id INTEGER PRIMARY KEY AUTOINCREMENT, customer TEXT, type TEXT);
    CREATE TABLE refunds (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, status TEXT);
  `);
  db.prepare(`INSERT INTO stripe_events (customer, type) VALUES ('cust_bad', 'chargeback.initiated')`).run();
  db.prepare(`INSERT INTO stripe_events (customer, type) VALUES ('cust_bad', 'chargeback.reversed')`).run();
  db.prepare(`INSERT INTO refunds (user_id, status) VALUES (1500, 'chargebacked')`).run();

  const decision = check_chargeback_history('cust_bad', 1500);
  expect(decision.decision).toBe('FAIL');
});

test('integration: full signup and subscription flow with challenges', () => {
  // First signup (PASS)
  const signupRes = signup({
    email: 'full@example.com',
    password: 'pwd',
    ip: '3.3.3.3',
    user_agent: 'ua',
    screen_resolution: '1920x1080',
    timezone: 'UTC',
    browser_language: 'en'
  });
  expect(signupRes.success).toBe(true);
  const user = signupRes.user!;
  // Record device fingerprint
  record_device_fingerprint({
    user_id: user.id,
    device: {
      user_agent: 'ua',
      screen_resolution: '1920x1080',
      timezone: 'UTC',
      browser_language: 'en'
    }
  });

  // Subscription creation with new payment method (PASS)
  const subRes = subscription_created({
    user_id: user.id,
    stripe_payment_method_id: 'pm_new2',
    stripe_customer_id: 'cust_new2'
  });
  expect(subRes.success).toBe(true);
  expect(subRes.challenge).toBeUndefined();
});

test('integration: payment method reuse challenge', () => {
  // Setup prior usage of payment method twice
  for (let i = 0; i < 2; i++) {
    db.prepare(`
      INSERT INTO trial_abuse_ledger (user_id, email, ip, stripe_payment_method_id, signup_date, trial_started_at, gate_flags, subscription_status)
      VALUES (?, ?, ?, ?, datetime('now'), datetime('now'), '{}', 'completed')
    `).run(2000 + i, `reuse${i}@example.com`, '4.4.4.4', 'pm_challenge');
  }

  // New user signup
  const signupRes = signup({
    email: 'reuse@example.com',
    password: 'pwd',
    ip: '5.5.5.5',
    user_agent: 'ua',
    screen_resolution: '1920x1080',
    timezone: 'UTC',
    browser_language: 'en'
  });
  expect(signupRes.success).toBe(true);
  const user = signupRes.user!;

  // Subscription with reused payment method (CHALLENGE)
  const subRes = subscription_created({
    user_id: user.id,
    stripe_payment_method_id: 'pm_challenge',
    stripe_customer_id: 'cust_challenge'
  });
  expect(subRes.success).toBe(true);
  expect(subRes.challenge?.type).toBe('email_confirm');
  expect(subRes.challenge?.flags).toContain('payment_reuse_2x');
});

/**
 * Inserts a users row and a ledger row whose trial started `daysAgo` days before `now`.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP; Phase B.2 the same day: also the users row, whose created_at the
 * timing gate now reads. Touches: in-memory SQLite.
 */
function trialStartedDaysAgo(userId: number, now: Date, daysAgo: number, paymentDaysAgo?: number) {
  const start = new Date(now.getTime() - daysAgo * 24 * 60 * 60 * 1000).toISOString();
  const paid = paymentDaysAgo === undefined ? null : new Date(now.getTime() - paymentDaysAgo * 24 * 60 * 60 * 1000).toISOString();
  addUser(userId, new Date(start));
  db.prepare(`
    INSERT INTO trial_abuse_ledger (user_id, email, ip, signup_date, trial_started_at, payment_added_date, gate_flags)
    VALUES (?, ?, '1.1.1.1', ?, ?, ?, '{}')
  `).run(userId, `t${userId}@example.com`, start, start, paid);
}

const NOW = new Date('2026-06-15T12:00:00.000Z');
const HOUR = 60 * 60 * 1000;

/**
 * TRIAL-10: a first payment during the trial and one 4 days (and 4 days 23 hours) after it ended both PASS, on a
 * pinned clock with a 14-day trial. In: ledger rows. Out: assertions only. Why: TRIAL-10 amendment 2026-11-10.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
 */
// TRIAL-10
test('trial_payment_timing PASS → during the trial and 4 days after it ended', () => {
  set_clock(() => NOW);
  trialStartedDaysAgo(1, NOW, 3);
  trialStartedDaysAgo(2, NOW, 18);
  expect(check_trial_payment_timing(1, 14)).toMatchObject({ decision: 'PASS', paymentDelay: -11 });
  expect(check_trial_payment_timing(2, 14)).toMatchObject({ decision: 'PASS', paymentDelay: 4 });
  set_clock(() => new Date(NOW.getTime() + 23 * HOUR));
  expect(check_trial_payment_timing(2, 14).decision).toBe('PASS');   // 4.96 days floors to 4
});

/**
 * TRIAL-11: a first payment exactly 90 days after the trial ended, with no earlier payment, is FAIL, and
 * subscription_created answers 403 trial_ended_no_payment_cannot_retry; trial_days is configurable (a 30-day trial
 * moves the boundary). In: ledger rows on a pinned clock. Out: assertions only. Why: TRIAL-11 amendment.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
 */
// TRIAL-11
test('trial_payment_timing FAIL → 90 days after the trial, no earlier payment; subscription refused 403', () => {
  set_clock(() => NOW);
  trialStartedDaysAgo(3, NOW, 104);
  expect(check_trial_payment_timing(3, 14)).toMatchObject({ decision: 'FAIL', paymentDelay: 90 });
  expect(check_trial_payment_timing(3, 30).decision).toBe('CHALLENGE');   // 74 days after a 30-day trial
  const res = subscription_created({ user_id: 3, stripe_payment_method_id: 'pm_late', stripe_customer_id: 'cus_late' });
  expect(res.success).toBe(false);
  expect(res.error).toMatchObject({ error: 'trial_ended_no_payment_cannot_retry', code: 403 });
});

/**
 * TRIAL-15: the timing boundaries: 5 days and 89 days after the trial are CHALLENGE, 90 days WITH an earlier payment
 * is CHALLENGE, and a moment just before the 5th day (4 days 23 h 59 m) is still PASS while 1 ms before the trial
 * end floors to -1 (PASS). In: ledger rows on pinned clocks. Out: assertions only. Why: TRIAL-15 amendment.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
 */
// TRIAL-15
test('trial_payment_timing boundaries → 5 and 89 days CHALLENGE; 90 days with an earlier payment CHALLENGE', () => {
  set_clock(() => NOW);
  trialStartedDaysAgo(4, NOW, 19);
  trialStartedDaysAgo(5, NOW, 103);
  trialStartedDaysAgo(6, NOW, 104, 100);
  expect(check_trial_payment_timing(4, 14)).toMatchObject({ decision: 'CHALLENGE', paymentDelay: 5 });
  expect(check_trial_payment_timing(5, 14)).toMatchObject({ decision: 'CHALLENGE', paymentDelay: 89 });
  expect(check_trial_payment_timing(6, 14)).toMatchObject({ decision: 'CHALLENGE', paymentDelay: 90 });
  set_clock(() => new Date(NOW.getTime() - 60 * 1000));
  expect(check_trial_payment_timing(4, 14)).toMatchObject({ decision: 'PASS', paymentDelay: 4 });
  trialStartedDaysAgo(7, NOW, 14);
  set_clock(() => new Date(NOW.getTime() - 1));
  expect(check_trial_payment_timing(7, 14).paymentDelay).toBe(-1);   // floor toward negative infinity, not truncation
});

/** A device the TRIAL-09/14 tests share. */
const FARM = { user_agent: 'ua_farm', screen_resolution: '1280x720', timezone: 'UTC', browser_language: 'en' };

/** Records FARM for each user id. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
function farm(userIds: number[]) {
  for (const id of userIds) record_device_fingerprint({ user_id: id, device: FARM });
}

/** Device rows for one user. */
function deviceRows(userId: number): number {
  return (db.prepare('SELECT COUNT(*) AS n FROM device_fingerprints WHERE user_id = ?').get(userId) as { n: number }).n;
}

/**
 * TRIAL-09: exactly 5 OTHER users on the device is FAIL (it used to need 6), and signup itself runs the device gate:
 * the 6th account from a device farm is refused 403 device_suspected_fraud and leaves no device or ledger row.
 * In: device rows. Out: assertions only. Why: TRIAL-09 amendment 2026-11-10 (signup recorded the device first, so a
 * farm never failed). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
 */
// TRIAL-09
test('device_fingerprint FAIL → 5 other users; signup from the farm is refused and records nothing', () => {
  farm([11, 12, 13, 14, 15]);
  expect(check_device_fingerprint(FARM, 99)).toMatchObject({ decision: 'FAIL', matchingUsers: 5 });
  const before = (db.prepare('SELECT COUNT(*) AS n FROM device_fingerprints').get() as { n: number }).n;
  const res = signup({ email: 'farm6@example.com', password: 'pwd', ip: '7.7.7.7', ...FARM });
  expect(res.success).toBe(false);
  expect(res.error).toMatchObject({ error: 'device_suspected_fraud', code: 403 });
  expect((db.prepare('SELECT COUNT(*) AS n FROM device_fingerprints').get() as { n: number }).n).toBe(before);
  expect((db.prepare("SELECT COUNT(*) AS n FROM trial_abuse_ledger WHERE email = 'farm6@example.com'").get() as { n: number }).n).toBe(0);
});

/**
 * TRIAL-14: device boundaries: 4 other users is CHALLENGE (and records the device), a user who already has the
 * device is PASS with 2-4 others, exactly 5 others is FAIL even for a user who already has the device, and a FAIL
 * records no device row; the user's own row never counts toward the others. In: device rows. Out: assertions only.
 * Why: TRIAL-14 amendment 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
 */
// TRIAL-14
test('device_fingerprint boundaries → 4 others CHALLENGE; 5 FAIL even for a known device; FAIL records nothing', () => {
  farm([21, 22, 23, 24]);
  expect(check_device_fingerprint(FARM, 30)).toMatchObject({ decision: 'CHALLENGE', matchingUsers: 4 });
  expect(device_fingerprint_gate(FARM, 30).decision).toBe('CHALLENGE');
  expect(deviceRows(30)).toBe(1);
  // user 21 already has the device and sees 4 others (22, 23, 24, 30): PASS, own row not counted
  expect(check_device_fingerprint(FARM, 21)).toMatchObject({ decision: 'PASS', matchingUsers: 4 });

  farm([25]);   // now 21..25 and 30 = 6 users
  expect(check_device_fingerprint(FARM, 21)).toMatchObject({ decision: 'FAIL', matchingUsers: 5 });
  expect(device_fingerprint_gate(FARM, 40).decision).toBe('FAIL');
  expect(deviceRows(40)).toBe(0);
});

/**
 * Phase B.2 trial spec amendment (gate 5, under TRIAL-10/11): a user with no users row is FAIL user_not_found (fail
 * closed) and subscription_created answers 403 {error: 'user_not_found'}; a user with a users row but no ledger row
 * is judged from users.created_at with no earlier payment (90 days after the trial is FAIL, 4 days is PASS), and a
 * payment for such a user is recorded in a new ledger row, so the next check sees the earlier payment.
 * In: users rows on a pinned clock. Out: assertions only. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: in-memory SQLite.
 */
// TRIAL-11
test('trial_payment_timing → no users row FAIL user_not_found; no ledger row judged from users.created_at', () => {
  set_clock(() => NOW);
  expect(check_trial_payment_timing(9001, 14)).toMatchObject({ decision: 'FAIL', error: 'user_not_found', paymentDelay: null });
  const refused = subscription_created({ user_id: 9001, stripe_payment_method_id: 'pm_ghost', stripe_customer_id: 'cus_ghost' });
  expect(refused.success).toBe(false);
  expect(refused.error).toMatchObject({ error: 'user_not_found', code: 403 });

  addUser(9002, new Date(NOW.getTime() - 104 * 24 * HOUR));   // 90 days after a 14-day trial, no ledger row
  expect(check_trial_payment_timing(9002, 14)).toMatchObject({ decision: 'FAIL', paymentDelay: 90 });

  addUser(9003, new Date(NOW.getTime() - 18 * 24 * HOUR));    // 4 days after the trial, no ledger row
  expect(check_trial_payment_timing(9003, 14)).toMatchObject({ decision: 'PASS', paymentDelay: 4 });
  expect(subscription_created({ user_id: 9003, stripe_payment_method_id: 'pm_new', stripe_customer_id: 'cus_new' }).success).toBe(true);
  const ledger = db.prepare('SELECT payment_added_date, subscription_status FROM trial_abuse_ledger WHERE user_id = ?').all(9003) as Array<{ payment_added_date: string; subscription_status: string }>;
  expect(ledger).toEqual([{ payment_added_date: NOW.toISOString(), subscription_status: 'completed' }]);

  // A later check for the same user now has an earlier payment: 90+ days after the trial is CHALLENGE, not FAIL.
  set_clock(() => new Date(NOW.getTime() + 90 * 24 * HOUR));
  expect(check_trial_payment_timing(9003, 14)).toMatchObject({ decision: 'CHALLENGE', paymentDelay: 94 });
});
