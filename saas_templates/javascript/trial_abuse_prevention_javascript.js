const crypto = require('crypto');
const Database = require('better-sqlite3');
const db = new Database(':memory:');

// ---------- Database Schema ----------
db.exec(`
CREATE TABLE IF NOT EXISTS trial_abuse_ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  email TEXT,
  stripe_payment_method_id TEXT,
  stripe_customer_id TEXT,
  ip TEXT,
  device_fingerprint TEXT,
  signup_date TEXT,
  trial_started_at TEXT,
  payment_added_date TEXT,
  subscription_status TEXT,
  chargeback_count INTEGER DEFAULT 0,
  refund_count INTEGER DEFAULT 0,
  gate_flags TEXT,
  alert_reason TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS device_fingerprints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  device_hash TEXT,
  user_agent TEXT,
  screen_resolution TEXT,
  timezone TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS gate_decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  gate_name TEXT,
  decision TEXT,
  rule_inputs TEXT,
  rule_outputs TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS signups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT,
  created_at TEXT,
  abuse_flags TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS stripe_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer TEXT,
  type TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS refunds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  status TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

// ---------- Helper Functions ----------
function sha256(obj) {
  const json = JSON.stringify(obj);
  return crypto.createHash('sha256').update(json).digest('hex');
}

// [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Injectable clock and trial length (spec: trial_days is configuration,
// default 14). configure({ now: () => ms, trialDays }) sets them; tests pin the clock so no result depends on the day.
const DAY_MS = 24 * 60 * 60 * 1000;
const settings = { now: () => Date.now(), trialDays: 14 };

/**
 * configure({ now?, trialDays? }) -> the current settings. In: a clock returning epoch ms and/or the trial length in
 * days (a positive integer). Why: deterministic gates (TRIAL-10/11/15) and configurable trial_days.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches module settings only.
 */
function configure({ now: clock, trialDays } = {}) {
  if (clock !== undefined) {
    if (typeof clock !== 'function') throw new TypeError('now must be a function returning epoch milliseconds');
    settings.now = clock;
  }
  if (trialDays !== undefined) {
    if (!Number.isInteger(trialDays) || trialDays < 1) throw new TypeError('trialDays must be a positive integer');
    settings.trialDays = trialDays;
  }
  return { ...settings };
}

/** The current time as an ISO string, from the configured clock. */
function now() {
  return new Date(settings.now()).toISOString();
}

function why_chain({gate, ...inputs}, decision, outputs = {}) {
  const stmt = db.prepare(`
    INSERT INTO gate_decisions (user_id, gate_name, decision, rule_inputs, rule_outputs)
    VALUES (@user_id, @gate_name, @decision, @rule_inputs, @rule_outputs)
  `);
  stmt.run({
    user_id: inputs.user_id || null,
    gate_name: gate,
    decision,
    rule_inputs: JSON.stringify(inputs),
    rule_outputs: JSON.stringify(outputs)
  });
}

// ---------- Gate Implementations ----------
// Every gate result carries `decision` ('PASS' | 'CHALLENGE' | 'FAIL'); the ledger's gate_flags store it
// (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the results had no decision field, so gate_flags held nulls).

/**
 * Gate 1: prior completed/charged-back trials for this e-mail. PASS 0, CHALLENGE 1, FAIL 2+ (409).
 * Out: { decision, success | error, code, challenge?, flags? }. [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] the
 * result now carries `decision`, which signup and subscription_created store in gate_flags.
 * Touches: reads trial_abuse_ledger, writes gate_decisions.
 */
async function check_email_trial_history(email) {
  const stmt = db.prepare(`
    SELECT COUNT(*) AS prior_count
    FROM trial_abuse_ledger
    WHERE email = ? AND subscription_status IN ('completed', 'chargebacked')
  `);
  const { prior_count } = stmt.get(email);
  let decision;
  if (prior_count === 0) decision = 'PASS';
  else if (prior_count === 1) decision = 'CHALLENGE';
  else decision = 'FAIL';

  why_chain({gate: 'email_trial_history', email, prior_count}, decision);

  if (decision === 'FAIL') {
    return { decision, error: 'email_has_trial_history', message: 'Email has prior trial history', code: 409 };
  }
  if (decision === 'CHALLENGE') {
    return { decision, success: true, challenge: 'email_confirm', flags: ['email_trial_attempt_2+'] };
  }
  return { decision, success: true };
}

/**
 * Gate 2: prior trials on this payment method. PASS < 2, CHALLENGE 2, FAIL 3+ (403).
 * Out: { decision, success | error, code, challenge?, flags? }. [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] the
 * result now carries `decision`, which signup and subscription_created store in gate_flags.
 * Touches: reads trial_abuse_ledger, writes gate_decisions.
 */
async function check_payment_method_history(stripe_payment_method_id) {
  const stmt = db.prepare(`
    SELECT COUNT(*) AS prior_count
    FROM trial_abuse_ledger
    WHERE stripe_payment_method_id = ? AND subscription_status IN ('completed', 'chargebacked')
  `);
  const { prior_count } = stmt.get(stripe_payment_method_id);
  let decision;
  if (prior_count < 2) decision = 'PASS';
  else if (prior_count === 2) decision = 'CHALLENGE';
  else decision = 'FAIL';

  why_chain({gate: 'payment_method_history', payment_id: stripe_payment_method_id, prior_count}, decision);

  if (decision === 'FAIL') {
    return { decision, error: 'payment_method_used_for_multiple_trials', message: 'Payment method used for multiple trials', code: 403 };
  }
  if (decision === 'CHALLENGE') {
    return { decision, success: true, challenge: 'email_confirm', flags: ['payment_reuse_2x'] };
  }
  return { decision, success: true };
}

/**
 * Gate 3: signups from this IP in the last 24 h by the configured clock. PASS < 5, CHALLENGE 5-9, FAIL >= 10 (429).
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] the window comes from the injectable clock, not SQLite's 'now'.
 * Touches: reads signups, writes gate_decisions.
 */
async function check_ip_signup_rate_limit(ip) {
  const since = new Date(settings.now() - DAY_MS).toISOString();
  const stmt = db.prepare(`
    SELECT COUNT(*) AS count
    FROM signups
    WHERE ip = ? AND datetime(created_at) > datetime(?)
  `);
  const { count } = stmt.get(ip, since);
  let decision;
  if (count < 5) decision = 'PASS';
  else if (count >= 5 && count < 10) decision = 'CHALLENGE';
  else decision = 'FAIL';

  why_chain({gate: 'ip_signup_rate_limit', ip, count}, decision);

  if (decision === 'FAIL') {
    return { decision, error: 'too_many_signups_from_ip', message: 'Too many signups from IP', code: 429, retry_after: 86400 };
  }
  if (decision === 'CHALLENGE') {
    return { decision, success: true, challenge: 'captcha' };
  }
  return { decision, success: true };
}

/**
 * The device-gate decision without side effects. count = OTHER users on this device (null-safe: with no user every
 * user counts). In order: FAIL if count >= 5; PASS if count < 2; PASS if this user already has the device;
 * CHALLENGE otherwise. Out: { decision, device_hash, matching_users, known_device }.
 * Why: TRIAL-09/14 amended 2026-11-10 (the old CHALLENGE range <= 5 overlapped FAIL at 5, and a known device skipped
 * FAIL). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads device_fingerprints.
 */
function device_decision(device, user_id) {
  const device_hash = sha256(device);
  const uid = user_id === undefined ? null : user_id;
  const { matching_users } = db.prepare(`
    SELECT COUNT(DISTINCT user_id) AS matching_users
    FROM device_fingerprints
    WHERE device_hash = ? AND (? IS NULL OR user_id IS NULL OR user_id != ?)
  `).get(device_hash, uid, uid);
  const known_device = uid !== null && db.prepare(`
    SELECT 1 FROM device_fingerprints WHERE user_id = ? AND device_hash = ? LIMIT 1
  `).get(uid, device_hash) !== undefined;
  let decision;
  if (matching_users >= 5) decision = 'FAIL';
  else if (matching_users < 2) decision = 'PASS';
  else if (known_device) decision = 'PASS';
  else decision = 'CHALLENGE';
  return { decision, device_hash, matching_users, known_device };
}

/**
 * Writes this user's device row unless it is already there. In: user_id, device, its hash.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: device_fingerprints.
 */
function record_device(user_id, device, device_hash) {
  const exists = db.prepare(`SELECT 1 FROM device_fingerprints WHERE user_id = ? AND device_hash = ? LIMIT 1`)
    .get(user_id, device_hash);
  if (exists) return;
  db.prepare(`
    INSERT INTO device_fingerprints (user_id, device_hash, user_agent, screen_resolution, timezone, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(user_id, device_hash, device.user_agent, device.screen_resolution, device.timezone, now());
}

/**
 * Gate 4: check_device_fingerprint(device, user_id = null) -> { decision, matching_users, success | error, code }.
 * Decides first (device_decision), logs the why_chain, and only then, for PASS or CHALLENGE and a known user, records
 * the device row. A FAIL records nothing (TRIAL-14). FAIL -> 403 device_suspected_fraud; CHALLENGE -> email confirm.
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: device_fingerprints, gate_decisions.
 */
async function check_device_fingerprint(device, user_id = null) {
  const { decision, device_hash, matching_users, known_device } = device_decision(device, user_id);

  why_chain({gate: 'device_fingerprint', device_hash, matching_users, known_device, user_id}, decision);

  if (decision === 'FAIL') {
    return { decision, matching_users, error: 'device_suspected_fraud', message: 'Device suspected fraud', code: 403 };
  }
  if (user_id !== null && user_id !== undefined) record_device(user_id, device, device_hash);
  if (decision === 'CHALLENGE') {
    return { decision, matching_users, success: true, challenge: 'email_confirm', flags: ['new_device_login_detected'] };
  }
  return { decision, matching_users, success: true };
}

/**
 * Gate 5: check_trial_payment_timing(user_id), judged as a payment method is added (payment date = now, from the
 * clock). trial_end = users.created_at + trialDays; days_after_trial = Math.floor((now - trial_end) / 1 day), which
 * rounds toward negative infinity; earlier_payment = a ledger row of this user already has payment_added_date.
 * PASS if days_after_trial < 5; FAIL if >= 90 and no earlier payment (403 trial_ended_no_payment_cannot_retry);
 * CHALLENGE otherwise (flag late_payment_entry). Out: { decision, days_after_trial, earlier_payment, ... }.
 * Why: TRIAL-10/11/15 amended 2026-11-10 (it counted days since the trial START with windows that overlapped).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads users and the ledger, writes gate_decisions.
 */
async function check_trial_payment_timing(user_id) {
  const user = db.prepare(`SELECT created_at FROM users WHERE id = ?`).get(user_id);
  if (!user) throw new Error('User not found');
  const startMs = Date.parse(user.created_at);
  if (Number.isNaN(startMs)) throw new Error('User has no valid created_at');

  const { payments } = db.prepare(`
    SELECT COUNT(payment_added_date) AS payments FROM trial_abuse_ledger WHERE user_id = ?
  `).get(user_id);
  const earlier_payment = payments > 0;
  const trial_end = startMs + settings.trialDays * DAY_MS;
  const days_after_trial = Math.floor((settings.now() - trial_end) / DAY_MS);

  let decision;
  if (days_after_trial < 5) decision = 'PASS';
  else if (days_after_trial >= 90 && !earlier_payment) decision = 'FAIL';
  else decision = 'CHALLENGE';

  why_chain({gate: 'trial_payment_timing', user_id, trial_duration: settings.trialDays, payment_delay: days_after_trial, earlier_payment}, decision);

  if (decision === 'FAIL') {
    return { decision, days_after_trial, earlier_payment, error: 'trial_ended_no_payment_cannot_retry', message: 'Trial ended, no payment, cannot retry', code: 403 };
  }
  if (decision === 'CHALLENGE') {
    return { decision, days_after_trial, earlier_payment, success: true, challenge: 'email_confirm', flags: ['late_payment_entry'] };
  }
  return { decision, days_after_trial, earlier_payment, success: true };
}

/**
 * Gate: counts chargebacks for the supplied Stripe customer, else the ledger's, plus charged-back refunds.
 * No customer means none is guessed. Output: { success } or { error, code: 403 }. Touches: reads the database. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] the result also carries `decision`.
 */
async function check_chargeback_history(user_id, supplied_customer_id = null) {
  // Chargebacks are counted against the Stripe customer supplied with this call (subscription_created passes it,
  // since the ledger stores it only after the gates pass), else the one stored on the ledger. A user with neither
  // has none: the id is never guessed, since a guessed id could match someone else's events.
  const ledger = db.prepare(`SELECT stripe_customer_id FROM trial_abuse_ledger WHERE user_id = ?`).get(user_id);
  const stripe_customer_id = supplied_customer_id ?? ledger?.stripe_customer_id ?? null;

  const stripeStmt = db.prepare(`
    SELECT COUNT(*) AS count
    FROM stripe_events
    WHERE customer = ? AND type LIKE '%chargeback%'
  `);
  const { count: stripe_count } = stripe_customer_id === null ? { count: 0 } : stripeStmt.get(stripe_customer_id);

  const refundStmt = db.prepare(`
    SELECT COUNT(*) AS count
    FROM refunds
    WHERE user_id = ? AND status = 'chargebacked'
  `);
  const { count: refund_count } = refundStmt.get(user_id);

  const total_chargebacks = stripe_count + refund_count;
  let decision;
  if (total_chargebacks === 0) decision = 'PASS';
  else if (total_chargebacks === 1) decision = 'CHALLENGE';
  else decision = 'FAIL';

  why_chain({gate: 'chargeback_history', chargebacks: total_chargebacks}, decision);

  if (decision === 'FAIL') {
    return { decision, error: 'chargeback_history_requires_prepayment', message: 'Chargeback history requires prepayment', code: 403 };
  }
  if (decision === 'CHALLENGE') {
    return { decision, success: true, challenge: 'email_confirm', flags: ['chargeback_1x'] };
  }
  return { decision, success: true };
}

// ---------- Integration Functions ----------
/**
 * signup(email, password, ip, device) -> { success, user_id, flags?, challenge? } | a gate's error.
 * Gates run BEFORE anything is recorded: email history (409), IP rate limit (429) and the device gate (403); the
 * device gate counts every user on the device, since the new user has none yet. Then the user, the ledger row, the
 * device row (only after a PASS or CHALLENGE) and the signup are written in one transaction.
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] TRIAL-09/14: the device row used to be written without running the
 * gate, so every later check passed and a device farm never failed; times come from the injectable clock.
 * Touches: users, trial_abuse_ledger, device_fingerprints, signups, gate_decisions.
 */
async function signup(email, password, ip, device) {
  const emailGate = await check_email_trial_history(email);
  const ipGate = await check_ip_signup_rate_limit(ip);

  if (emailGate.error) return emailGate;
  if (ipGate.error) return ipGate;

  const deviceGate = await check_device_fingerprint(device, null);
  if (deviceGate.error) return deviceGate;

  const user_id = db.transaction(() => {
    const at = now();
    const id = db.prepare(`INSERT INTO users (email, created_at) VALUES (?, ?)`).run(email, at).lastInsertRowid;
    db.prepare(`
      INSERT INTO trial_abuse_ledger
        (user_id, email, ip, device_fingerprint, signup_date, trial_started_at, gate_flags)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, email, ip, sha256(device), at, at,
      JSON.stringify({ email: emailGate.decision, ip: ipGate.decision, device: deviceGate.decision }));
    record_device(id, device, sha256(device));
    db.prepare(`INSERT INTO signups (ip, created_at) VALUES (?, ?)`).run(ip, at);
    return id;
  })();

  const result = { success: true, user_id };
  const flags = [...(emailGate.flags || []), ...(deviceGate.flags || [])];
  if (flags.length) result.flags = flags;
  if (ipGate.challenge) result.challenge = ipGate.challenge;
  return result;
}

/**
 * Runs the payment, timing and chargeback gates (checking the supplied customer before it is stored), then
 * records the result on the ledger without erasing a stored customer id. Output: { success, flags? } or the error. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] gate_flags is merged into '{}' when the row has none (json_set on
 * NULL returned NULL, losing every decision), and payment_added_date comes from the injectable clock.
 * Touches: trial_abuse_ledger, gate_decisions.
 */
async function subscription_created(user_id, stripe_payment_method_id, stripe_customer_id = null) {
  const paymentGate = await check_payment_method_history(stripe_payment_method_id);
  const timingGate = await check_trial_payment_timing(user_id);
  const chargebackGate = await check_chargeback_history(user_id, stripe_customer_id);

  if (paymentGate.error) return paymentGate;
  if (timingGate.error) return timingGate;
  if (chargebackGate.error) return chargebackGate;

  // Create subscription placeholder (not implemented)
  // Update abuse ledger
  const updateLedger = db.prepare(`
    UPDATE trial_abuse_ledger
    SET stripe_payment_method_id = ?, stripe_customer_id = COALESCE(?, stripe_customer_id), payment_added_date = ?, subscription_status = 'completed',
        gate_flags = json_set(COALESCE(gate_flags, '{}'), '$.payment', ?, '$.timing', ?, '$.chargeback', ?)
    WHERE user_id = ?
  `);
  updateLedger.run(
    stripe_payment_method_id,
    stripe_customer_id,
    now(),
    paymentGate.decision,
    timingGate.decision,
    chargebackGate.decision,
    user_id
  );

  const result = { success: true };
  if (paymentGate.flags) result.flags = paymentGate.flags;
  if (timingGate.flags) result.flags = result.flags ? [...result.flags, ...timingGate.flags] : timingGate.flags;
  if (chargebackGate.flags) result.flags = result.flags ? [...result.flags, ...chargebackGate.flags] : chargebackGate.flags;
  return result;
}

// ---------- Exports ----------
module.exports = {
  db,
  configure,
  check_email_trial_history,
  check_payment_method_history,
  check_ip_signup_rate_limit,
  check_device_fingerprint,
  check_trial_payment_timing,
  check_chargeback_history,
  signup,
  subscription_created
};
