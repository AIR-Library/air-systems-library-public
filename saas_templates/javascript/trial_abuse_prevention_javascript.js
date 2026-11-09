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

function now() {
  return new Date().toISOString();
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
const TRIAL_DAYS = 14;

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
    return { error: 'email_has_trial_history', message: 'Email has prior trial history', code: 409 };
  }
  if (decision === 'CHALLENGE') {
    return { success: true, challenge: 'email_confirm', flags: ['email_trial_attempt_2+'] };
  }
  return { success: true };
}

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
    return { error: 'payment_method_used_for_multiple_trials', message: 'Payment method used for multiple trials', code: 403 };
  }
  if (decision === 'CHALLENGE') {
    return { success: true, challenge: 'email_confirm', flags: ['payment_reuse_2x'] };
  }
  return { success: true };
}

async function check_ip_signup_rate_limit(ip) {
  const stmt = db.prepare(`
    SELECT COUNT(*) AS count
    FROM signups
    WHERE ip = ? AND datetime(created_at) > datetime('now', '-24 hours')
  `);
  const { count } = stmt.get(ip);
  let decision;
  if (count < 5) decision = 'PASS';
  else if (count >= 5 && count < 10) decision = 'CHALLENGE';
  else decision = 'FAIL';

  why_chain({gate: 'ip_signup_rate_limit', ip, count}, decision);

  if (decision === 'FAIL') {
    return { error: 'too_many_signups_from_ip', message: 'Too many signups from IP', code: 429, retry_after: 86400 };
  }
  if (decision === 'CHALLENGE') {
    return { success: true, challenge: 'captcha' };
  }
  return { success: true };
}

async function check_device_fingerprint(device, user_id = null) {
  const device_hash = sha256(device);
  const stmt = db.prepare(`
    SELECT COUNT(DISTINCT user_id) AS matching_users
    FROM device_fingerprints
    WHERE device_hash = ?
  `);
  const { matching_users } = stmt.get(device_hash);

  let decision;
  if (user_id) {
    const userStmt = db.prepare(`
      SELECT COUNT(*) AS count
      FROM device_fingerprints
      WHERE user_id = ? AND device_hash = ?
    `);
    const { count } = userStmt.get(user_id, device_hash);
    if (count > 0) decision = 'PASS';
    else if (matching_users < 2) decision = 'PASS';
    else if (matching_users >= 2 && matching_users <= 5) decision = 'CHALLENGE';
    else decision = 'FAIL';
  } else {
    if (matching_users < 2) decision = 'PASS';
    else if (matching_users >= 2 && matching_users <= 5) decision = 'CHALLENGE';
    else decision = 'FAIL';
  }

  why_chain({gate: 'device_fingerprint', device_hash, matching_users, user_id}, decision);

  if (decision === 'FAIL') {
    return { error: 'device_suspected_fraud', message: 'Device suspected fraud', code: 403 };
  }
  if (decision === 'CHALLENGE') {
    return { success: true, challenge: 'email_confirm', flags: ['new_device_login_detected'] };
  }
  return { success: true };
}

async function check_trial_payment_timing(user_id) {
  const userStmt = db.prepare(`SELECT created_at FROM users WHERE id = ?`);
  const user = userStmt.get(user_id);
  if (!user) throw new Error('User not found');

  const ledgerStmt = db.prepare(`
    SELECT trial_started_at, payment_added_date
    FROM trial_abuse_ledger
    WHERE user_id = ?
  `);
  const ledger = ledgerStmt.get(user_id);
  if (!ledger) throw new Error('Ledger not found');

  const trial_start_date = new Date(ledger.trial_started_at);
  const nowDate = new Date();
  const days_elapsed = Math.floor((nowDate - trial_start_date) / (1000 * 60 * 60 * 24));

  const payment_added_date = ledger.payment_added_date ? new Date(ledger.payment_added_date) : null;
  const payment_delay = payment_added_date ? Math.floor((payment_added_date - trial_start_date) / (1000 * 60 * 60 * 24)) : null;

  let decision;
  if (days_elapsed < TRIAL_DAYS + 5 && payment_added_date && payment_added_date > trial_start_date) {
    decision = 'PASS';
  } else if (days_elapsed > TRIAL_DAYS + 30 && payment_added_date && payment_added_date > new Date(trial_start_date.getTime() + TRIAL_DAYS * 24 * 60 * 60 * 1000)) {
    decision = 'CHALLENGE';
  } else if (!payment_added_date && days_elapsed >= TRIAL_DAYS + 90) {
    decision = 'FAIL';
  } else {
    decision = 'PASS';
  }

  why_chain({gate: 'trial_payment_timing', trial_duration: days_elapsed, payment_delay}, decision);

  if (decision === 'FAIL') {
    return { error: 'trial_ended_no_payment_cannot_retry', message: 'Trial ended, no payment, cannot retry', code: 403 };
  }
  if (decision === 'CHALLENGE') {
    return { success: true, challenge: 'email_confirm', flags: ['late_payment_entry'] };
  }
  return { success: true };
}

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
    return { error: 'chargeback_history_requires_prepayment', message: 'Chargeback history requires prepayment', code: 403 };
  }
  if (decision === 'CHALLENGE') {
    return { success: true, challenge: 'email_confirm', flags: ['chargeback_1x'] };
  }
  return { success: true };
}

// ---------- Integration Functions ----------
async function signup(email, password, ip, device) {
  const emailGate = await check_email_trial_history(email);
  const ipGate = await check_ip_signup_rate_limit(ip);

  if (emailGate.error) return emailGate;
  if (ipGate.error) return ipGate;

  const insertUser = db.prepare(`INSERT INTO users (email, created_at) VALUES (?, ?)`);
  const userInfo = insertUser.run(email, now());
  const user_id = userInfo.lastInsertRowid;

  // Log to abuse ledger
  const insertLedger = db.prepare(`
    INSERT INTO trial_abuse_ledger
      (user_id, email, ip, signup_date, trial_started_at, gate_flags)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  insertLedger.run(
    user_id,
    email,
    ip,
    now(),
    now(),
    JSON.stringify({ email: emailGate.decision, ip: ipGate.decision })
  );

  // Device fingerprint
  const device_hash = sha256(device);
  const insertDevice = db.prepare(`
    INSERT INTO device_fingerprints
      (user_id, device_hash, user_agent, screen_resolution, timezone)
    VALUES (?, ?, ?, ?, ?)
  `);
  insertDevice.run(
    user_id,
    device_hash,
    device.user_agent,
    device.screen_resolution,
    device.timezone
  );

  // Record signup for rate limiting
  const insertSignup = db.prepare(`INSERT INTO signups (ip) VALUES (?)`);
  insertSignup.run(ip);

  const result = { success: true, user_id };
  if (emailGate.flags) result.flags = emailGate.flags;
  if (ipGate.challenge) result.challenge = ipGate.challenge;
  return result;
}

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
        gate_flags = json_set(gate_flags, '$.payment', ?, '$.timing', ?, '$.chargeback', ?)
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
  check_email_trial_history,
  check_payment_method_history,
  check_ip_signup_rate_limit,
  check_device_fingerprint,
  check_trial_payment_timing,
  check_chargeback_history,
  signup,
  subscription_created
};
