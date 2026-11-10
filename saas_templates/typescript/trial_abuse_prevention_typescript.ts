import Database from 'better-sqlite3';
import { createHash } from 'crypto';

// ---------- Types ----------
type Decision = 'PASS' | 'CHALLENGE' | 'FAIL';

/**
 * What a gate returns: its decision and the numbers it decided on. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: paymentDelay may be null
 * and the chargeback gate reports its total in count. Touches: nothing.
 */
interface GateResult {
  decision: Decision;
  priorCount?: number;
  count?: number;
  matchingUsers?: number;
  deviceHash?: string;
  trialDuration?: number;
  paymentDelay?: number | null;
}

interface User {
  id: number;
  email: string;
  created_at: Date;
  abuse_flags: string[];
}

interface AbuseLedgerEntry {
  id?: number;
  user_id: number;
  email: string;
  stripe_payment_method_id?: string;
  ip: string;
  device_fingerprint?: string;
  signup_date: Date;
  trial_started_at: Date;
  payment_added_date?: Date;
  subscription_status?: string;
  chargeback_count?: number;
  refund_count?: number;
  gate_flags: Record<string, Decision>;
  alert_reason?: string;
  created_at: Date;
}

// ---------- DB Setup ----------
export const db = new Database(':memory:');

// Migration (DDL)
db.exec(`
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
  gate_flags TEXT NOT NULL, -- JSON
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
  rule_inputs TEXT,  -- JSON
  rule_outputs TEXT, -- JSON
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

// ---------- Clock ----------
let clock: () => Date = () => new Date();

/**
 * Replaces the clock the timing gate and the signup / payment timestamps read; call with nothing to restore the
 * system clock. In: a function returning now. Out: nothing. Why: the spec's injectable-clock rule, so the
 * TRIAL-10/11/15 day boundaries are tested exactly. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: module state.
 */
export function set_clock(fn?: () => Date): void {
  clock = fn ?? (() => new Date());
}

// ---------- Helper Functions ----------
function why_chain(params: {
  user_id: number;
  gate_name: string;
  decision: Decision;
  rule_inputs: any;
  rule_outputs: any;
}) {
  const stmt = db.prepare(`
    INSERT INTO gate_decisions (user_id, gate_name, decision, rule_inputs, rule_outputs)
    VALUES (?, ?, ?, ?, ?)
  `);
  stmt.run(
    params.user_id,
    params.gate_name,
    params.decision,
    JSON.stringify(params.rule_inputs),
    JSON.stringify(params.rule_outputs)
  );
}

// ---------- Gate Implementations ----------
export function check_email_trial_history(email: string, userId: number): GateResult {
  const rows = db.prepare(`
    SELECT subscription_status FROM trial_abuse_ledger
    WHERE email = ? AND subscription_status IN ('completed', 'chargebacked')
  `).all(email);

  const priorCount = rows.length;
  let decision: Decision = 'PASS';
  if (priorCount === 0) decision = 'PASS';
  else if (priorCount === 1) decision = 'CHALLENGE';
  else decision = 'FAIL';

  why_chain({
    user_id: userId,
    gate_name: 'email_trial_history',
    decision,
    rule_inputs: { email, priorCount },
    rule_outputs: { decision }
  });

  return { decision, priorCount };
}

export function check_payment_method_history(stripePaymentMethodId: string, userId: number): GateResult {
  const row = db.prepare(`
    SELECT COUNT(*) as cnt FROM trial_abuse_ledger
    WHERE stripe_payment_method_id = ? AND subscription_status IN ('completed', 'chargebacked')
  `).get(stripePaymentMethodId);
  const priorCount = row.cnt as number;

  let decision: Decision = 'PASS';
  if (priorCount < 2) decision = 'PASS';
  else if (priorCount === 2) decision = 'CHALLENGE';
  else decision = 'FAIL';

  why_chain({
    user_id: userId,
    gate_name: 'payment_method_history',
    decision,
    rule_inputs: { stripePaymentMethodId, priorCount },
    rule_outputs: { decision }
  });

  return { decision, priorCount };
}

export function check_ip_signup_rate_limit(ip: string, userId: number): GateResult {
  const row = db.prepare(`
    SELECT COUNT(*) as cnt FROM trial_abuse_ledger
    WHERE ip = ? AND signup_date > datetime('now', '-24 hours')
  `).get(ip);
  const count = row.cnt as number;

  let decision: Decision = 'PASS';
  if (count < 5) decision = 'PASS';
  else if (count >= 5 && count < 10) decision = 'CHALLENGE';
  else decision = 'FAIL';

  why_chain({
    user_id: userId,
    gate_name: 'ip_signup_rate_limit',
    decision,
    rule_inputs: { ip, count },
    rule_outputs: { decision }
  });

  return { decision, count };
}

/** The device hash: SHA-256 of user_agent|screen_resolution|timezone|browser_language. Touches nothing. */
function deviceHashOf(device: { user_agent: string; screen_resolution: string; timezone: string; browser_language: string }): string {
  const deviceString = `${device.user_agent}|${device.screen_resolution}|${device.timezone}|${device.browser_language}`;
  return createHash('sha256').update(deviceString).digest('hex');
}

/**
 * Gate 4, DEVICE_FINGERPRINT (check only; it writes no device row).
 *
 * In: the device and the user id being judged (null for a user not created yet). Out: { decision, matchingUsers
 * (OTHER users on this device), deviceHash }. Decision, in this order: FAIL if 5 or more other users; PASS if fewer
 * than 2; PASS if this user already has a row for this device; else CHALLENGE.
 * Why: TRIAL-09/14 amendment 2026-11-10. It counted the user themself, used CHALLENGE for 2..5 (overlapping FAIL at
 * exactly 5), and FAIL only from 6. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: reads device_fingerprints, writes one gate_decisions row.
 */
export function check_device_fingerprint(device: {
  user_agent: string;
  screen_resolution: string;
  timezone: string;
  browser_language: string;
}, userId: number | null): GateResult {
  const deviceHash = deviceHashOf(device);

  const row = db.prepare(`
    SELECT COUNT(DISTINCT user_id) as cnt FROM device_fingerprints
    WHERE device_hash = ? AND (? IS NULL OR user_id != ?)
  `).get(deviceHash, userId, userId) as { cnt: number };
  const matchingUsers = row.cnt;
  const known = userId !== null && db.prepare(
    `SELECT 1 FROM device_fingerprints WHERE device_hash = ? AND user_id = ? LIMIT 1`
  ).get(deviceHash, userId) !== undefined;

  let decision: Decision;
  if (matchingUsers >= 5) decision = 'FAIL';
  else if (matchingUsers < 2) decision = 'PASS';
  else if (known) decision = 'PASS';
  else decision = 'CHALLENGE';

  why_chain({
    user_id: userId ?? 0,
    gate_name: 'device_fingerprint',
    decision,
    rule_inputs: { deviceHash, matchingUsers, known_device: known },
    rule_outputs: { decision }
  });

  return { decision, matchingUsers, deviceHash };
}

/**
 * Runs the device gate and then, only for PASS or CHALLENGE, records the device for the user (once).
 * In: the device and the user id. Out: the gate result. Why: TRIAL-14: "the device row is written AFTER the
 * decision, and only for PASS or CHALLENGE" (recording first made every later check pass, so a device farm never
 * failed). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: device_fingerprints, gate_decisions.
 */
export function device_fingerprint_gate(device: {
  user_agent: string;
  screen_resolution: string;
  timezone: string;
  browser_language: string;
}, userId: number): GateResult {
  const result = check_device_fingerprint(device, userId);
  if (result.decision !== 'FAIL') {
    const has = db.prepare(`SELECT 1 FROM device_fingerprints WHERE device_hash = ? AND user_id = ? LIMIT 1`)
      .get(result.deviceHash, userId) !== undefined;
    if (!has) record_device_fingerprint({ user_id: userId, device });
  }
  return result;
}

/**
 * Reads a date stored by SQLite or by this module. SQLite's CURRENT_TIMESTAMP / datetime('now') give
 * "YYYY-MM-DD HH:MM:SS" in UTC with no zone marker, which `new Date()` would read as local time; this reads it as UTC.
 * In: the stored text (or null). Out: a Date, or null when nothing is stored.
 * Why: the timing gate must not depend on the machine's time zone (repair of trial_payment_timing, 2026-11-10,
 * session session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
 */
function parseDbDate(value: string | null | undefined): Date | null {
  if (value === null || value === undefined) return null;
  const text = String(value);
  const isoLike = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?$/.test(text) ? text.replace(' ', 'T') + 'Z' : text;
  const d = new Date(isoLike);
  return Number.isNaN(d.getTime()) ? null : d;
}

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Gate 5, TRIAL_PAYMENT_TIMING, judged when a payment method is being added (so the payment date is now).
 *
 * In: the user id and trial_days (configuration, default 14). Out: { decision, trialDuration (trial_days),
 * paymentDelay (days_after_trial, or null when no trial is on record) }.
 * trial_end = the user's trial start (the ledger's first trial_started_at) + trial_days;
 * days_after_trial = floor((now - trial_end) / 1 day), rounded toward negative infinity (Math.floor), negative while
 * the trial runs; earlier_payment = the ledger already has a payment_added_date for the user.
 * PASS if days_after_trial < 5; FAIL if days_after_trial >= 90 and no earlier payment (the API answers 403
 * trial_ended_no_payment_cannot_retry); CHALLENGE otherwise (flag late_payment_entry).
 * Why: TRIAL-10/11/15 amendment 2026-11-10 (review on PR 19); the old rule measured from the trial START, so a
 * payment 100 days after signup was FAIL, and its CHALLENGE window overlapped PASS. 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads trial_abuse_ledger, writes one gate_decisions row, reads the clock.
 */
export function check_trial_payment_timing(userId: number, trialDays: number = 14): GateResult {
  const ledgerRow = db.prepare(
    `SELECT trial_started_at FROM trial_abuse_ledger WHERE user_id = ? ORDER BY id ASC LIMIT 1`
  ).get(userId) as { trial_started_at: string } | undefined;
  const trialStart = ledgerRow ? parseDbDate(ledgerRow.trial_started_at) : null;
  if (!trialStart) {
    // No trial on record for this user: there is no trial to time, so the gate has nothing to object to.
    why_chain({
      user_id: userId,
      gate_name: 'trial_payment_timing',
      decision: 'PASS',
      rule_inputs: { trial_started_at: null },
      rule_outputs: { decision: 'PASS', reason: 'no_trial_on_record' }
    });
    return { decision: 'PASS', trialDuration: trialDays, paymentDelay: null };
  }

  const now = clock();
  const trialEnd = trialStart.getTime() + trialDays * DAY_MS;
  const daysAfterTrial = Math.floor((now.getTime() - trialEnd) / DAY_MS);

  const paymentRow = db.prepare(`
    SELECT payment_added_date FROM trial_abuse_ledger
    WHERE user_id = ? AND payment_added_date IS NOT NULL
    ORDER BY id ASC LIMIT 1
  `).get(userId) as { payment_added_date: string } | undefined;
  const earlierPayment = paymentRow !== undefined;

  let decision: Decision;
  if (daysAfterTrial < 5) decision = 'PASS';
  else if (daysAfterTrial >= 90 && !earlierPayment) decision = 'FAIL';
  else decision = 'CHALLENGE';

  why_chain({
    user_id: userId,
    gate_name: 'trial_payment_timing',
    decision,
    rule_inputs: { trial_started_at: trialStart.toISOString(), trial_days: trialDays, now: now.toISOString(),
      earlier_payment: earlierPayment },
    rule_outputs: { decision, trial_duration: trialDays, payment_delay: daysAfterTrial }
  });

  return { decision, trialDuration: trialDays, paymentDelay: daysAfterTrial };
}

/**
 * Says whether a table exists in this database. In: a table name. Out: true or false.
 * Why: stripe_events and refunds belong to the billing system (its Stripe webhook writes them), not to this module;
 * a deployment without billing has no chargeback records yet, which is not an error (failing test
 * "chargeback_history PASS", SqliteError no such table, repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP).
 * Touches: reads sqlite_master.
 */
function tableExists(name: string): boolean {
  return db.prepare(`SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?`).get(name) !== undefined;
}

/**
 * Gate 6, CHARGEBACK_HISTORY (spec trial abuse #6): counts Stripe chargeback events for the customer plus the user's
 * charged-back refunds. In: the Stripe customer id and the user id. Out: { decision, count } where 0 = PASS,
 * 1 = CHALLENGE, 2+ = FAIL (403 chargeback_history_requires_prepayment).
 * Why: it queried stripe_events and refunds unconditionally and threw when the billing tables were not installed; a
 * table that is not there now counts as no records (repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP).
 * Touches: reads stripe_events and refunds when present, writes one gate_decisions row.
 */
export function check_chargeback_history(stripeCustomerId: string, userId: number): GateResult {
  const chargebackCount = tableExists('stripe_events')
    ? (db.prepare(`
        SELECT COUNT(*) as cnt FROM stripe_events
        WHERE customer = ? AND type LIKE '%chargeback%'
      `).get(stripeCustomerId) as { cnt: number }).cnt
    : 0;

  const refundCount = tableExists('refunds')
    ? (db.prepare(`
        SELECT COUNT(*) as cnt FROM refunds
        WHERE user_id = ? AND status = 'chargebacked'
      `).get(userId) as { cnt: number }).cnt
    : 0;

  const totalChargebacks = chargebackCount + refundCount;

  let decision: Decision = 'PASS';
  if (totalChargebacks === 0) decision = 'PASS';
  else if (totalChargebacks === 1) decision = 'CHALLENGE';
  else decision = 'FAIL';

  why_chain({
    user_id: userId,
    gate_name: 'chargeback_history',
    decision,
    rule_inputs: { stripeCustomerId, totalChargebacks },
    rule_outputs: { decision }
  });

  return { decision, count: totalChargebacks };
}

// ---------- Core Flows ----------
let userIdSeq = 1;

/**
 * Signs a user up for a trial after the email, IP and device gates.
 *
 * In: email, password (not stored here), the client IP from the server, and the device attributes.
 * Out: { success, user?, challenge?, error? }. Errors: 409 email_has_trial_history, 429 too_many_signups_from_ip,
 * 403 device_suspected_fraud. Challenges: an email reused once flags 'email_trial_attempt_2+'; a device shared with
 * 2-4 other users flags 'new_device_login' (send "new device login detected"); 5-9 signups from the IP returns a
 * captcha challenge.
 * Why changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (TRIAL-09/14): signup never ran the device gate; it now
 * runs it BEFORE recording the device, and records the device and the ledger row only after every gate passed or
 * challenged. A captcha-challenged signup is now recorded too (it returned before writing its ledger row, so an IP
 * could never reach the 10-signup FAIL).
 * Touches: trial_abuse_ledger, device_fingerprints, gate_decisions; reads the clock.
 */
export function signup(params: {
  email: string;
  password: string; // not stored in this demo
  ip: string;
  user_agent: string;
  screen_resolution: string;
  timezone: string;
  browser_language: string;
}): { success: boolean; error?: any; challenge?: any; user?: User } {
  const {
    email,
    ip,
    user_agent,
    screen_resolution,
    timezone,
    browser_language
  } = params;
  const device = { user_agent, screen_resolution, timezone, browser_language };

  const tempUserId = userIdSeq++; // provisional ID for logging

  const emailGate = check_email_trial_history(email, tempUserId);
  const ipGate = check_ip_signup_rate_limit(ip, tempUserId);
  const deviceGate = check_device_fingerprint(device, null);

  if (emailGate.decision === 'FAIL') {
    return {
      success: false,
      error: { error: 'email_has_trial_history', message: 'Email has prior trial history', code: 409 }
    };
  }
  if (ipGate.decision === 'FAIL') {
    return {
      success: false,
      error: { error: 'too_many_signups_from_ip', message: 'Rate limit exceeded', code: 429, retry_after: 86400 }
    };
  }
  if (deviceGate.decision === 'FAIL') {
    return {
      success: false,
      error: { error: 'device_suspected_fraud', message: 'Device linked to too many accounts', code: 403 }
    };
  }

  const now = clock();
  const user: User = {
    id: tempUserId,
    email,
    created_at: now,
    abuse_flags: []
  };
  if (emailGate.decision === 'CHALLENGE') {
    user.abuse_flags.push('email_trial_attempt_2+');
  }
  if (deviceGate.decision === 'CHALLENGE') {
    user.abuse_flags.push('new_device_login');
  }

  // Recorded only now, after every gate has decided.
  record_device_fingerprint({ user_id: user.id, device });
  db.prepare(`
    INSERT INTO trial_abuse_ledger
    (user_id, email, ip, device_fingerprint, signup_date, trial_started_at, gate_flags)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    user.id,
    email,
    ip,
    deviceGate.deviceHash,
    now.toISOString(),
    now.toISOString(),
    JSON.stringify({ email: emailGate.decision, ip: ipGate.decision, device: deviceGate.decision })
  );

  if (ipGate.decision === 'CHALLENGE') {
    // In a real flow this requires a CAPTCHA before the account is usable.
    return { success: true, challenge: { type: 'captcha' }, user };
  }
  return { success: true, user };
}

/**
 * Runs the payment-method, timing and chargeback gates when a subscription (payment method) is created, then
 * records the payment. In: user id, Stripe payment method and customer ids, optional trial_days (default 14).
 * Out: { success, error?, challenge? }. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: trial_days is
 * configurable (TRIAL-10/11/15) and payment_added_date comes from the injected clock. Touches: trial_abuse_ledger,
 * gate_decisions; reads stripe_events and refunds when present.
 */
export function subscription_created(params: {
  user_id: number;
  stripe_payment_method_id: string;
  stripe_customer_id: string;
  trial_days?: number;
}): { success: boolean; error?: any; challenge?: any } {
  const { user_id, stripe_payment_method_id, stripe_customer_id } = params;

  const paymentGate = check_payment_method_history(stripe_payment_method_id, user_id);
  const timingGate = check_trial_payment_timing(user_id, params.trial_days ?? 14);
  const chargebackGate = check_chargeback_history(stripe_customer_id, user_id);

  const failGate = [paymentGate, timingGate, chargebackGate].find(g => g.decision === 'FAIL');
  if (failGate) {
    let errorObj;
    switch (failGate) {
      case paymentGate:
        errorObj = { error: 'payment_method_used_for_multiple_trials', message: 'Payment method reused', code: 403 };
        break;
      case timingGate:
        errorObj = { error: 'trial_ended_no_payment_cannot_retry', message: 'Trial ended without payment', code: 403 };
        break;
      case chargebackGate:
        errorObj = { error: 'chargeback_history_requires_prepayment', message: 'Chargeback history requires prepayment', code: 403 };
        break;
      default:
        errorObj = { error: 'unknown', message: 'Unknown failure', code: 403 };
    }
    return { success: false, error: errorObj };
  }

  // Update ledger with payment info
  const updateStmt = db.prepare(`
    UPDATE trial_abuse_ledger
    SET payment_added_date = ?, stripe_payment_method_id = ?, subscription_status = 'completed',
        gate_flags = json_set(gate_flags, '$.payment', ?, '$.timing', ?, '$.chargeback', ?)
    WHERE user_id = ?
  `);
  updateStmt.run(
    clock().toISOString(),
    stripe_payment_method_id,
    paymentGate.decision,
    timingGate.decision,
    chargebackGate.decision,
    user_id
  );

  // Handle challenges
  const challenges: string[] = [];
  if (paymentGate.decision === 'CHALLENGE') challenges.push('payment_reuse_2x');
  if (timingGate.decision === 'CHALLENGE') challenges.push('late_payment_entry');
  if (chargebackGate.decision === 'CHALLENGE') challenges.push('chargeback_1x');

  if (challenges.length > 0) {
    return {
      success: true,
      challenge: { type: 'email_confirm', flags: challenges }
    };
  }

  return { success: true };
}

// ---------- Device Fingerprint Recording ----------
export function record_device_fingerprint(params: {
  user_id: number;
  device: {
    user_agent: string;
    screen_resolution: string;
    timezone: string;
    browser_language: string;
  };
}) {
  const { user_id, device } = params;
  const deviceHash = deviceHashOf(device);

  const stmt = db.prepare(`
    INSERT INTO device_fingerprints
    (user_id, device_hash, user_agent, screen_resolution, timezone)
    VALUES (?, ?, ?, ?, ?)
  `);
  stmt.run(
    user_id,
    deviceHash,
    device.user_agent,
    device.screen_resolution,
    device.timezone
  );
}

// ---------- Exported for Tests ----------
export const tables = {
  trial_abuse_ledger: 'trial_abuse_ledger',
  device_fingerprints: 'device_fingerprints',
  gate_decisions: 'gate_decisions'
};