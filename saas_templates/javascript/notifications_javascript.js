'use strict';

/**
 * Notifications: templated e-mail, SMS and in-app messages with per-user preferences (do-not-disturb, quiet hours,
 * channels), unsubscribe, retries and open/click tracking. Contract: TIER_2_MASTER_SPEC_6SYSTEMS.txt, SYSTEM 2.
 *
 * Providers sit behind sender functions (`emailSender`, `smsSender`, `inAppSender`); the defaults are in-memory
 * no-ops, so the template runs with no network. Plug SMTP/SES and Twilio/SNS in through the constructor options.
 *
 * Repair, 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Five tests failed:
 *   - every user without saved preferences got quiet hours 22:00-08:00 in the SERVER's time zone, so e-mail and
 *     in-app sends were held as 'queued' at night and the suite passed or failed by the time of day. A user now has
 *     no quiet hours until they set some;
 *   - SMS was off for every user by default, so an explicitly requested SMS was skipped although nobody had turned
 *     it off. Channels now default to on; a channel the user turned off stays off, including when a caller asks for
 *     it by name (an earlier repair that let an explicit channel override the user's choice was rejected);
 *   - when the template's channel was turned off, auto-selection gave up instead of using another enabled channel.
 * Also fixed: unsubscribe links were an unkeyed hash anyone could compute, and the /unsubscribe route took a bare
 * user_id, so anyone could unsubscribe anyone; batch counts reported skipped and queued messages as sent; queued
 * messages were released without re-checking unsubscribe and channel choices made in the meantime.
 *
 * Touches: memory only (the Maps below; SCHEMA_SQL is the matching SQL schema), plus whatever senders are injected.
 */

const crypto = require('crypto');
const { EventEmitter } = require('events');

/* ============================================================================
 * DATABASE SCHEMA (executable DDL)
 * ========================================================================== */
const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS notification_templates (
  key             TEXT PRIMARY KEY,
  subject         TEXT,
  body_text       TEXT,
  body_html       TEXT,
  channels_default TEXT,
  variables       TEXT
);

CREATE TABLE IF NOT EXISTS notification_logs (
  id            TEXT PRIMARY KEY,
  user_id       INTEGER NOT NULL,
  template_key  TEXT NOT NULL,
  channel       TEXT NOT NULL,
  vars_used     TEXT,
  status        TEXT NOT NULL,      -- queued | sending | sent | skipped | failed (2026-11-10, NOTIF-12)
  scheduled_at  TEXT,               -- when a queued message is due (scheduled send or quiet_hours_end)
  claimed_at    TEXT,               -- when deliver_due claimed it ('sending')
  sent_at       TEXT,
  opened_at     TEXT,
  clicked_at    TEXT,
  bounced       INTEGER DEFAULT 0,
  error         TEXT
);

CREATE TABLE IF NOT EXISTS user_notification_preferences (
  user_id             INTEGER PRIMARY KEY,
  do_not_disturb      INTEGER DEFAULT 0,
  quiet_hours_start   TEXT,
  quiet_hours_end     TEXT,
  channels_enabled    TEXT
);

CREATE TABLE IF NOT EXISTS user_unsubscribes (
  user_id   INTEGER PRIMARY KEY,
  channel   TEXT NOT NULL,
  created_at TEXT
);
`;

/* ============================================================================
 * DEFAULT TEMPLATES
 * ========================================================================== */
const DEFAULT_TEMPLATES = {
  welcome_email: {
    key: 'welcome_email',
    subject: 'Welcome to {app_name}!',
    body_text: "Welcome to {app_name}! Here's your first step.",
    body_html: '<p>Welcome to <strong>{app_name}</strong>! Here\'s your first step.</p>',
    channels_default: 'email',
    variables: 'app_name',
  },
  trial_starting: {
    key: 'trial_starting',
    subject: 'Your free trial is starting',
    body_text: 'Your free trial is starting. You have {trial_days} days.',
    body_html: '<p>Your free trial is starting. You have <strong>{trial_days}</strong> days.</p>',
    channels_default: 'email',
    variables: 'trial_days',
  },
  trial_ending_soon: {
    key: 'trial_ending_soon',
    subject: 'Your trial ends in {days_left} days',
    body_text: 'Your trial ends in {days_left} days. Add payment method to continue.',
    body_html: '<p>Your trial ends in <strong>{days_left}</strong> days. Add payment method to continue.</p>',
    channels_default: 'email',
    variables: 'days_left',
  },
  subscription_changed: {
    key: 'subscription_changed',
    subject: 'Your plan changed',
    body_text: 'Your plan changed from {old_tier} to {new_tier}. Effective {effective_date}.',
    body_html: '<p>Your plan changed from <strong>{old_tier}</strong> to <strong>{new_tier}</strong>. Effective {effective_date}.</p>',
    channels_default: 'email',
    variables: 'old_tier,new_tier,effective_date',
  },
  payment_failed: {
    key: 'payment_failed',
    subject: 'Payment failed for invoice {invoice_id}',
    body_text: 'Payment failed for invoice {invoice_id}. {retry_date} retry, or update payment method.',
    body_html: '<p>Payment failed for invoice <strong>{invoice_id}</strong>. {retry_date} retry, or update payment method.</p>',
    channels_default: 'email',
    variables: 'invoice_id,retry_date',
  },
  deployment_live: {
    key: 'deployment_live',
    subject: 'Your deployment {deployment_name} is live',
    body_text: 'Your deployment {deployment_name} is now live at {url}.',
    body_html: '<p>Your deployment <strong>{deployment_name}</strong> is now live at <a href="{url}">{url}</a>.</p>',
    channels_default: 'email',
    variables: 'deployment_name,url',
  },
  user_invited: {
    key: 'user_invited',
    subject: 'You\'ve been invited to {workspace}',
    body_text: 'You\'ve been invited to {workspace}. Click here to join.',
    body_html: '<p>You\'ve been invited to <strong>{workspace}</strong>. <a href="{join_url}">Click here to join</a>.</p>',
    channels_default: 'email',
    variables: 'workspace,join_url',
  },
  invoice_ready: {
    key: 'invoice_ready',
    subject: 'Your invoice for {month} is ready',
    body_text: 'Your invoice for {month} is ready. Download here.',
    body_html: '<p>Your invoice for <strong>{month}</strong> is ready. <a href="{download_url}">Download here</a>.</p>',
    channels_default: 'email',
    variables: 'month,download_url',
  },
  admin_alert: {
    key: 'admin_alert',
    subject: 'Admin alert',
    body_text: '{actor} performed {action} on {resource}.',
    body_html: '<p>{actor} performed <strong>{action}</strong> on {resource}.</p>',
    channels_default: 'in_app',
    variables: 'actor,action,resource',
  },
};

// Statuses of a message that reached the user: 'sent', then the tracking statuses 'opened' and 'clicked'
// (NOTIF-07, Phase B.2, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
const DELIVERED = ['sent', 'opened', 'clicked'];

/* ============================================================================
 * UTILITIES
 * ========================================================================== */
function generateId(prefix) {
  const rand = crypto.randomBytes(16).toString('hex');
  return prefix ? `${prefix}_${rand}` : rand;
}


/**
 * Parses a quiet-hours time "HH:MM" (00:00-23:59, UTC) into minutes after midnight.
 * In: the string. Out: 0..1439, or null when it is not a valid HH:MM (so "25:00" or "9:7" is refused).
 * Why: the spec makes quiet hours "HH:MM" in UTC (Phase B.2); the old pattern accepted hours and minutes out of
 * range. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function parseTimeToMinutes(t) {
  if (!t) return null;
  const m = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(String(t).trim());
  if (!m) return null;
  return parseInt(m[1], 10) * 60 + parseInt(m[2], 10);
}

/**
 * True when `date` falls inside the quiet-hours window [start, end), both "HH:MM" in UTC; a window may cross
 * midnight (22:00-08:00). Equal or missing bounds mean no quiet hours.
 * In: start, end, date (default now). Out: boolean.
 * Why: bug fix (Phase B.2): it compared against the SERVER's local time; the spec now says UTC.
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function inQuietHours(start, end, date) {
  const s = parseTimeToMinutes(start);
  const e = parseTimeToMinutes(end);
  if (s === null || e === null) return false;
  const d = date || new Date();
  const cur = d.getUTCHours() * 60 + d.getUTCMinutes();
  if (s === e) return false;
  if (s < e) return cur >= s && cur < e;
  // wraps midnight
  return cur >= s || cur < e;
}

/**
 * The first moment after `now` whose UTC time is quiet_hours_end: when a message held by quiet hours is released.
 * In: end ("HH:MM", UTC), now (Date). Out: a Date.
 * Why: NOTIF-05 (queued with scheduled_at = quiet_hours_end) and deliver_due step 3 (Phase B.2); it used local
 * time before. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function nextQuietHoursEnd(end, now) {
  const endMin = parseTimeToMinutes(end);
  const release = new Date(now.getTime());
  release.setUTCHours(Math.floor(endMin / 60), endMin % 60, 0, 0);
  if (release <= now) release.setUTCDate(release.getUTCDate() + 1);
  return release;
}

function renderTemplate(text, vars) {
  if (text == null) return '';
  return String(text).replace(/\{([a-zA-Z0-9_]+)\}/g, (match, name) => {
    if (Object.prototype.hasOwnProperty.call(vars, name)) {
      return String(vars[name]);
    }
    return match;
  });
}

/**
 * The unsubscribe token for one user and channel: HMAC-SHA256 under the service's secret.
 * In: secret, user id, channel. Out: hex string.
 * Why: the token was sha256(user:channel:unsubscribe), which anyone can compute for any user (2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
 */
function unsubscribeToken(secret, userId, channel) {
  return crypto.createHmac('sha256', secret).update(`unsubscribe:${userId}:${channel}`).digest('hex');
}

/**
 * Builds the unsubscribe link put in every e-mail (a legal requirement, spec).
 * In: base URL, secret, user id, channel. Out: URL with user_id, channel and the signed token.
 * Why: see unsubscribeToken (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
 */
function buildUnsubscribeUrl(baseUrl, secret, userId, channel) {
  const q = new URLSearchParams({ user_id: String(userId), channel, token: unsubscribeToken(secret, userId, channel) });
  return `${baseUrl}/unsubscribe?${q.toString()}`;
}

const CHANNELS = ['email', 'sms', 'in_app'];

/**
 * The preferences of a user who has saved none: no do-not-disturb, no quiet hours, channels {email: true, sms: false,
 * in_app: true}. SMS is opt-in: it costs money per message and marketing texts need prior consent in many countries.
 * Out: a fresh object. Why: spec "Default preferences" (amended 2026-11-10; this file had turned SMS on by default).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function defaultPreferences() {
  return {
    do_not_disturb: false,
    quiet_hours_start: null,
    quiet_hours_end: null,
    channels_enabled: { email: true, sms: false, in_app: true },
  };
}

/** Seconds after which a 'sending' claim is treated as a crashed worker and re-queued (spec deliver_due step 1). */
const CLAIM_TIMEOUT_MS = 300 * 1000;

/** A well-formed unsubscribe token: exactly 64 lowercase hex characters. */
const TOKEN_RE = /^[0-9a-f]{64}$/;

/**
 * Normalizes a time given as a Date, epoch ms or ISO string to a Date; null/undefined -> null.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function toDate(value) {
  if (value == null) return null;
  const d = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (Number.isNaN(d.getTime())) throw new Error('invalid time');
  return d;
}

/**
 * The tracking URL put in an e-mail. In: base URL, message id, action ('open' | 'click'). Out: the URL.
 * The open pixel points at the spec's GET /notifications/open/:message_id (NOTIF-07, Phase B.2); a click still goes
 * to /track/:message_id/click. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function buildTrackUrl(baseUrl, messageId, action) {
  if (action === 'open') return `${baseUrl}/notifications/open/${messageId}`;
  return `${baseUrl}/track/${messageId}/${action}`;
}

/* ============================================================================
 * NOTIFICATION SERVICE
 * ========================================================================== */
/**
 * The notification service.
 * In (constructor options): baseUrl, maxRetries (default 3 retries after the first attempt, so 4 attempts),
 * retryBaseDelayMs (default 1000: waits of 1 s, 2 s, 4 s; NOTIF-08, Phase B.2 2026-11-10, was 100), nowFn (clock
 * returning a Date; quiet hours, compared in UTC, and timestamps use it), sleep, unsubscribeSecret (else env NOTIFICATIONS_UNSUBSCRIBE_SECRET),
 * emailSender, smsSender, inAppSender. Events: 'sent', 'failed' (the log entry).
 * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] The constructor throws unless the unsubscribe secret is at least 32
 * bytes (NOTIF-11: an empty or short key makes a forgeable HMAC; a random per-process key broke every link at the
 * next restart). Queued messages live in the logs (status, scheduled_at, claimed_at) and go out through
 * deliverDue(now) (NOTIF-12), never an in-process timer.
 * Touches: memory; the injected senders (e-mail, SMS providers).
 */
class NotificationService extends EventEmitter {
  constructor(options) {
    super();
    const opts = options || {};
    this.baseUrl = opts.baseUrl || 'http://localhost:3000';
    this.maxRetries = opts.maxRetries != null ? opts.maxRetries : 3;
    this.retryBaseDelayMs = opts.retryBaseDelayMs != null ? opts.retryBaseDelayMs : 1000;
    this.nowFn = opts.nowFn || (() => new Date());
    const secret = opts.unsubscribeSecret != null ? opts.unsubscribeSecret : process.env.NOTIFICATIONS_UNSUBSCRIBE_SECRET;
    if (typeof secret !== 'string' || Buffer.byteLength(secret, 'utf8') < 32) {
      throw new Error('unsubscribeSecret (or NOTIFICATIONS_UNSUBSCRIBE_SECRET) must be at least 32 bytes');
    }
    this.unsubscribeSecret = secret;
    this.sleep = opts.sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));

    // In-memory stores
    this.templates = new Map();
    this.logs = new Map();
    this.preferences = new Map();
    this.unsubscribes = new Set();

    // Channel senders (overridable for testing / real providers)
    this.emailSender = opts.emailSender || this._defaultEmailSender.bind(this);
    this.smsSender = opts.smsSender || this._defaultSmsSender.bind(this);
    this.inAppSender = opts.inAppSender || this._defaultInAppSender.bind(this);

    this._seedTemplates();
  }

  _seedTemplates() {
    for (const t of Object.values(DEFAULT_TEMPLATES)) {
      this.templates.set(t.key, { ...t });
    }
  }

  /* ---- Template management ---- */
  getTemplate(key) {
    return this.templates.get(key) || null;
  }

  upsertTemplate(template) {
    if (!template || !template.key) {
      throw new Error('template.key is required');
    }
    this.templates.set(template.key, { ...template });
    return this.templates.get(template.key);
  }

  /* ---- Preference management ---- */
  /**
   * A user's notification preferences, in the spec's response shape.
   * In: user id. Out: { user_id, do_not_disturb, quiet_hours_start, quiet_hours_end, channels_enabled }; quiet hours
   * are null when the user has set none. Why: defaults no longer switch SMS off or impose quiet hours (2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP). Touches: memory (read).
   */
  getPreferences(userId) {
    const p = this.preferences.get(userId) || defaultPreferences();
    return {
      user_id: userId,
      do_not_disturb: !!p.do_not_disturb,
      quiet_hours_start: p.quiet_hours_start || null,
      quiet_hours_end: p.quiet_hours_end || null,
      channels_enabled: { ...p.channels_enabled },
    };
  }

  /**
   * Saves part of a user's preferences; keys not given keep their value.
   * In: user id, { do_not_disturb?, quiet_hours_start?, quiet_hours_end?, channels_enabled? }; quiet hours as "HH:MM"
   * or null to clear, channels_enabled as { email|sms|in_app: boolean } (other keys are ignored).
   * Out: { success: true }, or throws on a malformed time. Why: unvalidated input could store channel names or times
   * the sender then misread (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: memory.
   */
  updatePreferences(userId, updates) {
    const u = updates || {};
    const existing = this.preferences.get(userId) || defaultPreferences();
    const merged = { ...existing, channels_enabled: { ...existing.channels_enabled } };
    if (u.do_not_disturb !== undefined) merged.do_not_disturb = !!u.do_not_disturb;
    for (const key of ['quiet_hours_start', 'quiet_hours_end']) {
      if (u[key] === undefined) continue;
      if (u[key] !== null && parseTimeToMinutes(u[key]) === null) throw new Error(`${key} must be HH:MM`);
      merged[key] = u[key];
    }
    if (u.channels_enabled && typeof u.channels_enabled === 'object') {
      for (const ch of CHANNELS) {
        if (typeof u.channels_enabled[ch] === 'boolean') {
          merged.channels_enabled[ch] = u.channels_enabled[ch];
          // The user turning a channel back on is their own new consent: it clears an earlier unsubscribe.
          if (u.channels_enabled[ch]) this.unsubscribes.delete(`${userId}:${ch}`);
        }
      }
    }
    this.preferences.set(userId, merged);
    return { success: true };
  }

  /* ---- Unsubscribe ---- */
  isUnsubscribed(userId, channel) {
    return this.unsubscribes.has(`${userId}:${channel}`);
  }

  /**
   * Unsubscribes a user from one channel: records it and sets channels_enabled[channel] = false (spec NOTIF-11).
   * In: user id, channel. Out: { success: true }. [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] now also turns the
   * channel off in the preferences, as the amended spec says. Touches: memory.
   */
  unsubscribe(userId, channel) {
    if (!CHANNELS.includes(channel)) throw new Error(`Unknown channel: ${channel}`);
    this.unsubscribes.add(`${userId}:${channel}`);
    const existing = this.preferences.get(userId) || defaultPreferences();
    this.preferences.set(userId, {
      ...existing,
      channels_enabled: { ...existing.channels_enabled, [channel]: false },
    });
    return { success: true };
  }

  /**
   * Checks an unsubscribe link's parameters BEFORE any user lookup. In: { user_id, channel, token } as strings from
   * the query. Out: { userId, channel } when the token is exactly 64 lowercase hex characters, the channel is known
   * and the token equals HMAC-SHA256(secret, "unsubscribe:" + user_id + ":" + channel) (constant-time compare of
   * two equal-length values, so nothing throws); otherwise null. Every refusal is the same.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-11). Touches nothing.
   */
  verifyUnsubscribe(query) {
    const q = query || {};
    const rawUser = q.user_id;
    const channel = q.channel;
    const token = q.token;
    if (typeof rawUser !== 'string' && typeof rawUser !== 'number') return null;
    if (String(rawUser).length === 0) return null;
    if (typeof channel !== 'string' || !CHANNELS.includes(channel)) return null;
    if (typeof token !== 'string' || !TOKEN_RE.test(token)) return null;
    const expected = unsubscribeToken(this.unsubscribeSecret, String(rawUser), channel);
    if (!crypto.timingSafeEqual(Buffer.from(token, 'utf8'), Buffer.from(expected, 'utf8'))) return null;
    const userId = /^\d+$/.test(String(rawUser)) ? Number(rawUser) : String(rawUser);
    return { userId, channel };
  }

  /* ---- Channel resolution ---- */
  /**
   * Picks the channel for a send.
   * In: the channel the caller named (or null), the template, the user's preferences. Out: a channel name.
   * A named channel is returned as is; send() then skips it if the user turned it off, so a caller can never override
   * the user's choice. With no channel named: the template's default channels in order, then email, sms, in_app,
   * first one the user has on; if all are off, the template's first default (send() then skips it).
   * Why: auto-selection gave up when the template's channel was off instead of using another enabled channel (spec
   * test "User preferences honored: channels_enabled respected"; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
   * Touches: nothing.
   */
  _resolveChannel(requestedChannel, template, prefs) {
    if (requestedChannel) return requestedChannel;
    const defaults = (template && template.channels_default)
      ? String(template.channels_default).split(',').map((s) => s.trim()).filter(Boolean)
      : ['email'];
    const enabled = prefs.channels_enabled || {};
    for (const ch of [...defaults, ...CHANNELS]) {
      if (enabled[ch] === true) return ch;
    }
    return defaults[0] || 'email';
  }

  /* ---- Core send ---- */
  /**
   * Sends one notification, or records why it was not sent.
   * In: { user_id, template_key, channel ('email'|'sms'|'in_app'|null for auto), vars, scheduled_at }.
   * Out: { success, message_id, status: 'sent'|'queued'|'skipped'|'failed' }; throws on a missing user, unknown
   * template or unknown channel. Order: do-not-disturb, unsubscribe, channel turned off (all 'skipped'), then
   * scheduled_at and quiet hours ('queued' in the log with scheduled_at, for deliverDue), then delivery with retries.
   * [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] queued messages are log rows (NOTIF-05/12), not an in-memory queue.
   * Why: spec endpoint 1. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: unknown channels refused; the user's channel choice is honoured even when the caller
   * names the channel. Touches: memory, the senders.
   */
  async send(payload) {
    if (!payload || payload.user_id == null) {
      throw new Error('user_id is required');
    }
    if (!payload.template_key) {
      throw new Error('template_key is required');
    }
    const template = this.getTemplate(payload.template_key);
    if (!template) {
      throw new Error(`Unknown template: ${payload.template_key}`);
    }

    if (payload.channel != null && !CHANNELS.includes(payload.channel)) {
      throw new Error(`Unknown channel: ${payload.channel}`);
    }
    const prefs = this.getPreferences(payload.user_id);
    const channel = this._resolveChannel(payload.channel, template, prefs);
    const vars = payload.vars || {};
    const messageId = generateId('msg');

    const log = {
      id: messageId,
      user_id: payload.user_id,
      template_key: payload.template_key,
      channel,
      vars_used: JSON.stringify(vars),
      sent_at: null,
      opened_at: null,
      clicked_at: null,
      bounced: false,
      error: null,
      status: 'pending',
      scheduled_at: null,
      claimed_at: null,
      seq: this._seq = (this._seq || 0) + 1,
    };
    this.logs.set(messageId, log);

    // Do-not-disturb: skip
    if (prefs.do_not_disturb) {
      log.status = 'skipped';
      log.error = 'do_not_disturb';
      return { success: true, message_id: messageId, status: 'skipped' };
    }

    // Unsubscribe check (email/sms)
    if ((channel === 'email' || channel === 'sms') && this.isUnsubscribed(payload.user_id, channel)) {
      log.status = 'skipped';
      log.error = 'unsubscribed';
      return { success: true, message_id: messageId, status: 'skipped' };
    }

    // Channel disabled check
    const enabled = prefs.channels_enabled || {};
    if (enabled[channel] === false) {
      log.status = 'skipped';
      log.error = 'channel_disabled';
      return { success: true, message_id: messageId, status: 'skipped' };
    }

    // Scheduled delivery: stored 'queued' with its scheduled_at; deliverDue() sends it (no in-process timer).
    const now = this.nowFn();
    if (payload.scheduled_at) {
      const scheduled = toDate(payload.scheduled_at);
      if (scheduled > now) {
        log.status = 'queued';
        log.scheduled_at = scheduled.toISOString();
        return { success: true, message_id: messageId, status: 'queued' };
      }
    }

    // Quiet hours (UTC, may cross midnight): stored 'queued' with scheduled_at = quiet_hours_end (the next one after now).
    if (inQuietHours(prefs.quiet_hours_start, prefs.quiet_hours_end, now)) {
      log.status = 'queued';
      log.scheduled_at = nextQuietHoursEnd(prefs.quiet_hours_end, now).toISOString();
      return { success: true, message_id: messageId, status: 'queued' };
    }

    // Deliver
    const result = await this._deliverWithRetry(messageId, channel, template, vars, payload.user_id);
    return result;
  }

  /**
   * Delivers with up to maxRetries retries after the first attempt (default 3, so at most 4 attempts), waiting
   * retryBaseDelayMs x 2^(n-1) between attempts (default 1 s, 2 s, 4 s); after the last failure the row is 'failed'.
   * In: message id, channel, template, vars, user id. Out: { success, message_id, status }.
   * Why: spec "Retry: up to 3 times after the first attempt, 1 s / 2 s / 4 s" (NOTIF-08, Phase B.2 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: sent_at from nowFn;
   * optional claim (the claimed_at of a deliverDue claim) makes the final write conditional on that claim.
   * Touches: memory, the senders.
   */
  async _deliverWithRetry(messageId, channel, template, vars, userId, claim = null) {
    const log = this.logs.get(messageId);
    // With a claim (deliverDue), every final write is conditional on the row still being ours: status 'sending' and
    // the same claimed_at (spec deliver_due step 4). A claim that lost the row writes nothing.
    const stillOurs = () => claim === null || (log.status === 'sending' && log.claimed_at === claim);
    let attempt = 0;
    let lastError = null;
    while (attempt <= this.maxRetries) {
      try {
        await this._deliverOnce(messageId, channel, template, vars, userId);
        if (!stillOurs()) return { success: false, message_id: messageId, status: 'lost_claim' };
        log.status = 'sent';
        log.sent_at = this.nowFn().toISOString();
        log.error = null;
        log.bounced = false;
        this.emit('sent', log);
        return { success: true, message_id: messageId, status: 'sent' };
      } catch (err) {
        lastError = err;
        attempt += 1;
        if (attempt > this.maxRetries) break;
        const delay = this.retryBaseDelayMs * Math.pow(2, attempt - 1);
        await this.sleep(delay);
      }
    }
    if (!stillOurs()) return { success: false, message_id: messageId, status: 'lost_claim' };
    log.status = 'failed';
    log.error = lastError ? lastError.message : 'unknown';
    log.bounced = true;
    this.emit('failed', log);
    return { success: false, message_id: messageId, status: 'failed', error: log.error };
  }

  /**
   * One delivery attempt on one channel; e-mails carry a signed unsubscribe link and tracking links.
   * In: message id, channel, template, vars, user id. Out: a promise; rejects when the sender fails.
   * Why: spec channels and "Unsubscribe: include unsubscribe link in emails". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the link is now signed.
   * Touches: the senders.
   */
  async _deliverOnce(messageId, channel, template, vars, userId) {
    const subject = renderTemplate(template.subject, vars);
    const bodyText = renderTemplate(template.body_text, vars);
    const bodyHtml = renderTemplate(template.body_html, vars);

    if (channel === 'email') {
      const unsubscribeUrl = buildUnsubscribeUrl(this.baseUrl, this.unsubscribeSecret, userId, 'email');
      const trackOpenUrl = buildTrackUrl(this.baseUrl, messageId, 'open');
      const trackClickUrl = buildTrackUrl(this.baseUrl, messageId, 'click');
      const html = `${bodyHtml}<hr><p><a href="${unsubscribeUrl}">Unsubscribe</a></p>`;
      const openPixel = `<img src="${trackOpenUrl}" width="1" height="1" alt="">`;
      await this.emailSender({
        to: userId,
        subject,
        text: bodyText,
        html: `${openPixel}${html}`,
        unsubscribeUrl,
        trackOpenUrl,
        trackClickUrl,
      });
    } else if (channel === 'sms') {
      await this.smsSender({ to: userId, body: bodyText });
    } else if (channel === 'in_app') {
      await this.inAppSender({ userId, subject, body: bodyText, template_key: template.key, vars });
    } else {
      throw new Error(`Unsupported channel: ${channel}`);
    }
  }

  /* ---- Default senders (no-op success; real providers plug in here) ---- */
  async _defaultEmailSender() { /* provider no-op */ }
  async _defaultSmsSender() { /* provider no-op */ }
  async _defaultInAppSender() { /* stored in logs */ }

  /* ---- Batch send ---- */
  /**
   * Sends many notifications one after another, in order.
   * In: an array of send() payloads. Out: { success, sent, failed, queued, skipped, message_ids } where `sent` counts
   * only delivered messages and `failed` includes payloads that were refused as invalid.
   * Why: skipped and queued messages were counted as sent (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
   * Touches: memory, and the senders.
   */
  async sendBatch(items) {
    if (!Array.isArray(items)) throw new Error('batch must be an array');
    const counts = { sent: 0, failed: 0, queued: 0, skipped: 0 };
    const messageIds = [];
    for (const item of items) {
      try {
        const res = await this.send(item);
        messageIds.push(res.message_id);
        if (Object.prototype.hasOwnProperty.call(counts, res.status)) counts[res.status] += 1;
        else counts.failed += 1;
      } catch (err) {
        counts.failed += 1;
      }
    }
    return { success: true, ...counts, message_ids: messageIds };
  }

  /* ---- Tracking ---- */
  track(messageId) {
    const log = this.logs.get(messageId);
    if (!log) {
      return { error: 'not_found', message: `Message ${messageId} not found` };
    }
    let status = 'sent';
    if (log.bounced) status = 'bounced';
    else if (log.clicked_at) status = 'clicked';
    else if (log.opened_at) status = 'opened';
    else if (log.status === 'sent') status = 'sent';
    else if (log.status === 'failed') status = 'failed';
    else if (log.status === 'skipped') status = 'skipped';
    else if (log.status === 'queued') status = 'queued';
    else if (log.status === 'sending') status = 'sending';
    return {
      message_id: log.id,
      user_id: log.user_id,
      template_key: log.template_key,
      channel: log.channel,
      status,
      sent_at: log.sent_at,
      opened_at: log.opened_at,
      clicked_at: log.clicked_at,
    };
  }

  /**
   * Records that a message was opened (the tracking pixel or link; GET /notifications/open/:message_id). The first
   * open of a sent message sets opened_at and status 'opened'; any later call, or a message that was never sent
   * (queued, skipped, failed), changes nothing.
   * In: message id. Out: { success, message_id, status, changed } ({ success: false, error: 'not_found' } for an
   * unknown id).
   * Why: NOTIF-07 (Phase B.2): status was left at 'sent'. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (time
   * from nowFn). Touches: memory.
   */
  markOpened(messageId) {
    const log = this.logs.get(messageId);
    if (!log) return { success: false, error: 'not_found' };
    let changed = false;
    if (!log.opened_at && log.status === 'sent') {
      log.opened_at = this.nowFn().toISOString();
      log.status = 'opened';
      changed = true;
    }
    return { success: true, message_id: messageId, status: log.status, changed };
  }

  /**
   * Records a click (which implies an open) on a delivered message. The first click sets clicked_at and status
   * 'clicked' (and opened_at if it was not set); later calls, or a message that was never sent, change nothing.
   * In: message id. Out: { success, message_id, status }.
   * Why: spec tracking. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (time from nowFn; Phase B.2: the
   * status follows the tracking, as markOpened's does). Touches: memory.
   */
  markClicked(messageId) {
    const log = this.logs.get(messageId);
    if (!log) return { success: false, error: 'not_found' };
    if (!log.clicked_at && (log.status === 'sent' || log.status === 'opened')) {
      const at = this.nowFn().toISOString();
      if (!log.opened_at) log.opened_at = at;
      log.clicked_at = at;
      log.status = 'clicked';
    }
    return { success: true, message_id: messageId, status: log.status };
  }

  /* ---- In-app fetch ---- */
  /**
   * The user's delivered in-app messages, read or not. In: user id. Out: [{ message_id, template_key, vars, sent_at,
   * read }]. Why: spec "In-app: fetch via /notifications"; changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
   * (Phase B.2: an opened message now has status 'opened' or 'clicked' and must still be listed). Touches: memory.
   */
  getInAppNotifications(userId) {
    const out = [];
    for (const log of this.logs.values()) {
      if (log.user_id === userId && log.channel === 'in_app' && DELIVERED.includes(log.status)) {
        out.push({
          message_id: log.id,
          template_key: log.template_key,
          vars: JSON.parse(log.vars_used || '{}'),
          sent_at: log.sent_at,
          read: !!log.opened_at,
        });
      }
    }
    return out;
  }

  /* ---- Deliver due (scheduled / quiet-hours) messages ---- */
  /**
   * deliverDue(now) -> [{ success, message_id, status }]: sends every queued message that is due, in the spec's four
   * steps (NOTIF-12, amended 2026-11-10):
   *   1. 'sending' rows whose claimed_at + 300 s < now go back to 'queued' (a crashed worker);
   *   2. 'queued' rows with scheduled_at <= now, by scheduled_at then insertion order, are claimed one by one with a
   *      conditional write (status 'queued' -> 'sending', claimed_at = now); a row claimed first elsewhere is skipped;
   *   3. preferences are checked NOW: do-not-disturb, unsubscribed or channel off -> 'skipped'; inside the user's
   *      quiet hours (UTC) -> back to 'queued' with scheduled_at = quiet_hours_end (Phase B.2, 2026-11-10);
   *   4. the final write is conditional on status 'sending' and the same claimed_at.
   * Each message is sent once when no worker crashes, at least once after a crash. In: now (Date, ms or ISO; default
   * the clock). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (replaces processQueue's in-memory queue).
   * Touches: memory (the logs), the senders.
   */
  async deliverDue(now) {
    const at = now == null ? this.nowFn() : toDate(now);
    const nowMs = at.getTime();
    for (const log of this.logs.values()) {
      if (log.status === 'sending' && log.claimed_at && Date.parse(log.claimed_at) + CLAIM_TIMEOUT_MS < nowMs) {
        log.status = 'queued';
        log.claimed_at = null;
      }
    }
    const due = Array.from(this.logs.values())
      .filter((log) => log.status === 'queued' && log.scheduled_at && Date.parse(log.scheduled_at) <= nowMs)
      .sort((a, b) => (Date.parse(a.scheduled_at) - Date.parse(b.scheduled_at)) || (a.seq - b.seq))
      .map((log) => log.id);
    const results = [];
    for (const id of due) {
      const log = this.logs.get(id);
      if (!log || log.status !== 'queued') continue; // claimed by someone else meanwhile
      const claim = at.toISOString();
      log.status = 'sending';
      log.claimed_at = claim;
      const prefs = this.getPreferences(log.user_id);
      let skip = null;
      if (prefs.do_not_disturb) skip = 'do_not_disturb';
      else if (this.isUnsubscribed(log.user_id, log.channel)) skip = 'unsubscribed';
      else if (prefs.channels_enabled[log.channel] !== true) skip = 'channel_disabled';
      if (skip) {
        if (log.status === 'sending' && log.claimed_at === claim) {
          log.status = 'skipped';
          log.error = skip;
        }
        results.push({ success: true, message_id: id, status: 'skipped' });
        continue;
      }
      if (inQuietHours(prefs.quiet_hours_start, prefs.quiet_hours_end, at)) {
        if (log.status === 'sending' && log.claimed_at === claim) {
          log.status = 'queued';
          log.claimed_at = null;
          log.scheduled_at = nextQuietHoursEnd(prefs.quiet_hours_end, at).toISOString();
        }
        results.push({ success: true, message_id: id, status: 'queued' });
        continue;
      }
      const template = this.getTemplate(log.template_key);
      const vars = JSON.parse(log.vars_used || '{}');
      results.push(await this._deliverWithRetry(id, log.channel, template, vars, log.user_id, claim));
    }
    return results;
  }

  /** Kept for callers of the old name: deliverDue() at the clock's now. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
  async processQueue() {
    return this.deliverDue(this.nowFn());
  }

  /* ---- DDL export ---- */
  getSchemaSql() {
    return SCHEMA_SQL;
  }
}

/* ============================================================================
 * HTTP ROUTER (Express-compatible)
 * ========================================================================== */
/**
 * Framework-free router over the service, with the spec's routes plus tracking and unsubscribe.
 * In: a NotificationService. Out: { routes, handle(method, path, { query, body, user }) } resolving to { status, body }.
 * `user` is the verified caller from your auth layer; the preference and in-app routes answer 404 unless it is the
 * user in the path (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). /unsubscribe: GET confirms, POST unsubscribes.
 * Why: spec ENDPOINTS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: /unsubscribe needs the signed token; bad preference input answers 400.
 * Touches: as the service.
 */
function createRouter(service) {
  const routes = [];
  function add(method, pattern, handler) {
    const keys = [];
    const regex = new RegExp(
      '^' + pattern.replace(/:[^/]+/g, (m) => {
        keys.push(m.slice(1));
        return '([^/]+)';
      }) + '$'
    );
    routes.push({ method, regex, keys, handler });
  }

  add('POST', '/notifications/send', async (req) => {
    try {
      const res = await service.send(req.body || {});
      return { status: 200, body: res };
    } catch (err) {
      return { status: 400, body: { success: false, error: err.message } };
    }
  });

  add('POST', '/notifications/send-batch', async (req) => {
    try {
      const res = await service.sendBatch(req.body || []);
      return { status: 200, body: res };
    } catch (err) {
      return { status: 400, body: { success: false, error: err.message } };
    }
  });

  add('GET', '/notifications/track/:message_id', async (req) => {
    const res = service.track(req.params.message_id);
    if (res.error) return { status: 404, body: res };
    return { status: 200, body: res };
  });

  // The caller is the VERIFIED user the auth layer put on the request (req.user), never the id in the path: a user
  // reads and changes only their own preferences and in-app messages (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
  const isSelf = (req) => req.user != null && req.user.id != null && String(req.user.id) === String(req.params.user_id);
  const notFound = { status: 404, body: { success: false, error: 'not_found' } };

  add('GET', '/notifications/in-app/:user_id', async (req) => {
    if (!isSelf(req)) return notFound;
    return { status: 200, body: { user_id: Number(req.params.user_id), notifications: service.getInAppNotifications(Number(req.params.user_id)) } };
  });

  add('GET', '/users/:user_id/notification-preferences', async (req) => {
    if (!isSelf(req)) return notFound;
    return { status: 200, body: service.getPreferences(Number(req.params.user_id)) };
  });

  add('PUT', '/users/:user_id/notification-preferences', async (req) => {
    if (!isSelf(req)) return notFound;
    try {
      service.updatePreferences(Number(req.params.user_id), req.body || {});
    } catch (err) {
      return { status: 400, body: { success: false, error: err.message } };
    }
    return { status: 200, body: { success: true } };
  });

  // GET /notifications/open/:message_id (NOTIF-07, Phase B.2, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): the
  // tracking pixel or link. Sets opened_at and status 'opened' the first time only and answers 204 with no body
  // either way, also for an unknown id, so the pixel says nothing about which messages exist.
  add('GET', '/notifications/open/:message_id', async (req) => {
    service.markOpened(req.params.message_id);
    return { status: 204, body: null };
  });

  // The old open URL, kept for links already sent; it now answers like the route above.
  add('GET', '/track/:message_id/open', async (req) => {
    service.markOpened(req.params.message_id);
    return { status: 204, body: null };
  });

  add('GET', '/track/:message_id/click', async (req) => {
    const res = service.markClicked(req.params.message_id);
    return { status: res.success ? 200 : 404, body: res };
  });

  // Unsubscribe link from an e-mail (NOTIF-11, amended 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). The token is
  // checked before any user lookup; a missing, malformed, wrong or unknown-channel token is the same 403. GET only
  // confirms (a mail scanner following the link changes nothing); POST unsubscribes (RFC 8058 one-click).
  const invalidToken = { status: 403, body: { success: false, error: 'invalid_unsubscribe_token' } };
  add('GET', '/unsubscribe', async (req) => {
    const ok = service.verifyUnsubscribe(req.query);
    if (!ok) return invalidToken;
    return { status: 200, body: { success: true, confirm: true, channel: ok.channel, method: 'POST' } };
  });

  add('POST', '/unsubscribe', async (req) => {
    const ok = service.verifyUnsubscribe({ ...(req.body || {}), ...(req.query || {}) });
    if (!ok) return invalidToken;
    service.unsubscribe(ok.userId, ok.channel);
    return { status: 200, body: { success: true, channel: ok.channel } };
  });

  return {
    routes,
    async handle(method, path, req) {
      for (const r of routes) {
        if (r.method !== method) continue;
        const m = r.regex.exec(path);
        if (!m) continue;
        const params = {};
        r.keys.forEach((k, i) => { params[k] = m[i + 1]; });
        const out = await r.handler({ params, query: (req && req.query) || {}, body: req && req.body, user: req && req.user });
        return out;
      }
      return { status: 404, body: { success: false, error: 'not_found' } };
    },
  };
}

module.exports = {
  NotificationService,
  createRouter,
  DEFAULT_TEMPLATES,
  SCHEMA_SQL,
  renderTemplate,
  inQuietHours,
  nextQuietHoursEnd,
  generateId,
  buildUnsubscribeUrl,
  unsubscribeToken,
  defaultPreferences,
};