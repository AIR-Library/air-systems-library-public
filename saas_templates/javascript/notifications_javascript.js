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

/* ============================================================================
 * UTILITIES
 * ========================================================================== */
function generateId(prefix) {
  const rand = crypto.randomBytes(16).toString('hex');
  return prefix ? `${prefix}_${rand}` : rand;
}


function parseTimeToMinutes(t) {
  if (!t) return null;
  const m = /^(\d{1,2}):(\d{2})$/.exec(String(t).trim());
  if (!m) return null;
  return parseInt(m[1], 10) * 60 + parseInt(m[2], 10);
}

function inQuietHours(start, end, date) {
  const s = parseTimeToMinutes(start);
  const e = parseTimeToMinutes(end);
  if (s === null || e === null) return false;
  const d = date || new Date();
  const cur = d.getHours() * 60 + d.getMinutes();
  if (s === e) return false;
  if (s < e) return cur >= s && cur < e;
  // wraps midnight
  return cur >= s || cur < e;
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

/**
 * Compares two strings in constant time. In: two values. Out: true only for equal strings of equal length.
 * Why: unsubscribe tokens must not leak through timing (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
 * Touches: nothing.
 */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

const CHANNELS = ['email', 'sms', 'in_app'];

/**
 * The preferences of a user who has saved none: every channel on, no do-not-disturb, no quiet hours.
 * Out: a fresh object. Why: defaults used to switch SMS off and impose 22:00-08:00 quiet hours in the server's time
 * zone, which made sends depend on the time of day (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
 */
function defaultPreferences() {
  return {
    do_not_disturb: false,
    quiet_hours_start: null,
    quiet_hours_end: null,
    channels_enabled: { email: true, sms: true, in_app: true },
  };
}

function buildTrackUrl(baseUrl, messageId, action) {
  return `${baseUrl}/track/${messageId}/${action}`;
}

/* ============================================================================
 * NOTIFICATION SERVICE
 * ========================================================================== */
/**
 * The notification service.
 * In (constructor options): baseUrl, maxRetries (default 3), retryBaseDelayMs (default 100), nowFn (clock returning a
 * Date; quiet hours and timestamps use it), sleep, unsubscribeSecret (default env NOTIFICATIONS_UNSUBSCRIBE_SECRET,
 * else random per process), emailSender, smsSender, inAppSender. Events: 'sent', 'failed' (the log entry).
 * Why: spec SYSTEM 2. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: unsubscribeSecret added, every timestamp taken from nowFn.
 * Touches: memory; the injected senders (e-mail, SMS providers).
 */
class NotificationService extends EventEmitter {
  constructor(options) {
    super();
    const opts = options || {};
    this.baseUrl = opts.baseUrl || 'http://localhost:3000';
    this.maxRetries = opts.maxRetries != null ? opts.maxRetries : 3;
    this.retryBaseDelayMs = opts.retryBaseDelayMs != null ? opts.retryBaseDelayMs : 100;
    this.nowFn = opts.nowFn || (() => new Date());
    this.unsubscribeSecret = opts.unsubscribeSecret || process.env.NOTIFICATIONS_UNSUBSCRIBE_SECRET
      || crypto.randomBytes(32).toString('hex');
    this.sleep = opts.sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));

    // In-memory stores
    this.templates = new Map();
    this.logs = new Map();
    this.preferences = new Map();
    this.unsubscribes = new Set();
    this.queue = [];

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
        if (typeof u.channels_enabled[ch] === 'boolean') merged.channels_enabled[ch] = u.channels_enabled[ch];
      }
    }
    this.preferences.set(userId, merged);
    return { success: true };
  }

  /* ---- Unsubscribe ---- */
  isUnsubscribed(userId, channel) {
    return this.unsubscribes.has(`${userId}:${channel}`);
  }

  unsubscribe(userId, channel) {
    this.unsubscribes.add(`${userId}:${channel}`);
    return { success: true };
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
   * scheduled_at and quiet hours ('queued'), then delivery with retries.
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

    // Scheduled delivery
    if (payload.scheduled_at) {
      const scheduled = new Date(payload.scheduled_at);
      const now = this.nowFn();
      if (scheduled > now) {
        log.status = 'queued';
        this.queue.push({ messageId, payload, channel, template, prefs, vars, scheduledAt: scheduled });
        this.queue.sort((a, b) => a.scheduledAt - b.scheduledAt);
        return { success: true, message_id: messageId, status: 'queued' };
      }
    }

    // Quiet hours: queue for quiet_hours_end
    const now = this.nowFn();
    if (inQuietHours(prefs.quiet_hours_start, prefs.quiet_hours_end, now)) {
      log.status = 'queued';
      const endMin = parseTimeToMinutes(prefs.quiet_hours_end);
      const release = new Date(now);
      release.setHours(Math.floor(endMin / 60), endMin % 60, 0, 0);
      if (release <= now) release.setDate(release.getDate() + 1);
      this.queue.push({ messageId, payload, channel, template, prefs, vars, scheduledAt: release });
      this.queue.sort((a, b) => a.scheduledAt - b.scheduledAt);
      return { success: true, message_id: messageId, status: 'queued' };
    }

    // Deliver
    const result = await this._deliverWithRetry(messageId, channel, template, vars, payload.user_id);
    return result;
  }

  /**
   * Delivers with up to maxRetries retries, waiting retryBaseDelayMs x 2^(n-1) between attempts.
   * In: message id, channel, template, vars, user id. Out: { success, message_id, status }.
   * Why: spec "Retry: Email/SMS failures retry 3x with exponential backoff". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: sent_at from nowFn.
   * Touches: memory, the senders.
   */
  async _deliverWithRetry(messageId, channel, template, vars, userId) {
    const log = this.logs.get(messageId);
    let attempt = 0;
    let lastError = null;
    while (attempt <= this.maxRetries) {
      try {
        await this._deliverOnce(messageId, channel, template, vars, userId);
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
   * Records that a message was opened (first time only). In: message id. Out: { success, message_id, status }.
   * Why: spec tracking. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: time from nowFn. Touches: memory.
   */
  markOpened(messageId) {
    const log = this.logs.get(messageId);
    if (!log) return { success: false, error: 'not_found' };
    if (!log.opened_at) log.opened_at = this.nowFn().toISOString();
    return { success: true, message_id: messageId, status: 'opened' };
  }

  /**
   * Records a click (which implies an open). In: message id. Out: { success, message_id, status }.
   * Why: spec tracking. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: time from nowFn. Touches: memory.
   */
  markClicked(messageId) {
    const log = this.logs.get(messageId);
    if (!log) return { success: false, error: 'not_found' };
    if (!log.opened_at) log.opened_at = this.nowFn().toISOString();
    if (!log.clicked_at) log.clicked_at = this.nowFn().toISOString();
    return { success: true, message_id: messageId, status: 'clicked' };
  }

  /* ---- In-app fetch ---- */
  getInAppNotifications(userId) {
    const out = [];
    for (const log of this.logs.values()) {
      if (log.user_id === userId && log.channel === 'in_app' && log.status === 'sent') {
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

  /* ---- Process queued (scheduled / quiet-hours) messages ---- */
  /**
   * Delivers queued messages (scheduled or held by quiet hours) whose time has come, re-checking do-not-disturb,
   * unsubscribe and channel choices first, since the user may have changed them while the message waited.
   * Out: an array of send results. Why: spec "queue for quiet_hours_end". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the re-checks.
   * Touches: memory, the senders.
   */
  async processQueue() {
    const now = this.nowFn();
    const due = [];
    this.queue = this.queue.filter((item) => {
      if (item.scheduledAt <= now) {
        due.push(item);
        return false;
      }
      return true;
    });
    const results = [];
    for (const item of due) {
      const log = this.logs.get(item.messageId);
      if (!log) continue;
      // Preferences may have changed while the message waited: check them again before delivering.
      const prefs = this.getPreferences(item.payload.user_id);
      let skip = null;
      if (prefs.do_not_disturb) skip = 'do_not_disturb';
      else if ((item.channel === 'email' || item.channel === 'sms')
        && this.isUnsubscribed(item.payload.user_id, item.channel)) skip = 'unsubscribed';
      else if (prefs.channels_enabled[item.channel] === false) skip = 'channel_disabled';
      if (skip) {
        log.status = 'skipped';
        log.error = skip;
        results.push({ success: true, message_id: item.messageId, status: 'skipped' });
        continue;
      }
      const res = await this._deliverWithRetry(item.messageId, item.channel, item.template, item.vars, item.payload.user_id);
      results.push(res);
    }
    return results;
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
 * In: a NotificationService. Out: { routes, handle(method, path, { query, body }) } resolving to { status, body }.
 * Authenticate callers before handle(): the preference routes act on the user id in the path.
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

  add('GET', '/notifications/in-app/:user_id', async (req) => {
    return { status: 200, body: { user_id: Number(req.params.user_id), notifications: service.getInAppNotifications(Number(req.params.user_id)) } };
  });

  add('GET', '/users/:user_id/notification-preferences', async (req) => {
    return { status: 200, body: service.getPreferences(Number(req.params.user_id)) };
  });

  add('PUT', '/users/:user_id/notification-preferences', async (req) => {
    try {
      service.updatePreferences(Number(req.params.user_id), req.body || {});
    } catch (err) {
      return { status: 400, body: { success: false, error: err.message } };
    }
    return { status: 200, body: { success: true } };
  });

  add('GET', '/track/:message_id/open', async (req) => {
    const res = service.markOpened(req.params.message_id);
    return { status: res.success ? 200 : 404, body: res };
  });

  add('GET', '/track/:message_id/click', async (req) => {
    const res = service.markClicked(req.params.message_id);
    return { status: res.success ? 200 : 404, body: res };
  });

  // Unsubscribe link from an e-mail: only a token signed by this service for that user and channel is accepted
  // (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP; it used to accept any user_id).
  add('GET', '/unsubscribe', async (req) => {
    const q = req.query || {};
    const channel = q.channel || 'email';
    if (q.user_id == null || !CHANNELS.includes(channel)) {
      return { status: 400, body: { success: false, error: 'user_id and a valid channel required' } };
    }
    const userId = Number(q.user_id);
    if (!safeEqual(q.token, unsubscribeToken(service.unsubscribeSecret, userId, channel))) {
      return { status: 403, body: { success: false, error: 'invalid_token' } };
    }
    service.unsubscribe(userId, channel);
    return { status: 200, body: { success: true } };
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
        const out = await r.handler({ params, query: req.query, body: req.body });
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
  generateId,
  buildUnsubscribeUrl,
};