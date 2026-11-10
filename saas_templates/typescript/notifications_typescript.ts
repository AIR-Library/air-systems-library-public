import { Database } from 'sqlite3';
import { open, Database as SQLiteDatabase } from 'sqlite';
import nodemailer, { Transporter } from 'nodemailer';
import { v4 as uuidv4 } from 'uuid';
import { Twilio } from 'twilio';
import { createHmac, timingSafeEqual } from 'crypto';

type NotificationChannel = 'email' | 'sms' | 'in_app';
/**
 * 'queued' is a message waiting for its scheduled_at (or about to be sent); 'sending' is a scheduled message that
 * deliverDue() has claimed and is sending now. 'sending' added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP
 * (CodeRabbit review on PR 19).
 */
type NotificationStatus = 'sent' | 'queued' | 'sending' | 'failed' | 'skipped' | 'bounced' | 'opened' | 'clicked';

interface NotificationTemplate {
  key: string;
  subject: string;
  body_text: string;
  body_html: string;
  channels_default: NotificationChannel[];
  variables: string[];
}

interface NotificationLog {
  id: string;
  user_id: number;
  template_key: string;
  channel: NotificationChannel;
  vars_used: string;
  sent_at: string | null;
  opened_at: string | null;
  clicked_at: string | null;
  bounced: boolean;
  error: string | null;
  status: NotificationStatus;
  /** When a scheduled message is due (ISO 8601, UTC), or null for one sent at once. Added 2026-11-10, session
   * session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19: the schedule is persisted, not kept in a timer). */
  scheduled_at?: string | null;
  /** When deliverDue() claimed the row (ISO 8601), or null. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-12). */
  claimed_at?: string | null;
}

interface UserPreferences {
  user_id: number;
  do_not_disturb: boolean;
  /** Start of the quiet window, "HH:mm" in UTC, or null for none (the default until the user sets one). */
  quiet_hours_start: string | null;
  /** End of the quiet window, "HH:mm" in UTC, inclusive of that whole minute, or null for none. */
  quiet_hours_end: string | null;
  channels_enabled: { [key in NotificationChannel]?: boolean };
}

interface SendParams {
  user_id: number;
  template_key: string;
  channel: NotificationChannel | null;
  vars: { [key: string]: any };
  scheduled_at: string | null; // ISO 8601
}

interface SendBatchParams extends SendParams {}

interface TrackParams {
  message_id: string;
  status: NotificationStatus;
}

/**
 * Options for {@link NotificationService}.
 * - `now`: the clock used for quiet hours, scheduling and timestamps (default: the system clock).
 * - `retryBaseDelayMs`: the first retry waits 2 x this, the second 4 x this (default 250 ms: 0.5 s then 1 s).
 * - `sleep`: how to wait between retries (default: a timer).
 * Why: retries waited 2 s then 4 s, longer than a request (and the test) can wait, and nothing could be pinned to a
 * moment (repair of the failing Retry test, 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP). Touches: nothing.
 */
export interface NotificationServiceOptions {
  now?: () => Date;
  retryBaseDelayMs?: number;
  sleep?: (ms: number) => Promise<void>;
  /**
   * The HMAC key for unsubscribe links, at least 32 bytes (default: NOTIFICATIONS_UNSUBSCRIBE_SECRET from the
   * environment). Never hard-coded. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-11).
   */
  unsubscribeSecret?: string;
  /** Base URL of the unsubscribe link (default https://example.com). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
  baseUrl?: string;
}

/** The channels a link or preference may name. */
const CHANNELS: readonly NotificationChannel[] = ['email', 'sms', 'in_app'];

/** A 'sending' row claimed longer ago than this is taken to belong to a crashed worker (spec deliver_due step 1). */
const STALE_CLAIM_MS = 300 * 1000;

/** The answer to an unsubscribe request: an HTTP status and a JSON body. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
export interface UnsubscribeResponse {
  http_status: number;
  body: Record<string, unknown>;
}

/** Attempts per message, the first included: one send and two retries (spec: "retry ... with exponential backoff"). */
const MAX_SEND_ATTEMPTS = 3;

/**
 * Notification service (spec TIER_2 system 2): templated email, SMS and in-app messages with per-user preferences
 * (do-not-disturb, quiet hours, enabled channels), retries and delivery tracking, stored in SQLite.
 * In: a database path, an email transport and an SMS client (tests pass fakes), and options. Out: the methods below.
 * Why changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): six tests failed because new users got quiet
 * hours 22:00-08:00 in the server's local time, so whether anything was sent depended on the hour the suite ran; an
 * explicit channel the user had switched off was still used; retries waited 6 s. Provider credentials now come only
 * from the environment, never from the source. Touches: the SQLite database, SMTP and Twilio (network) when sending.
 */
export class NotificationService {
  private db: SQLiteDatabase;
  private emailTransport: Transporter | null;
  private smsClient: Twilio | null;
  private templates: Map<string, NotificationTemplate> = new Map();
  private readonly now: () => Date;
  private readonly retryBaseDelayMs: number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly unsubscribeSecret: string;
  private readonly baseUrl: string;

  /**
   * In: the SQLite path (default in-memory), the email transport and SMS client (default: built on first use from
   * SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASS and TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN), and options.
   * Out: a service; call init() before use. Touches: nothing until init().
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-11): refuses to start (throws) without an unsubscribe secret
   * of at least 32 bytes, from options.unsubscribeSecret or NOTIFICATIONS_UNSUBSCRIBE_SECRET; an empty key would
   * make a forgeable HMAC. Reads the environment.
   */
  constructor(
    private dbPath: string = ':memory:',
    emailTransport?: Transporter,
    smsClient?: Twilio,
    options: NotificationServiceOptions = {}
  ) {
    this.emailTransport = emailTransport ?? null;
    this.smsClient = smsClient ?? null;
    this.now = options.now ?? (() => new Date());
    this.retryBaseDelayMs = options.retryBaseDelayMs ?? 250;
    this.sleep = options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
    const secret = options.unsubscribeSecret ?? process.env.NOTIFICATIONS_UNSUBSCRIBE_SECRET ?? '';
    if (Buffer.byteLength(secret, 'utf8') < 32) {
      throw new Error('unsubscribe_secret_too_short: configure an unsubscribe secret of at least 32 bytes');
    }
    this.unsubscribeSecret = secret;
    this.baseUrl = (options.baseUrl ?? 'https://example.com').replace(/\/+$/, '');
  }

  /**
   * The email transport, built from the environment the first time it is needed when none was given.
   * Out: a nodemailer transport. Throws when SMTP_HOST is not set. Added 2026-11-10, session
   * session_012zDydZCZ4AChqhEZ4oVtaP, replacing credentials written in the source. Touches: reads the environment.
   */
  private getEmailTransport(): Transporter {
    if (!this.emailTransport) {
      const host = process.env.SMTP_HOST;
      if (!host) throw new Error('email_not_configured: set SMTP_HOST (and SMTP_USER / SMTP_PASS) or pass a transport');
      this.emailTransport = nodemailer.createTransport({
        host,
        port: Number(process.env.SMTP_PORT || 587),
        auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS || '' } : undefined,
      });
    }
    return this.emailTransport;
  }

  /**
   * The SMS client, built from the environment the first time it is needed when none was given.
   * Out: a Twilio client. Throws when TWILIO_ACCOUNT_SID or TWILIO_AUTH_TOKEN is not set. Added 2026-11-10, session
   * session_012zDydZCZ4AChqhEZ4oVtaP, replacing credentials written in the source. Touches: reads the environment.
   */
  private getSmsClient(): Twilio {
    if (!this.smsClient) {
      const sid = process.env.TWILIO_ACCOUNT_SID;
      const token = process.env.TWILIO_AUTH_TOKEN;
      if (!sid || !token) throw new Error('sms_not_configured: set TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN or pass a client');
      this.smsClient = new Twilio(sid, token);
    }
    return this.smsClient;
  }

  /**
   * Closes the database. In/out: nothing. Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP, so callers can
   * release the handle. Touches: the SQLite connection.
   */
  async close(): Promise<void> {
    if (this.db) await this.db.close();
  }

  async init(): Promise<void> {
    this.db = await open({
      filename: this.dbPath,
      driver: Database,
    });
    await this.runDDL();
    await this.loadTemplates();
  }

  /**
   * Creates the tables when missing and adds notification_logs.scheduled_at to a database created before it existed.
   * In/out: nothing. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19:
   * scheduled sends are persisted, so the log row carries scheduled_at). Touches: the SQLite schema.
   */
  private async runDDL(): Promise<void> {
    const ddl = `
      CREATE TABLE IF NOT EXISTS notification_templates (
        key TEXT PRIMARY KEY,
        subject TEXT,
        body_text TEXT,
        body_html TEXT,
        channels_default TEXT,
        variables TEXT
      );
      CREATE TABLE IF NOT EXISTS notification_logs (
        id TEXT PRIMARY KEY,
        user_id INTEGER,
        template_key TEXT,
        channel TEXT,
        vars_used TEXT,
        sent_at TEXT,
        opened_at TEXT,
        clicked_at TEXT,
        bounced INTEGER,
        error TEXT,
        status TEXT,
        scheduled_at TEXT,
        claimed_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_notification_logs_due ON notification_logs (status, scheduled_at);
      CREATE TABLE IF NOT EXISTS user_notification_preferences (
        user_id INTEGER PRIMARY KEY,
        do_not_disturb INTEGER,
        quiet_hours_start TEXT,
        quiet_hours_end TEXT,
        channels_enabled TEXT
      );
    `;
    // A table created before scheduled_at existed: CREATE TABLE IF NOT EXISTS leaves it as it was, so add the column
    // before the index on it is created.
    const columns = await this.db.all<{ name: string }[]>(`PRAGMA table_info(notification_logs)`);
    if (columns.length > 0 && !columns.some((c) => c.name === 'scheduled_at')) {
      await this.db.exec(`ALTER TABLE notification_logs ADD COLUMN scheduled_at TEXT`);
    }
    // claimed_at added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-12: deliverDue's claim time).
    if (columns.length > 0 && !columns.some((c) => c.name === 'claimed_at')) {
      await this.db.exec(`ALTER TABLE notification_logs ADD COLUMN claimed_at TEXT`);
    }
    await this.db.exec(ddl);
    await this.seedTemplates();
  }

  private async seedTemplates(): Promise<void> {
    const templates: NotificationTemplate[] = [
      {
        key: 'welcome_email',
        subject: 'Welcome to {app_name}!',
        body_text: 'Welcome to {app_name}! Here\'s your first step.',
        body_html: '<p>Welcome to {app_name}! Here\'s your first step.</p>',
        channels_default: ['email'],
        variables: ['app_name'],
      },
      {
        key: 'trial_starting',
        subject: 'Your free trial is starting',
        body_text: 'Your free trial is starting. You have {trial_days} days.',
        body_html: '<p>Your free trial is starting. You have {trial_days} days.</p>',
        channels_default: ['email'],
        variables: ['trial_days'],
      },
      {
        key: 'trial_ending_soon',
        subject: 'Your trial ends soon',
        body_text: 'Your trial ends in {days_left} days. Add payment method to continue.',
        body_html: '<p>Your trial ends in {days_left} days. Add payment method to continue.</p>',
        channels_default: ['email'],
        variables: ['days_left'],
      },
      {
        key: 'subscription_changed',
        subject: 'Your plan changed',
        body_text: 'Your plan changed from {old_tier} to {new_tier}. Effective {effective_date}.',
        body_html: '<p>Your plan changed from {old_tier} to {new_tier}. Effective {effective_date}.</p>',
        channels_default: ['email'],
        variables: ['old_tier', 'new_tier', 'effective_date'],
      },
      {
        key: 'payment_failed',
        subject: 'Payment failed',
        body_text: 'Payment failed for invoice {invoice_id}. {retry_date} retry, or update payment method.',
        body_html: '<p>Payment failed for invoice {invoice_id}. {retry_date} retry, or update payment method.</p>',
        channels_default: ['email'],
        variables: ['invoice_id', 'retry_date'],
      },
      {
        key: 'deployment_live',
        subject: 'Deployment live',
        body_text: 'Your deployment {deployment_name} is now live at {url}.',
        body_html: '<p>Your deployment {deployment_name} is now live at {url}.</p>',
        channels_default: ['email'],
        variables: ['deployment_name', 'url'],
      },
      {
        key: 'user_invited',
        subject: 'You\'ve been invited',
        body_text: 'You\'ve been invited to {workspace}. Click here to join.',
        body_html: '<p>You\'ve been invited to {workspace}. <a href="#">Click here to join</a>.</p>',
        channels_default: ['email'],
        variables: ['workspace'],
      },
      {
        key: 'invoice_ready',
        subject: 'Your invoice is ready',
        body_text: 'Your invoice for {month} is ready. Download here.',
        body_html: '<p>Your invoice for {month} is ready. <a href="#">Download here</a>.</p>',
        channels_default: ['email'],
        variables: ['month'],
      },
      {
        key: 'admin_alert',
        subject: 'Admin alert',
        body_text: '{actor} performed {action} on {resource}.',
        body_html: '<p>{actor} performed {action} on {resource}.</p>',
        channels_default: ['email'],
        variables: ['actor', 'action', 'resource'],
      },
    ];
    for (const tmpl of templates) {
      await this.db.run(
        `INSERT OR REPLACE INTO notification_templates
        (key, subject, body_text, body_html, channels_default, variables)
        VALUES (?, ?, ?, ?, ?, ?)`,
        tmpl.key,
        tmpl.subject,
        tmpl.body_text,
        tmpl.body_html,
        JSON.stringify(tmpl.channels_default),
        JSON.stringify(tmpl.variables)
      );
    }
  }

  private async loadTemplates(): Promise<void> {
    const rows = await this.db.all<NotificationTemplate[]>(`SELECT * FROM notification_templates`);
    for (const row of rows) {
      row.channels_default = JSON.parse(row.channels_default);
      row.variables = JSON.parse(row.variables);
      this.templates.set(row.key, row);
    }
  }

  /**
   * A user's preferences, created with the defaults (no do-not-disturb, no quiet window, every channel on) the first
   * time they are asked for. In: the user id. Out: the preferences. Touches: reads and may insert one row.
   * Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the default quiet window is none (was 22:00-08:00).
   * Changed again the same day (NOTIF-02 amendment): SMS is off by default (opt-in: it costs money per message and
   * marketing texts need prior consent); defaults are email on, sms off, in_app on.
   */
  private async getUserPreferences(user_id: number): Promise<UserPreferences> {
    const row = await this.db.get<UserPreferences>(`SELECT * FROM user_notification_preferences WHERE user_id = ?`, user_id);
    if (!row) {
      // default preferences
      const defaultPrefs: UserPreferences = {
        user_id,
        do_not_disturb: false,
        // No quiet window until the user sets one: a fixed default would silence people at a different hour of their
        // own day depending on where they live, and made sending depend on the hour (repaired 2026-11-10).
        quiet_hours_start: null,
        quiet_hours_end: null,
        channels_enabled: { email: true, sms: false, in_app: true },
      };
      await this.db.run(
        `INSERT INTO user_notification_preferences
        (user_id, do_not_disturb, quiet_hours_start, quiet_hours_end, channels_enabled)
        VALUES (?, ?, ?, ?, ?)`,
        user_id,
        defaultPrefs.do_not_disturb ? 1 : 0,
        defaultPrefs.quiet_hours_start,
        defaultPrefs.quiet_hours_end,
        JSON.stringify(defaultPrefs.channels_enabled)
      );
      return defaultPrefs;
    }
    row.channels_enabled = JSON.parse(row.channels_enabled);
    row.do_not_disturb = !!row.do_not_disturb;
    return row;
  }

  async updateUserPreferences(user_id: number, prefs: Partial<UserPreferences>): Promise<{ success: boolean }> {
    const current = await this.getUserPreferences(user_id);
    const updated: UserPreferences = {
      ...current,
      ...prefs,
      channels_enabled: { ...current.channels_enabled, ...prefs.channels_enabled },
    };
    await this.db.run(
      `UPDATE user_notification_preferences SET
        do_not_disturb = ?,
        quiet_hours_start = ?,
        quiet_hours_end = ?,
        channels_enabled = ?
      WHERE user_id = ?`,
      updated.do_not_disturb ? 1 : 0,
      updated.quiet_hours_start,
      updated.quiet_hours_end,
      JSON.stringify(updated.channels_enabled),
      user_id
    );
    return { success: true };
  }

  /**
   * Whether a message may go out now: not under do-not-disturb and not inside the quiet window. The window is in UTC
   * at minute resolution and includes both ends' whole minutes, so 00:00-23:59 covers the whole day; a window whose
   * start is after its end runs over midnight. In: the preferences. Out: true to send.
   * Why: it compared against the server's local clock to the second, so 23:59:30 fell outside 00:00-23:59, and it
   * read the real clock only (2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP). Touches: reads the clock.
   */
  private async shouldSendNow(prefs: UserPreferences): Promise<boolean> {
    if (prefs.do_not_disturb) return false;
    if (!prefs.quiet_hours_start || !prefs.quiet_hours_end) return true;
    const start = this.parseMinutes(prefs.quiet_hours_start);
    const end = this.parseMinutes(prefs.quiet_hours_end);
    if (start === null || end === null) return true;
    const now = this.now();
    const minute = now.getUTCHours() * 60 + now.getUTCMinutes();
    const inQuiet = start <= end ? minute >= start && minute <= end : minute >= start || minute <= end;
    return !inQuiet;
  }

  /**
   * When the user's quiet window ends next: today's quiet_hours_end (UTC, HH:mm:00) unless that whole minute has
   * already passed, else tomorrow's. In: the preferences (with a window). Out: the moment, or null when there is no
   * valid window. Why: spec "in quiet hours the message is stored 'queued' with scheduled_at = quiet_hours_end"
   * (NOTIF-05 amendment). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: reads the clock.
   */
  private quietHoursEndAt(prefs: UserPreferences): Date | null {
    if (!prefs.quiet_hours_end) return null;
    const end = this.parseMinutes(prefs.quiet_hours_end);
    if (end === null) return null;
    const now = this.now();
    const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), Math.floor(end / 60), end % 60);
    return new Date(today + 60_000 <= now.getTime() ? today + 24 * 60 * 60 * 1000 : today);
  }

  /**
   * Minutes after midnight for "HH:mm". In: the text. Out: 0-1439, or null when it is not a valid time.
   * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
   */
  private parseMinutes(timeStr: string): number | null {
    const m = /^(\d{1,2}):(\d{2})$/.exec(timeStr.trim());
    if (!m) return null;
    const h = Number(m[1]);
    const min = Number(m[2]);
    if (h > 23 || min > 59) return null;
    return h * 60 + min;
  }

  private renderTemplate(template: NotificationTemplate, vars: { [key: string]: any }): { subject: string; body_text: string; body_html: string } {
    const replace = (text: string) => {
      return text.replace(/{(\w+)}/g, (_, key) => {
        return vars[key] !== undefined ? String(vars[key]) : `{${key}}`;
      });
    };
    return {
      subject: replace(template.subject),
      body_text: replace(template.body_text),
      body_html: replace(template.body_html),
    };
  }

  /**
   * Inserts one log row and returns its id. In: the row without id (scheduled_at optional, default null).
   * Out: the new id. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (CodeRabbit review on PR 19): it
   * also stores scheduled_at. Touches: notification_logs.
   */
  private async logMessage(log: Omit<NotificationLog, 'id'>): Promise<string> {
    const id = uuidv4();
    await this.db.run(
      `INSERT INTO notification_logs
      (id, user_id, template_key, channel, vars_used, sent_at, opened_at, clicked_at, bounced, error, status, scheduled_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      id,
      log.user_id,
      log.template_key,
      log.channel,
      JSON.stringify(log.vars_used),
      log.sent_at,
      log.opened_at,
      log.clicked_at,
      log.bounced ? 1 : 0,
      log.error,
      log.status,
      log.scheduled_at ?? null
    );
    return id;
  }

  /**
   * Updates the given fields of one log row with a parameterized statement (column names are fixed here, never taken
   * from input). In: the log id and the fields. Out: nothing. Touches: notification_logs.
   * Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: sent_at was silently dropped, so a sent message
   * never had its send time.
   */
  private async updateLogStatus(id: string, updates: Partial<NotificationLog>): Promise<void> {
    const fields = [];
    const values: any[] = [];
    if (updates.status !== undefined) {
      fields.push('status = ?');
      values.push(updates.status);
    }
    if (updates.sent_at !== undefined) {
      fields.push('sent_at = ?');
      values.push(updates.sent_at);
    }
    if (updates.opened_at !== undefined) {
      fields.push('opened_at = ?');
      values.push(updates.opened_at);
    }
    if (updates.clicked_at !== undefined) {
      fields.push('clicked_at = ?');
      values.push(updates.clicked_at);
    }
    if (updates.bounced !== undefined) {
      fields.push('bounced = ?');
      values.push(updates.bounced ? 1 : 0);
    }
    if (updates.error !== undefined) {
      fields.push('error = ?');
      values.push(updates.error);
    }
    if (fields.length === 0) return;
    values.push(id);
    await this.db.run(`UPDATE notification_logs SET ${fields.join(', ')} WHERE id = ?`, ...values);
  }

  /**
   * Renders a template and sends it by email with a SIGNED unsubscribe link (2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP: the link carried only user_id and channel, so anyone could unsubscribe anyone).
   * In: user, template, variables, log id.
   * Out: nothing; throws on a transport error. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the transport comes from getEmailTransport().
   * Touches: SMTP (network).
   */
  private async sendEmail(user_id: number, template: NotificationTemplate, vars: any, message_id: string): Promise<void> {
    const rendered = this.renderTemplate(template, vars);
    const mailOptions = {
      from: '"Example App" <no-reply@example.com>',
      to: `user${user_id}@example.com`,
      subject: rendered.subject,
      text: rendered.body_text,
      html: rendered.body_html + `<p><a href="${this.unsubscribeUrl(user_id, 'email')}">Unsubscribe</a></p>`,
    };
    await this.getEmailTransport().sendMail(mailOptions);
  }

  /**
   * Renders a template's text and sends it by SMS. In: user, template, variables, log id. Out: nothing; throws on
   * a provider error. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the client comes from getSmsClient(). Touches: Twilio (network).
   */
  private async sendSMS(user_id: number, template: NotificationTemplate, vars: any, message_id: string): Promise<void> {
    const rendered = this.renderTemplate(template, vars);
    await this.getSmsClient().messages.create({
      body: rendered.body_text,
      from: '+15555555555',
      to: `+1555${user_id}`,
    });
  }

  private async sendInApp(user_id: number, template: NotificationTemplate, vars: any, message_id: string): Promise<void> {
    // In-app notifications are stored in logs; nothing else to do
  }

  /**
   * Sends one message on its channel, retrying a failed email or SMS with exponential backoff (2 x base, then
   * 4 x base) up to {@link MAX_SEND_ATTEMPTS} attempts. In: the channel, user, template, variables and log id.
   * Out: { ok: true } or { ok: false, error }. Writes nothing: the caller records the outcome (sendSingle directly,
   * deliverDue only while it still holds its claim).
   * Why: rewritten as a loop 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP); split from the status write the
   * same day so deliverDue's final write can be conditional on its claim (NOTIF-12). Touches: SMTP / Twilio (network).
   */
  private async trySend(channel: NotificationChannel, user_id: number, template: NotificationTemplate, vars: any, message_id: string): Promise<{ ok: true } | { ok: false; error: string }> {
    for (let attempt = 1; attempt <= MAX_SEND_ATTEMPTS; attempt++) {
      try {
        if (channel === 'email') {
          await this.sendEmail(user_id, template, vars, message_id);
        } else if (channel === 'sms') {
          await this.sendSMS(user_id, template, vars, message_id);
        } else if (channel === 'in_app') {
          await this.sendInApp(user_id, template, vars, message_id);
        }
        return { ok: true };
      } catch (err: any) {
        if (attempt === MAX_SEND_ATTEMPTS) {
          return { ok: false, error: String(err?.message ?? err) };
        }
        await this.sleep(Math.pow(2, attempt) * this.retryBaseDelayMs);
      }
    }
    return { ok: false, error: 'unreachable' };
  }

  /**
   * Sends one logged message now and records 'sent' (with sent_at) or 'failed' (with the error).
   * In: the channel, user, template, variables and log id. Out: nothing. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: SMTP / Twilio (network), notification_logs.
   */
  private async attemptSend(channel: NotificationChannel, user_id: number, template: NotificationTemplate, vars: any, message_id: string): Promise<void> {
    const outcome = await this.trySend(channel, user_id, template, vars, message_id);
    if (outcome.ok) {
      await this.updateLogStatus(message_id, { status: 'sent', sent_at: this.now().toISOString() });
    } else {
      await this.updateLogStatus(message_id, { status: 'failed', error: outcome.error });
    }
  }

  /**
   * Sends one notification. The channel is the one asked for, or when null the template's default channels and
   * then email, SMS, in-app, the first the user has enabled. A channel the user switched off (unsubscribed), no
   * enabled channel, do-not-disturb and the quiet window each log the message as 'skipped'.
   * A scheduled_at in the future is not sent now: the row stays 'queued' with its scheduled_at stored, and
   * {@link deliverDue} sends it once the clock has passed that moment (the host calls deliverDue periodically, e.g.
   * every minute). A scheduled_at that is not in the future is sent at once. An unparseable scheduled_at throws
   * before anything is logged.
   * In: { user_id, template_key, channel, vars, scheduled_at }. Out: { success, message_id, status }.
   * Why changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): an explicit channel was used even when the user
   * had disabled it, so unsubscribed users were still emailed. Later the same day (CodeRabbit review on PR 19):
   * scheduled sends used setTimeout, which fires after 1 ms for delays over 2,147,483,647 ms (about 24.8 days) and is
   * lost on restart; the schedule is now persisted. Touches: notification_logs, preferences, providers.
   * Changed again 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-05 amendment): inside the quiet window the
   * message is no longer skipped; it is stored 'queued' with scheduled_at = the end of the window and deliverDue
   * sends it then. Do-not-disturb still skips.
   */
  async sendSingle(params: SendParams): Promise<{ success: boolean; message_id: string; status: NotificationStatus }> {
    const { user_id, template_key, channel, vars, scheduled_at } = params;
    const template = this.templates.get(template_key);
    if (!template) throw new Error(`Template ${template_key} not found`);
    let dueAt: Date | null = null;
    if (scheduled_at) {
      dueAt = new Date(scheduled_at);
      if (Number.isNaN(dueAt.getTime())) throw new Error(`invalid scheduled_at: ${scheduled_at}`);
    }
    const isFuture = dueAt !== null && dueAt.getTime() > this.now().getTime();
    const prefs = await this.getUserPreferences(user_id);
    const enabled = (ch: NotificationChannel) => prefs.channels_enabled[ch] !== false;
    const inQuietHours = !prefs.do_not_disturb && !(await this.shouldSendNow(prefs));
    const quietEnd = !isFuture && inQuietHours ? this.quietHoursEndAt(prefs) : null;
    let chosenChannel: NotificationChannel | null;
    if (channel) {
      chosenChannel = channel;
    } else {
      const order: NotificationChannel[] = [...template.channels_default, 'email', 'sms', 'in_app'];
      chosenChannel = order.find(enabled) ?? null;
    }
    const message_id = await this.logMessage({
      user_id,
      template_key,
      channel: (chosenChannel ?? channel ?? template.channels_default[0]) as NotificationChannel,
      vars_used: vars,
      sent_at: null,
      opened_at: null,
      clicked_at: null,
      bounced: false,
      error: null,
      status: 'queued',
      // Stored in toISOString() form so deliverDue can compare it with the clock as text.
      scheduled_at: isFuture ? dueAt!.toISOString() : quietEnd ? quietEnd.toISOString() : null,
    });
    if (chosenChannel === null || !enabled(chosenChannel)) {
      await this.updateLogStatus(message_id, { status: 'skipped', error: chosenChannel === null ? 'no_enabled_channel' : 'channel_disabled' });
      return { success: true, message_id, status: 'skipped' };
    }
    if (prefs.do_not_disturb) {
      await this.updateLogStatus(message_id, { status: 'skipped', error: 'do_not_disturb' });
      return { success: true, message_id, status: 'skipped' };
    }
    if (inQuietHours && !isFuture && quietEnd === null) {
      // A window without a usable end time cannot be scheduled: keep the old behaviour of skipping.
      await this.updateLogStatus(message_id, { status: 'skipped', error: 'quiet_hours' });
      return { success: true, message_id, status: 'skipped' };
    }
    const sendOn: NotificationChannel = chosenChannel;
    if (isFuture || quietEnd !== null) {
      // Persisted: deliverDue() sends it once due, across restarts and for any delay.
      return { success: true, message_id, status: 'queued' };
    }
    await this.attemptSend(sendOn, user_id, template, vars, message_id);
    const log = await this.db.get<NotificationLog>(`SELECT status FROM notification_logs WHERE id = ?`, message_id);
    return { success: true, message_id, status: log!.status };
  }

  /**
   * Sends every queued message that is due, in the spec's four steps (NOTIF-12):
   * 1. 'sending' rows claimed more than 300 s ago go back to 'queued' (their worker crashed);
   * 2. 'queued' rows with scheduled_at <= now, by scheduled_at then insertion order, at most `limit`, are claimed one
   *    by one with UPDATE ... SET status = 'sending', claimed_at = now WHERE id = ? AND status = 'queued' (a row
   *    another worker claimed first is skipped);
   * 3. the user's preferences are read NOW: channel switched off (unsubscribed) or do-not-disturb -> 'skipped';
   * 4. the outcome ('sent' / 'failed' / 'skipped') is written only WHERE id = ? AND status = 'sending' AND
   *    claimed_at = this claim, so a worker whose claim was taken over cannot overwrite the newer outcome.
   * Each message is sent exactly once when no worker crashes, at least once after a crash; one send must finish in
   * under 300 s. The host calls this periodically; nothing in this class runs it by itself (no timers).
   * In: now (default the service clock) and limit (default 100). Out: { delivered, failed, skipped, message_ids }
   * for the rows this call claimed. Why: NOTIF-12 amendment 2026-11-10 (claimed_at, the stale-claim reset, the
   * preference re-check and the conditional final write were missing). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: notification_logs, preferences, SMTP / Twilio.
   */
  async deliverDue(now: Date = this.now(), limit: number = 100): Promise<{ delivered: number; failed: number; skipped: number; message_ids: string[] }> {
    const nowIso = now.toISOString();
    // 1. Re-queue rows whose claim is stale.
    await this.db.run(
      `UPDATE notification_logs SET status = 'queued', claimed_at = NULL
       WHERE status = 'sending' AND claimed_at IS NOT NULL AND claimed_at < ?`,
      new Date(now.getTime() - STALE_CLAIM_MS).toISOString()
    );
    // 2. Due rows, by scheduled_at then insertion order (rowid).
    const due = await this.db.all<NotificationLog[]>(
      `SELECT * FROM notification_logs
       WHERE status = 'queued' AND scheduled_at IS NOT NULL AND scheduled_at <= ?
       ORDER BY scheduled_at, rowid LIMIT ?`,
      nowIso,
      limit
    );
    let delivered = 0;
    let failed = 0;
    let skipped = 0;
    const message_ids: string[] = [];
    const finish = async (id: string, fields: Partial<NotificationLog>): Promise<boolean> => {
      const sets: string[] = ['status = ?'];
      const values: any[] = [fields.status];
      if (fields.sent_at !== undefined) { sets.push('sent_at = ?'); values.push(fields.sent_at); }
      if (fields.error !== undefined) { sets.push('error = ?'); values.push(fields.error); }
      const res = await this.db.run(
        `UPDATE notification_logs SET ${sets.join(', ')} WHERE id = ? AND status = 'sending' AND claimed_at = ?`,
        ...values, id, nowIso
      );
      return !!res.changes;
    };
    for (const row of due) {
      const claim = await this.db.run(
        `UPDATE notification_logs SET status = 'sending', claimed_at = ? WHERE id = ? AND status = 'queued'`,
        nowIso,
        row.id
      );
      if (!claim.changes) continue; // another worker claimed it first
      message_ids.push(row.id);
      const template = this.templates.get(row.template_key);
      if (!template) {
        if (await finish(row.id, { status: 'failed', error: `template_not_found: ${row.template_key}` })) failed++;
        continue;
      }
      // 3. Preferences as they are now, not as they were when the message was queued.
      const prefs = await this.getUserPreferences(row.user_id);
      if (prefs.channels_enabled[row.channel] === false || prefs.do_not_disturb) {
        const reason = prefs.do_not_disturb ? 'do_not_disturb' : 'channel_disabled';
        if (await finish(row.id, { status: 'skipped', error: reason })) skipped++;
        continue;
      }
      let vars: any = {};
      try {
        vars = JSON.parse(row.vars_used || '{}');
      } catch {
        vars = {};
      }
      const outcome = await this.trySend(row.channel, row.user_id, template, vars, row.id);
      // 4. Final write only while this claim still holds.
      if (outcome.ok) {
        if (await finish(row.id, { status: 'sent', sent_at: this.now().toISOString() })) delivered++;
      } else if (await finish(row.id, { status: 'failed', error: outcome.error })) {
        failed++;
      }
    }
    return { delivered, failed, skipped, message_ids };
  }

  /**
   * The signed unsubscribe token: lowercase hex HMAC-SHA256(secret, "unsubscribe:" + user_id + ":" + channel).
   * In: user id and channel. Out: 64 hex characters. Why: NOTIF-11 amendment. 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  unsubscribeToken(user_id: number | string, channel: string): string {
    return createHmac('sha256', this.unsubscribeSecret).update(`unsubscribe:${user_id}:${channel}`).digest('hex');
  }

  /**
   * The unsubscribe link: <base_url>/unsubscribe?user_id=<id>&channel=<channel>&token=<token>.
   * In: user id and channel. Out: the URL. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  unsubscribeUrl(user_id: number, channel: NotificationChannel): string {
    const q = new URLSearchParams({ user_id: String(user_id), channel, token: this.unsubscribeToken(user_id, channel) });
    return `${this.baseUrl}/unsubscribe?${q.toString()}`;
  }

  /**
   * The unsubscribe route. GET only confirms (a mail scanner following links changes nothing); POST sets
   * channels_enabled[channel] = false. Before any user lookup, a token that is not exactly 64 characters of [0-9a-f],
   * an unknown channel, a malformed user id or a token that does not match (compared in constant time on two
   * 32-byte digests, so unequal lengths never throw) all get the same 403 { error: 'invalid_unsubscribe_token' }.
   * In: the HTTP method and the link's query { user_id, channel, token }. Out: { http_status, body }.
   * Why: NOTIF-11 amendment 2026-11-10 (the link was unsigned, so anyone could unsubscribe anyone).
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: user_notification_preferences (POST only).
   */
  async handleUnsubscribe(
    method: string,
    query: { user_id?: string | number | null; channel?: string | null; token?: string | null }
  ): Promise<UnsubscribeResponse> {
    const refused: UnsubscribeResponse = { http_status: 403, body: { error: 'invalid_unsubscribe_token' } };
    const token = typeof query.token === 'string' ? query.token : '';
    const channel = typeof query.channel === 'string' ? query.channel : '';
    const userIdText = query.user_id === undefined || query.user_id === null ? '' : String(query.user_id);
    if (!/^[0-9a-f]{64}$/.test(token) || !(CHANNELS as readonly string[]).includes(channel) || !/^[1-9][0-9]{0,15}$/.test(userIdText)) {
      return refused;
    }
    const expected = Buffer.from(this.unsubscribeToken(userIdText, channel), 'hex');
    const given = Buffer.from(token, 'hex');
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
      return refused;
    }
    const user_id = Number(userIdText);
    const m = method.toUpperCase();
    if (m === 'GET') {
      return { http_status: 200, body: { confirm: true, user_id, channel, action: 'POST to this link to unsubscribe' } };
    }
    if (m !== 'POST') {
      return { http_status: 405, body: { error: 'method_not_allowed' } };
    }
    await this.updateUserPreferences(user_id, { channels_enabled: { [channel]: false } as UserPreferences['channels_enabled'] });
    return { http_status: 200, body: { success: true, user_id, channel, unsubscribed: true } };
  }

  async sendBatch(paramsArray: SendBatchParams[]): Promise<{ success: boolean; sent: number; failed: number; message_ids: string[] }> {
    const results: string[] = [];
    let sent = 0;
    let failed = 0;
    for (const params of paramsArray) {
      try {
        const res = await this.sendSingle(params);
        results.push(res.message_id);
        if (res.status === 'sent' || res.status === 'queued') sent++;
        else failed++;
      } catch (e) {
        failed++;
      }
    }
    return { success: true, sent, failed, message_ids: results };
  }

  /**
   * Records an opened / clicked / bounced event for a message and returns its log row (any other status only reads).
   * In: { message_id, status }. Out: the log row or undefined. Touches: notification_logs.
   * Documented 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP (timestamps now from the service clock).
   */
  async track(params: TrackParams): Promise<NotificationLog | null> {
    const { message_id, status } = params;
    const now = this.now().toISOString();
    if (status === 'opened') {
      await this.updateLogStatus(message_id, { status: 'opened', opened_at: now });
    } else if (status === 'clicked') {
      await this.updateLogStatus(message_id, { status: 'clicked', clicked_at: now });
    } else if (status === 'bounced') {
      await this.updateLogStatus(message_id, { status: 'bounced', bounced: true });
    }
    return await this.db.get<NotificationLog>(`SELECT * FROM notification_logs WHERE id = ?`, message_id);
  }

  async getPreferences(user_id: number): Promise<UserPreferences> {
    return await this.getUserPreferences(user_id);
  }
}