import { Database } from 'sqlite3';
import { open, Database as SQLiteDatabase } from 'sqlite';
import nodemailer, { Transporter } from 'nodemailer';
import { v4 as uuidv4 } from 'uuid';
import { Twilio } from 'twilio';

type NotificationChannel = 'email' | 'sms' | 'in_app';
type NotificationStatus = 'sent' | 'queued' | 'failed' | 'skipped' | 'bounced' | 'opened' | 'clicked';

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

  /**
   * In: the SQLite path (default in-memory), the email transport and SMS client (default: built on first use from
   * SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASS and TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN), and options.
   * Out: a service; call init() before use. Touches: nothing until init().
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
        status TEXT
      );
      CREATE TABLE IF NOT EXISTS user_notification_preferences (
        user_id INTEGER PRIMARY KEY,
        do_not_disturb INTEGER,
        quiet_hours_start TEXT,
        quiet_hours_end TEXT,
        channels_enabled TEXT
      );
    `;
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
        channels_enabled: { email: true, sms: true, in_app: true },
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

  private async logMessage(log: Omit<NotificationLog, 'id'>): Promise<string> {
    const id = uuidv4();
    await this.db.run(
      `INSERT INTO notification_logs
      (id, user_id, template_key, channel, vars_used, sent_at, opened_at, clicked_at, bounced, error, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
      log.status
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
   * Renders a template and sends it by email with an unsubscribe link. In: user, template, variables, log id.
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
      html: rendered.body_html + `<p><a href="https://example.com/unsubscribe?user_id=${user_id}&channel=email">Unsubscribe</a></p>`,
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
   * Sends one logged message on its channel, retrying a failed email or SMS with exponential backoff (2 x base, then
   * 4 x base) up to {@link MAX_SEND_ATTEMPTS} attempts, and records 'sent' (with sent_at) or 'failed' (with the
   * error). In: the channel, user, template, variables and log id. Out: nothing.
   * Why: rewritten as a loop 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP); the wait comes from the options
   * (it was 2 s then 4 s, more than a request can wait). Touches: SMTP / Twilio (network), notification_logs.
   */
  private async attemptSend(channel: NotificationChannel, user_id: number, template: NotificationTemplate, vars: any, message_id: string): Promise<void> {
    for (let attempt = 1; attempt <= MAX_SEND_ATTEMPTS; attempt++) {
      try {
        if (channel === 'email') {
          await this.sendEmail(user_id, template, vars, message_id);
        } else if (channel === 'sms') {
          await this.sendSMS(user_id, template, vars, message_id);
        } else if (channel === 'in_app') {
          await this.sendInApp(user_id, template, vars, message_id);
        }
        await this.updateLogStatus(message_id, { status: 'sent', sent_at: this.now().toISOString() });
        return;
      } catch (err: any) {
        if (attempt === MAX_SEND_ATTEMPTS) {
          await this.updateLogStatus(message_id, { status: 'failed', error: String(err?.message ?? err) });
          return;
        }
        await this.sleep(Math.pow(2, attempt) * this.retryBaseDelayMs);
      }
    }
  }

  /**
   * Sends one notification. The channel is the one asked for, or when null the template's default channels and
   * then email, SMS, in-app, the first the user has enabled. A channel the user switched off (unsubscribed), no
   * enabled channel, do-not-disturb and the quiet window each log the message as 'skipped'.
   * In: { user_id, template_key, channel, vars, scheduled_at }. Out: { success, message_id, status }.
   * Why changed 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): an explicit channel was used even when the user
   * had disabled it, so unsubscribed users were still emailed. Touches: notification_logs, preferences, providers.
   */
  async sendSingle(params: SendParams): Promise<{ success: boolean; message_id: string; status: NotificationStatus }> {
    const { user_id, template_key, channel, vars, scheduled_at } = params;
    const template = this.templates.get(template_key);
    if (!template) throw new Error(`Template ${template_key} not found`);
    const prefs = await this.getUserPreferences(user_id);
    const enabled = (ch: NotificationChannel) => prefs.channels_enabled[ch] !== false;
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
    });
    if (chosenChannel === null || !enabled(chosenChannel)) {
      await this.updateLogStatus(message_id, { status: 'skipped', error: chosenChannel === null ? 'no_enabled_channel' : 'channel_disabled' });
      return { success: true, message_id, status: 'skipped' };
    }
    const shouldSend = await this.shouldSendNow(prefs);
    if (!shouldSend) {
      await this.updateLogStatus(message_id, { status: 'skipped', error: prefs.do_not_disturb ? 'do_not_disturb' : 'quiet_hours' });
      return { success: true, message_id, status: 'skipped' };
    }
    const sendOn: NotificationChannel = chosenChannel;
    if (scheduled_at) {
      const delay = new Date(scheduled_at).getTime() - this.now().getTime();
      setTimeout(() => {
        this.attemptSend(sendOn, user_id, template, vars, message_id).catch(() => undefined);
      }, delay > 0 ? delay : 0);
      return { success: true, message_id, status: 'queued' };
    }
    await this.attemptSend(sendOn, user_id, template, vars, message_id);
    const log = await this.db.get<NotificationLog>(`SELECT status FROM notification_logs WHERE id = ?`, message_id);
    return { success: true, message_id, status: log!.status };
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