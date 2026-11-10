import { NotificationService } from './notifications_typescript';
import nodemailer from 'nodemailer';
import { Twilio } from 'twilio';
import { jest } from '@jest/globals';

/** A test-only unsubscribe secret of 32+ bytes (the service refuses a shorter one). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
const SECRET = 'test-unsubscribe-secret-0123456789abcdef';

describe('NotificationService', () => {
  let service: NotificationService;
  let mockEmailTransport: nodemailer.Transporter;
  let mockSmsClient: Twilio;

  beforeAll(async () => {
    // Mock email transport
    mockEmailTransport = {
      sendMail: jest.fn(),
    } as any;
    // Mock SMS client
    mockSmsClient = {
      messages: {
        create: jest.fn(),
      },
    } as any;
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the service now requires an unsubscribe secret (NOTIF-11).
    service = new NotificationService(':memory:', mockEmailTransport, mockSmsClient, { unsubscribeSecret: SECRET });
    await service.init();
  });

  // NOTIF-01
  test('Send email with template variables', async () => {
    (mockEmailTransport.sendMail as jest.Mock).mockResolvedValueOnce({});
    const res = await service.sendSingle({
      user_id: 1,
      template_key: 'welcome_email',
      channel: 'email',
      vars: { app_name: 'TestApp' },
      scheduled_at: null,
    });
    expect(res.status).toBe('sent');
    expect(mockEmailTransport.sendMail).toHaveBeenCalled();
    const log = await service.track({ message_id: res.message_id, status: 'sent' });
    expect(log?.status).toBe('sent');
  });

  // NOTIF-02
  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: SMS is now off by default (spec amendment, opt-in), so the user
  // turns it on first, as the spec's NOTIF-02 note says.
  test('Send SMS', async () => {
    (mockSmsClient.messages.create as jest.Mock).mockResolvedValueOnce({});
    await service.updateUserPreferences(2, { channels_enabled: { sms: true } });
    const res = await service.sendSingle({
      user_id: 2,
      template_key: 'trial_starting',
      channel: 'sms',
      vars: { trial_days: 14 },
      scheduled_at: null,
    });
    expect(res.status).toBe('sent');
    expect(mockSmsClient.messages.create).toHaveBeenCalled();
  });

  // NOTIF-03
  test('Send in-app (stores in DB)', async () => {
    const res = await service.sendSingle({
      user_id: 3,
      template_key: 'admin_alert',
      channel: 'in_app',
      vars: { actor: 'Admin', action: 'deleted', resource: 'user' },
      scheduled_at: null,
    });
    expect(res.status).toBe('sent');
    const log = await service.track({ message_id: res.message_id, status: 'sent' });
    expect(log?.channel).toBe('in_app');
  });

  // NOTIF-04
  test('Batch send 1000+ notifications', async () => {
    const batch = [];
    for (let i = 0; i < 1000; i++) {
      batch.push({
        user_id: i + 10,
        template_key: 'welcome_email',
        channel: 'email',
        vars: { app_name: 'BatchApp' },
        scheduled_at: null,
      });
    }
    (mockEmailTransport.sendMail as jest.Mock).mockResolvedValue({});
    const res = await service.sendBatch(batch);
    expect(res.sent).toBe(1000);
    expect(res.failed).toBe(0);
  });

  // NOTIF-05
  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: rewritten for the NOTIF-05 amendment. Inside the quiet window a
  // message is no longer skipped: it is stored 'queued' with scheduled_at = the end of the window, and deliverDue
  // sends it then. The old test expected 'skipped' and depended on the wall clock; this one pins the clock.
  test('Quiet hours: queued until the window ends, then sent by deliverDue', async () => {
    let clock = new Date('2026-01-01T23:00:00.000Z');
    const sendMail = jest.fn(async (_mail: any) => ({}));
    const quiet = new NotificationService(':memory:', { sendMail } as any, mockSmsClient, { now: () => clock, unsubscribeSecret: SECRET });
    await quiet.init();
    try {
      await quiet.updateUserPreferences(4, { quiet_hours_start: '22:00', quiet_hours_end: '07:00' });
      const res = await quiet.sendSingle({
        user_id: 4, template_key: 'welcome_email', channel: 'email', vars: { app_name: 'QuietApp' }, scheduled_at: null,
      });
      expect(res.status).toBe('queued');
      expect(sendMail).not.toHaveBeenCalled();
      const log = await quiet.track({ message_id: res.message_id, status: 'queued' });
      expect(log?.scheduled_at).toBe('2026-01-02T07:00:00.000Z');

      clock = new Date('2026-01-02T06:59:00.000Z');
      expect((await quiet.deliverDue()).message_ids).toEqual([]);
      clock = new Date('2026-01-02T07:00:00.000Z');
      expect(await quiet.deliverDue()).toEqual({ delivered: 1, failed: 0, skipped: 0, message_ids: [res.message_id] });
      expect(sendMail).toHaveBeenCalledTimes(1);
    } finally {
      await quiet.close();
    }
  });

  // NOTIF-06
  test('Do-not-disturb: skip if enabled', async () => {
    const prefs = await service.getPreferences(5);
    await service.updateUserPreferences(5, { do_not_disturb: true });
    const res = await service.sendSingle({
      user_id: 5,
      template_key: 'welcome_email',
      channel: 'email',
      vars: { app_name: 'DNDApp' },
      scheduled_at: null,
    });
    expect(res.status).toBe('skipped');
    const log = await service.track({ message_id: res.message_id, status: 'skipped' });
    expect(log?.status).toBe('skipped');
    await service.updateUserPreferences(5, prefs);
  });

  // NOTIF-07
  test('Track: message marked as opened when user clicks link', async () => {
    const res = await service.sendSingle({
      user_id: 6,
      template_key: 'welcome_email',
      channel: 'email',
      vars: { app_name: 'TrackApp' },
      scheduled_at: null,
    });
    await service.track({ message_id: res.message_id, status: 'opened' });
    const log = await service.track({ message_id: res.message_id, status: 'opened' });
    expect(log?.status).toBe('opened');
    expect(log?.opened_at).toBeDefined();
  });

  // NOTIF-08
  test('Retry: failed email retries and eventually succeeds', async () => {
    const sendMailMock = mockEmailTransport.sendMail as jest.Mock;
    // The transport mock is shared by the whole file, so its call count already includes the earlier tests' 1,000+
    // sends; count only this test's attempts (2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP).
    sendMailMock.mockClear();
    sendMailMock.mockRejectedValueOnce(new Error('SMTP error'));
    sendMailMock.mockRejectedValueOnce(new Error('SMTP error'));
    sendMailMock.mockResolvedValueOnce({});
    const res = await service.sendSingle({
      user_id: 7,
      template_key: 'welcome_email',
      channel: 'email',
      vars: { app_name: 'RetryApp' },
      scheduled_at: null,
    });
    expect(res.status).toBe('sent');
    expect(sendMailMock).toHaveBeenCalledTimes(3);
  });

  // NOTIF-09
  test('Unsubscribe: user unsubscribed, future emails skipped', async () => {
    // Unsubscribe by disabling email channel
    await service.updateUserPreferences(8, { channels_enabled: { email: false } });
    const res = await service.sendSingle({
      user_id: 8,
      template_key: 'welcome_email',
      channel: 'email',
      vars: { app_name: 'UnsubApp' },
      scheduled_at: null,
    });
    expect(res.status).toBe('skipped');
    const log = await service.track({ message_id: res.message_id, status: 'skipped' });
    expect(log?.status).toBe('skipped');
    // Restore
    await service.updateUserPreferences(8, { channels_enabled: { email: true } });
  });

  // NOTIF-10
  test('User preferences honored: channels_enabled respected', async () => {
    await service.updateUserPreferences(9, { channels_enabled: { email: false, sms: true } });
    const res = await service.sendSingle({
      user_id: 9,
      template_key: 'welcome_email',
      channel: null,
      vars: { app_name: 'PrefApp' },
      scheduled_at: null,
    });
    expect(res.status).toBe('sent');
    const log = await service.track({ message_id: res.message_id, status: 'sent' });
    expect(log?.channel).toBe('sms');
    await service.updateUserPreferences(9, { channels_enabled: { email: true, sms: false } });
  });

  /**
   * A message scheduled 30 days ahead (past setTimeout's 2,147,483,647 ms limit) is not sent now; deliverDue() does
   * not send it before its time, and sends it once the clock has passed scheduled_at.
   * In: a service on its own database with a movable clock. Out: assertions only.
   * Why 2026-11-10 (session session_012zDydZCZ4AChqhEZ4oVtaP): CodeRabbit review on PR 19 (long delays fired after
   * 1 ms and timers were lost on restart). Touches: an in-memory SQLite database only.
   */
  // NOTIF-12
  test('Scheduled: 30 days ahead is not sent now, and deliverDue sends it once due', async () => {
    let clock = new Date('2026-01-01T12:00:00.000Z');
    const sendMail = jest.fn(async (_mail: any) => ({}));
    const scheduled = new NotificationService(':memory:', { sendMail } as any, mockSmsClient, { now: () => clock, unsubscribeSecret: SECRET });
    await scheduled.init();
    try {
      const dueAt = new Date(clock.getTime() + 30 * 24 * 60 * 60 * 1000);
      const res = await scheduled.sendSingle({
        user_id: 42,
        template_key: 'welcome_email',
        channel: 'email',
        vars: { app_name: 'LaterApp' },
        scheduled_at: dueAt.toISOString(),
      });
      expect(res.status).toBe('queued');
      // Let any timer that would fire "after 1 ms" run: nothing may be sent.
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(sendMail).not.toHaveBeenCalled();
      const queued = await scheduled.track({ message_id: res.message_id, status: 'queued' });
      expect(queued?.status).toBe('queued');
      expect(queued?.scheduled_at).toBe(dueAt.toISOString());

      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: deliverDue's result also counts 'skipped' rows now (NOTIF-12
      // re-checks preferences at delivery), so each expected result carries skipped: 0.
      clock = new Date(dueAt.getTime() - 60 * 1000);
      expect(await scheduled.deliverDue()).toEqual({ delivered: 0, failed: 0, skipped: 0, message_ids: [] });
      expect(sendMail).not.toHaveBeenCalled();

      clock = new Date(dueAt.getTime() + 60 * 1000);
      expect(await scheduled.deliverDue()).toEqual({ delivered: 1, failed: 0, skipped: 0, message_ids: [res.message_id] });
      expect(sendMail).toHaveBeenCalledTimes(1);
      const sent = await scheduled.track({ message_id: res.message_id, status: 'sent' });
      expect(sent?.status).toBe('sent');
      expect(sent?.sent_at).toBe(clock.toISOString());

      // Delivered once: a second pass finds nothing due.
      expect(await scheduled.deliverDue()).toEqual({ delivered: 0, failed: 0, skipped: 0, message_ids: [] });
      expect(sendMail).toHaveBeenCalledTimes(1);
    } finally {
      await scheduled.close();
    }
  });

  /**
   * NOTIF-02 / NOTIF-10: a user who set nothing gets the spec defaults: no quiet hours, do_not_disturb false,
   * channels {email: true, sms: false, in_app: true}; an SMS to them is skipped until they turn SMS on.
   * In: the shared service. Out: assertions only. Why: NOTIF-02 amendment (SMS was on by default).
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
   */
  // NOTIF-02
  test('Default preferences: SMS is off until the user turns it on', async () => {
    const prefs = await service.getPreferences(5001);
    expect(prefs).toEqual({
      user_id: 5001, do_not_disturb: false, quiet_hours_start: null, quiet_hours_end: null,
      channels_enabled: { email: true, sms: false, in_app: true },
    });
    (mockSmsClient.messages.create as jest.Mock).mockClear();
    const res = await service.sendSingle({ user_id: 5001, template_key: 'trial_starting', channel: 'sms', vars: { trial_days: 14 }, scheduled_at: null });
    expect(res.status).toBe('skipped');
    expect(mockSmsClient.messages.create).not.toHaveBeenCalled();
  });

  /**
   * NOTIF-11: the signed unsubscribe link. POST with a valid token turns the channel off; GET with it changes
   * nothing; missing, short, non-hex, upper-case, altered, other-user and unknown-channel tokens all get the same
   * 403 invalid_unsubscribe_token and the user stays subscribed; the e-mail carries the signed link; a secret under
   * 32 bytes refuses to start. In: the shared service. Out: assertions only. Why: NOTIF-11 amendment (the link was
   * unsigned). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
   */
  // NOTIF-11
  test('Unsubscribe link: signed, POST-only, and every bad token is the same 403', async () => {
    const user = 6001;
    const token = service.unsubscribeToken(user, 'email');
    expect(token).toMatch(/^[0-9a-f]{64}$/);
    const refused = { http_status: 403, body: { error: 'invalid_unsubscribe_token' } };
    const altered = (token[0] === 'a' ? 'b' : 'a') + token.slice(1);
    const bad: Array<Record<string, any>> = [
      { user_id: user, channel: 'email' },
      { user_id: user, channel: 'email', token: token.slice(0, 63) },
      { user_id: user, channel: 'email', token: 'z'.repeat(64) },
      { user_id: user, channel: 'email', token: token.toUpperCase() },
      { user_id: user, channel: 'email', token: altered },
      { user_id: user + 1, channel: 'email', token },
      { user_id: user, channel: 'sms', token },
      { user_id: user, channel: 'fax', token: service.unsubscribeToken(user, 'fax') },
    ];
    for (const q of bad) {
      expect(await service.handleUnsubscribe('POST', q)).toEqual(refused);
    }
    expect((await service.getPreferences(user)).channels_enabled.email).toBe(true);

    const get = await service.handleUnsubscribe('GET', { user_id: String(user), channel: 'email', token });
    expect(get.http_status).toBe(200);
    expect((await service.getPreferences(user)).channels_enabled.email).toBe(true);

    const post = await service.handleUnsubscribe('POST', { user_id: String(user), channel: 'email', token });
    expect(post).toEqual({ http_status: 200, body: { success: true, user_id: user, channel: 'email', unsubscribed: true } });
    expect((await service.getPreferences(user)).channels_enabled.email).toBe(false);

    const sendMail = mockEmailTransport.sendMail as jest.Mock;
    sendMail.mockClear();
    sendMail.mockResolvedValueOnce({});
    await service.sendSingle({ user_id: 6002, template_key: 'welcome_email', channel: 'email', vars: { app_name: 'X' }, scheduled_at: null });
    const html = (sendMail.mock.calls[0][0] as any).html as string;
    expect(html).toContain(`token=${service.unsubscribeToken(6002, 'email')}`);

    expect(() => new NotificationService(':memory:', mockEmailTransport, mockSmsClient, { unsubscribeSecret: 'short' }))
      .toThrow(/unsubscribe_secret_too_short/);
  });

  /**
   * NOTIF-12: deliverDue's safety steps: a user who unsubscribed after the message was queued is skipped at
   * delivery, and a row stuck at 'sending' (a crashed worker) for over 300 s is re-queued and sent exactly once,
   * while one claimed under 300 s ago is left alone. In: a service on a hand-moved clock. Out: assertions only.
   * Why: NOTIF-12 amendment 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory SQLite.
   */
  // NOTIF-12
  test('deliverDue skips a user who unsubscribed meanwhile and re-queues a stale sending row', async () => {
    let clock = new Date('2026-03-01T00:00:00.000Z');
    const sendMail = jest.fn(async (_mail: any) => ({}));
    const svc = new NotificationService(':memory:', { sendMail } as any, mockSmsClient, { now: () => clock, unsubscribeSecret: SECRET });
    await svc.init();
    try {
      const later = new Date(clock.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
      const gone = await svc.sendSingle({ user_id: 71, template_key: 'welcome_email', channel: 'email', vars: {}, scheduled_at: later });
      const stuck = await svc.sendSingle({ user_id: 72, template_key: 'welcome_email', channel: 'email', vars: {}, scheduled_at: later });
      expect([gone.status, stuck.status]).toEqual(['queued', 'queued']);
      await svc.handleUnsubscribe('POST', { user_id: '71', channel: 'email', token: svc.unsubscribeToken(71, 'email') });

      // Simulate a worker that claimed user 72's row and crashed.
      clock = new Date(later);
      const db = (svc as any).db;
      await db.run(`UPDATE notification_logs SET status = 'sending', claimed_at = ? WHERE id = ?`, clock.toISOString(), stuck.message_id);

      const first = await svc.deliverDue();
      expect(first).toEqual({ delivered: 0, failed: 0, skipped: 1, message_ids: [gone.message_id] });
      expect((await svc.track({ message_id: gone.message_id, status: 'queued' }))?.status).toBe('skipped');
      expect(sendMail).not.toHaveBeenCalled();

      clock = new Date(clock.getTime() + 299 * 1000);
      expect((await svc.deliverDue()).message_ids).toEqual([]);   // claim not stale yet
      clock = new Date(clock.getTime() + 2 * 1000);
      expect(await svc.deliverDue()).toEqual({ delivered: 1, failed: 0, skipped: 0, message_ids: [stuck.message_id] });
      expect(await svc.deliverDue()).toEqual({ delivered: 0, failed: 0, skipped: 0, message_ids: [] });
      expect(sendMail).toHaveBeenCalledTimes(1);
      const row = await db.get(`SELECT status, claimed_at FROM notification_logs WHERE id = ?`, stuck.message_id);
      expect(row).toEqual({ status: 'sent', claimed_at: clock.toISOString() });
    } finally {
      await svc.close();
    }
  });
});
