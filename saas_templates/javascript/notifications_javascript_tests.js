'use strict';

const assert = require('assert');
const crypto = require('crypto');
const { NotificationService, createRouter, inQuietHours, nextQuietHoursEnd, unsubscribeToken } = require('./notifications_javascript.js');

// A fresh 32-byte secret per run (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): the service now refuses a missing or
// short unsubscribe secret, and no secret is hard-coded.
const SECRET = crypto.randomBytes(32).toString('hex');

let passed = 0;
let failed = 0;
const failures = [];

async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  ✓ ${name}`);
  } catch (err) {
    failed += 1;
    failures.push({ name, err });
    console.log(`  ✗ ${name}`);
    console.log(`      ${err.message}`);
  }
}

function makeService(overrides) {
  return new NotificationService({
    baseUrl: 'http://localhost:3000',
    maxRetries: 3,
    retryBaseDelayMs: 1,
    unsubscribeSecret: SECRET,
    ...(overrides || {}),
  });
}

async function run() {
  console.log('Notifications Test Suite\n');

  // NOTIF-01
  await test('Send email with template variables', async () => {
    let mail = null;
    const svc = makeService({ emailSender: async (m) => { mail = m; } });
    const res = await svc.send({
      user_id: 123,
      template_key: 'trial_ending_soon',
      channel: 'email',
      vars: { days_left: 3 },
    });
    assert.strictEqual(res.success, true);
    assert.strictEqual(res.status, 'sent');
    assert.ok(res.message_id);
    const log = svc.logs.get(res.message_id);
    assert.strictEqual(log.channel, 'email');
    assert.strictEqual(log.status, 'sent');
    assert.ok(log.sent_at);
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: prove the variables were substituted (the row's title).
    assert.strictEqual(mail.text, 'Your trial ends in 3 days. Add payment method to continue.');
    assert.strictEqual(mail.subject, 'Your trial ends in 3 days');
  });

  // NOTIF-02
  // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: SMS is opt-in by default (spec amended), so the user turns it on first.
  await test('Send SMS', async () => {
    let smsPayload = null;
    const svc = makeService({
      smsSender: async (p) => { smsPayload = p; },
    });
    assert.strictEqual(svc.getPreferences(456).channels_enabled.sms, false);
    svc.updatePreferences(456, { channels_enabled: { sms: true } });
    const res = await svc.send({
      user_id: 456,
      template_key: 'trial_starting',
      channel: 'sms',
      vars: { trial_days: 14 },
    });
    assert.strictEqual(res.success, true);
    assert.strictEqual(res.status, 'sent');
    assert.ok(smsPayload);
    assert.strictEqual(smsPayload.to, 456);
    assert.ok(smsPayload.body.includes('14'));
  });

  // NOTIF-03
  await test('Send in-app (stores in DB)', async () => {
    const svc = makeService();
    const res = await svc.send({
      user_id: 789,
      template_key: 'admin_alert',
      channel: 'in_app',
      vars: { actor: 'admin', action: 'deleted', resource: 'user 5' },
    });
    assert.strictEqual(res.success, true);
    assert.strictEqual(res.status, 'sent');
    const inApp = svc.getInAppNotifications(789);
    assert.strictEqual(inApp.length, 1);
    assert.strictEqual(inApp[0].template_key, 'admin_alert');
  });

  // NOTIF-04
  await test('Batch send 1000+ notifications', async () => {
    const svc = makeService();
    const items = [];
    for (let i = 0; i < 1000; i += 1) {
      items.push({
        user_id: i,
        template_key: 'welcome_email',
        channel: 'email',
        vars: { app_name: 'Acme' },
      });
    }
    const res = await svc.sendBatch(items);
    assert.strictEqual(res.success, true);
    assert.strictEqual(res.sent, 1000);
    assert.strictEqual(res.failed, 0);
    assert.strictEqual(res.message_ids.length, 1000);
  });

  // NOTIF-05
  await test('Quiet hours: a send inside the window is queued with scheduled_at = quiet_hours_end', async () => {
    // Fixed clock at 12:00 (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): with the real clock this test
    // failed during the one minute a day, 23:59, that lies outside 00:00-23:59.
    // Phase B.2, same day: quiet hours are UTC now, so the clock and the expected time are UTC (they were local).
    const svc = makeService({ nowFn: () => new Date(Date.UTC(2024, 0, 1, 12, 0)) });
    svc.updatePreferences(11, {
      quiet_hours_start: '00:00',
      quiet_hours_end: '23:59',
    });
    const res = await svc.send({
      user_id: 11,
      template_key: 'welcome_email',
      channel: 'email',
      vars: { app_name: 'Acme' },
    });
    assert.strictEqual(res.success, true);
    assert.strictEqual(res.status, 'queued');
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: queued messages are log rows now (no in-memory queue); the spec
    // stores them with scheduled_at = quiet_hours_end.
    const log = svc.logs.get(res.message_id);
    assert.strictEqual(log.status, 'queued');
    assert.strictEqual(log.scheduled_at, new Date(Date.UTC(2024, 0, 1, 23, 59)).toISOString());
    assert.strictEqual(log.sent_at, null);
  });

  // NOTIF-06
  await test('Do-not-disturb: skip if enabled', async () => {
    const svc = makeService();
    svc.updatePreferences(22, { do_not_disturb: true });
    const res = await svc.send({
      user_id: 22,
      template_key: 'welcome_email',
      channel: 'email',
      vars: { app_name: 'Acme' },
    });
    assert.strictEqual(res.success, true);
    assert.strictEqual(res.status, 'skipped');
    const log = svc.logs.get(res.message_id);
    assert.strictEqual(log.error, 'do_not_disturb');
  });

  // NOTIF-07
  /**
   * NOTIF-07 (wording changed in Phase B.2): GET /notifications/open/:message_id sets opened_at and status 'opened'
   * the first time and answers 204; a second call answers 204 and changes nothing; an unknown id is 204 too. The
   * e-mail's open pixel points at that route. A click then moves the status to 'clicked'.
   * In: a service with a moving clock. Out: assertions. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (it
   * called markOpened directly and never checked the stored status or a second open). Touches: memory.
   */
  await test('Track: GET /notifications/open/:message_id sets opened_at and status opened once (204)', async () => {
    let clock = Date.UTC(2024, 0, 1, 9, 0);
    let mail = null;
    const svc = makeService({ nowFn: () => new Date(clock), emailSender: async (m) => { mail = m; } });
    const router = createRouter(svc);
    const res = await svc.send({
      user_id: 33,
      template_key: 'invoice_ready',
      channel: 'email',
      vars: { month: 'January', download_url: 'http://x' },
    });
    const mid = res.message_id;
    assert.strictEqual(mail.trackOpenUrl, `http://localhost:3000/notifications/open/${mid}`);
    clock += 60 * 1000;
    const first = await router.handle('GET', `/notifications/open/${mid}`, {});
    assert.strictEqual(first.status, 204);
    const log = svc.logs.get(mid);
    assert.strictEqual(log.status, 'opened');
    assert.strictEqual(log.opened_at, new Date(clock).toISOString());
    const openedAt = log.opened_at;
    clock += 60 * 1000;
    const second = await router.handle('GET', `/notifications/open/${mid}`, {});
    assert.strictEqual(second.status, 204);
    assert.strictEqual(log.opened_at, openedAt);
    assert.strictEqual(log.status, 'opened');
    assert.strictEqual((await router.handle('GET', '/notifications/open/msg_unknown', {})).status, 204);
    let tracked = svc.track(mid);
    assert.strictEqual(tracked.status, 'opened');
    assert.ok(tracked.opened_at);
    svc.markClicked(mid);
    tracked = svc.track(mid);
    assert.strictEqual(tracked.status, 'clicked');
    assert.ok(tracked.clicked_at);
  });

  // NOTIF-08
  /**
   * NOTIF-08 (wording changed in Phase B.2): with the default settings a failed e-mail is retried at most 3 times
   * after the first attempt, waiting 1 s, 2 s and 4 s; it is sent when the sender recovers on the 4th attempt, and a
   * 4th failure marks it 'failed' with no 5th attempt. In: services with the default retry settings and a recording
   * sleep. Out: assertions. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (it recovered on the 3rd attempt
   * with a 1 ms base delay and never checked the waits or the limit). Touches: memory.
   */
  await test('Retry: a failed email is retried at most 3 times (1 s / 2 s / 4 s); a 4th failure marks it failed', async () => {
    const withSender = (failures, waits) => {
      let calls = 0;
      const svc = new NotificationService({
        unsubscribeSecret: SECRET,
        sleep: async (ms) => { waits.push(ms); },
        emailSender: async () => {
          calls += 1;
          if (calls <= failures) throw new Error('transient failure');
        },
      });
      return { svc, calls: () => calls };
    };
    const payload = { user_id: 44, template_key: 'welcome_email', channel: 'email', vars: { app_name: 'Acme' } };

    const recoverWaits = [];
    const recover = withSender(3, recoverWaits);
    const res = await recover.svc.send(payload);
    assert.strictEqual(res.success, true);
    assert.strictEqual(res.status, 'sent');
    assert.strictEqual(recover.calls(), 4);
    assert.deepStrictEqual(recoverWaits, [1000, 2000, 4000]);

    const failWaits = [];
    const down = withSender(Infinity, failWaits);
    const failedRes = await down.svc.send(payload);
    assert.strictEqual(failedRes.success, false);
    assert.strictEqual(failedRes.status, 'failed');
    assert.strictEqual(down.calls(), 4);
    assert.deepStrictEqual(failWaits, [1000, 2000, 4000]);
    assert.strictEqual(down.svc.logs.get(failedRes.message_id).status, 'failed');
  });

  // NOTIF-09
  await test('Unsubscribe: user unsubscribed, future emails skipped', async () => {
    const svc = makeService();
    svc.unsubscribe(55, 'email');
    const res = await svc.send({
      user_id: 55,
      template_key: 'welcome_email',
      channel: 'email',
      vars: { app_name: 'Acme' },
    });
    assert.strictEqual(res.success, true);
    assert.strictEqual(res.status, 'skipped');
    const log = svc.logs.get(res.message_id);
    assert.strictEqual(log.error, 'unsubscribed');
  });

  // NOTIF-10
  await test('User preferences honored: channels_enabled respected', async () => {
    const svc = makeService();
    svc.updatePreferences(66, { channels_enabled: { email: false, sms: true, in_app: true } });
    // template default is email, but email disabled -> should fall back to sms
    const res = await svc.send({
      user_id: 66,
      template_key: 'welcome_email',
      vars: { app_name: 'Acme' },
    });
    assert.strictEqual(res.success, true);
    assert.strictEqual(res.status, 'sent');
    const log = svc.logs.get(res.message_id);
    assert.strictEqual(log.channel, 'sms');
  });

  // Added 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): naming a channel must never override the user turning it off
  // (an earlier repair that did so was rejected), and a user without saved preferences gets the SMS they were sent.
  await test('User preferences honored: explicitly requested channel the user turned off is skipped', async () => {
    let smsCalls = 0;
    const svc = makeService({ smsSender: async () => { smsCalls += 1; } });
    svc.updatePreferences(67, { channels_enabled: { sms: false } });
    const res = await svc.send({ user_id: 67, template_key: 'trial_starting', channel: 'sms', vars: { trial_days: 7 } });
    assert.strictEqual(res.status, 'skipped');
    assert.strictEqual(svc.logs.get(res.message_id).error, 'channel_disabled');
    assert.strictEqual(smsCalls, 0);
  });

  /**
   * NOTIF-11: the e-mail carries <base>/unsubscribe?user_id&channel&token with token = lowercase hex
   * HMAC-SHA256(secret, "unsubscribe:" + user_id + ":" + channel). GET only confirms; POST with the valid token sets
   * channels_enabled.email = false. A missing, short, non-hex (upper-case included) or altered token, another user's
   * token, or an unknown channel gets the same 403 invalid_unsubscribe_token, nothing throws, and the user stays
   * subscribed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (rewritten for the amended spec: the old test
   * unsubscribed on GET). Touches memory only.
   */
  // NOTIF-11
  await test('Unsubscribe link: POST with a valid token unsubscribes; GET and bad tokens change nothing', async () => {
    let mail = null;
    const svc = makeService({ emailSender: async (m) => { mail = m; } });
    const router = createRouter(svc);
    await svc.send({ user_id: 77, template_key: 'welcome_email', channel: 'email', vars: { app_name: 'Acme' } });
    const url = new URL(mail.unsubscribeUrl);
    assert.strictEqual(`${url.origin}${url.pathname}`, 'http://localhost:3000/unsubscribe');
    const query = Object.fromEntries(url.searchParams);
    assert.deepStrictEqual(Object.keys(query).sort(), ['channel', 'token', 'user_id']);
    const expected = crypto.createHmac('sha256', SECRET).update('unsubscribe:77:email').digest('hex');
    assert.strictEqual(query.token, expected);
    assert.strictEqual(unsubscribeToken(SECRET, 77, 'email'), expected);

    const bad = [
      { user_id: '77', channel: 'email' },                                   // missing token
      { ...query, token: query.token.slice(0, 63) },                          // short
      { ...query, token: 'x'.repeat(64) },                                    // non-hex
      { ...query, token: query.token.toUpperCase() },                         // not lowercase
      { ...query, token: (query.token[0] === 'a' ? 'b' : 'a') + query.token.slice(1) }, // altered
      { ...query, user_id: '78' },                                            // another user
      { ...query, channel: 'push' },                                          // unknown channel
      { ...query, channel: 'sms' },                                           // token for another channel
    ];
    for (const q of bad) {
      for (const method of ['GET', 'POST']) {
        const out = await router.handle(method, '/unsubscribe', { query: q });
        assert.strictEqual(out.status, 403);
        assert.strictEqual(out.body.error, 'invalid_unsubscribe_token');
      }
    }
    assert.strictEqual(svc.getPreferences(77).channels_enabled.email, true);
    assert.strictEqual(svc.getPreferences(78).channels_enabled.email, true);

    const confirm = await router.handle('GET', '/unsubscribe', { query });
    assert.strictEqual(confirm.status, 200);
    assert.strictEqual(svc.getPreferences(77).channels_enabled.email, true);

    const out = await router.handle('POST', '/unsubscribe', { query });
    assert.strictEqual(out.status, 200);
    assert.strictEqual(svc.getPreferences(77).channels_enabled.email, false);
    const later = await svc.send({ user_id: 77, template_key: 'welcome_email', channel: 'email', vars: { app_name: 'Acme' } });
    assert.strictEqual(later.status, 'skipped');
  });

  /**
   * NOTIF-11: the service refuses to start with a missing or short (< 32 bytes) unsubscribe secret.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  // NOTIF-11
  await test('Unsubscribe secret shorter than 32 bytes: the service refuses to start', async () => {
    const saved = process.env.NOTIFICATIONS_UNSUBSCRIBE_SECRET;
    delete process.env.NOTIFICATIONS_UNSUBSCRIBE_SECRET;
    try {
      for (const secret of [undefined, '', 'x'.repeat(31)]) {
        assert.throws(() => new NotificationService({ unsubscribeSecret: secret }), /32 bytes/);
      }
      assert.ok(new NotificationService({ unsubscribeSecret: 'y'.repeat(32) }));
    } finally {
      if (saved !== undefined) process.env.NOTIFICATIONS_UNSUBSCRIBE_SECRET = saved;
    }
  });

  /**
   * NOTIF-12: a send 30 days ahead is queued and not sent; deliverDue before it is due sends nothing; once due it is
   * sent exactly once (a second deliverDue sends nothing); a user who unsubscribed meanwhile is skipped; a row stuck
   * at 'sending' for over 300 s is re-queued and sent, one stuck for exactly 300 s is left alone.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
   */
  // NOTIF-12
  await test('Scheduled send: queued, sent once when due, skipped after unsubscribe, stale claims re-queued', async () => {
    const start = Date.parse('2026-01-01T12:00:00.000Z');
    let clock = start;
    const sent = [];
    const svc = makeService({ nowFn: () => new Date(clock), emailSender: async (m) => { sent.push(m.to); } });
    const due = new Date(start + 30 * 24 * 60 * 60 * 1000);
    const a = await svc.send({ user_id: 1, template_key: 'welcome_email', channel: 'email', vars: { app_name: 'A' }, scheduled_at: due.toISOString() });
    const b = await svc.send({ user_id: 2, template_key: 'welcome_email', channel: 'email', vars: { app_name: 'B' }, scheduled_at: due.toISOString() });
    assert.strictEqual(a.status, 'queued');
    assert.strictEqual(svc.logs.get(a.message_id).scheduled_at, due.toISOString());
    assert.deepStrictEqual(sent, []);
    assert.deepStrictEqual(await svc.deliverDue(new Date(due.getTime() - 1)), []);
    assert.deepStrictEqual(sent, []);

    svc.unsubscribe(2, 'email');
    const first = await svc.deliverDue(due);
    assert.deepStrictEqual(first.map(r => r.status), ['sent', 'skipped']);
    assert.deepStrictEqual(sent, [1]);
    assert.strictEqual(svc.logs.get(b.message_id).status, 'skipped');
    assert.deepStrictEqual(await svc.deliverDue(new Date(due.getTime() + 1000)), []);
    assert.deepStrictEqual(sent, [1]);

    // A worker crashed after claiming: the row sits at 'sending'.
    const c = await svc.send({ user_id: 3, template_key: 'welcome_email', channel: 'email', vars: { app_name: 'C' }, scheduled_at: due.toISOString() });
    const row = svc.logs.get(c.message_id);
    row.status = 'sending';
    row.claimed_at = due.toISOString();
    assert.deepStrictEqual(await svc.deliverDue(new Date(due.getTime() + 300 * 1000)), []);
    assert.strictEqual(row.status, 'sending');
    const again = await svc.deliverDue(new Date(due.getTime() + 300 * 1000 + 1));
    assert.deepStrictEqual(again.map(r => r.status), ['sent']);
    assert.deepStrictEqual(sent, [1, 3]);
    assert.strictEqual(row.status, 'sent');
  });

  await test('Router: POST /notifications/send returns spec shape', async () => {
    const svc = makeService();
    const router = createRouter(svc);
    const out = await router.handle('POST', '/notifications/send', {
      body: { user_id: 1, template_key: 'welcome_email', channel: 'email', vars: { app_name: 'Acme' } },
    });
    assert.strictEqual(out.status, 200);
    assert.strictEqual(out.body.success, true);
    assert.ok(out.body.message_id);
    assert.ok(['sent', 'queued', 'failed'].includes(out.body.status));
  });

  await test('Router: GET /users/:id/notification-preferences returns spec shape', async () => {
    const svc = makeService();
    const router = createRouter(svc);
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the route acts for the verified caller only, so the request
    // carries user 9; another caller gets 404.
    const out = await router.handle('GET', '/users/9/notification-preferences', { user: { id: 9 } });
    assert.strictEqual(out.status, 200);
    assert.strictEqual((await router.handle('GET', '/users/9/notification-preferences', { user: { id: 10 } })).status, 404);
    assert.strictEqual((await router.handle('GET', '/users/9/notification-preferences', {})).status, 404);
    assert.deepStrictEqual(out.body.channels_enabled, { email: true, sms: false, in_app: true });
    assert.strictEqual(out.body.quiet_hours_start, null);
    assert.strictEqual(out.body.user_id, 9);
    assert.strictEqual(typeof out.body.do_not_disturb, 'boolean');
    assert.ok(out.body.channels_enabled);
  });

  await test('Router: PUT /users/:id/notification-preferences returns success', async () => {
    const svc = makeService();
    const router = createRouter(svc);
    const out = await router.handle('PUT', '/users/9/notification-preferences', {
      user: { id: 9 },
      body: { do_not_disturb: true, channels_enabled: { email: true, sms: false } },
    });
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: another user cannot change user 9's preferences.
    const other = await router.handle('PUT', '/users/9/notification-preferences', { user: { id: 10 }, body: { do_not_disturb: false } });
    assert.strictEqual(other.status, 404);
    assert.strictEqual(out.status, 200);
    assert.strictEqual(out.body.success, true);
    const prefs = svc.getPreferences(9);
    assert.strictEqual(prefs.do_not_disturb, true);
    assert.strictEqual(prefs.channels_enabled.sms, false);
  });

  await test('Router: GET /notifications/track/:id returns spec shape', async () => {
    const svc = makeService();
    const router = createRouter(svc);
    const sendOut = await router.handle('POST', '/notifications/send', {
      body: { user_id: 1, template_key: 'welcome_email', channel: 'email', vars: { app_name: 'Acme' } },
    });
    const mid = sendOut.body.message_id;
    const out = await router.handle('GET', `/notifications/track/${mid}`, {});
    assert.strictEqual(out.status, 200);
    assert.strictEqual(out.body.message_id, mid);
    assert.ok(['sent', 'bounced', 'opened', 'clicked', 'failed', 'skipped', 'queued'].includes(out.body.status));
  });

  // NOTIF-05
  /**
   * inQuietHours compares in UTC and handles a window that crosses midnight, whatever the server's time zone (the
   * bug: it used local time). The process time zone is switched to UTC-5 and UTC+9 for the check and restored.
   * In: UTC instants. Out: assertions. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2: the dates
   * were local, which only matched the rule on a UTC server). Touches: process.env.TZ (restored).
   */
  await test('inQuietHours utility handles wrap-around, in UTC whatever the server time zone', async () => {
    const savedTz = process.env.TZ;
    try {
      for (const tz of ['UTC', 'America/New_York', 'Asia/Tokyo']) {
        process.env.TZ = tz;
        assert.strictEqual(inQuietHours('22:00', '08:00', new Date(Date.UTC(2024, 0, 1, 23, 0))), true, tz);
        assert.strictEqual(inQuietHours('22:00', '08:00', new Date(Date.UTC(2024, 0, 1, 7, 0))), true, tz);
        assert.strictEqual(inQuietHours('22:00', '08:00', new Date(Date.UTC(2024, 0, 1, 12, 0))), false, tz);
        assert.strictEqual(inQuietHours('22:00', '08:00', new Date(Date.UTC(2024, 0, 1, 8, 0))), false, tz);
        assert.strictEqual(nextQuietHoursEnd('08:00', new Date(Date.UTC(2024, 0, 1, 23, 0))).toISOString(),
          '2024-01-02T08:00:00.000Z', tz);
      }
    } finally {
      if (savedTz === undefined) delete process.env.TZ; else process.env.TZ = savedTz;
    }
    assert.throws(() => makeService().updatePreferences(1, { quiet_hours_start: '25:00' }), /HH:MM/);
  });

  // NOTIF-05
  /**
   * deliver_due step 3 (Phase B.2): a due message whose user is now inside quiet hours (a window crossing midnight,
   * UTC) is not sent; it goes back to 'queued' with scheduled_at = quiet_hours_end, and is sent by deliverDue once
   * that time comes. In: a service with a moving UTC clock. Out: assertions. Added 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
   */
  await test('deliverDue re-queues a due message inside quiet hours with scheduled_at = quiet_hours_end', async () => {
    let clock = Date.UTC(2024, 0, 1, 12, 0);
    const sent = [];
    const svc = makeService({ nowFn: () => new Date(clock), emailSender: async (m) => { sent.push(m.to); } });
    const due = new Date(Date.UTC(2024, 0, 1, 23, 0)).toISOString();
    const res = await svc.send({ user_id: 77, template_key: 'welcome_email', channel: 'email', vars: { app_name: 'Acme' }, scheduled_at: due });
    assert.strictEqual(res.status, 'queued');
    svc.updatePreferences(77, { quiet_hours_start: '22:00', quiet_hours_end: '08:00' });

    clock = Date.UTC(2024, 0, 1, 23, 30);
    const out = await svc.deliverDue(new Date(clock));
    assert.deepStrictEqual(out.map((r) => r.status), ['queued']);
    const log = svc.logs.get(res.message_id);
    assert.strictEqual(log.status, 'queued');
    assert.strictEqual(log.scheduled_at, '2024-01-02T08:00:00.000Z');
    assert.strictEqual(log.claimed_at, null);
    assert.deepStrictEqual(sent, []);

    assert.deepStrictEqual(await svc.deliverDue(new Date(Date.UTC(2024, 0, 2, 7, 59))), []);
    const later = await svc.deliverDue(new Date(Date.UTC(2024, 0, 2, 8, 0)));
    assert.deepStrictEqual(later.map((r) => r.status), ['sent']);
    assert.deepStrictEqual(sent, [77]);
  });

  // NOTIF-05
  /**
   * Phase B.3: the quiet-hours window is [start, end). With quiet hours 22:00-08:00 UTC, an e-mail sent at 07:59 is
   * queued for 08:00, and one sent exactly at 08:00 (quiet_hours_end) goes out at once.
   * In: a service with a settable UTC clock. Out: assertions. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches: memory.
   */
  await test('Quiet hours are [start, end): a message due exactly at quiet_hours_end is sent', async () => {
    let clock = Date.UTC(2024, 0, 2, 7, 59);
    const sent = [];
    const svc = makeService({ nowFn: () => new Date(clock), emailSender: async (m) => { sent.push(m.to); } });
    svc.updatePreferences(81, { quiet_hours_start: '22:00', quiet_hours_end: '08:00' });
    const held = await svc.send({ user_id: 81, template_key: 'welcome_email', channel: 'email', vars: { app_name: 'Acme' } });
    assert.strictEqual(held.status, 'queued');
    assert.strictEqual(svc.logs.get(held.message_id).scheduled_at, '2024-01-02T08:00:00.000Z');
    assert.deepStrictEqual(sent, []);
    clock = Date.UTC(2024, 0, 2, 8, 0);
    const atEnd = await svc.send({ user_id: 81, template_key: 'welcome_email', channel: 'email', vars: { app_name: 'Acme' } });
    assert.strictEqual(atEnd.status, 'sent');
    assert.deepStrictEqual(sent, [81]);
    clock = Date.UTC(2024, 0, 2, 22, 0);
    const atStart = await svc.send({ user_id: 81, template_key: 'welcome_email', channel: 'email', vars: { app_name: 'Acme' } });
    assert.strictEqual(atStart.status, 'queued');
    assert.strictEqual(svc.logs.get(atStart.message_id).scheduled_at, '2024-01-03T08:00:00.000Z');
  });

  // NOTIF-05
  /**
   * Phase B.3: quiet hours hold e-mail and SMS only. Inside the window an in-app message is stored at once (status
   * 'sent', listed for the user), while an e-mail and an SMS sent at the same moment are queued until quiet_hours_end;
   * deliverDue also delivers a due in-app message inside quiet hours instead of re-queueing it.
   * In: a service with a fixed UTC clock at 12:00 and quiet hours 00:00-23:59. Out: assertions. Added 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
   */
  await test('Quiet hours hold email and SMS only; an in-app message is stored at once', async () => {
    let clock = Date.UTC(2024, 0, 1, 12, 0);
    const inApp = [];
    const sms = [];
    const svc = makeService({
      nowFn: () => new Date(clock),
      inAppSender: async (m) => { inApp.push(m.userId); },
      smsSender: async (m) => { sms.push(m.to); },
    });
    const due = new Date(Date.UTC(2024, 0, 1, 12, 30)).toISOString();
    const scheduled = await svc.send({ user_id: 82, template_key: 'admin_alert', channel: 'in_app', vars: { actor: 'a', action: 'b', resource: 'c' }, scheduled_at: due });
    assert.strictEqual(scheduled.status, 'queued');
    svc.updatePreferences(82, { quiet_hours_start: '00:00', quiet_hours_end: '23:59', channels_enabled: { email: true, sms: true, in_app: true } });
    const app = await svc.send({ user_id: 82, template_key: 'admin_alert', channel: 'in_app', vars: { actor: 'a', action: 'b', resource: 'c' } });
    assert.strictEqual(app.status, 'sent');
    assert.strictEqual(svc.logs.get(app.message_id).scheduled_at || null, null);
    assert.deepStrictEqual(svc.getInAppNotifications(82).map((n) => n.message_id), [app.message_id]);
    const mail = await svc.send({ user_id: 82, template_key: 'welcome_email', channel: 'email', vars: { app_name: 'Acme' } });
    const text = await svc.send({ user_id: 82, template_key: 'welcome_email', channel: 'sms', vars: { app_name: 'Acme' } });
    assert.strictEqual(mail.status, 'queued');
    assert.strictEqual(text.status, 'queued');
    assert.strictEqual(svc.logs.get(text.message_id).scheduled_at, '2024-01-01T23:59:00.000Z');
    assert.deepStrictEqual(sms, []);
    clock = Date.UTC(2024, 0, 1, 12, 30);
    const out = await svc.deliverDue(new Date(clock));
    assert.deepStrictEqual(out.map((r) => [r.message_id, r.status]), [[scheduled.message_id, 'sent']]);
    assert.deepStrictEqual(inApp, [82, 82]);
  });

  console.log(`\nResults: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    process.exitCode = 1;
  }
}

run().catch((err) => {
  console.error('Test runner error:', err);
  process.exitCode = 1;
});