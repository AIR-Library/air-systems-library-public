'use strict';

const assert = require('assert');
const { NotificationService, createRouter, inQuietHours } = require('./notifications_javascript.js');

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
    ...(overrides || {}),
  });
}

async function run() {
  console.log('Notifications Test Suite\n');

  await test('Send email with template variables', async () => {
    const svc = makeService();
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
  });

  await test('Send SMS', async () => {
    let smsPayload = null;
    const svc = makeService({
      smsSender: async (p) => { smsPayload = p; },
    });
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

  await test('Quiet hours: skip if in range', async () => {
    // Fixed clock at 12:00 local time (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): with the real clock this test
    // failed during the one minute a day, 23:59, that lies outside 00:00-23:59.
    const svc = makeService({ nowFn: () => new Date(2024, 0, 1, 12, 0) });
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
    assert.ok(svc.queue.length >= 1);
  });

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

  await test('Track: message marked as opened when user clicks link', async () => {
    const svc = makeService();
    const res = await svc.send({
      user_id: 33,
      template_key: 'invoice_ready',
      channel: 'email',
      vars: { month: 'January', download_url: 'http://x' },
    });
    const mid = res.message_id;
    svc.markOpened(mid);
    let tracked = svc.track(mid);
    assert.strictEqual(tracked.status, 'opened');
    assert.ok(tracked.opened_at);
    svc.markClicked(mid);
    tracked = svc.track(mid);
    assert.strictEqual(tracked.status, 'clicked');
    assert.ok(tracked.clicked_at);
  });

  await test('Retry: failed email retries and eventually succeeds', async () => {
    let calls = 0;
    const svc = makeService({
      emailSender: async () => {
        calls += 1;
        if (calls < 3) throw new Error('transient failure');
      },
    });
    const res = await svc.send({
      user_id: 44,
      template_key: 'welcome_email',
      channel: 'email',
      vars: { app_name: 'Acme' },
    });
    assert.strictEqual(res.success, true);
    assert.strictEqual(res.status, 'sent');
    assert.strictEqual(calls, 3);
  });

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

  await test('Unsubscribe link: only a token signed by the service unsubscribes', async () => {
    let mail = null;
    const svc = makeService({ emailSender: async (m) => { mail = m; } });
    const router = createRouter(svc);
    await svc.send({ user_id: 77, template_key: 'welcome_email', channel: 'email', vars: { app_name: 'Acme' } });
    const forged = await router.handle('GET', '/unsubscribe', { query: { user_id: '78', channel: 'email', token: 'x' } });
    assert.strictEqual(forged.status, 403);
    assert.strictEqual(svc.isUnsubscribed(78, 'email'), false);
    const query = Object.fromEntries(new URL(mail.unsubscribeUrl).searchParams);
    const out = await router.handle('GET', '/unsubscribe', { query });
    assert.strictEqual(out.status, 200);
    assert.strictEqual(svc.isUnsubscribed(77, 'email'), true);
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
    const out = await router.handle('GET', '/users/9/notification-preferences', {});
    assert.strictEqual(out.status, 200);
    assert.strictEqual(out.body.user_id, 9);
    assert.strictEqual(typeof out.body.do_not_disturb, 'boolean');
    assert.ok(out.body.channels_enabled);
  });

  await test('Router: PUT /users/:id/notification-preferences returns success', async () => {
    const svc = makeService();
    const router = createRouter(svc);
    const out = await router.handle('PUT', '/users/9/notification-preferences', {
      body: { do_not_disturb: true, channels_enabled: { email: true, sms: false } },
    });
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

  await test('inQuietHours utility handles wrap-around', async () => {
    assert.strictEqual(inQuietHours('22:00', '08:00', new Date(2024, 0, 1, 23, 0)), true);
    assert.strictEqual(inQuietHours('22:00', '08:00', new Date(2024, 0, 1, 7, 0)), true);
    assert.strictEqual(inQuietHours('22:00', '08:00', new Date(2024, 0, 1, 12, 0)), false);
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