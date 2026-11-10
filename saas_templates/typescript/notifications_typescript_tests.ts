import { NotificationService } from './notifications_typescript';
import nodemailer from 'nodemailer';
import { Twilio } from 'twilio';
import { jest } from '@jest/globals';

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
    service = new NotificationService(':memory:', mockEmailTransport, mockSmsClient);
    await service.init();
  });

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

  test('Send SMS', async () => {
    (mockSmsClient.messages.create as jest.Mock).mockResolvedValueOnce({});
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

  test('Quiet hours: skip if in range', async () => {
    const prefs = await service.getPreferences(4);
    await service.updateUserPreferences(4, {
      quiet_hours_start: '00:00',
      quiet_hours_end: '23:59',
    });
    const res = await service.sendSingle({
      user_id: 4,
      template_key: 'welcome_email',
      channel: 'email',
      vars: { app_name: 'QuietApp' },
      scheduled_at: null,
    });
    expect(res.status).toBe('skipped');
    const log = await service.track({ message_id: res.message_id, status: 'skipped' });
    expect(log?.status).toBe('skipped');
    // restore prefs
    await service.updateUserPreferences(4, prefs);
  });

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
});