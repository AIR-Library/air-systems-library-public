const crypto = require('crypto');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { createComplianceService } = require('./data_export_compliance_javascript');

jest.setTimeout(30000);

// Test setup, 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP):
// - time is a clock the test moves (the grace period and link expiry are measured on it), instead of sleeping for
//   background jobs and patching Date.now with fake timers;
// - export files go to the in-memory storage fake, never to AWS;
// - callers prove who they are with an auth-system access token; there is no admin header to trust.
const DAY_MS = 24 * 60 * 60 * 1000;
const JWT_SECRET = crypto.randomBytes(32).toString('hex');
let clock = Date.parse('2026-01-01T09:00:00.000Z');
const service = createComplianceService({ now: () => clock, jwtSecret: JWT_SECRET, autoRunJobs: false });
const { app, run, all, get, transporter, storage } = service;

const authFor = (userId, tier = 'free') => ({
    Authorization: `Bearer ${jwt.sign({ user_id: userId, tier }, JWT_SECRET, { algorithm: 'HS256' })}`,
});

beforeAll(async () => {
    await service.ready;
    // Insert a test user
    const userId = 'test-user-1';
    const now = new Date(clock).toISOString();
    await run(`INSERT INTO users (id,email,name,created_at,tier,status) VALUES (?,?,?,?,?,?)`,
        [userId, 'user@example.com', 'Test User', now, 'free', 'active']);
    // Add related data
    await run(`INSERT INTO sessions (id,user_id,ip,device,created_at) VALUES (?,?,?,?,?)`,
        [uuidv4(), userId, '127.0.0.1', 'Chrome', now]);
    await run(`INSERT INTO activity (id,user_id,type,details,created_at) VALUES (?,?,?,?,?)`,
        [uuidv4(), userId, 'login', '{}', now]);
    await run(`INSERT INTO files (id,user_id,filename,size,created_at) VALUES (?,?,?,?,?)`,
        [uuidv4(), userId, 'doc.txt', 1234, now]);
    await run(`INSERT INTO preferences (user_id,notifications,theme,language) VALUES (?,?,?,?)`,
        [userId, 'all', 'dark', 'en']);
    await run(`INSERT INTO transactions (id,user_id,amount,currency,type,created_at) VALUES (?,?,?,?,?,?)`,
        [uuidv4(), userId, 9.99, 'USD', 'payment', now]);
    await run(`INSERT INTO api_keys (id,user_id,name,created_at) VALUES (?,?,?,?)`,
        [uuidv4(), userId, 'ci', now]);
    // An admin, and a second ordinary user
    await run(`INSERT INTO users (id,email,name,created_at,tier,status) VALUES (?,?,?,?,?,?)`,
        ['admin-1', 'admin@example.com', 'Admin', now, 'admin', 'active']);
    await run(`INSERT INTO users (id,email,name,created_at,tier,status) VALUES (?,?,?,?,?,?)`,
        ['other-user', 'other@example.com', 'Other', now, 'free', 'active']);
});

afterAll(async () => {
    await service.close();
});

describe('Export Endpoints', () => {
    test('Request JSON export returns pending status', async () => {
        const res = await request(app)
            .post('/compliance/export')
            .set(authFor('test-user-1'))
            .send({ format: 'json' });
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        expect(res.body.status).toBe('pending');
        expect(res.body.export_id).toBeDefined();
    });

    test('Export generation creates file and sends email', async () => {
        // Spy on transporter.sendMail
        const sendMailSpy = jest.spyOn(transporter, 'sendMail');
        const exportRes = await request(app)
            .post('/compliance/export')
            .set(authFor('test-user-1'))
            .send({ format: 'json' });
        const exportId = exportRes.body.export_id;

        // Run the background export jobs
        await service.runPendingJobs();

        const statusRes = await request(app)
            .get(`/compliance/exports/${exportId}`)
            .set(authFor('test-user-1'));
        expect(statusRes.body.status).toBe('completed');
        expect(statusRes.body.file_url).toMatch(/^https?:\/\//);
        expect(statusRes.body.expires_at).toBeTruthy();

        // Email sent (the queue also held the previous test's export, so pick this export's message)
        expect(sendMailSpy).toHaveBeenCalled();
        const mailArgs = sendMailSpy.mock.calls.map((c) => c[0]).find((m) => m.text.includes(statusRes.body.file_url));
        expect(mailArgs).toBeDefined();
        expect(mailArgs.to).toBe('user@example.com');
        expect(mailArgs.text).toContain(statusRes.body.file_url);
        sendMailSpy.mockRestore();

        // The file holds every data category, and only this user's export is visible to them
        const file = JSON.parse((await storage.getBySignedUrl(statusRes.body.file_url)).body);
        for (const key of ['profile', 'sessions', 'activity', 'files', 'preferences', 'transactions', 'audit_trail']) {
            expect(file).toHaveProperty(key);
        }
        expect(file.profile.email).toBe('user@example.com');
        const otherRes = await request(app).get(`/compliance/exports/${exportId}`).set(authFor('other-user'));
        expect(otherRes.status).toBe(404);
    });

    test('Signed URL expires after 7 days (simulated)', async () => {
        const exportRes = await request(app)
            .post('/compliance/export')
            .set(authFor('test-user-1'))
            .send({ format: 'csv' });
        const exportId = exportRes.body.export_id;
        await service.runPendingJobs();
        const statusRes = await request(app)
            .get(`/compliance/exports/${exportId}`)
            .set(authFor('test-user-1'));
        const url = statusRes.body.file_url;
        const start = clock;
        // Works now and after 6 days
        expect((await storage.getBySignedUrl(url)).body).toContain('user@example.com');
        clock = start + 6 * DAY_MS;
        await expect(storage.getBySignedUrl(url)).resolves.toBeDefined();
        // Fast-forward time by 8 days: the link no longer works
        clock = start + 8 * DAY_MS;
        await expect(storage.getBySignedUrl(url)).rejects.toThrow('signed_url_expired');
        clock = start;
        // A link whose expiry was edited is refused
        const tampered = url.replace(/expires=(\d+)/, (m, e) => `expires=${Number(e) + DAY_MS}`);
        await expect(storage.getBySignedUrl(tampered)).rejects.toThrow('signed_url_invalid');
    });
});

describe('Deletion Endpoints', () => {
    let deletionId;
    let confirmationToken;

    test('Request deletion creates pending request and sends email', async () => {
        const sendMailSpy = jest.spyOn(transporter, 'sendMail');
        const res = await request(app)
            .post('/compliance/delete')
            .set(authFor('test-user-1'))
            .send({ reason: 'gdpr_request' });
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        deletionId = res.body.deletion_id;
        expect(deletionId).toBeDefined();

        expect(sendMailSpy).toHaveBeenCalled();
        const mail = sendMailSpy.mock.calls[0][0];
        const tokenMatch = mail.text.match(/token=([a-f0-9]{40})/);
        expect(tokenMatch).toBeTruthy();
        confirmationToken = tokenMatch[1];
        sendMailSpy.mockRestore();
    });

    test('Confirm deletion updates status to approved and schedules job', async () => {
        const wrong = await request(app)
            .post(`/compliance/delete/${deletionId}/confirm`)
            .set(authFor('test-user-1'))
            .send({ confirmation_token: 'f'.repeat(40) });
        expect(wrong.status).toBe(400);
        const res = await request(app)
            .post(`/compliance/delete/${deletionId}/confirm`)
            .set(authFor('test-user-1'))
            .send({ confirmation_token: confirmationToken });
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        expect(res.body.deletion_scheduled_for).toBeTruthy();
        expect(Date.parse(res.body.deletion_scheduled_for)).toBe(clock + 30 * DAY_MS);

        const row = await get(`SELECT status FROM deletion_requests WHERE id = ?`, [deletionId]);
        expect(row.status).toBe('approved');
    });

    test('Cancel deletion within grace period works', async () => {
        // Create a new deletion request to cancel
        const res = await request(app)
            .post('/compliance/delete')
            .set(authFor('test-user-1'))
            .send({ reason: 'user_requested' });
        const newDelId = res.body.deletion_id;
        const cancelRes = await request(app)
            .delete(`/compliance/delete/${newDelId}`)
            .set(authFor('test-user-1'));
        expect(cancelRes.status).toBe(200);
        expect(cancelRes.body.success).toBe(true);
        const row = await get(`SELECT status FROM deletion_requests WHERE id = ?`, [newDelId]);
        expect(row.status).toBe('cancelled');
    });

    test('Cascade delete removes user data but keeps audit log', async () => {
        const start = clock;
        // Still inside the 30-day grace period: nothing is deleted yet
        clock = start + 29 * DAY_MS;
        expect(await service.processDueDeletions()).toEqual([]);
        expect(await get(`SELECT * FROM users WHERE id = ?`, ['test-user-1'])).toBeDefined();
        // Fast-forward 31 days to trigger scheduled deletion
        clock = start + 31 * DAY_MS;
        expect(await service.processDueDeletions()).toEqual([deletionId]);
        // Verify user and related tables are gone
        const user = await get(`SELECT * FROM users WHERE id = ?`, ['test-user-1']);
        expect(user).toBeUndefined();
        const sessions = await all(`SELECT * FROM sessions WHERE user_id = ?`, ['test-user-1']);
        expect(sessions.length).toBe(0);
        for (const table of ['activity', 'files', 'preferences', 'transactions', 'api_keys', 'export_requests']) {
            expect(await all(`SELECT * FROM ${table} WHERE user_id = ?`, ['test-user-1'])).toHaveLength(0);
        }
        expect(storage.objects.size).toBe(0);
        // Audit log should still have entries
        const audits = await all(`SELECT * FROM audit_log WHERE user_id = ?`, ['test-user-1']);
        expect(audits.length).toBeGreaterThan(0);
        expect(audits.map((a) => a.action)).toContain('account_deleted');
        clock = start;
    });
});

describe('Admin Endpoints', () => {
    test('Admin can list export requests', async () => {
        const res = await request(app)
            .get('/admin/compliance/exports')
            .set(authFor('admin-1', 'admin'))
            .query({ status: 'completed' });
        expect(res.status).toBe(200);
        expect(Array.isArray(res.body.exports)).toBe(true);
        // Not admins: an ordinary user, and the old admin header without a token
        const user = await request(app).get('/admin/compliance/exports').set(authFor('other-user', 'admin'));
        expect(user.status).toBe(403);
        const header = await request(app).get('/admin/compliance/exports').set('x-admin', 'true');
        expect(header.status).toBe(401);
    });

    test('Admin can list deletion requests', async () => {
        const res = await request(app)
            .get('/admin/compliance/deletions')
            .set(authFor('admin-1', 'admin'))
            .query({ status: 'pending' });
        expect(res.status).toBe(200);
        expect(Array.isArray(res.body.deletions)).toBe(true);
        const completed = await request(app)
            .get('/admin/compliance/deletions')
            .set(authFor('admin-1', 'admin'))
            .query({ status: 'completed' });
        expect(completed.body.deletions).toHaveLength(1);
        expect(completed.body.deletions[0]).not.toHaveProperty('confirmation_token_hash');
    });
});
