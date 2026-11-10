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
// A fake of the audit system's eraser (EXPORT-13, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). When it is called it
// records what the database looks like at that moment, so the tests can prove the cascade order.
const erasures = [];
let get;
const auditEraser = {
    async erase_subject(userId) {
        const user = await get('SELECT id FROM users WHERE id = ?', [userId]);
        const audits = await get('SELECT COUNT(*) AS n FROM audit_log WHERE user_id = ?', [userId]);
        const cascadeLogged = await get(`SELECT COUNT(*) AS n FROM audit_log WHERE user_id = ? AND action = 'user_deleted_cascade'`, [userId]);
        erasures.push({ userId, userGone: !user, auditRows: audits.n, cascadeLogged: cascadeLogged.n });
    },
};
const service = createComplianceService({ now: () => clock, jwtSecret: JWT_SECRET, autoRunJobs: false, auditEraser });
const { app, run, all, transporter, storage } = service;
get = service.get;

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

    // EXPORT-01 EXPORT-02 EXPORT-03
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

    // EXPORT-01 EXPORT-04
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

    // EXPORT-09
    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: reason user_requested (a gdpr_request now has no grace period,
    // EXPORT-12), and the token is 32 random bytes (64 hex characters), no longer 20.
    test('Request deletion creates pending request and sends email', async () => {
        const sendMailSpy = jest.spyOn(transporter, 'sendMail');
        const res = await request(app)
            .post('/compliance/delete')
            .set(authFor('test-user-1'))
            .send({ reason: 'user_requested' });
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        deletionId = res.body.deletion_id;
        expect(deletionId).toBeDefined();

        expect(sendMailSpy).toHaveBeenCalled();
        const mail = sendMailSpy.mock.calls[0][0];
        const tokenMatch = mail.text.match(/token=([a-f0-9]{64})\b/);
        expect(tokenMatch).toBeTruthy();
        confirmationToken = tokenMatch[1];
        sendMailSpy.mockRestore();
    });

    // EXPORT-05 EXPORT-09
    test('Confirm deletion updates status to approved and schedules job', async () => {
        const row0 = await get(`SELECT requested_at, will_delete_at FROM deletion_requests WHERE id = ?`, [deletionId]);
        expect(Date.parse(row0.will_delete_at)).toBe(Date.parse(row0.requested_at) + 30 * DAY_MS);
        const wrong = await request(app)
            .post(`/compliance/delete/${deletionId}/confirm`)
            .set(authFor('test-user-1'))
            .send({ confirmation_token: 'f'.repeat(64) });
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

    // EXPORT-06
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

    // EXPORT-07 EXPORT-08 EXPORT-13
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
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the cascade logs 'user_deleted_cascade' (spec amended; it was
        // 'account_deleted', written after the cascade), then calls the audit eraser LAST, and nothing logs the user
        // afterwards; the request rows no longer name the user.
        expect(audits.map((a) => a.action)).toContain('user_deleted_cascade');
        expect(erasures).toEqual([{ userId: 'test-user-1', userGone: true, auditRows: audits.length, cascadeLogged: 1 }]);
        expect(audits[audits.length - 1].action).toBe('user_deleted_cascade');
        const req = await get(`SELECT user_id, status FROM deletion_requests WHERE id = ?`, [deletionId]);
        expect(req).toEqual({ user_id: null, status: 'completed' });
        expect(await all(`SELECT id FROM deletion_requests WHERE user_id = ?`, ['test-user-1'])).toHaveLength(0);
        clock = start;
    });

    /**
     * EXPORT-11: every export and deletion request is in the audit log with its details (the why-chain inputs:
     * export id and format, deletion id and reason), and the log survives the account's deletion.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the test database.
     */
    // EXPORT-11
    test('Every export and deletion request is audited with its details', async () => {
        const rows = await all(`SELECT action, details FROM audit_log WHERE user_id = ? ORDER BY created_at, rowid`, ['test-user-1']);
        const actions = rows.map((r) => r.action);
        for (const a of ['data_export_requested', 'data_export_completed', 'deletion_requested', 'deletion_confirmed',
            'deletion_cancelled', 'user_deleted_cascade']) {
            expect(actions).toContain(a);
        }
        const requested = rows.filter((r) => r.action === 'deletion_requested').map((r) => JSON.parse(r.details));
        expect(requested.map((d) => d.reason)).toEqual(['user_requested', 'user_requested']);
        const exported = rows.filter((r) => r.action === 'data_export_requested').map((r) => JSON.parse(r.details));
        expect(exported.map((d) => d.format)).toEqual(['json', 'json', 'csv']);
    });
});

describe('Admin Endpoints', () => {
    // EXPORT-10
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

    // EXPORT-10
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

/**
 * Seeds one active user with a session and an API key. In: id, email. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 */
async function seedUser(id, email) {
    const at = new Date(clock).toISOString();
    await run(`INSERT INTO users (id,email,name,created_at,tier,status) VALUES (?,?,?,?,?,?)`, [id, email, id, at, 'free', 'active']);
    await run(`INSERT INTO sessions (id,user_id,ip,device,created_at) VALUES (?,?,?,?,?)`, [uuidv4(), id, '203.0.113.9', 'Firefox', at]);
    await run(`INSERT INTO api_keys (id,user_id,name,created_at) VALUES (?,?,?,?)`, [uuidv4(), id, 'k', at]);
}

/** Requests a deletion for userId and returns { deletion_id, will_delete_at, token } (token from the e-mail). */
async function requestDeletion(userId, reason) {
    const spy = jest.spyOn(transporter, 'sendMail');
    const res = await request(app).post('/compliance/delete').set(authFor(userId)).send({ reason });
    const token = spy.mock.calls[0][0].text.match(/token=([a-f0-9]{64})\b/)[1];
    spy.mockRestore();
    return { ...res.body, token };
}

describe('Deletion rules amended 2026-11-10', () => {
    /**
     * EXPORT-12: a statutory erasure request (gdpr_request or gdpr_right_to_be_forgotten) gets no grace period:
     * will_delete_at = requested_at, and confirm runs the cascade before it returns (status completed, deleted_at =
     * deletion_scheduled_for = now). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the test database.
     */
    // EXPORT-12
    test('A gdpr_request or gdpr_right_to_be_forgotten request is not held for 30 days', async () => {
        for (const reason of ['gdpr_request', 'gdpr_right_to_be_forgotten']) {
            const id = `gdpr-${reason}`;
            await seedUser(id, `${id}@example.com`);
            const d = await requestDeletion(id, reason);
            expect(d.will_delete_at).toBe(new Date(clock).toISOString());
            expect(await get('SELECT id FROM users WHERE id = ?', [id])).toBeDefined(); // nothing deleted before confirm
            clock += 60 * 1000;
            const res = await request(app).post(`/compliance/delete/${d.deletion_id}/confirm`).set(authFor(id))
                .send({ confirmation_token: d.token });
            expect(res.status).toBe(200);
            expect(res.body.status).toBe('completed');
            expect(res.body.deletion_scheduled_for).toBe(new Date(clock).toISOString());
            expect(await get('SELECT id FROM users WHERE id = ?', [id])).toBeUndefined();
            expect(await all('SELECT id FROM sessions WHERE user_id = ?', [id])).toHaveLength(0);
            const row = await get('SELECT status, deleted_at, user_id FROM deletion_requests WHERE id = ?', [d.deletion_id]);
            expect(row).toEqual({ status: 'completed', deleted_at: new Date(clock).toISOString(), user_id: null });
            expect(erasures[erasures.length - 1]).toMatchObject({ userId: id, userGone: true, cascadeLogged: 1 });
        }
    });

    /**
     * EXPORT-14: nothing is deleted before confirm; a wrong token, a reused token and a token older than 24 h are
     * refused; another user's deletion request is 404 for both confirm and cancel and is left as it was.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the test database.
     */
    // EXPORT-14
    test('Confirmation token: wrong, reused and expired tokens refused; another user\'s request is 404', async () => {
        await seedUser('confirm-user', 'confirm@example.com');
        await seedUser('intruder', 'intruder@example.com');
        const d = await requestDeletion('confirm-user', 'user_requested');
        expect(await get('SELECT id FROM users WHERE id = ?', ['confirm-user'])).toBeDefined();
        expect(await all('SELECT id FROM sessions WHERE user_id = ?', ['confirm-user'])).toHaveLength(1);

        const confirm = (userId, token) => request(app).post(`/compliance/delete/${d.deletion_id}/confirm`)
            .set(authFor(userId)).send({ confirmation_token: token });
        expect((await confirm('intruder', d.token)).status).toBe(404);
        expect((await request(app).delete(`/compliance/delete/${d.deletion_id}`).set(authFor('intruder'))).status).toBe(404);
        expect((await confirm('confirm-user', d.token.replace(/^./, (c) => (c === 'a' ? 'b' : 'a')))).status).toBe(400);
        expect((await confirm('confirm-user', d.token.slice(0, 40))).status).toBe(400);
        expect((await get('SELECT status FROM deletion_requests WHERE id = ?', [d.deletion_id])).status).toBe('pending');

        const ok = await confirm('confirm-user', d.token);
        expect(ok.status).toBe(200);
        const reused = await confirm('confirm-user', d.token);
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, EXPORT-15): was 409; the spec now gives a reused
        // token the same 400 invalid_confirmation_token as a wrong or expired one.
        expect(reused.status).toBe(400);
        expect(await get('SELECT id FROM users WHERE id = ?', ['confirm-user'])).toBeDefined(); // grace period: still there

        const late = await requestDeletion('intruder', 'other');
        clock += 24 * 60 * 60 * 1000 + 1;
        const expired = await request(app).post(`/compliance/delete/${late.deletion_id}/confirm`).set(authFor('intruder'))
            .send({ confirmation_token: late.token });
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2, EXPORT-15): was 410; an expired token is now the
        // same 400 invalid_confirmation_token as a wrong or reused one.
        expect(expired.status).toBe(400);
        expect((await get('SELECT status FROM deletion_requests WHERE id = ?', [late.deletion_id])).status).toBe('pending');
        expect(await get('SELECT id FROM users WHERE id = ?', ['intruder'])).toBeDefined();
    });

    /**
     * EXPORT-15: a wrong, a reused and an expired (over 24 h) token all get the same 400
     * {error: "invalid_confirmation_token"}; confirm or cancel of a cancelled request is 409
     * {error: "deletion_not_pending"}; of a completed request, and of another user's request, 404 {error: "not_found"}
     * (the completed case per the lead's clarification, commit 3abb340).
     * In: the test app and clock. Out: assertions. Why: Phase B.2 gave these one answer in every language.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches the test database.
     */
    // EXPORT-15
    test('One 400 for a wrong, reused or expired token; 409 deletion_not_pending once cancelled; 404 once completed', async () => {
        await seedUser('e15-user', 'e15@example.com');
        await seedUser('e15-other', 'e15-other@example.com');
        const confirm = (deletionId, userId, token) => request(app).post(`/compliance/delete/${deletionId}/confirm`)
            .set(authFor(userId)).send({ confirmation_token: token });
        const cancel = (deletionId, userId) => request(app).delete(`/compliance/delete/${deletionId}`).set(authFor(userId));

        const d = await requestDeletion('e15-user', 'user_requested');
        const intruderConfirm = await confirm(d.deletion_id, 'e15-other', d.token);
        expect(intruderConfirm.status).toBe(404);
        expect(intruderConfirm.body.error).toBe('not_found');
        const intruderCancel = await cancel(d.deletion_id, 'e15-other');
        expect(intruderCancel.status).toBe(404);
        expect(intruderCancel.body.error).toBe('not_found');

        const wrong = await confirm(d.deletion_id, 'e15-user', 'f'.repeat(64));
        expect(wrong.status).toBe(400);
        expect(wrong.body.error).toBe('invalid_confirmation_token');
        expect((await confirm(d.deletion_id, 'e15-user', d.token)).status).toBe(200);
        const reused = await confirm(d.deletion_id, 'e15-user', d.token);
        expect(reused.status).toBe(400);
        expect(reused.body.error).toBe('invalid_confirmation_token');

        // cancelled: confirm and cancel are both 409
        expect((await cancel(d.deletion_id, 'e15-user')).status).toBe(200);
        const confirmCancelled = await confirm(d.deletion_id, 'e15-user', d.token);
        expect(confirmCancelled.status).toBe(409);
        expect(confirmCancelled.body.error).toBe('deletion_not_pending');
        const cancelCancelled = await cancel(d.deletion_id, 'e15-user');
        expect(cancelCancelled.status).toBe(409);
        expect(cancelCancelled.body.error).toBe('deletion_not_pending');

        // expired: the same 400, and the request stays pending
        const late = await requestDeletion('e15-other', 'other');
        clock += DAY_MS + 1;
        const expired = await confirm(late.deletion_id, 'e15-other', late.token);
        expect(expired.status).toBe(400);
        expect(expired.body).toEqual(wrong.body);
        expect((await get('SELECT status FROM deletion_requests WHERE id = ?', [late.deletion_id])).status).toBe('pending');

        // completed: 404 not_found for confirm and cancel (spec clarification, commit 3abb340: a completed request has no
        // owner any more, EXPORT-13). Even a completed row that still names its user is 404 to that user.
        await seedUser('e15-done', 'e15-done@example.com');
        const c = await requestDeletion('e15-done', 'user_requested');
        await run(`UPDATE deletion_requests SET status = 'completed', deleted_at = ? WHERE id = ?`,
            [new Date(clock).toISOString(), c.deletion_id]);
        const confirmCompleted = await confirm(c.deletion_id, 'e15-done', c.token);
        expect(confirmCompleted.status).toBe(404);
        expect(confirmCompleted.body.error).toBe('not_found');
        const cancelCompleted = await cancel(c.deletion_id, 'e15-done');
        expect(cancelCompleted.status).toBe(404);
        expect(cancelCompleted.body.error).toBe('not_found');

        // after a real cascade (statutory reason) the former owner cannot authenticate (401) and anyone else gets 404
        await seedUser('e15-gdpr', 'e15-gdpr@example.com');
        const g = await requestDeletion('e15-gdpr', 'gdpr_request');
        expect((await confirm(g.deletion_id, 'e15-gdpr', g.token)).body.status).toBe('completed');
        expect((await confirm(g.deletion_id, 'e15-gdpr', g.token)).status).toBe(401);
        const strangerOnCompleted = await cancel(g.deletion_id, 'e15-other');
        expect(strangerOnCompleted.status).toBe(404);
        expect(strangerOnCompleted.body.error).toBe('not_found');
    });

    /**
     * EXPORT-06 (Phase B.3): the user can cancel only WITHIN the grace period. One second before will_delete_at a
     * confirmed request is cancelled (200); at will_delete_at, and after it, while the deletion is due but has not
     * run yet, cancel is 409 {error: "grace_period_over"}, the request stays approved, and the due deletion still runs.
     * In: the test app and clock. Out: assertions. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches the test database.
     */
    // EXPORT-06
    test('Cancel after will_delete_at has passed → 409 grace_period_over; one second before it → cancelled', async () => {
        const start = clock;
        const confirmAndSchedule = async (userId) => {
            await seedUser(userId, `${userId}@example.com`);
            const d = await requestDeletion(userId, 'user_requested');
            const ok = await request(app).post(`/compliance/delete/${d.deletion_id}/confirm`).set(authFor(userId))
                .send({ confirmation_token: d.token });
            expect(ok.body.status).toBe('approved');
            return d;
        };
        const cancel = (deletionId, userId) => request(app).delete(`/compliance/delete/${deletionId}`).set(authFor(userId));
        try {
            const early = await confirmAndSchedule('b3-early');
            clock = Date.parse(early.will_delete_at) - 1000;
            const inTime = await cancel(early.deletion_id, 'b3-early');
            expect(inTime.status).toBe(200);
            expect(inTime.body).toEqual({ success: true, status: 'cancelled' });

            clock = start;
            const late = await confirmAndSchedule('b3-late');
            for (const at of [Date.parse(late.will_delete_at), Date.parse(late.will_delete_at) + DAY_MS]) {
                clock = at;
                const res = await cancel(late.deletion_id, 'b3-late');
                expect(res.status).toBe(409);
                expect(res.body.error).toBe('grace_period_over');
                expect((await get('SELECT status FROM deletion_requests WHERE id = ?', [late.deletion_id])).status).toBe('approved');
            }
            expect(await service.processDueDeletions()).toContain(late.deletion_id);
            expect(await get('SELECT id FROM users WHERE id = ?', ['b3-late'])).toBeUndefined();
            expect(await get('SELECT id FROM users WHERE id = ?', ['b3-early'])).toBeDefined();
        } finally {
            clock = start;
        }
    });
});
