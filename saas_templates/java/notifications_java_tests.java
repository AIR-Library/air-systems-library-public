import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import java.time.*;
import java.util.*;

public class NotificationServiceTest {
    private NotificationService service;
    /** Fixed test time (UTC) and a test-only unsubscribe secret (32+ bytes). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    static final Instant NOW = Instant.parse("2026-01-15T12:00:00Z");
    static final LocalDateTime NOW_LOCAL = LocalDateTime.ofInstant(NOW, ZoneOffset.UTC);
    static final byte[] SECRET = "test-only-unsubscribe-secret-0123456789".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    final List<Long> sleeps = new ArrayList<>();
    final List<String> emailsTo = new ArrayList<>();

    /** A service on the fixed clock with recording senders and a no-op sleeper. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    NotificationService newService(NotificationService.EmailSender email) throws Exception {
        return new NotificationService(email, new NotificationService.SimpleSmsSender(), new NotificationService.SimpleInAppSender(),
                SECRET, Clock.fixed(NOW, ZoneOffset.UTC), "https://app.example.test", sleeps::add);
    }

    /**
     * Fresh service and preferences for users 1 and 2. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: a fixed
     * clock (12:00 UTC) with the quiet window 14:00-15:00, so nothing depends on the time of day; the service needs an
     * unsubscribe secret now (NOTIF-11). Touches: in-memory H2.
     */
    @BeforeEach
    public void setUp() throws Exception {
        service = newService((to, subject, body) -> emailsTo.add(to + "|" + body));
        String quietStart = "14:00";
        String quietEnd = "15:00";
        // Set default preferences for user 1
        service.updateUserPreferences(1L, new NotificationService.UserNotificationPreferences(
                1L, false, quietStart, quietEnd,
                new HashMap<>(Map.of("email", true, "sms", true, "in_app", true))));
        // Set default preferences for user 2
        service.updateUserPreferences(2L, new NotificationService.UserNotificationPreferences(
                2L, false, quietStart, quietEnd,
                new HashMap<>(Map.of("email", true, "sms", false, "in_app", true))));
    }

    // NOTIF-01
    @Test
    public void testSendEmailWithTemplateVariables() {
        Map<String, Object> vars = new HashMap<>();
        vars.put("app_name", "TestApp");
        NotificationService.NotificationRequest req = new NotificationService.NotificationRequest(
                1L, "welcome_email", "email", vars, null);
        NotificationService.SendResponse resp = service.sendSingle(req);
        assertTrue(resp.success);
        assertEquals("sent", resp.status);
        NotificationService.TrackResponse track = service.track(resp.messageId);
        assertNotNull(track);
        assertEquals("email", track.channel);
        assertEquals("sent", track.status);
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the rendered body (variables filled) and its unsubscribe link.
        String sent = emailsTo.get(emailsTo.size() - 1);
        assertTrue(sent.contains("Welcome to TestApp! Here's your first step."), sent);
        assertTrue(sent.contains("https://app.example.test/unsubscribe?user_id=1&channel=email&token="
                + service.unsubscribeToken("1", "email")), sent);
    }

    // NOTIF-02
    @Test
    public void testSendSMS() {
        Map<String, Object> vars = new HashMap<>();
        vars.put("days_left", 5);
        NotificationService.NotificationRequest req = new NotificationService.NotificationRequest(
                1L, "trial_ending_soon", "sms", vars, null);
        NotificationService.SendResponse resp = service.sendSingle(req);
        assertTrue(resp.success);
        assertEquals("sent", resp.status);
        NotificationService.TrackResponse track = service.track(resp.messageId);
        assertNotNull(track);
        assertEquals("sms", track.channel);
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-02 amendment): SMS is opt-in; user 1 enabled it in
        // setUp, and a user with default preferences is skipped.
        assertEquals("skipped", service.sendSingle(new NotificationService.NotificationRequest(
                3L, "trial_ending_soon", "sms", vars, null)).status);
    }

    // NOTIF-03
    @Test
    public void testSendInApp() {
        Map<String, Object> vars = new HashMap<>();
        vars.put("month", "January");
        NotificationService.NotificationRequest req = new NotificationService.NotificationRequest(
                1L, "invoice_ready", "in_app", vars, null);
        NotificationService.SendResponse resp = service.sendSingle(req);
        assertTrue(resp.success);
        assertEquals("sent", resp.status);
        NotificationService.TrackResponse track = service.track(resp.messageId);
        assertNotNull(track);
        assertEquals("in_app", track.channel);
    }

    // NOTIF-04
    @Test
    public void testBatchSendLarge() {
        List<NotificationService.NotificationRequest> batch = new ArrayList<>();
        for (int i = 0; i < 1000; i++) {
            Map<String, Object> vars = new HashMap<>();
            vars.put("days_left", 3);
            batch.add(new NotificationService.NotificationRequest(
                    1L, "trial_ending_soon", null, vars, null));
        }
        NotificationService.BatchSendResponse resp = service.sendBatch(batch);
        assertTrue(resp.success);
        assertEquals(1000, resp.sent);
        assertEquals(0, resp.failed);
    }

    /**
     * NOTIF-05: inside quiet hours the message is queued with scheduled_at = the end of the window and sent by
     * deliverDue once it ends. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: fixed clock (11:00-13:00 around
     * 12:00) and the delivery at 13:00 is checked (spec amendment).
     */
    // NOTIF-05
    @Test
    public void testQuietHoursSkip() {
        String start = "11:00";
        String end = "13:00";
        service.updateUserPreferences(1L, new NotificationService.UserNotificationPreferences(
                1L, false, start, end,
                new HashMap<>(Map.of("email", true, "sms", true, "in_app", true))));
        Map<String, Object> vars = new HashMap<>();
        vars.put("days_left", 2);
        NotificationService.NotificationRequest req = new NotificationService.NotificationRequest(
                1L, "trial_ending_soon", "email", vars, null);
        NotificationService.SendResponse resp = service.sendSingle(req);
        assertTrue(resp.success);
        assertEquals("queued", resp.status);
        assertEquals(0, service.deliverDue(NOW_LOCAL.withHour(12).withMinute(59)));
        assertEquals("queued", service.track(resp.messageId).status);
        assertEquals(1, service.deliverDue(NOW_LOCAL.withHour(13).withMinute(0)));
        assertEquals("sent", service.track(resp.messageId).status);
    }

    /**
     * NOTIF-05: quiet hours are HH:MM in UTC and may cross midnight. At 23:00 UTC inside 22:00-08:00 a send is queued
     * for 08:00 the next day and sent then, not before; and deliver_due step 3 re-queues a due message that falls inside
     * the window (scheduled for 14:30 inside 14:00-15:00) with scheduled_at = 15:00 instead of sending it.
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 amendment). Touches: in-memory H2.
     */
    // NOTIF-05
    @Test
    public void testQuietHoursCrossMidnightAndDeliverDueRequeues() throws Exception {
        Instant late = Instant.parse("2026-01-15T23:00:00Z");
        List<String> sent = new ArrayList<>();
        NotificationService night = new NotificationService((to, subject, body) -> sent.add(to),
                new NotificationService.SimpleSmsSender(), new NotificationService.SimpleInAppSender(),
                SECRET, Clock.fixed(late, ZoneOffset.UTC), "https://app.example.test", sleeps::add);
        night.updateUserPreferences(7L, new NotificationService.UserNotificationPreferences(
                7L, false, "22:00", "08:00", new HashMap<>(Map.of("email", true, "sms", false, "in_app", true))));
        NotificationService.SendResponse resp = night.sendSingle(new NotificationService.NotificationRequest(
                7L, "trial_ending_soon", "email", new HashMap<>(Map.of("days_left", 1)), null));
        assertEquals("queued", resp.status);
        assertTrue(sent.isEmpty());
        LocalDateTime nextMorning = LocalDateTime.parse("2026-01-16T08:00:00");
        assertEquals(0, night.deliverDue(nextMorning.minusMinutes(1)));
        assertEquals("queued", night.track(resp.messageId).status);
        assertEquals(1, night.deliverDue(nextMorning));
        assertEquals("sent", night.track(resp.messageId).status);

        // deliver_due step 3: user 1's window is 14:00-15:00 (setUp); a message scheduled for 14:30 is due at 14:30
        // but inside the window, so it goes back to the queue until 15:00.
        NotificationService.SendResponse scheduled = service.sendSingle(new NotificationService.NotificationRequest(
                1L, "trial_ending_soon", "email", new HashMap<>(Map.of("days_left", 2)), NOW_LOCAL.withHour(14).withMinute(30)));
        assertEquals("queued", scheduled.status);
        int before = emailsTo.size();
        assertEquals(0, service.deliverDue(NOW_LOCAL.withHour(14).withMinute(30)));
        assertEquals("queued", service.track(scheduled.messageId).status);
        assertEquals(0, service.deliverDue(NOW_LOCAL.withHour(14).withMinute(59)));
        assertEquals(before, emailsTo.size(), "nothing is sent inside quiet hours");
        assertEquals(1, service.deliverDue(NOW_LOCAL.withHour(15).withMinute(0)));
        assertEquals("sent", service.track(scheduled.messageId).status);
    }

    // NOTIF-06
    @Test
    public void testDoNotDisturbSkip() {
        service.updateUserPreferences(1L, new NotificationService.UserNotificationPreferences(
                1L, true, "22:00", "08:00",
                new HashMap<>(Map.of("email", true, "sms", true, "in_app", true))));
        Map<String, Object> vars = new HashMap<>();
        vars.put("days_left", 2);
        NotificationService.NotificationRequest req = new NotificationService.NotificationRequest(
                1L, "trial_ending_soon", "email", vars, null);
        NotificationService.SendResponse resp = service.sendSingle(req);
        assertTrue(resp.success);
        assertEquals("skipped", resp.status);
    }

    // NOTIF-07
    @Test
    public void testTrackOpened() {
        Map<String, Object> vars = new HashMap<>();
        vars.put("days_left", 4);
        NotificationService.NotificationRequest req = new NotificationService.NotificationRequest(
                1L, "trial_ending_soon", "email", vars, null);
        NotificationService.SendResponse resp = service.sendSingle(req);
        assertEquals("sent", resp.status);
        service.openMessage(resp.messageId);
        NotificationService.TrackResponse track = service.track(resp.messageId);
        assertNotNull(track.openedAt);
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-07 amendment): the status becomes 'opened' too.
        assertEquals("opened", track.status);
    }

    /** A clock the test moves by hand. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing. */
    static final class MovableClock extends Clock {
        Instant now;
        MovableClock(Instant start) { now = start; }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }

    /**
     * NOTIF-07: GET /notifications/open/:message_id (handleOpen) answers 204 and sets opened_at and status 'opened' the
     * first time; a second call an hour later answers 204 and changes nothing; an unknown id also answers 204.
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 amendment). Touches: in-memory H2.
     */
    // NOTIF-07
    @Test
    public void testOpenEndpointRecordsOnce() throws Exception {
        MovableClock clock = new MovableClock(NOW);
        NotificationService svc = new NotificationService((to, subject, body) -> { },
                new NotificationService.SimpleSmsSender(), new NotificationService.SimpleInAppSender(),
                SECRET, clock, "https://app.example.test", sleeps::add);
        NotificationService.SendResponse resp = svc.sendSingle(new NotificationService.NotificationRequest(
                1L, "trial_ending_soon", "email", new HashMap<>(Map.of("days_left", 4)), null));
        assertEquals("sent", resp.status);
        assertNull(svc.track(resp.messageId).openedAt);

        NotificationService.HandlerResponse first = svc.handleOpen("GET", resp.messageId);
        assertEquals(204, first.status);
        assertTrue(first.body.isEmpty());
        NotificationService.TrackResponse opened = svc.track(resp.messageId);
        assertEquals("opened", opened.status);
        assertEquals(NOW_LOCAL, opened.openedAt);

        clock.now = NOW.plusSeconds(3600);
        assertEquals(204, svc.handleOpen("GET", resp.messageId).status);
        NotificationService.TrackResponse again = svc.track(resp.messageId);
        assertEquals("opened", again.status);
        assertEquals(NOW_LOCAL, again.openedAt, "a second open changes nothing");

        assertEquals(204, svc.handleOpen("GET", "no-such-message").status);
    }

    // NOTIF-08
    @Test
    public void testRetryEmail() throws Exception {
        // Mock email sender that fails twice then succeeds
        NotificationService.EmailSender mockSender = new NotificationService.EmailSender() {
            int attempts = 0;
            @Override
            public void send(String to, String subject, String body) throws Exception {
                attempts++;
                if (attempts < 3) throw new Exception("Simulated failure");
            }
        };
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: fixed clock and a recording no-op sleeper (no real 3 s wait).
        NotificationService serviceWithMock = newService(mockSender);
        Map<String, Object> vars = new HashMap<>();
        vars.put("days_left", 3);
        NotificationService.NotificationRequest req = new NotificationService.NotificationRequest(
                1L, "trial_ending_soon", "email", vars, null);
        NotificationService.SendResponse resp = serviceWithMock.sendSingle(req);
        assertTrue(resp.success);
        assertEquals("sent", resp.status);
        assertEquals(List.of(1000L, 2000L), sleeps, "exponential backoff between the three attempts");
    }

    /**
     * NOTIF-08: a failed email is retried at most 3 times after the first attempt (4 attempts, waits 1 s / 2 s / 4 s);
     * a sender that recovers on the 4th attempt is sent, and a 4th failure marks the message failed with no 5th try.
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2 amendment; the code made 3 attempts in all).
     * Touches: in-memory H2.
     */
    // NOTIF-08
    @Test
    public void testRetryCountsFourAttemptsThenFails() throws Exception {
        int[] attempts = {0};
        NotificationService recovers = newService((to, subject, body) -> {
            if (++attempts[0] < 4) throw new Exception("Simulated failure");
        });
        Map<String, Object> vars = new HashMap<>(Map.of("days_left", 3));
        NotificationService.SendResponse ok = recovers.sendSingle(
                new NotificationService.NotificationRequest(1L, "trial_ending_soon", "email", vars, null));
        assertEquals("sent", ok.status);
        assertEquals(4, attempts[0]);
        assertEquals(List.of(1000L, 2000L, 4000L), sleeps);

        sleeps.clear();
        int[] tries = {0};
        NotificationService broken = newService((to, subject, body) -> {
            tries[0]++;
            throw new Exception("Simulated failure");
        });
        NotificationService.SendResponse failed = broken.sendSingle(
                new NotificationService.NotificationRequest(1L, "trial_ending_soon", "email", vars, null));
        assertFalse(failed.success);
        assertEquals("failed", failed.status);
        assertEquals("failed", broken.track(failed.messageId).status);
        assertEquals(4, tries[0], "4 attempts in all, no 5th");
        assertEquals(List.of(1000L, 2000L, 4000L), sleeps);
    }

    /** Unsubscribed users get no more emails. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: through the signed link (POST). */
    // NOTIF-09
    @Test
    public void testUnsubscribe() {
        // Unsubscribe email through the link the emails carry
        assertEquals(200, service.handleUnsubscribe("POST", "1", "email", service.unsubscribeToken("1", "email")).status);
        Map<String, Object> vars = new HashMap<>();
        vars.put("days_left", 3);
        NotificationService.NotificationRequest req = new NotificationService.NotificationRequest(
                1L, "trial_ending_soon", "email", vars, null);
        NotificationService.SendResponse resp = service.sendSingle(req);
        assertTrue(resp.success);
        assertEquals("skipped", resp.status);
    }

    // NOTIF-10
    @Test
    public void testUserPreferencesHonored() {
        // User 2 has sms disabled
        Map<String, Object> vars = new HashMap<>();
        vars.put("days_left", 3);
        NotificationService.NotificationRequest req = new NotificationService.NotificationRequest(
                2L, "trial_ending_soon", "sms", vars, null);
        NotificationService.SendResponse resp = service.sendSingle(req);
        assertTrue(resp.success);
        assertEquals("skipped", resp.status);
    }

    /**
     * NOTIF-11: the signed unsubscribe link. POST with a valid token sets channels_enabled[channel] false; GET changes
     * nothing; a missing, short, non-hex or altered token, a token for another user, or an unknown channel gets the
     * same 403 invalid_unsubscribe_token and the user stays subscribed; a secret under 32 bytes is refused at start.
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory H2.
     */
    // NOTIF-11
    @Test
    public void testSignedUnsubscribeLink() throws Exception {
        String good = service.unsubscribeToken("1", "email");
        assertEquals(64, good.length());
        assertTrue(good.matches("[0-9a-f]{64}"));
        char flipped = good.charAt(10) == 'a' ? 'b' : 'a';
        String altered = good.substring(0, 10) + flipped + good.substring(11);
        for (String[] bad : new String[][] {
                {"1", "email", null}, {"1", "email", ""}, {"1", "email", good.substring(0, 63)},
                {"1", "email", good.toUpperCase(Locale.ROOT)}, {"1", "email", "zz" + good.substring(2)},
                {"1", "email", altered}, {"2", "email", good}, {"1", "fax", service.unsubscribeToken("1", "fax")},
                {"1", "sms", good}}) {
            NotificationService.HandlerResponse r = service.handleUnsubscribe("POST", bad[0], bad[1], bad[2]);
            assertEquals(403, r.status, Arrays.toString(bad));
            assertEquals(Map.of("error", "invalid_unsubscribe_token"), r.body);
        }
        assertTrue(service.getUserPreferences(1L).channelsEnabled.get("email"), "still subscribed");
        NotificationService.HandlerResponse get = service.handleUnsubscribe("GET", "1", "email", good);
        assertEquals(200, get.status);
        assertTrue(service.getUserPreferences(1L).channelsEnabled.get("email"), "GET changes nothing");
        assertEquals(200, service.handleUnsubscribe("POST", "1", "email", good).status);
        assertFalse(service.getUserPreferences(1L).channelsEnabled.get("email"));
        // A user with no saved preferences: defaults with the channel off.
        assertEquals(200, service.handleUnsubscribe("POST", "7", "in_app", service.unsubscribeToken("7", "in_app")).status);
        assertEquals(Map.of("email", true, "sms", false, "in_app", false), service.getUserPreferences(7L).channelsEnabled);
        assertThrows(IllegalArgumentException.class, () -> new NotificationService(
                new NotificationService.SimpleEmailSender(), new NotificationService.SimpleSmsSender(),
                new NotificationService.SimpleInAppSender(), new byte[31], Clock.fixed(NOW, ZoneOffset.UTC),
                "https://app.example.test", ms -> { }));
    }

    /**
     * NOTIF-12: a send 30 days ahead is not sent now; deliverDue sends it once due, exactly once; a user who
     * unsubscribed meanwhile is skipped; a row stuck at 'sending' over 300 s is re-queued and sent.
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory H2.
     */
    // NOTIF-12
    @Test
    public void testScheduledSendsAreDeliveredOnceByDeliverDue() throws Exception {
        Map<String, Object> vars = Map.of("days_left", 3);
        LocalDateTime later = NOW_LOCAL.plusDays(30);
        NotificationService.SendResponse scheduled = service.sendSingle(
                new NotificationService.NotificationRequest(1L, "trial_ending_soon", "email", vars, later));
        assertEquals("queued", scheduled.status);
        int before = emailsTo.size();
        assertEquals(0, service.deliverDue(NOW_LOCAL));
        assertEquals(0, service.deliverDue(later.minusSeconds(1)));
        assertEquals(1, service.deliverDue(later));
        assertEquals(0, service.deliverDue(later.plusMinutes(5)), "exactly once");
        assertEquals(before + 1, emailsTo.size());
        assertEquals("sent", service.track(scheduled.messageId).status);

        NotificationService.SendResponse second = service.sendSingle(
                new NotificationService.NotificationRequest(1L, "trial_ending_soon", "email", vars, later));
        service.handleUnsubscribe("POST", "1", "email", service.unsubscribeToken("1", "email"));
        assertEquals(0, service.deliverDue(later.plusDays(1)));
        assertEquals("skipped", service.track(second.messageId).status);

        // A worker that crashes mid-send leaves the row 'sending'; after 300 s it is re-queued and sent.
        int[] calls = {0};
        NotificationService crashy = newService((to, subject, body) -> {
            if (calls[0]++ == 0) throw new Error("worker killed");
        });
        NotificationService.SendResponse stuck = crashy.sendSingle(
                new NotificationService.NotificationRequest(5L, "trial_ending_soon", "email", vars, later));
        assertThrows(Error.class, () -> crashy.deliverDue(later));
        assertEquals("sending", crashy.track(stuck.messageId).status);
        assertEquals(0, crashy.deliverDue(later.plusSeconds(300)), "a claim younger than 300 s is left alone");
        assertEquals(1, crashy.deliverDue(later.plusSeconds(301)));
        assertEquals("sent", crashy.track(stuck.messageId).status);
    }
}
