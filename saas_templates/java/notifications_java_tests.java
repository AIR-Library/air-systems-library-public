import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import java.time.*;
import java.util.*;

public class NotificationServiceTest {
    private NotificationService service;

    /** Fresh service and preferences for users 1 and 2. Changed 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the quiet window is placed 2 to 3 hours from now so the suite no longer fails between 22:00 and 08:00. Touches: in-memory H2. */
    @BeforeEach
    public void setUp() throws Exception {
        service = new NotificationService();
        // A quiet window that never covers the moment the tests run. Changed 2026-11-10, session
        // session_012zDydZCZ4AChqhEZ4oVtaP: it was a fixed 22:00 to 08:00, so between 22:00 and 08:00 every
        // "sent" expectation below failed because the message was correctly queued (time-of-day dependence;
        // the Python suite made the same change on 2026-11-08).
        LocalTime now = LocalTime.now();
        java.time.format.DateTimeFormatter hhmm = java.time.format.DateTimeFormatter.ofPattern("HH:mm");
        String quietStart = now.plusHours(2).format(hhmm);
        String quietEnd = now.plusHours(3).format(hhmm);
        // Set default preferences for user 1
        service.updateUserPreferences(1L, new NotificationService.UserNotificationPreferences(
                1L, false, quietStart, quietEnd,
                new HashMap<>(Map.of("email", true, "sms", true, "in_app", true))));
        // Set default preferences for user 2
        service.updateUserPreferences(2L, new NotificationService.UserNotificationPreferences(
                2L, false, quietStart, quietEnd,
                new HashMap<>(Map.of("email", true, "sms", false, "in_app", true))));
    }

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
    }

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
    }

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

    @Test
    public void testQuietHoursSkip() {
        // Set quiet hours to cover now
        LocalTime now = LocalTime.now();
        String start = now.minusHours(1).format(java.time.format.DateTimeFormatter.ofPattern("HH:mm"));
        String end = now.plusHours(1).format(java.time.format.DateTimeFormatter.ofPattern("HH:mm"));
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
    }

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
    }

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
        NotificationService serviceWithMock = new NotificationService(mockSender, new NotificationService.SimpleSmsSender(), new NotificationService.SimpleInAppSender());
        Map<String, Object> vars = new HashMap<>();
        vars.put("days_left", 3);
        NotificationService.NotificationRequest req = new NotificationService.NotificationRequest(
                1L, "trial_ending_soon", "email", vars, null);
        NotificationService.SendResponse resp = serviceWithMock.sendSingle(req);
        assertTrue(resp.success);
        assertEquals("sent", resp.status);
    }

    @Test
    public void testUnsubscribe() {
        // Unsubscribe email
        service.unsubscribeEmail(1L);
        Map<String, Object> vars = new HashMap<>();
        vars.put("days_left", 3);
        NotificationService.NotificationRequest req = new NotificationService.NotificationRequest(
                1L, "trial_ending_soon", "email", vars, null);
        NotificationService.SendResponse resp = service.sendSingle(req);
        assertTrue(resp.success);
        assertEquals("skipped", resp.status);
    }

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
}