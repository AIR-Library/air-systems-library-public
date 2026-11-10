import java.sql.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;

/**
 * Notifications (email, SMS, in-app) with templates, user preferences (do-not-disturb, quiet hours, channels),
 * delivery tracking and retry with exponential backoff. Email/SMS/in-app delivery sits behind the EmailSender,
 * SmsSender and InAppSender interfaces; the Simple* senders are in-memory stand-ins that send nothing.
 *
 * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: it did not compile (two toJson overloads with
 * the same erasure); every instance shared one in-memory database, so the second instance failed seeding the
 * templates; the template key column was the reserved word KEY; logs had no status column, so every insert
 * failed silently and track() returned null; vars were written to JSON unescaped; the log recorded the requested
 * channel (null when auto-selected) instead of the one used; unsubscribing a user with no saved preferences did
 * nothing. Touches: an in-memory H2 database per instance; the injected senders (network in a real deployment).
 */
public class NotificationService {
    private static final Logger logger = Logger.getLogger(NotificationService.class.getName());
    /** A 'sending' row whose claim is older than this is taken to belong to a crashed worker (spec deliver_due step 1). */
    public static final Duration CLAIM_TIMEOUT = Duration.ofSeconds(300);
    private static final Set<String> CHANNELS = Set.of("email", "sms", "in_app");
    private static final java.util.regex.Pattern TOKEN_FORMAT = java.util.regex.Pattern.compile("^[0-9a-f]{64}$");
    private static final com.fasterxml.jackson.databind.ObjectMapper JSON = new com.fasterxml.jackson.databind.ObjectMapper();
    private final Connection conn;
    private final EmailSender emailSender;
    private final SmsSender smsSender;
    private final InAppSender inAppSender;
    private final byte[] unsubscribeSecret;
    private final Clock clock;
    private final String baseUrl;
    private final java.util.function.LongConsumer sleeper;

    /**
     * Service with the in-memory stand-in senders, the system UTC clock and the unsubscribe secret from the
     * NOTIFICATION_UNSUBSCRIBE_SECRET environment variable (refuses to start without one of 32+ bytes).
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-11). Touches: in-memory H2, the environment.
     */
    public NotificationService() throws SQLException {
        this(new SimpleEmailSender(), new SimpleSmsSender(), new SimpleInAppSender());
    }

    /**
     * Service with the given senders; secret from NOTIFICATION_UNSUBSCRIBE_SECRET, system UTC clock, base URL from
     * NOTIFICATION_BASE_URL (default https://app.example.com), real sleeps between retries.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory H2; the senders; the environment.
     */
    public NotificationService(EmailSender emailSender, SmsSender smsSender, InAppSender inAppSender) throws SQLException {
        this(emailSender, smsSender, inAppSender, envSecret(), Clock.systemUTC(),
                Optional.ofNullable(System.getenv("NOTIFICATION_BASE_URL")).orElse("https://app.example.com"),
                ms -> {
                    try {
                        Thread.sleep(ms);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                });
    }

    /**
     * The full constructor. In: the three senders (network in a real deployment), the unsubscribe HMAC secret (at least
     * 32 bytes, from configuration, never hard-coded), the clock every time decision uses, the base URL of unsubscribe
     * links, and the retry sleeper (tests pass a no-op). Out: a service on its own private in-memory database.
     * Throws IllegalArgumentException for a missing or short secret: an empty key makes a forgeable HMAC (NOTIF-11).
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory H2.
     */
    public NotificationService(EmailSender emailSender, SmsSender smsSender, InAppSender inAppSender,
                               byte[] unsubscribeSecret, Clock clock, String baseUrl,
                               java.util.function.LongConsumer sleeper) throws SQLException {
        if (unsubscribeSecret == null || unsubscribeSecret.length < 32) {
            throw new IllegalArgumentException("the unsubscribe secret must be at least 32 bytes");
        }
        this.unsubscribeSecret = unsubscribeSecret.clone();
        this.clock = Objects.requireNonNull(clock);
        this.baseUrl = Objects.requireNonNull(baseUrl).replaceAll("/+$", "");
        this.sleeper = Objects.requireNonNull(sleeper);
        this.conn = DriverManager.getConnection(newDatabaseUrl());
        this.emailSender = emailSender;
        this.smsSender = smsSender;
        this.inAppSender = inAppSender;
        initDatabase();
        seedTemplates();
    }

    private static byte[] envSecret() {
        String v = System.getenv("NOTIFICATION_UNSUBSCRIBE_SECRET");
        return v == null ? null : v.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    /** "Now" from the injected clock, as UTC local time (the stored timestamps are UTC). */
    private LocalDateTime now() {
        return LocalDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
    }

    /**
     * A JDBC URL for a fresh, private in-memory H2 database; it lives as long as this instance's connection.
     * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing (pure).
     */
    private static String newDatabaseUrl() {
        return "jdbc:h2:mem:notifications_" + UUID.randomUUID().toString().replace("-", "");
    }

    /**
     * Creates the three tables of the spec's schema. notification_templates.template_key holds the spec's
     * "key" (KEY is reserved in H2 and MySQL); notification_logs also stores the delivery status that track()
     * returns. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database.
     */
    private void initDatabase() throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS notification_templates (" +
                    "template_key VARCHAR(255) PRIMARY KEY," +
                    "subject VARCHAR(255)," +
                    "body_text TEXT," +
                    "body_html TEXT," +
                    "channels_default VARCHAR(255)," +
                    "variables TEXT" +
                    ")");
            stmt.execute("CREATE TABLE IF NOT EXISTS notification_logs (" +
                    "id VARCHAR(36) PRIMARY KEY," +
                    "user_id BIGINT," +
                    "template_key VARCHAR(255)," +
                    "channel VARCHAR(20)," +
                    "vars_used TEXT," +
                    "sent_at TIMESTAMP," +
                    "opened_at TIMESTAMP," +
                    "clicked_at TIMESTAMP," +
                    "bounced BOOLEAN," +
                    "error TEXT," +
                    "status VARCHAR(20)," +
                    // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-05/12): scheduled and quiet-hours sends
                    // wait as 'queued' with scheduled_at; claimed_at marks a deliver_due claim; seq keeps
                    // insertion order for ties.
                    "scheduled_at TIMESTAMP," +
                    "claimed_at TIMESTAMP," +
                    "seq BIGINT AUTO_INCREMENT" +
                    ")");
            stmt.execute("CREATE TABLE IF NOT EXISTS user_notification_preferences (" +
                    "user_id BIGINT PRIMARY KEY," +
                    "do_not_disturb BOOLEAN," +
                    "quiet_hours_start VARCHAR(5)," +
                    "quiet_hours_end VARCHAR(5)," +
                    "channels_enabled TEXT" +
                    ")");
        }
    }

    private void seedTemplates() throws SQLException {
        addTemplate(new NotificationTemplate("welcome_email",
                "Welcome to {app_name}!",
                "Welcome to {app_name}! Here's your first step.",
                null,
                "email",
                "[\"app_name\"]"));
        addTemplate(new NotificationTemplate("trial_starting",
                null,
                "Your free trial is starting. You have {trial_days} days.",
                null,
                "email",
                "[\"trial_days\"]"));
        addTemplate(new NotificationTemplate("trial_ending_soon",
                null,
                "Your trial ends in {days_left} days. Add payment method to continue.",
                null,
                "email",
                "[\"days_left\"]"));
        addTemplate(new NotificationTemplate("subscription_changed",
                null,
                "Your plan changed from {old_tier} to {new_tier}. Effective {effective_date}.",
                null,
                "email",
                "[\"old_tier\",\"new_tier\",\"effective_date\"]"));
        addTemplate(new NotificationTemplate("payment_failed",
                null,
                "Payment failed for invoice {invoice_id}. {retry_date} retry, or update payment method.",
                null,
                "email",
                "[\"invoice_id\",\"retry_date\"]"));
        addTemplate(new NotificationTemplate("deployment_live",
                null,
                "Your deployment {deployment_name} is now live at {url}.",
                null,
                "email",
                "[\"deployment_name\",\"url\"]"));
        addTemplate(new NotificationTemplate("user_invited",
                null,
                "You've been invited to {workspace}. Click here to join.",
                null,
                "email",
                "[\"workspace\"]"));
        addTemplate(new NotificationTemplate("invoice_ready",
                null,
                "Your invoice for {month} is ready. Download here.",
                null,
                "email",
                "[\"month\"]"));
        addTemplate(new NotificationTemplate("admin_alert",
                null,
                "{actor} performed {action} on {resource}.",
                null,
                "email",
                "[\"actor\",\"action\",\"resource\"]"));
    }

    /**
     * Stores a template. Input: NotificationTemplate. Output: none; throws SQLException on a duplicate key.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: column renamed to template_key.
     * Touches: the database.
     */
    public void addTemplate(NotificationTemplate template) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO notification_templates (template_key, subject, body_text, body_html, channels_default, variables) VALUES (?,?,?,?,?,?)")) {
            ps.setString(1, template.key);
            ps.setString(2, template.subject);
            ps.setString(3, template.bodyText);
            ps.setString(4, template.bodyHtml);
            ps.setString(5, template.channelsDefault);
            ps.setString(6, template.variables);
            ps.executeUpdate();
        }
    }

    /** Default preferences for a user who has set none: no quiet hours, do_not_disturb false, SMS off (opt-in). */
    private static UserNotificationPreferences defaultPreferences(long userId) {
        return new UserNotificationPreferences(userId, false, null, null,
                new HashMap<>(Map.of("email", true, "sms", false, "in_app", true)));
    }

    /**
     * Sends one notification. Order: do-not-disturb -> 'skipped'; no enabled channel -> 'skipped'; scheduled_at in the
     * future -> 'queued' with that scheduled_at; inside quiet hours -> 'queued' with scheduled_at = the end of the quiet
     * window; otherwise sent now, retrying a failing send up to 3 times after the first attempt (4 attempts, waits 1 s,
     * 2 s, 4 s) through the injected sleeper; a bounce is not retried. Queued rows are sent by deliverDue, never by a timer.
     * In: NotificationRequest. Out: SendResponse(success, messageId, status sent|queued|skipped|failed).
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-02/05/12): defaults (SMS off, no quiet hours), queued
     * rows carry scheduled_at, injected clock and sleeper, emails carry a signed unsubscribe link.
     * Touches: the database; the senders (network).
     */
    public SendResponse sendSingle(NotificationRequest request) {
        String messageId = UUID.randomUUID().toString();
        LocalDateTime now = now();
        UserNotificationPreferences prefs = getUserPreferences(request.userId);
        if (prefs == null) {
            prefs = defaultPreferences(request.userId);
        }
        if (prefs.doNotDisturb) {
            logMessage(messageId, request, request.channel, "skipped", null, null, null, false, "Do-not-disturb");
            return new SendResponse(true, messageId, "skipped");
        }
        String channel = request.channel;
        if (channel == null) {
            channel = selectChannel(prefs, null);
        }
        if (channel == null || !isChannelEnabled(prefs, channel)) {
            logMessage(messageId, request, channel, "skipped", null, null, null, false, "Channel disabled");
            return new SendResponse(true, messageId, "skipped");
        }
        if (request.scheduledAt != null && request.scheduledAt.isAfter(now)) {
            logQueued(messageId, request, channel, request.scheduledAt);
            return new SendResponse(true, messageId, "queued");
        }
        if (isInQuietHours(prefs, now.toLocalTime())) {
            logQueued(messageId, request, channel, quietHoursEnd(prefs, now));
            return new SendResponse(true, messageId, "queued");
        }
        NotificationTemplate template = getTemplate(request.templateKey);
        if (template == null) {
            logMessage(messageId, request, channel, "failed", null, null, null, false, "Template not found");
            return new SendResponse(false, messageId, "failed");
        }
        DeliveryOutcome outcome = deliver(request.userId, channel, template, request.vars);
        if (outcome.success) {
            logMessage(messageId, request, channel, "sent", now, null, null, false, null);
            return new SendResponse(true, messageId, "sent");
        }
        logMessage(messageId, request, channel, outcome.bounced ? "bounced" : "failed", now, null, null, outcome.bounced, outcome.error);
        return new SendResponse(false, messageId, "failed");
    }

    /** Result of one delivery with retries. */
    private static final class DeliveryOutcome {
        final boolean success;
        final boolean bounced;
        final String error;

        DeliveryOutcome(boolean success, boolean bounced, String error) {
            this.success = success;
            this.bounced = bounced;
            this.error = error;
        }
    }

    /** Most attempts for one email/SMS send: the first plus 3 retries (NOTIF-08, amended 2026-11-10 Phase B.2). */
    public static final int MAX_ATTEMPTS = 4;

    /**
     * Renders the template and sends it on the channel, retrying a failure up to 3 times after the first attempt (at
     * most 4 attempts) with 1 s, 2 s and 4 s waits; an email's body ends with the user's signed unsubscribe link.
     * In: user id, channel, template, vars. Out: the outcome (failed after the 4th failure).
     * Split out of sendSingle 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, so deliverDue sends the same way.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-08, Phase B.2: "retry up to 3 times after the first
     * attempt", the same counting as background jobs): it made 3 attempts in all. Touches: the senders (network).
     */
    private DeliveryOutcome deliver(long userId, String channel, NotificationTemplate template, Map<String, Object> vars) {
        String body = renderTemplate(template.bodyText, vars);
        String subject = template.subject != null ? renderTemplate(template.subject, vars) : null;
        if ("email".equals(channel)) {
            body = body + "\n\nUnsubscribe: " + unsubscribeLink(userId, "email");
        }
        String error = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                if (channel.equals("email")) {
                    emailSender.send(userId + "@example.com", subject, body);
                } else if (channel.equals("sms")) {
                    smsSender.send(userId + "@example.com", body);
                } else if (channel.equals("in_app")) {
                    inAppSender.send(userId, body);
                }
                return new DeliveryOutcome(true, false, null);
            } catch (BounceException be) {
                return new DeliveryOutcome(false, true, be.getMessage());
            } catch (Exception e) {
                error = e.getMessage();
                if (attempt < MAX_ATTEMPTS) {
                    sleeper.accept(1000L << (attempt - 1));   // 1 s, 2 s, 4 s
                }
            }
        }
        return new DeliveryOutcome(false, false, error);
    }

    /** The next moment the quiet window ends (today or tomorrow), the scheduled_at of a message held by quiet hours. */
    private LocalDateTime quietHoursEnd(UserNotificationPreferences prefs, LocalDateTime now) {
        LocalTime end = LocalTime.parse(prefs.quietHoursEnd);
        LocalDateTime candidate = now.toLocalDate().atTime(end);
        return candidate.isAfter(now) ? candidate : candidate.plusDays(1);
    }

    /** Writes a 'queued' row with its scheduled_at. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database. */
    private void logQueued(String messageId, NotificationRequest request, String channel, LocalDateTime scheduledAt) {
        logMessage(messageId, request, channel, "queued", null, null, null, false, null);
        try (PreparedStatement ps = conn.prepareStatement("UPDATE notification_logs SET scheduled_at = ? WHERE id = ?")) {
            ps.setTimestamp(1, Timestamp.valueOf(scheduledAt));
            ps.setString(2, messageId);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("could not queue notification", e);
        }
    }

    /**
     * deliver_due(now): sends queued messages whose time has come, never from an in-process timer. Steps, in order:
     * (1) 'sending' rows claimed more than 300 s ago go back to 'queued' (a crashed worker); (2) 'queued' rows with
     * scheduled_at <= now, by scheduled_at then insertion order, are claimed one by one with a conditional UPDATE
     * (a row another worker claimed first is skipped); (3) preferences are read NOW: do-not-disturb, an unsubscribed
     * or disabled channel -> 'skipped'; inside the user's quiet hours (UTC, may cross midnight) -> back to 'queued'
     * with scheduled_at = quiet_hours_end, unsent; (4) the final write is conditional on the same claim.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-05, Phase B.2: step 3 re-queues a due message that
     * falls inside quiet hours; it was sent).
     * In: now (the caller's clock). Out: how many messages were sent. Each message is sent exactly once when no
     * worker crashes, at least once after a crash. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-12).
     * Touches: the database; the senders (network).
     */
    public synchronized int deliverDue(LocalDateTime now) {
        Timestamp nowTs = Timestamp.valueOf(now);
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE notification_logs SET status = 'queued', claimed_at = NULL WHERE status = 'sending' AND claimed_at < ?")) {
            ps.setTimestamp(1, Timestamp.valueOf(now.minus(CLAIM_TIMEOUT)));
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("deliver_due: re-queue failed", e);
        }
        List<String> due = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id FROM notification_logs WHERE status = 'queued' AND scheduled_at <= ? ORDER BY scheduled_at, seq")) {
            ps.setTimestamp(1, nowTs);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) due.add(rs.getString(1));
            }
        } catch (SQLException e) {
            throw new IllegalStateException("deliver_due: select failed", e);
        }
        int sent = 0;
        for (String id : due) {
            Timestamp claim = nowTs;
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE notification_logs SET status = 'sending', claimed_at = ? WHERE id = ? AND status = 'queued'")) {
                ps.setTimestamp(1, claim);
                ps.setString(2, id);
                if (ps.executeUpdate() == 0) continue;
            } catch (SQLException e) {
                throw new IllegalStateException("deliver_due: claim failed", e);
            }
            long userId;
            String channel;
            String templateKey;
            String varsJson;
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT user_id, channel, template_key, vars_used FROM notification_logs WHERE id = ?")) {
                ps.setString(1, id);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    userId = rs.getLong(1);
                    channel = rs.getString(2);
                    templateKey = rs.getString(3);
                    varsJson = rs.getString(4);
                }
            } catch (SQLException e) {
                throw new IllegalStateException("deliver_due: read failed", e);
            }
            UserNotificationPreferences prefs = getUserPreferences(userId);
            if (prefs == null) prefs = defaultPreferences(userId);
            String finalStatus;
            String error = null;
            boolean bounced = false;
            NotificationTemplate template = getTemplate(templateKey);
            if (prefs.doNotDisturb || channel == null || !isChannelEnabled(prefs, channel)) {
                finalStatus = "skipped";
            } else if (isInQuietHours(prefs, now.toLocalTime())) {
                // Step 3: still inside the user's quiet hours -> back to 'queued' until the window ends.
                try (PreparedStatement ps = conn.prepareStatement(
                        "UPDATE notification_logs SET status = 'queued', claimed_at = NULL, scheduled_at = ? WHERE id = ? AND status = 'sending' AND claimed_at = ?")) {
                    ps.setTimestamp(1, Timestamp.valueOf(quietHoursEnd(prefs, now)));
                    ps.setString(2, id);
                    ps.setTimestamp(3, claim);
                    ps.executeUpdate();
                } catch (SQLException e) {
                    throw new IllegalStateException("deliver_due: re-queue for quiet hours failed", e);
                }
                continue;
            } else if (template == null) {
                finalStatus = "failed";
                error = "Template not found";
            } else {
                DeliveryOutcome outcome = deliver(userId, channel, template, parseVars(varsJson));
                finalStatus = outcome.success ? "sent" : (outcome.bounced ? "bounced" : "failed");
                error = outcome.error;
                bounced = outcome.bounced;
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE notification_logs SET status = ?, sent_at = ?, error = ?, bounced = ? WHERE id = ? AND status = 'sending' AND claimed_at = ?")) {
                ps.setString(1, finalStatus);
                ps.setTimestamp(2, "skipped".equals(finalStatus) ? null : nowTs);
                ps.setString(3, error);
                ps.setBoolean(4, bounced);
                ps.setString(5, id);
                ps.setTimestamp(6, claim);
                if (ps.executeUpdate() == 1 && "sent".equals(finalStatus)) sent++;
            } catch (SQLException e) {
                throw new IllegalStateException("deliver_due: final write failed", e);
            }
        }
        return sent;
    }

    /** Reads a queued row's stored vars (JSON object) back; empty map for none. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> parseVars(String json) {
        if (json == null || json.isEmpty()) return new HashMap<>();
        try {
            return JSON.readValue(json, Map.class);
        } catch (Exception e) {
            return new HashMap<>();
        }
    }

    /**
     * The unsubscribe token: lowercase hex of HMAC-SHA256(secret, "unsubscribe:" + user_id + ":" + channel).
     * In: user id (as it appears in the link), channel. Out: 64 hex characters. Added 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-11). Touches: nothing.
     */
    public String unsubscribeToken(String userId, String channel) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(unsubscribeSecret, "HmacSHA256"));
            byte[] d = mac.doFinal(("unsubscribe:" + userId + ":" + channel).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(d);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** <base_url>/unsubscribe?user_id=<id>&channel=<channel>&token=<token>. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    public String unsubscribeLink(long userId, String channel) {
        return baseUrl + "/unsubscribe?user_id=" + userId + "&channel=" + channel + "&token="
                + unsubscribeToken(String.valueOf(userId), channel);
    }

    /** An HTTP-shaped answer of the unsubscribe handler. */
    public static final class HandlerResponse {
        public final int status;
        public final Map<String, Object> body;

        public HandlerResponse(int status, Map<String, Object> body) {
            this.status = status;
            this.body = body;
        }
    }

    /**
     * The unsubscribe link handler. The token, the channel and the user id are checked BEFORE any user lookup: a token
     * that is not exactly 64 characters of [0-9a-f], an unknown channel, or a token that does not match (compared in
     * constant time) all get the same 403 {error: "invalid_unsubscribe_token"}. GET only answers 200 with a
     * confirmation (a mail scanner following links changes nothing); POST sets channels_enabled[channel] = false.
     * In: HTTP method, the link's user_id, channel and token. Out: HandlerResponse. Added 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-11: an unsigned link let anyone unsubscribe anyone). Touches: the
     * database (POST only).
     */
    public HandlerResponse handleUnsubscribe(String method, String userId, String channel, String token) {
        HandlerResponse refused = new HandlerResponse(403, Map.of("error", "invalid_unsubscribe_token"));
        if (token == null || !TOKEN_FORMAT.matcher(token).matches() || channel == null || !CHANNELS.contains(channel)
                || userId == null || !userId.matches("^[0-9]{1,18}$")) {
            return refused;
        }
        byte[] expected = unsubscribeToken(userId, channel).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        if (!java.security.MessageDigest.isEqual(expected, token.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
            return refused;
        }
        long uid = Long.parseLong(userId);
        if ("GET".equalsIgnoreCase(method)) {
            return new HandlerResponse(200, Map.of("confirm", true, "user_id", uid, "channel", channel,
                    "message", "Press the button to unsubscribe from " + channel + " notifications."));
        }
        if (!"POST".equalsIgnoreCase(method)) {
            return new HandlerResponse(405, Map.of("error", "method_not_allowed"));
        }
        setChannelEnabled(uid, channel, false);
        return new HandlerResponse(200, Map.of("success", true, "user_id", uid, "channel", channel, "unsubscribed", true));
    }

    /** Sets one channel on or off, starting from the defaults for a user with no saved preferences. Touches: the database. */
    private void setChannelEnabled(long userId, String channel, boolean enabled) {
        UserNotificationPreferences prefs = getUserPreferences(userId);
        if (prefs == null) prefs = defaultPreferences(userId);
        prefs.channelsEnabled = new HashMap<>(prefs.channelsEnabled);
        prefs.channelsEnabled.put(channel, enabled);
        updateUserPreferences(userId, prefs);
    }

    public BatchSendResponse sendBatch(List<NotificationRequest> requests) {
        int sent = 0;
        int failed = 0;
        List<String> messageIds = new ArrayList<>();
        for (NotificationRequest req : requests) {
            SendResponse resp = sendSingle(req);
            messageIds.add(resp.messageId);
            if (resp.status.equals("sent") || resp.status.equals("queued")) {
                sent++;
            } else {
                failed++;
            }
        }
        return new BatchSendResponse(true, sent, failed, messageIds);
    }

    public TrackResponse track(String messageId) {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT * FROM notification_logs WHERE id = ?")) {
            ps.setString(1, messageId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return new TrackResponse(
                            rs.getString("id"),
                            rs.getLong("user_id"),
                            rs.getString("template_key"),
                            rs.getString("channel"),
                            rs.getString("status"),
                            rs.getTimestamp("sent_at") != null ? rs.getTimestamp("sent_at").toLocalDateTime() : null,
                            rs.getTimestamp("opened_at") != null ? rs.getTimestamp("opened_at").toLocalDateTime() : null,
                            rs.getTimestamp("clicked_at") != null ? rs.getTimestamp("clicked_at").toLocalDateTime() : null
                    );
                }
            }
        } catch (SQLException e) {
            logger.severe("Track error: " + e.getMessage());
        }
        return null;
    }

    public UserNotificationPreferences getUserPreferences(long userId) {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT * FROM user_notification_preferences WHERE user_id = ?")) {
            ps.setLong(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    Map<String, Boolean> channels = parseChannelsEnabled(rs.getString("channels_enabled"));
                    return new UserNotificationPreferences(
                            rs.getLong("user_id"),
                            rs.getBoolean("do_not_disturb"),
                            rs.getString("quiet_hours_start"),
                            rs.getString("quiet_hours_end"),
                            channels
                    );
                }
            }
        } catch (SQLException e) {
            logger.severe("Get prefs error: " + e.getMessage());
        }
        return null;
    }

    public boolean updateUserPreferences(long userId, UserNotificationPreferences prefs) {
        try (PreparedStatement ps = conn.prepareStatement(
                "MERGE INTO user_notification_preferences KEY(user_id) VALUES (?,?,?,?,?)")) {
            ps.setLong(1, userId);
            ps.setBoolean(2, prefs.doNotDisturb);
            ps.setString(3, prefs.quietHoursStart);
            ps.setString(4, prefs.quietHoursEnd);
            ps.setString(5, toJson(prefs.channelsEnabled));
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            logger.severe("Update prefs error: " + e.getMessage());
            return false;
        }
    }

    /**
     * Records that a message was opened (tracking pixel or link): sets opened_at and status 'opened' the first time
     * only; a second call, or an unknown id, changes nothing. In: message id. Out: none.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-07, Phase B.2): it overwrote opened_at on every call
     * and never set the status. Touches: the database.
     */
    public void openMessage(String messageId) {
        if (messageId == null) return;
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE notification_logs SET opened_at = ?, status = 'opened' WHERE id = ? AND opened_at IS NULL")) {
            ps.setTimestamp(1, Timestamp.valueOf(now()));
            ps.setString(2, messageId);
            ps.executeUpdate();
        } catch (SQLException e) {
            logger.severe("Open error: " + e.getMessage());
        }
    }

    /**
     * GET /notifications/open/:message_id (this template has no router, so the route is this method): records the
     * open once through openMessage and answers 204 with no body either way, so the reply never says whether the id
     * exists. In: HTTP method, message id. Out: HandlerResponse 204 (405 for a method other than GET).
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (NOTIF-07, Phase B.2). Touches: the database.
     */
    public HandlerResponse handleOpen(String method, String messageId) {
        if (!"GET".equals(method)) {
            return new HandlerResponse(405, Map.of("error", "method_not_allowed"));
        }
        openMessage(messageId);
        return new HandlerResponse(204, Map.of());
    }

    public void clickMessage(String messageId) {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE notification_logs SET clicked_at = ? WHERE id = ?")) {
            ps.setTimestamp(1, Timestamp.valueOf(now()));
            ps.setString(2, messageId);
            ps.executeUpdate();
        } catch (SQLException e) {
            logger.severe("Click error: " + e.getMessage());
        }
    }

    /**
     * Turns off the email channel for a user (the unsubscribe link). A user with no saved preferences gets the
     * defaults with email off. Input: user id. Output: none.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: a user without saved preferences stayed
     * subscribed. Touches: the database.
     */
    public void unsubscribeEmail(long userId) {
        setChannelEnabled(userId, "email", false);
    }

    /**
     * Loads a template by key, or null. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: column
     * renamed to template_key. Touches: reads the database.
     */
    private NotificationTemplate getTemplate(String key) {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT * FROM notification_templates WHERE template_key = ?")) {
            ps.setString(1, key);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return new NotificationTemplate(
                            rs.getString("template_key"),
                            rs.getString("subject"),
                            rs.getString("body_text"),
                            rs.getString("body_html"),
                            rs.getString("channels_default"),
                            rs.getString("variables")
                    );
                }
            }
        } catch (SQLException e) {
            logger.severe("Get template error: " + e.getMessage());
        }
        return null;
    }

    /**
     * Writes one notification_logs row. Input: message id, request, the channel used (may be null when no
     * channel was chosen), status, timestamps, bounce flag, error text. Output: none (SQL errors are logged).
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: takes the channel actually used; the
     * status column it writes now exists. Touches: the database.
     */
    private void logMessage(String messageId, NotificationRequest request, String channel, String status,
                            LocalDateTime sentAt, LocalDateTime openedAt, LocalDateTime clickedAt,
                            boolean bounced, String error) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO notification_logs (id, user_id, template_key, channel, vars_used, sent_at, opened_at, clicked_at, bounced, error, status) VALUES (?,?,?,?,?,?,?,?,?,?,?)")) {
            ps.setString(1, messageId);
            ps.setLong(2, request.userId);
            ps.setString(3, request.templateKey);
            ps.setString(4, channel);
            ps.setString(5, request.vars != null ? toJson(request.vars) : null);
            ps.setTimestamp(6, sentAt != null ? Timestamp.valueOf(sentAt) : null);
            ps.setTimestamp(7, openedAt != null ? Timestamp.valueOf(openedAt) : null);
            ps.setTimestamp(8, clickedAt != null ? Timestamp.valueOf(clickedAt) : null);
            ps.setBoolean(9, bounced);
            ps.setString(10, error);
            ps.setString(11, status);
            ps.executeUpdate();
        } catch (SQLException e) {
            logger.severe("Log error: " + e.getMessage());
        }
    }

    /** True inside [start, end) of the quiet window (it may wrap midnight); no window when either end is unset. */
    private boolean isInQuietHours(UserNotificationPreferences prefs, LocalTime now) {
        if (prefs.quietHoursStart == null || prefs.quietHoursEnd == null) return false;
        LocalTime start = LocalTime.parse(prefs.quietHoursStart);
        LocalTime end = LocalTime.parse(prefs.quietHoursEnd);
        if (start.equals(end)) return false;
        if (start.isBefore(end)) {
            return !now.isBefore(start) && now.isBefore(end);
        } else {
            return !now.isBefore(start) || now.isBefore(end);
        }
    }

    private boolean isChannelEnabled(UserNotificationPreferences prefs, String channel) {
        return prefs.channelsEnabled.getOrDefault(channel, false);
    }

    private String selectChannel(UserNotificationPreferences prefs, String requested) {
        if (requested != null) return requested;
        if (prefs.channelsEnabled.getOrDefault("email", false)) return "email";
        if (prefs.channelsEnabled.getOrDefault("sms", false)) return "sms";
        if (prefs.channelsEnabled.getOrDefault("in_app", false)) return "in_app";
        return null;
    }

    /**
     * Simple {variable} substitution. Input: template text, vars (may be null). Output: rendered text.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: null vars or values no longer throw.
     * Touches: nothing (pure).
     */
    private String renderTemplate(String template, Map<String, Object> vars) {
        if (template == null) return null;
        if (vars == null) return template;
        String result = template;
        for (Map.Entry<String, Object> e : vars.entrySet()) {
            result = result.replace("{" + e.getKey() + "}", String.valueOf(e.getValue()));
        }
        return result;
    }

    private Map<String, Boolean> parseChannelsEnabled(String json) {
        Map<String, Boolean> map = new HashMap<>();
        if (json == null || json.isEmpty()) return map;
        json = json.trim();
        if (json.startsWith("{") && json.endsWith("}")) {
            json = json.substring(1, json.length() - 1);
            String[] pairs = json.split(",");
            for (String pair : pairs) {
                String[] kv = pair.split(":");
                if (kv.length == 2) {
                    String key = kv[0].trim().replaceAll("\"", "");
                    String val = kv[1].trim();
                    boolean boolVal = val.equalsIgnoreCase("true");
                    map.put(key, boolVal);
                }
            }
        }
        return map;
    }

    /**
     * Serializes a flat map (preferences' channels_enabled, or a request's vars) to a JSON object. Numbers and
     * booleans are written bare, null as null, everything else as an escaped JSON string.
     * Input: map with String keys. Output: JSON text.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: replaces two overloads whose erasures
     * clashed (the file did not compile); keys and string values are now escaped, so a quote in a variable
     * cannot break or inject into the stored JSON. Touches: nothing (pure).
     */
    private static String toJson(Map<String, ?> map) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        boolean first = true;
        for (Map.Entry<String, ?> e : map.entrySet()) {
            if (!first) sb.append(",");
            appendJsonString(sb, e.getKey());
            sb.append(":");
            Object val = e.getValue();
            if (val == null) {
                sb.append("null");
            } else if (val instanceof Number || val instanceof Boolean) {
                sb.append(val);
            } else {
                appendJsonString(sb, val.toString());
            }
            first = false;
        }
        sb.append("}");
        return sb.toString();
    }

    /**
     * Appends s as a quoted JSON string, escaping quotes, backslashes and control characters.
     * Added 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing (pure).
     */
    private static void appendJsonString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }

    // Data classes
    public static class NotificationRequest {
        public long userId;
        public String templateKey;
        public String channel; // email, sms, in_app, or null
        public Map<String, Object> vars;
        public LocalDateTime scheduledAt; // null or future

        public NotificationRequest(long userId, String templateKey, String channel,
                                   Map<String, Object> vars, LocalDateTime scheduledAt) {
            this.userId = userId;
            this.templateKey = templateKey;
            this.channel = channel;
            this.vars = vars;
            this.scheduledAt = scheduledAt;
        }
    }

    public static class SendResponse {
        public boolean success;
        public String messageId;
        public String status; // sent|queued|failed|skipped

        public SendResponse(boolean success, String messageId, String status) {
            this.success = success;
            this.messageId = messageId;
            this.status = status;
        }
    }

    public static class BatchSendResponse {
        public boolean success;
        public int sent;
        public int failed;
        public List<String> messageIds;

        public BatchSendResponse(boolean success, int sent, int failed, List<String> messageIds) {
            this.success = success;
            this.sent = sent;
            this.failed = failed;
            this.messageIds = messageIds;
        }
    }

    public static class TrackResponse {
        public String messageId;
        public long userId;
        public String templateKey;
        public String channel;
        public String status;
        public LocalDateTime sentAt;
        public LocalDateTime openedAt;
        public LocalDateTime clickedAt;

        public TrackResponse(String messageId, long userId, String templateKey, String channel,
                             String status, LocalDateTime sentAt, LocalDateTime openedAt, LocalDateTime clickedAt) {
            this.messageId = messageId;
            this.userId = userId;
            this.templateKey = templateKey;
            this.channel = channel;
            this.status = status;
            this.sentAt = sentAt;
            this.openedAt = openedAt;
            this.clickedAt = clickedAt;
        }
    }

    public static class UserNotificationPreferences {
        public long userId;
        public boolean doNotDisturb;
        public String quietHoursStart; // HH:mm
        public String quietHoursEnd;   // HH:mm
        public Map<String, Boolean> channelsEnabled; // email, sms, in_app

        public UserNotificationPreferences(long userId, boolean doNotDisturb,
                                           String quietHoursStart, String quietHoursEnd,
                                           Map<String, Boolean> channelsEnabled) {
            this.userId = userId;
            this.doNotDisturb = doNotDisturb;
            this.quietHoursStart = quietHoursStart;
            this.quietHoursEnd = quietHoursEnd;
            this.channelsEnabled = channelsEnabled;
        }
    }

    public static class NotificationTemplate {
        public String key;
        public String subject;
        public String bodyText;
        public String bodyHtml;
        public String channelsDefault;
        public String variables; // JSON array

        public NotificationTemplate(String key, String subject, String bodyText,
                                    String bodyHtml, String channelsDefault, String variables) {
            this.key = key;
            this.subject = subject;
            this.bodyText = bodyText;
            this.bodyHtml = bodyHtml;
            this.channelsDefault = channelsDefault;
            this.variables = variables;
        }
    }

    // Sender interfaces
    public interface EmailSender {
        void send(String to, String subject, String body) throws Exception;
    }

    public interface SmsSender {
        void send(String to, String body) throws Exception;
    }

    public interface InAppSender {
        void send(long userId, String body);
    }

    /**
     * In-memory stand-ins for the three senders: they accept and drop the message, so the template runs with
     * no SMTP/SMS provider and no network. Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: they
     * logged recipients and message bodies at INFO; they now log nothing personal. Touches: nothing.
     */
    public static class SimpleEmailSender implements EmailSender {
        @Override
        public void send(String to, String subject, String body) throws Exception {
            // In-memory stand-in: sends nothing. Message contents are not logged (they can hold personal data).
            logger.fine("Email accepted by the in-memory sender");
        }
    }

    public static class SimpleSmsSender implements SmsSender {
        @Override
        public void send(String to, String body) throws Exception {
            // In-memory stand-in: sends nothing. Message contents are not logged (they can hold personal data).
            logger.fine("SMS accepted by the in-memory sender");
        }
    }

    public static class SimpleInAppSender implements InAppSender {
        @Override
        public void send(long userId, String body) {
            // In-memory stand-in: a real one stores it for the user's inbox. Contents are not logged.
            logger.fine("In-app notification accepted by the in-memory sender");
        }
    }

    // Custom exception for bounce
    public static class BounceException extends Exception {
        public BounceException(String message) {
            super(message);
        }
    }
}