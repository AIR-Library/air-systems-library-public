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
    private final Connection conn;
    private final EmailSender emailSender;
    private final SmsSender smsSender;
    private final InAppSender inAppSender;

    /**
     * Creates a service with the in-memory stand-in senders and its own private in-memory database.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: one database per instance (a shared
     * "test" database made the second instance fail on duplicate templates). Touches: in-memory H2.
     */
    public NotificationService() throws SQLException {
        this.conn = DriverManager.getConnection(newDatabaseUrl());
        this.emailSender = new SimpleEmailSender();
        this.smsSender = new SimpleSmsSender();
        this.inAppSender = new SimpleInAppSender();
        initDatabase();
        seedTemplates();
    }

    /**
     * Creates a service with the given senders (real or fake) and its own private in-memory database.
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: one database per instance.
     * Touches: in-memory H2; the senders.
     */
    public NotificationService(EmailSender emailSender, SmsSender smsSender, InAppSender inAppSender) throws SQLException {
        this.conn = DriverManager.getConnection(newDatabaseUrl());
        this.emailSender = emailSender;
        this.smsSender = smsSender;
        this.inAppSender = inAppSender;
        initDatabase();
        seedTemplates();
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
                    "status VARCHAR(20)" +
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

    /**
     * Sends one notification, honouring do-not-disturb (skipped), quiet hours (queued), disabled channels
     * (skipped) and scheduled_at (queued); retries a failing email/SMS/in-app send up to 3 attempts with
     * exponential backoff (1s, 2s); a bounce is not retried. Every outcome is logged.
     * Input: NotificationRequest. Output: SendResponse(success, messageId, status sent|queued|skipped|failed).
     * Repaired 2026-11-10, session session_012zDydZCZ4AChqhEZ4oVtaP: the log now records the channel actually
     * used (it recorded null for auto-selected channels). Touches: the database; the senders.
     */
    public SendResponse sendSingle(NotificationRequest request) {
        String messageId = UUID.randomUUID().toString();
        LocalDateTime now = LocalDateTime.now();
        UserNotificationPreferences prefs = getUserPreferences(request.userId);
        if (prefs == null) {
            prefs = new UserNotificationPreferences(request.userId, false, "00:00", "00:00",
                    Map.of("email", true, "sms", true, "in_app", true));
        }
        if (prefs.doNotDisturb) {
            logMessage(messageId, request, request.channel, "skipped", null, null, null, false, "Do-not-disturb");
            return new SendResponse(true, messageId, "skipped");
        }
        if (isInQuietHours(prefs, now.toLocalTime())) {
            logMessage(messageId, request, request.channel, "queued", null, null, null, false, null);
            return new SendResponse(true, messageId, "queued");
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
            logMessage(messageId, request, channel, "queued", null, null, null, false, null);
            return new SendResponse(true, messageId, "queued");
        }
        NotificationTemplate template = getTemplate(request.templateKey);
        if (template == null) {
            logMessage(messageId, request, channel, "failed", null, null, null, false, "Template not found");
            return new SendResponse(false, messageId, "failed");
        }
        String body = renderTemplate(template.bodyText, request.vars);
        String subject = template.subject != null ? renderTemplate(template.subject, request.vars) : null;
        boolean success = false;
        String error = null;
        boolean bounced = false;
        int attempts = 0;
        while (attempts < 3 && !success) {
            try {
                attempts++;
                if (channel.equals("email")) {
                    emailSender.send(request.userId + "@example.com", subject, body);
                } else if (channel.equals("sms")) {
                    smsSender.send(request.userId + "@example.com", body);
                } else if (channel.equals("in_app")) {
                    inAppSender.send(request.userId, body);
                }
                success = true;
            } catch (BounceException be) {
                bounced = true;
                error = be.getMessage();
                break;
            } catch (Exception e) {
                error = e.getMessage();
                if (attempts < 3) {
                    try { Thread.sleep((long) Math.pow(2, attempts - 1) * 1000); } catch (InterruptedException ie) {}
                }
            }
        }
        if (success) {
            logMessage(messageId, request, channel, "sent", now, null, null, bounced, error);
            return new SendResponse(true, messageId, "sent");
        } else {
            logMessage(messageId, request, channel, bounced ? "bounced" : "failed", now, null, null, bounced, error);
            return new SendResponse(false, messageId, "failed");
        }
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

    public void openMessage(String messageId) {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE notification_logs SET opened_at = ? WHERE id = ?")) {
            ps.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
            ps.setString(2, messageId);
            ps.executeUpdate();
        } catch (SQLException e) {
            logger.severe("Open error: " + e.getMessage());
        }
    }

    public void clickMessage(String messageId) {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE notification_logs SET clicked_at = ? WHERE id = ?")) {
            ps.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
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
        UserNotificationPreferences prefs = getUserPreferences(userId);
        if (prefs == null) {
            prefs = new UserNotificationPreferences(userId, false, "00:00", "00:00",
                    new HashMap<>(Map.of("email", true, "sms", true, "in_app", true)));
        }
        prefs.channelsEnabled.put("email", false);
        updateUserPreferences(userId, prefs);
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

    private boolean isInQuietHours(UserNotificationPreferences prefs, LocalTime now) {
        LocalTime start = LocalTime.parse(prefs.quietHoursStart);
        LocalTime end = LocalTime.parse(prefs.quietHoursEnd);
        if (start.equals(end)) return false;
        if (start.isBefore(end)) {
            return !now.isBefore(start) && !now.isAfter(end);
        } else {
            return !now.isBefore(start) || !now.isAfter(end);
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