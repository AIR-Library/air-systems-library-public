import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;

/**
 * Data export and account deletion for a SaaS application (GDPR right of access and portability, right to be forgotten;
 * CCPA access and deletion requests). Same system as the other seven languages in this library.
 *
 * <p>What it does:
 * <ul>
 *   <li>A user asks for their data as JSON or CSV. The file is built in the background, stored encrypted at rest, and
 *       the user gets an e-mail with a download link that works for 7 days.</li>
 *   <li>A user asks to delete their account. They confirm through a link sent by e-mail, then have a 30 day grace period
 *       in which they can cancel. After that, {@link #executeScheduledDeletions()} removes their data.</li>
 *   <li>Every request and outcome goes to the audit log. Admins can list both kinds of request.</li>
 * </ul>
 *
 * <p>Inputs and outputs: every outside service is an interface passed to the constructor (see {@link Services}), so this
 * class runs on any storage or mail provider. Methods return small records and throw {@link ComplianceException}, whose
 * {@code code()} is a stable word a route can turn into an HTTP status.
 *
 * <p>Choices made for safety, which a copy should keep:
 * <ul>
 *   <li>The confirmation token is stored only as a SHA-256 hash, and compared in constant time.</li>
 *   <li>A download link is a bearer secret, so it never goes into the audit log, and only the owner or an admin can read
 *       the export's status. Anyone else gets "not_found", so ids cannot be probed.</li>
 *   <li>CSV cells that a spreadsheet would run as a formula are neutralized.</li>
 *   <li>Error messages stay out of the audit log, because they can quote user data. Only the error's type is kept.</li>
 * </ul>
 *
 * <p>Why it exists: this file was 1,180 import lines and no code from the first public release until 2026-11-05 (AIR
 * record finding:2026-11-05:3a00300d16). Written that day by session f3daac6e-b278-43cb-9d78-1188871af05a from the
 * library's system spec and the Python version.
 *
 * <p>Touches: the database (tables export_requests and deletion_requests, see {@link #createTables()}), object storage,
 * outgoing e-mail, the audit log, and the application's user data, which {@link #executeScheduledDeletions()} erases.
 */
public class DataExportCompliance {

    /** How long a download link works. */
    public static final Duration DOWNLOAD_LINK_TTL = Duration.ofDays(7);
    /** The estimate shown to the user for when the e-mail will arrive. */
    public static final Duration EXPORT_ESTIMATE = Duration.ofMinutes(5);
    /** How long a user can change their mind before their data is erased. */
    public static final Duration GRACE_PERIOD = Duration.ofDays(30);

    public static final Set<String> FORMATS = Set.of("json", "csv");
    public static final Set<String> DELETION_REASONS =
            Set.of("user_requested", "gdpr_request", "gdpr_right_to_be_forgotten", "other");

    private static final int TOKEN_BYTES = 32;
    private static final String EXPORT_COLUMNS =
            "id, user_id, requested_at, status, format, file_url, completed_at, expires_at";
    private static final String DELETION_COLUMNS =
            "id, user_id, requested_at, status, reason, will_delete_at, deleted_at";

    /** Where an export stands. {@code value()} is the word stored in the database and shown to callers. */
    public enum ExportStatus {
        PENDING, COMPLETED, FAILED;

        public String value() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /** Where a deletion stands: pending until confirmed, approved until the grace period ends, then completed. */
    public enum DeletionStatus {
        PENDING, APPROVED, COMPLETED, CANCELLED;

        public String value() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /** A refused or failed request. {@code code()} is one of: invalid_format, invalid_reason, not_found, invalid_token,
     *  not_pending, cannot_cancel, grace_period_expired, forbidden, email_failed, storage_error. */
    public static class ComplianceException extends RuntimeException {
        private final String code;

        public ComplianceException(String code) {
            super(code);
            this.code = code;
        }

        public ComplianceException(String code, Throwable cause) {
            super(code, cause);
            this.code = code;
        }

        public String code() {
            return code;
        }
    }

    public record ExportReceipt(UUID exportId, ExportStatus status, Instant willEmailAt) {}

    public record ExportView(UUID exportId, UUID userId, Instant requestedAt, ExportStatus status, String format,
                             String fileUrl, Instant completedAt, Instant expiresAt) {}

    public record DeletionReceipt(UUID deletionId, DeletionStatus status, Instant willDeleteAt) {}

    public record DeletionView(UUID deletionId, UUID userId, Instant requestedAt, DeletionStatus status, String reason,
                               Instant willDeleteAt, Instant deletedAt) {}

    /** One page of an admin listing, with the number of rows it holds. */
    public record Listing<T>(List<T> items, int total) {}

    /** Where export files live. An implementation must encrypt at rest and sign links for download only. */
    public interface ObjectStore {
        void put(String key, byte[] body, String contentType) throws Exception;

        String signedDownloadUrl(String key, Duration validFor) throws Exception;
    }

    public interface EmailSender {
        void send(String to, String subject, String body) throws Exception;
    }

    public interface AuditLog {
        void record(String action, UUID userId, Map<String, String> details);
    }

    /** The application's own data about a user. */
    public interface UserData {
        /** Everything held on a user, by category: profile, sessions, activity, files (names and sizes, not contents),
         *  preferences, transactions and audit_trail. The profile must carry "email". */
        Map<String, Object> export(UUID userId) throws Exception;

        /** Erases the user from every table except the audit log, which the law requires to be kept. */
        void eraseAll(UUID userId) throws Exception;
    }

    public interface AdminCheck {
        boolean isAdmin(UUID userId);
    }

    /** Runs work outside the request, for example on a queue or a thread pool. */
    public interface TaskRunner {
        void run(Runnable task);
    }

    /** The outside services this class uses. */
    public record Services(ObjectStore store, EmailSender email, AuditLog audit, UserData users, AdminCheck admins,
                           TaskRunner tasks) {}

    private interface RowMapper<T> {
        T map(ResultSet row) throws SQLException;
    }

    private final DataSource db;
    private final Services services;
    private final Clock clock;
    private final String appBaseUrl;
    private final SecureRandom random = new SecureRandom();
    private final ObjectMapper json = new ObjectMapper();

    /**
     * @param db         the database holding the two tables
     * @param services   the outside services
     * @param clock      the time source; pass {@code Clock.systemUTC()} outside tests
     * @param appBaseUrl the site's address for links in e-mails, for example {@code https://app.example.com}
     */
    public DataExportCompliance(DataSource db, Services services, Clock clock, String appBaseUrl) {
        this.db = db;
        this.services = services;
        this.clock = clock;
        this.appBaseUrl = appBaseUrl.replaceAll("/+$", "");
    }

    /**
     * Creates the two tables if they are missing. Works on PostgreSQL and H2. {@code claimed_at} marks an export a worker
     * has taken, so it is built once even when a task runs twice. In a real deployment, run this as a migration.
     *
     * @throws ComplianceException storage_error when the database refuses
     */
    public void createTables() {
        try (Connection c = db.getConnection(); Statement s = c.createStatement()) {
            s.execute("""
                    CREATE TABLE IF NOT EXISTS export_requests (
                        id UUID PRIMARY KEY,
                        user_id UUID NOT NULL,
                        requested_at TIMESTAMP WITH TIME ZONE NOT NULL,
                        status VARCHAR(20) NOT NULL,
                        format VARCHAR(10) NOT NULL,
                        file_url TEXT,
                        claimed_at TIMESTAMP WITH TIME ZONE,
                        completed_at TIMESTAMP WITH TIME ZONE,
                        expires_at TIMESTAMP WITH TIME ZONE
                    )""");
            s.execute("""
                    CREATE TABLE IF NOT EXISTS deletion_requests (
                        id UUID PRIMARY KEY,
                        user_id UUID NOT NULL,
                        requested_at TIMESTAMP WITH TIME ZONE NOT NULL,
                        status VARCHAR(20) NOT NULL,
                        reason VARCHAR(50) NOT NULL,
                        confirmation_token_hash VARCHAR(64) NOT NULL,
                        will_delete_at TIMESTAMP WITH TIME ZONE NOT NULL,
                        deleted_at TIMESTAMP WITH TIME ZONE
                    )""");
        } catch (SQLException e) {
            throw new ComplianceException("storage_error", e);
        }
    }

    /* ---------- Export ---------- */

    /**
     * Records an export request and starts building it in the background. POST /compliance/export.
     *
     * @param userId the signed-in user
     * @param format "json" or "csv"
     * @return the new export's id, its status, and when the e-mail should arrive
     * @throws ComplianceException invalid_format
     */
    public ExportReceipt requestDataExport(UUID userId, String format) {
        if (format == null || !FORMATS.contains(format)) {
            throw new ComplianceException("invalid_format");
        }
        UUID exportId = UUID.randomUUID();
        Instant now = clock.instant();
        Instant willEmailAt = now.plus(EXPORT_ESTIMATE);
        update("INSERT INTO export_requests (id, user_id, requested_at, status, format) VALUES (?, ?, ?, ?, ?)",
                exportId, userId, now, ExportStatus.PENDING.value(), format);
        services.audit().record("data_export_requested", userId,
                Map.of("export_id", exportId.toString(), "format", format));
        services.tasks().run(() -> processExport(exportId));
        return new ExportReceipt(exportId, ExportStatus.PENDING, willEmailAt);
    }

    /**
     * Builds one export: reads the user's data, stores the file, signs a 7 day link, e-mails it. A failure marks the export
     * failed rather than throwing, because this runs in the background with nobody to catch it. A second call for the same
     * export does nothing.
     *
     * @param exportId the export to build
     */
    public void processExport(UUID exportId) {
        Instant now = clock.instant();
        int claimed = update("UPDATE export_requests SET claimed_at = ? WHERE id = ? AND status = ? AND claimed_at IS NULL",
                now, exportId, ExportStatus.PENDING.value());
        if (claimed == 0) {
            return;
        }
        ExportView export = findExport(exportId).orElseThrow(() -> new ComplianceException("not_found"));
        Map<String, Object> userData;
        String url;
        Instant expiresAt;
        try {
            userData = services.users().export(export.userId());
            boolean asJson = "json".equals(export.format());
            byte[] body = asJson ? toJson(userData) : toCsv(userData);
            String key = "exports/" + exportId + "." + export.format();
            services.store().put(key, body, asJson ? "application/json" : "text/csv");
            url = services.store().signedDownloadUrl(key, DOWNLOAD_LINK_TTL);
            Instant done = clock.instant();
            expiresAt = done.plus(DOWNLOAD_LINK_TTL);
            update("UPDATE export_requests SET status = ?, file_url = ?, completed_at = ?, expires_at = ? WHERE id = ?",
                    ExportStatus.COMPLETED.value(), url, done, expiresAt, exportId);
        } catch (Exception e) {
            update("UPDATE export_requests SET status = ?, completed_at = ? WHERE id = ?",
                    ExportStatus.FAILED.value(), clock.instant(), exportId);
            services.audit().record("data_export_failed", export.userId(),
                    Map.of("export_id", exportId.toString(), "error", e.getClass().getSimpleName()));
            return;
        }
        services.audit().record("data_export_completed", export.userId(), Map.of("export_id", exportId.toString()));
        emailDownloadLink(export.userId(), exportId, userData, url);
    }

    /** Sends the link. The file is ready even if this fails, and the status call still returns the link, so a mail
     *  problem is audited and does not fail the export. */
    private void emailDownloadLink(UUID userId, UUID exportId, Map<String, Object> userData, String url) {
        Optional<String> to = emailOf(userData);
        try {
            if (to.isEmpty()) {
                throw new IllegalStateException("profile has no e-mail address");
            }
            services.email().send(to.get(), "Your data export is ready",
                    "Download your data export: " + url + "\nThis link expires in 7 days.");
        } catch (Exception e) {
            services.audit().record("data_export_email_failed", userId,
                    Map.of("export_id", exportId.toString(), "error", e.getClass().getSimpleName()));
        }
    }

    /**
     * Reads one export. GET /compliance/exports/:export_id.
     *
     * @param exportId    the export
     * @param requesterId the signed-in user, who must be its owner or an admin
     * @return the export, with its download link once it is ready
     * @throws ComplianceException not_found, also when the requester may not see it
     */
    public ExportView getExportStatus(UUID exportId, UUID requesterId) {
        ExportView export = findExport(exportId).orElseThrow(() -> new ComplianceException("not_found"));
        if (!export.userId().equals(requesterId) && !services.admins().isAdmin(requesterId)) {
            throw new ComplianceException("not_found");
        }
        return export;
    }

    /* ---------- Deletion ---------- */

    /**
     * Records a deletion request and e-mails the confirmation link. Nothing is erased unless the user confirms, so a mail
     * failure leaves a harmless pending row and the user can ask again. POST /compliance/delete.
     *
     * @param userId the signed-in user
     * @param reason one of {@link #DELETION_REASONS}
     * @return the new request's id, its status, and when the data would go. The token is only ever in the e-mail.
     * @throws ComplianceException invalid_reason, or email_failed
     */
    public DeletionReceipt requestAccountDeletion(UUID userId, String reason) {
        if (reason == null || !DELETION_REASONS.contains(reason)) {
            throw new ComplianceException("invalid_reason");
        }
        Map<String, Object> userData;
        try {
            userData = services.users().export(userId);
        } catch (Exception e) {
            throw new ComplianceException("email_failed", e);
        }
        String to = emailOf(userData).orElseThrow(() -> new ComplianceException("email_failed"));

        UUID deletionId = UUID.randomUUID();
        Instant now = clock.instant();
        Instant willDeleteAt = now.plus(GRACE_PERIOD);
        String token = newToken();
        update("""
                INSERT INTO deletion_requests
                    (id, user_id, requested_at, status, reason, confirmation_token_hash, will_delete_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                deletionId, userId, now, DeletionStatus.PENDING.value(), reason, sha256(token), willDeleteAt);
        services.audit().record("deletion_requested", userId,
                Map.of("deletion_id", deletionId.toString(), "reason", reason));
        String link = appBaseUrl + "/compliance/delete/" + deletionId + "/confirm?token=" + token;
        try {
            services.email().send(to, "Confirm account deletion",
                    "Please confirm your deletion request: " + link + "\nThis link expires in 30 days.");
        } catch (Exception e) {
            throw new ComplianceException("email_failed", e);
        }
        return new DeletionReceipt(deletionId, DeletionStatus.PENDING, willDeleteAt);
    }

    /**
     * Confirms a deletion with the token from the e-mail, which proves the request came from the mailbox's owner. POST
     * /compliance/delete/:deletion_id/confirm.
     *
     * @param deletionId the request
     * @param token      the token from the link
     * @return when the data will be erased
     * @throws ComplianceException not_found, invalid_token, not_pending, grace_period_expired
     */
    public Instant confirmDeletion(UUID deletionId, String token) {
        List<String> hashes = query("SELECT confirmation_token_hash FROM deletion_requests WHERE id = ?",
                row -> row.getString(1), deletionId);
        if (hashes.isEmpty()) {
            throw new ComplianceException("not_found");
        }
        byte[] expected = hashes.get(0).getBytes(StandardCharsets.UTF_8);
        byte[] given = sha256(token == null ? "" : token).getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(expected, given)) {
            throw new ComplianceException("invalid_token");
        }
        DeletionView deletion = findDeletion(deletionId).orElseThrow(() -> new ComplianceException("not_found"));
        if (deletion.status() != DeletionStatus.PENDING) {
            throw new ComplianceException("not_pending");
        }
        if (clock.instant().isAfter(deletion.willDeleteAt())) {
            throw new ComplianceException("grace_period_expired");
        }
        int changed = update("UPDATE deletion_requests SET status = ? WHERE id = ? AND status = ?",
                DeletionStatus.APPROVED.value(), deletionId, DeletionStatus.PENDING.value());
        if (changed == 0) {
            throw new ComplianceException("not_pending");
        }
        services.audit().record("deletion_confirmed", deletion.userId(), Map.of("deletion_id", deletionId.toString()));
        return deletion.willDeleteAt();
    }

    /**
     * Cancels a deletion during the grace period. DELETE /compliance/delete/:deletion_id.
     *
     * @param deletionId  the request
     * @param requesterId the signed-in user, who must be its owner or an admin
     * @return the new status
     * @throws ComplianceException not_found, also when the requester may not see it; cannot_cancel; grace_period_expired
     */
    public DeletionStatus cancelDeletion(UUID deletionId, UUID requesterId) {
        DeletionView deletion = findDeletion(deletionId).orElseThrow(() -> new ComplianceException("not_found"));
        if (!deletion.userId().equals(requesterId) && !services.admins().isAdmin(requesterId)) {
            throw new ComplianceException("not_found");
        }
        if (deletion.status() != DeletionStatus.PENDING && deletion.status() != DeletionStatus.APPROVED) {
            throw new ComplianceException("cannot_cancel");
        }
        if (clock.instant().isAfter(deletion.willDeleteAt())) {
            throw new ComplianceException("grace_period_expired");
        }
        int changed = update("UPDATE deletion_requests SET status = ? WHERE id = ? AND status IN (?, ?)",
                DeletionStatus.CANCELLED.value(), deletionId,
                DeletionStatus.PENDING.value(), DeletionStatus.APPROVED.value());
        if (changed == 0) {
            throw new ComplianceException("cannot_cancel");
        }
        services.audit().record("deletion_cancelled", deletion.userId(), Map.of("deletion_id", deletionId.toString()));
        return DeletionStatus.CANCELLED;
    }

    /**
     * Erases every user whose confirmed request has reached the end of its grace period. Call this from a daily scheduled
     * job. An unconfirmed request never erases anything. If erasing one user fails, that request stays approved and is
     * tried again on the next run, and the others still go ahead.
     *
     * @return how many users were erased
     */
    public int executeScheduledDeletions() {
        Instant now = clock.instant();
        List<DeletionView> due = query("SELECT " + DELETION_COLUMNS
                        + " FROM deletion_requests WHERE status = ? AND will_delete_at <= ?",
                DataExportCompliance::toDeletion, DeletionStatus.APPROVED.value(), now);
        int erased = 0;
        for (DeletionView deletion : due) {
            Map<String, String> details = Map.of("deletion_id", deletion.deletionId().toString());
            try {
                services.users().eraseAll(deletion.userId());
            } catch (Exception e) {
                services.audit().record("deletion_failed", deletion.userId(),
                        Map.of("deletion_id", deletion.deletionId().toString(), "error", e.getClass().getSimpleName()));
                continue;
            }
            update("UPDATE deletion_requests SET status = ?, deleted_at = ? WHERE id = ?",
                    DeletionStatus.COMPLETED.value(), clock.instant(), deletion.deletionId());
            services.audit().record("deletion_completed", deletion.userId(), details);
            erased++;
        }
        return erased;
    }

    /* ---------- Admin ---------- */

    /**
     * Lists export requests, newest first. GET /admin/compliance/exports.
     *
     * @param adminId the signed-in admin
     * @param userId  only this user's exports, or null for everyone's
     * @param status  only this status, or null for all
     * @return the matching exports and their number
     * @throws ComplianceException forbidden
     */
    public Listing<ExportView> listExportRequests(UUID adminId, UUID userId, ExportStatus status) {
        requireAdmin(adminId);
        StringBuilder sql = new StringBuilder("SELECT " + EXPORT_COLUMNS + " FROM export_requests WHERE 1 = 1");
        List<Object> params = new ArrayList<>();
        if (userId != null) {
            sql.append(" AND user_id = ?");
            params.add(userId);
        }
        if (status != null) {
            sql.append(" AND status = ?");
            params.add(status.value());
        }
        sql.append(" ORDER BY requested_at DESC");
        List<ExportView> rows = query(sql.toString(), DataExportCompliance::toExport, params.toArray());
        return new Listing<>(rows, rows.size());
    }

    /**
     * Lists deletion requests, newest first. The token hash is never included. GET /admin/compliance/deletions.
     *
     * @param adminId the signed-in admin
     * @param status  only this status, or null for all
     * @return the matching requests and their number
     * @throws ComplianceException forbidden
     */
    public Listing<DeletionView> listDeletionRequests(UUID adminId, DeletionStatus status) {
        requireAdmin(adminId);
        String sql = "SELECT " + DELETION_COLUMNS + " FROM deletion_requests"
                + (status == null ? "" : " WHERE status = ?") + " ORDER BY requested_at DESC";
        Object[] params = status == null ? new Object[0] : new Object[] {status.value()};
        List<DeletionView> rows = query(sql, DataExportCompliance::toDeletion, params);
        return new Listing<>(rows, rows.size());
    }

    private void requireAdmin(UUID userId) {
        if (!services.admins().isAdmin(userId)) {
            throw new ComplianceException("forbidden");
        }
    }

    /* ---------- File formats ---------- */

    private byte[] toJson(Map<String, Object> userData) throws JsonProcessingException {
        return json.writerWithDefaultPrettyPrinter().writeValueAsBytes(userData);
    }

    /** One row per value: category, key, value. Nested maps become dotted keys, and list items repeat the key. */
    private static byte[] toCsv(Map<String, Object> userData) {
        StringBuilder out = new StringBuilder("category,key,value\n");
        for (Map.Entry<String, Object> category : userData.entrySet()) {
            appendRows(out, category.getKey(), "", category.getValue());
        }
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void appendRows(StringBuilder out, String category, String key, Object value) {
        if (value instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                appendRows(out, category, key.isEmpty() ? String.valueOf(entry.getKey()) : key + "." + entry.getKey(),
                        entry.getValue());
            }
        } else if (value instanceof Iterable<?> list) {
            for (Object item : list) {
                appendRows(out, category, key.isEmpty() && !(item instanceof Map) ? "item" : key, item);
            }
        } else {
            out.append(csvCell(category)).append(',')
                    .append(csvCell(key.isEmpty() ? "value" : key)).append(',')
                    .append(csvCell(String.valueOf(value))).append('\n');
        }
    }

    /** Quotes a cell when it needs it, and puts an apostrophe before anything a spreadsheet would run as a formula. A
     *  user controls much of this text, so an export must not be able to attack whoever opens it. */
    static String csvCell(String text) {
        String cell = text;
        if (!cell.isEmpty() && "=+-@\t\r".indexOf(cell.charAt(0)) >= 0 && !cell.matches("-?\\d+(\\.\\d+)?")) {
            cell = "'" + cell;
        }
        if (cell.contains(",") || cell.contains("\"") || cell.contains("\n") || cell.contains("\r")) {
            return "\"" + cell.replace("\"", "\"\"") + "\"";
        }
        return cell;
    }

    private static Optional<String> emailOf(Map<String, Object> userData) {
        if (userData.get("profile") instanceof Map<?, ?> profile && profile.get("email") instanceof String email
                && !email.isBlank()) {
            return Optional.of(email);
        }
        return Optional.empty();
    }

    /* ---------- Tokens ---------- */

    private String newToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String sha256(String text) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("every Java runtime has SHA-256", e);
        }
    }

    /* ---------- Database ---------- */

    private Optional<ExportView> findExport(UUID exportId) {
        return query("SELECT " + EXPORT_COLUMNS + " FROM export_requests WHERE id = ?",
                DataExportCompliance::toExport, exportId).stream().findFirst();
    }

    private Optional<DeletionView> findDeletion(UUID deletionId) {
        return query("SELECT " + DELETION_COLUMNS + " FROM deletion_requests WHERE id = ?",
                DataExportCompliance::toDeletion, deletionId).stream().findFirst();
    }

    private static ExportView toExport(ResultSet row) throws SQLException {
        return new ExportView(row.getObject("id", UUID.class), row.getObject("user_id", UUID.class),
                instant(row, "requested_at"), ExportStatus.valueOf(row.getString("status").toUpperCase(Locale.ROOT)),
                row.getString("format"), row.getString("file_url"), instant(row, "completed_at"),
                instant(row, "expires_at"));
    }

    private static DeletionView toDeletion(ResultSet row) throws SQLException {
        return new DeletionView(row.getObject("id", UUID.class), row.getObject("user_id", UUID.class),
                instant(row, "requested_at"), DeletionStatus.valueOf(row.getString("status").toUpperCase(Locale.ROOT)),
                row.getString("reason"), instant(row, "will_delete_at"), instant(row, "deleted_at"));
    }

    private static Instant instant(ResultSet row, String column) throws SQLException {
        OffsetDateTime value = row.getObject(column, OffsetDateTime.class);
        return value == null ? null : value.toInstant();
    }

    private <T> List<T> query(String sql, RowMapper<T> mapper, Object... params) {
        try (Connection c = db.getConnection(); PreparedStatement ps = prepare(c, sql, params);
             ResultSet rows = ps.executeQuery()) {
            List<T> out = new ArrayList<>();
            while (rows.next()) {
                out.add(mapper.map(rows));
            }
            return out;
        } catch (SQLException e) {
            throw new ComplianceException("storage_error", e);
        }
    }

    private int update(String sql, Object... params) {
        try (Connection c = db.getConnection(); PreparedStatement ps = prepare(c, sql, params)) {
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new ComplianceException("storage_error", e);
        }
    }

    private static PreparedStatement prepare(Connection c, String sql, Object... params) throws SQLException {
        PreparedStatement ps = c.prepareStatement(sql);
        for (int i = 0; i < params.length; i++) {
            Object value = params[i] instanceof Instant t ? t.atOffset(ZoneOffset.UTC) : params[i];
            ps.setObject(i + 1, value);
        }
        return ps;
    }
}
