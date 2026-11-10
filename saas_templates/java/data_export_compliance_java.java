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
import java.time.temporal.ChronoUnit;
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
    /** How long a worker's claim on an export or an erase holds. After that the worker is taken to have stopped, and
     *  another may take the job over (2026-11-08, session f3daac6e, from review: a claim used to hold forever). */
    public static final Duration CLAIM_LEASE = Duration.ofMinutes(15);

    public static final Set<String> FORMATS = Set.of("json", "csv");
    public static final Set<String> DELETION_REASONS =
            Set.of("user_requested", "gdpr_request", "gdpr_right_to_be_forgotten", "other");
    /** Statutory erasure reasons: no grace period, the cascade runs at confirmation (EXPORT-12, amended 2026-11-10). */
    public static final Set<String> STATUTORY_REASONS = Set.of("gdpr_request", "gdpr_right_to_be_forgotten");
    /** How long a deletion confirmation token is valid (EXPORT-14, amended 2026-11-10). */
    public static final Duration CONFIRMATION_TOKEN_TTL = Duration.ofHours(24);

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

    /** A refused or failed request. {@code code()} is one of: invalid_format, invalid_reason, not_found,
     *  invalid_confirmation_token, deletion_not_pending, cannot_cancel, grace_period_expired (a late confirm),
     *  grace_period_over (a cancel once the deletion is due; Phase B.3, 2026-11-10), forbidden, email_failed,
     *  deletion_failed, storage_error; {@code httpStatus()} is the status the endpoint answers with.
     *  Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-15, Phase B.2): invalid_token became
     *  invalid_confirmation_token (400) and not_pending became deletion_not_pending (409), and each code carries its
     *  HTTP status. */
    public static class ComplianceException extends RuntimeException {
        private final String code;

        /**
         * The HTTP status for this refusal. In: none. Out: 400 (invalid_format, invalid_reason,
         * invalid_confirmation_token), 403 forbidden, 404 not_found, 409 (deletion_not_pending, cannot_cancel,
         * grace_period_expired, grace_period_over: added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, Phase B.3), else 500 (email_failed, deletion_failed, storage_error). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
         * (EXPORT-15: the spec names a status with each answer). Touches: nothing.
         */
        public int httpStatus() {
            return switch (code) {
                case "invalid_format", "invalid_reason", "invalid_confirmation_token" -> 400;
                case "forbidden" -> 403;
                case "not_found" -> 404;
                case "deletion_not_pending", "cannot_cancel", "grace_period_expired", "grace_period_over" -> 409;
                default -> 500;
            };
        }

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

        /** Erases the user from every table except the audit log, which the law requires to be kept. It must be
         *  safe to run twice: a worker that stalls past CLAIM_LEASE can overlap the one that takes over. */
        void eraseAll(UUID userId) throws Exception;
    }

    public interface AdminCheck {
        boolean isAdmin(UUID userId);
    }

    /** Runs work outside the request, for example on a queue or a thread pool. */
    public interface TaskRunner {
        void run(Runnable task);
    }

    /**
     * The audit system's erasure entry point (audit_logging.md erase_subject): removes the user's personal audit data.
     * Called LAST in the deletion cascade (EXPORT-13). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, after the
     * security review found nothing erased the user's audit personal data. Touches: the audit store.
     */
    public interface AuditEraser {
        void eraseSubject(UUID userId) throws Exception;
    }

    /**
     * The outside services this class uses. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: auditEraser added (EXPORT-13);
     * it is required, so a deployment cannot forget to erase audit personal data.
     */
    public record Services(ObjectStore store, EmailSender email, AuditLog audit, UserData users, AdminCheck admins,
                           TaskRunner tasks, AuditEraser auditEraser) {}

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
                        user_id UUID,
                        requested_at TIMESTAMP WITH TIME ZONE NOT NULL,
                        status VARCHAR(20) NOT NULL,
                        reason VARCHAR(50) NOT NULL,
                        confirmation_token_hash VARCHAR(64) NOT NULL,
                        token_expires_at TIMESTAMP WITH TIME ZONE,
                        token_used_at TIMESTAMP WITH TIME ZONE,
                        will_delete_at TIMESTAMP WITH TIME ZONE NOT NULL,
                        erase_started_at TIMESTAMP WITH TIME ZONE,
                        deleted_at TIMESTAMP WITH TIME ZONE
                    )""");
            // Tables made before 2026-11-08 lack the erase claim (2026-11-08, session f3daac6e, from review of PR 17).
            s.execute("ALTER TABLE deletion_requests ADD COLUMN IF NOT EXISTS erase_started_at TIMESTAMP WITH TIME ZONE");
            // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-13/14): single-use 24 h tokens, and user_id is set NULL
            // when a deletion completes, so the row cannot re-identify the erased audit entries.
            s.execute("ALTER TABLE deletion_requests ADD COLUMN IF NOT EXISTS token_expires_at TIMESTAMP WITH TIME ZONE");
            s.execute("ALTER TABLE deletion_requests ADD COLUMN IF NOT EXISTS token_used_at TIMESTAMP WITH TIME ZONE");
            s.execute("ALTER TABLE deletion_requests ALTER COLUMN user_id DROP NOT NULL");
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
     * export does nothing while the first call's claim is younger than {@link #CLAIM_LEASE}.
     *
     * @param exportId the export to build
     */
    public void processExport(UUID exportId) {
        // The claim time is also this worker's fence: its final writes only land while the claim is still its own.
        Instant now = clock.instant().truncatedTo(ChronoUnit.MILLIS);
        int claimed = update("UPDATE export_requests SET claimed_at = ? WHERE id = ? AND status = ?"
                        + " AND (claimed_at IS NULL OR claimed_at < ?)",
                now, exportId, ExportStatus.PENDING.value(), now.minus(CLAIM_LEASE));
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
            int finished = update("UPDATE export_requests SET status = ?, file_url = ?, completed_at = ?, expires_at = ?"
                            + " WHERE id = ? AND claimed_at = ?",
                    ExportStatus.COMPLETED.value(), url, done, expiresAt, exportId, now);
            if (finished == 0) {
                return;   // another worker took the export over after the lease; it reports the result
            }
        } catch (Exception e) {
            if (update("UPDATE export_requests SET status = ?, completed_at = ? WHERE id = ? AND claimed_at = ?",
                    ExportStatus.FAILED.value(), clock.instant(), exportId, now) == 0) {
                return;
            }
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
     * Records a deletion request and e-mails the confirmation link. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: a
     * statutory reason (gdpr_request, gdpr_right_to_be_forgotten) gets will_delete_at = now (EXPORT-12), others now +
     * 30 days (EXPORT-05); the token (32 random bytes, stored as SHA-256) is valid 24 hours (EXPORT-14). Nothing is erased unless the user confirms, so a mail
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
        // EXPORT-05/12 (amended 2026-11-10): 30 days' grace for user_requested / other; none for a statutory reason.
        Instant willDeleteAt = STATUTORY_REASONS.contains(reason) ? now : now.plus(GRACE_PERIOD);
        String token = newToken();
        update("""
                INSERT INTO deletion_requests
                    (id, user_id, requested_at, status, reason, confirmation_token_hash, token_expires_at, will_delete_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                deletionId, userId, now, DeletionStatus.PENDING.value(), reason, sha256(token),
                now.plus(CONFIRMATION_TOKEN_TTL), willDeleteAt);
        services.audit().record("deletion_requested", userId,
                Map.of("deletion_id", deletionId.toString(), "reason", reason));
        String link = appBaseUrl + "/compliance/delete/" + deletionId + "/confirm?token=" + token;
        try {
            services.email().send(to, "Confirm account deletion",
                    "Please confirm your deletion request: " + link + "\nThis link expires in 24 hours.");
        } catch (Exception e) {
            throw new ComplianceException("email_failed", e);
        }
        return new DeletionReceipt(deletionId, DeletionStatus.PENDING, willDeleteAt);
    }

    /**
     * Confirms a deletion with the token from the e-mail, which proves the request came from the mailbox's owner. POST
     * /compliance/delete/:deletion_id/confirm. Only the caller's own request: anyone else's (admins included) is
     * not_found. The token is single-use, valid 24 hours and bound to this deletion id (its hash is stored on the row),
     * and is compared in constant time; a wrong, reused or expired token is invalid_confirmation_token (400). For a
     * statutory reason the cascade runs before this returns (status completed, deleted_at = the returned time = now).
     * Checks run in this order: owner (404 not_found; a completed request has user_id NULL, so it is 404 to every
     * caller), cancelled (409 deletion_not_pending), token (400 invalid_confirmation_token), still pending (409
     * deletion_not_pending).
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-15, Phase B.2): codes renamed from invalid_token /
     * not_pending, and a closed request is refused before the token is looked at, so a still-valid token on a
     * cancelled request answers 409, not 400.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-12/14): it took no caller, so anyone holding a link
     * for someone else's request could confirm it, and the token was valid for the whole grace period.
     *
     * @param callerId   the signed-in user (from the verified session, never from the request body)
     * @param deletionId the request
     * @param token      the token from the link
     * @return when the data will be (or, for a statutory reason, was) erased
     * @throws ComplianceException not_found, deletion_not_pending, invalid_confirmation_token, grace_period_expired,
     *                             deletion_failed
     */
    public Instant confirmDeletion(UUID callerId, UUID deletionId, String token) {
        List<Object[]> rows = query("SELECT confirmation_token_hash, token_expires_at, token_used_at FROM deletion_requests WHERE id = ?",
                row -> new Object[] {row.getString(1), instant(row, "token_expires_at"), instant(row, "token_used_at")}, deletionId);
        DeletionView deletion = rows.isEmpty() ? null : findDeletion(deletionId).orElse(null);
        if (deletion == null || callerId == null || !callerId.equals(deletion.userId())) {
            throw new ComplianceException("not_found");
        }
        refuseIfClosed(deletion);
        byte[] expected = ((String) rows.get(0)[0]).getBytes(StandardCharsets.UTF_8);
        byte[] given = sha256(token == null ? "" : token).getBytes(StandardCharsets.UTF_8);
        boolean matches = MessageDigest.isEqual(expected, given);
        Instant now = clock.instant();
        Instant tokenExpiresAt = (Instant) rows.get(0)[1];
        boolean usable = rows.get(0)[2] == null && tokenExpiresAt != null && !now.isAfter(tokenExpiresAt);
        if (!matches || !usable) {
            throw new ComplianceException("invalid_confirmation_token");
        }
        if (deletion.status() != DeletionStatus.PENDING) {
            throw new ComplianceException("deletion_not_pending");
        }
        boolean statutory = STATUTORY_REASONS.contains(deletion.reason());
        if (!statutory && now.isAfter(deletion.willDeleteAt())) {
            throw new ComplianceException("grace_period_expired");
        }
        int changed = update("UPDATE deletion_requests SET status = ?, token_used_at = ? WHERE id = ? AND status = ? AND token_used_at IS NULL",
                DeletionStatus.APPROVED.value(), now, deletionId, DeletionStatus.PENDING.value());
        if (changed == 0) {
            // Another confirm with the same token won the race: for this caller the token is now a reused one.
            throw new ComplianceException("invalid_confirmation_token");
        }
        services.audit().record("deletion_confirmed", deletion.userId(), Map.of("deletion_id", deletionId.toString()));
        if (!statutory) {
            return deletion.willDeleteAt();
        }
        Instant claimedAt = clock.instant().truncatedTo(ChronoUnit.MILLIS);
        if (update("UPDATE deletion_requests SET erase_started_at = ? WHERE id = ? AND status = ? AND erase_started_at IS NULL",
                claimedAt, deletionId, DeletionStatus.APPROVED.value()) == 0 || !runCascade(deletion, claimedAt)) {
            throw new ComplianceException("deletion_failed");
        }
        return claimedAt;
    }

    /**
     * Cancels a deletion. DELETE /compliance/delete/:deletion_id. Only the caller's own request: anyone else's
     * (admins included) is not_found. A pending (unconfirmed) request can always be cancelled; a confirmed one only
     * until will_delete_at and before its erase has started.
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-14: "confirm and cancel act only on the caller's own
     * request"; admins could cancel anyone's).
     *
     * @param deletionId  the request
     * @param requesterId the signed-in user, who must be its owner
     * @return the new status
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-15, Phase B.2): a cancelled or completed request is
     * 409 deletion_not_pending (it was cannot_cancel); a completed one has user_id NULL and is 404 not_found (spec
     * clarification 3abb340); cannot_cancel (409) is left only for an erase already started.
     *
     * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.3 ruling, d4f4ed7): a confirmed request whose
     * will_delete_at has passed (the deletion is due but not yet run) is 409 grace_period_over (it was
     * grace_period_expired).
     *
     * @throws ComplianceException not_found, also when the requester may not see it; deletion_not_pending;
     *                             grace_period_over; cannot_cancel
     */
    public DeletionStatus cancelDeletion(UUID deletionId, UUID requesterId) {
        DeletionView deletion = findDeletion(deletionId).orElseThrow(() -> new ComplianceException("not_found"));
        if (requesterId == null || !requesterId.equals(deletion.userId())) {
            throw new ComplianceException("not_found");
        }
        refuseIfClosed(deletion);
        // Phase B.3 (d4f4ed7), 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: after will_delete_at has passed, cancelling
        // is 409 grace_period_over. Exactly at will_delete_at a cancel still wins over the eraser (the conditional
        // update below decides), as before.
        if (deletion.status() == DeletionStatus.APPROVED && clock.instant().isAfter(deletion.willDeleteAt())) {
            throw new ComplianceException("grace_period_over");
        }
        // Only an erase that has not started can be cancelled, so a cancellation and the eraser never both win.
        int changed = update("UPDATE deletion_requests SET status = ? WHERE id = ? AND status IN (?, ?)"
                        + " AND erase_started_at IS NULL",
                DeletionStatus.CANCELLED.value(), deletionId,
                DeletionStatus.PENDING.value(), DeletionStatus.APPROVED.value());
        if (changed == 0) {
            throw new ComplianceException("cannot_cancel");
        }
        services.audit().record("deletion_cancelled", deletion.userId(), Map.of("deletion_id", deletionId.toString()));
        return DeletionStatus.CANCELLED;
    }

    /**
     * Refuses a cancelled request: 409 deletion_not_pending, checked before the token. A completed request never gets
     * here: its user_id is NULL (EXPORT-13), so the owner check has already answered 404 not_found. In: the caller's own
     * request. Out: nothing, or the exception. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-15, Phase B.2,
     * as clarified in spec commit 3abb340). Touches: nothing.
     */
    private static void refuseIfClosed(DeletionView deletion) {
        if (deletion.status() == DeletionStatus.CANCELLED) {
            throw new ComplianceException("deletion_not_pending");
        }
    }

    /**
     * The deletion cascade for one claimed request, in the spec's order: (1) erase the user's rows (every table but the
     * audit tables), (2) log 'user_deleted_cascade' with the user as subject, (3) call the audit eraser's
     * eraseSubject(user_id) LAST; then the request is completed with user_id set NULL. Nothing logs this user after
     * step 3 (a failure there is logged without the user). In: the request, its claim time. Out: true when completed
     * (false if another worker took the claim over, or a step failed and the claim stays for a retry).
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-13). Touches: the application's user data (through
     * UserData), the audit log and audit store, the database.
     */
    private boolean runCascade(DeletionView deletion, Instant claimedAt) {
        Map<String, String> details = Map.of("deletion_id", deletion.deletionId().toString());
        try {
            services.users().eraseAll(deletion.userId());
        } catch (Exception e) {
            services.audit().record("deletion_failed", deletion.userId(),
                    Map.of("deletion_id", deletion.deletionId().toString(), "error", e.getClass().getSimpleName()));
            return false;
        }
        try {
            services.audit().record("user_deleted_cascade", deletion.userId(), details);
            services.auditEraser().eraseSubject(deletion.userId());
        } catch (Exception e) {
            // Without the user: their audit personal data may already be partly erased.
            services.audit().record("deletion_failed", null,
                    Map.of("deletion_id", deletion.deletionId().toString(), "error", e.getClass().getSimpleName()));
            return false;
        }
        return update("UPDATE deletion_requests SET status = ?, deleted_at = ?, user_id = NULL WHERE id = ? AND erase_started_at = ?",
                DeletionStatus.COMPLETED.value(), clock.instant(), deletion.deletionId(), claimedAt) == 1;
    }

    /**
     * Erases every user whose confirmed request has reached the end of its grace period. Call this from a daily scheduled
     * job. An unconfirmed request never erases anything. Each request is claimed before its data is touched, and a
     * cancellation only succeeds before that claim, so the two cannot both win. If erasing one user fails, the claim
     * stays (part of the data may be gone, so it can no longer be cancelled) and the next run after
     * {@link #CLAIM_LEASE} tries again. The others still go ahead.
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
            Instant claimedAt = clock.instant().truncatedTo(ChronoUnit.MILLIS);
            int claimed = update("UPDATE deletion_requests SET erase_started_at = ? WHERE id = ? AND status = ?"
                            + " AND (erase_started_at IS NULL OR erase_started_at < ?)",
                    claimedAt, deletion.deletionId(), DeletionStatus.APPROVED.value(), claimedAt.minus(CLAIM_LEASE));
            if (claimed == 0) {
                continue;
            }
            // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-13): the spec's cascade order, ending with the audit
            // eraser; no "deletion_completed" entry naming the user is written after it any more.
            if (runCascade(deletion, claimedAt)) {
                erased++;
            }
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

    /** One row per value: category, key, value. Nested maps become dotted keys and each list item keeps its position,
     *  as in {@code sessions,[1].ip,...}, so the fields of one record never mix with the next ({S}). */
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
            int position = 0;
            for (Object item : list) {
                appendRows(out, category, key + "[" + position++ + "]", item);
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
