import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests for DataExportCompliance, against a real in-memory H2 database and hand-written fakes for the outside services.
 * They cover the system spec's seven endpoints (the same cases as the Python suite) and the choices the class documents:
 * hashed tokens, owner-only reads, no links in the audit log, safe CSV cells, and erasing only after the grace period.
 *
 * <p>Why: this file did not exist until 2026-11-05 (AIR record finding:2026-11-05:3a00300d16). Written that day by session
 * f3daac6e-b278-43cb-9d78-1188871af05a. Touches: an in-memory database only, no network.
 */
public class DataExportComplianceTest {

    private static final Instant START = Instant.parse("2026-11-05T12:00:00Z");
    private static final UUID ADMIN = UUID.randomUUID();
    private static final UUID USER = UUID.randomUUID();
    private static final UUID STRANGER = UUID.randomUUID();

    /** A clock the test can move forward. */
    private static final class TestClock extends Clock {
        private Instant now = START;

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private record Mail(String to, String subject, String body) {}

    private record AuditEntry(String action, UUID userId, Map<String, String> details) {}

    private final Map<String, byte[]> stored = new HashMap<>();
    private final Map<String, String> storedTypes = new HashMap<>();
    private final List<Duration> linkLifetimes = new ArrayList<>();
    private final List<Mail> mail = new ArrayList<>();
    private final List<AuditEntry> audit = new ArrayList<>();
    private final List<Runnable> queued = new ArrayList<>();
    private final List<UUID> erased = new ArrayList<>();
    /** Every audit write, eraseAll and eraseSubject call in order, as "audit:<action>:<user>", "eraseAll:<user>",
     *  "eraseSubject:<user>" (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: EXPORT-13 checks the cascade order). */
    private final List<String> events = new ArrayList<>();
    private final Map<String, Object> userData = new LinkedHashMap<>();
    private boolean storeFails;
    private boolean eraseFails;
    private TestClock clock;
    private JdbcDataSource db;
    private DataExportCompliance compliance;

    @BeforeEach
    void setUp() {
        clock = new TestClock();
        db = new JdbcDataSource();
        db.setURL("jdbc:h2:mem:" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1");

        userData.put("profile", new LinkedHashMap<>(Map.of("email", "test@example.com", "name", "Test User")));
        userData.put("sessions", List.of(Map.of("ip", "192.168.1.1", "device_info", "Chrome on Windows")));
        userData.put("activity", List.of(Map.of("action", "login")));
        userData.put("files", List.of(Map.of("name", "document.pdf", "size", 1024)));
        userData.put("preferences", Map.of("notifications", Map.of("email", true), "theme", "dark"));
        userData.put("transactions", List.of(Map.of("type", "invoice", "amount", 99.99)));
        userData.put("audit_trail", List.of(Map.of("action", "profile_update")));

        DataExportCompliance.ObjectStore store = new DataExportCompliance.ObjectStore() {
            @Override
            public void put(String key, byte[] body, String contentType) throws Exception {
                if (storeFails) {
                    throw new java.io.IOException("secret detail from the storage provider");
                }
                stored.put(key, body);
                storedTypes.put(key, contentType);
            }

            @Override
            public String signedDownloadUrl(String key, Duration validFor) {
                linkLifetimes.add(validFor);
                return "https://files.example.com/" + key + "?signature=abc";
            }
        };
        DataExportCompliance.UserData users = new DataExportCompliance.UserData() {
            @Override
            public Map<String, Object> export(UUID userId) {
                return userData;
            }

            @Override
            public void eraseAll(UUID userId) throws Exception {
                if (eraseFails) {
                    throw new java.io.IOException("database busy");
                }
                erased.add(userId);
                events.add("eraseAll:" + userId);
            }
        };
        // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the audit eraser is a required service now (EXPORT-13).
        DataExportCompliance.Services services = new DataExportCompliance.Services(store,
                (to, subject, body) -> mail.add(new Mail(to, subject, body)),
                (action, userId, details) -> {
                    audit.add(new AuditEntry(action, userId, details));
                    events.add("audit:" + action + ":" + userId);
                },
                users, ADMIN::equals, queued::add,
                userId -> events.add("eraseSubject:" + userId));
        compliance = new DataExportCompliance(db, services, clock, "https://app.example.com/");
        compliance.createTables();
    }

    /* ---------- helpers ---------- */

    private void assertRefused(String code, Runnable call) {
        DataExportCompliance.ComplianceException e =
                assertThrows(DataExportCompliance.ComplianceException.class, call::run);
        assertEquals(code, e.code());
    }

    /**
     * Asserts the call is refused with this HTTP status and code; returns the exception so a test can compare answers.
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-15 names a status with each answer). Touches: nothing.
     */
    private DataExportCompliance.ComplianceException assertRefused(int status, String code, Runnable call) {
        DataExportCompliance.ComplianceException e =
                assertThrows(DataExportCompliance.ComplianceException.class, call::run);
        assertEquals(code, e.code());
        assertEquals(status, e.httpStatus());
        return e;
    }

    private AuditEntry auditOf(String action) {
        return audit.stream().filter(a -> a.action().equals(action)).findFirst()
                .orElseThrow(() -> new AssertionError("no audit entry for " + action + ": " + audit));
    }

    private String tokenFromLastMail() {
        Matcher m = Pattern.compile("token=([A-Za-z0-9_-]+)").matcher(mail.get(mail.size() - 1).body());
        assertTrue(m.find(), "the e-mail has no token");
        return m.group(1);
    }

    private UUID requestAndProcessExport(String format) {
        UUID id = compliance.requestDataExport(USER, format).exportId();
        queued.remove(0).run();
        return id;
    }

    private UUID confirmedDeletion() {
        UUID id = compliance.requestAccountDeletion(USER, "user_requested").deletionId();
        compliance.confirmDeletion(USER, id, tokenFromLastMail());
        return id;
    }

    private DataExportCompliance.DeletionView deletion(UUID id) {
        return compliance.listDeletionRequests(ADMIN, null).items().stream()
                .filter(d -> d.deletionId().equals(id)).findFirst().orElseThrow();
    }

    /* ---------- export ---------- */

    // EXPORT-11
    @Test
    void exportRequestIsPendingAndRunsInTheBackground() {
        DataExportCompliance.ExportReceipt receipt = compliance.requestDataExport(USER, "json");

        assertEquals(DataExportCompliance.ExportStatus.PENDING, receipt.status());
        assertEquals(START.plus(Duration.ofMinutes(5)), receipt.willEmailAt());
        assertEquals(1, queued.size(), "the export must run in the background");
        assertTrue(stored.isEmpty(), "nothing is built before the background task runs");
        AuditEntry entry = auditOf("data_export_requested");
        assertEquals(USER, entry.userId());
        assertEquals("json", entry.details().get("format"));
    }

    @Test
    void exportRefusesAnUnknownFormat() {
        assertRefused("invalid_format", () -> compliance.requestDataExport(USER, "xml"));
        assertRefused("invalid_format", () -> compliance.requestDataExport(USER, null));
        assertTrue(queued.isEmpty());
    }

    // EXPORT-01
    // EXPORT-02
    // EXPORT-03
    // EXPORT-04
    @Test
    void jsonExportHoldsEveryCategoryAndIsEmailedWithASevenDayLink() {
        UUID id = requestAndProcessExport("json");

        String key = "exports/" + id + ".json";
        String body = new String(stored.get(key), StandardCharsets.UTF_8);
        for (String category : List.of("profile", "sessions", "activity", "files", "preferences", "transactions",
                "audit_trail")) {
            assertTrue(body.contains("\"" + category + "\""), category + " is missing from the export");
        }
        assertEquals("application/json", storedTypes.get(key));
        assertEquals(List.of(Duration.ofDays(7)), linkLifetimes);

        DataExportCompliance.ExportView view = compliance.getExportStatus(id, USER);
        assertEquals(DataExportCompliance.ExportStatus.COMPLETED, view.status());
        assertEquals(START.plus(Duration.ofDays(7)), view.expiresAt());
        assertNotNull(view.completedAt());

        Mail sent = mail.get(0);
        assertEquals("test@example.com", sent.to());
        assertTrue(sent.body().contains(view.fileUrl()), "the e-mail must carry the download link");
    }

    // EXPORT-01
    @Test
    void csvExportFlattensNestedDataAndIsStoredAsCsv() {
        UUID id = requestAndProcessExport("csv");

        String key = "exports/" + id + ".csv";
        String body = new String(stored.get(key), StandardCharsets.UTF_8);
        assertTrue(body.startsWith("category,key,value\n"));
        assertTrue(body.contains("profile,email,test@example.com\n"));
        assertTrue(body.contains("preferences,notifications.email,true\n"), "nested maps become dotted keys");
        assertTrue(body.contains("files,[0].size,1024\n"));
        assertEquals("text/csv", storedTypes.get(key));
    }

    @Test
    void csvCellsCannotRunAsFormulasOrBreakTheFile() {
        assertEquals("'=HYPERLINK(1)", DataExportCompliance.csvCell("=HYPERLINK(1)"));
        assertEquals("'@cmd", DataExportCompliance.csvCell("@cmd"));
        assertEquals("'+1 555", DataExportCompliance.csvCell("+1 555"));
        assertEquals("-12.50", DataExportCompliance.csvCell("-12.50"), "a plain negative number stays a number");
        assertEquals("\"a,b\"", DataExportCompliance.csvCell("a,b"));
        assertEquals("\"say \"\"hi\"\"\"", DataExportCompliance.csvCell("say \"hi\""));
        assertEquals("\"two\nlines\"", DataExportCompliance.csvCell("two\nlines"));
    }

    @Test
    void theDownloadLinkNeverReachesTheAuditLog() {
        requestAndProcessExport("json");

        assertFalse(auditOf("data_export_completed").details().toString().contains("signature"));
        assertFalse(audit.toString().contains("files.example.com"));
    }

    @Test
    void aStorageFailureMarksTheExportFailedAndKeepsDetailsOutOfTheAuditLog() {
        storeFails = true;

        UUID id = requestAndProcessExport("json");

        DataExportCompliance.ExportView view = compliance.getExportStatus(id, USER);
        assertEquals(DataExportCompliance.ExportStatus.FAILED, view.status());
        assertNull(view.fileUrl());
        assertEquals("IOException", auditOf("data_export_failed").details().get("error"));
        assertFalse(audit.toString().contains("secret detail"));
        assertTrue(mail.isEmpty());
    }

    @Test
    void anExportIsBuiltOnlyOnceEvenIfTheTaskRunsTwice() {
        UUID id = compliance.requestDataExport(USER, "json").exportId();

        compliance.processExport(id);
        compliance.processExport(id);

        assertEquals(1, mail.size());
        assertEquals(1, linkLifetimes.size());
    }

    @Test
    void aMissingEmailAddressDoesNotFailTheExportOrSendItElsewhere() {
        userData.put("profile", Map.of("name", "No Mail"));

        UUID id = requestAndProcessExport("json");

        assertEquals(DataExportCompliance.ExportStatus.COMPLETED, compliance.getExportStatus(id, USER).status());
        assertTrue(mail.isEmpty());
        assertEquals("IllegalStateException", auditOf("data_export_email_failed").details().get("error"));
    }

    @Test
    void exportStatusIsForTheOwnerAndAdminsOnly() {
        UUID id = requestAndProcessExport("json");

        assertEquals(id, compliance.getExportStatus(id, USER).exportId());
        assertEquals(id, compliance.getExportStatus(id, ADMIN).exportId());
        assertRefused("not_found", () -> compliance.getExportStatus(id, STRANGER));
        assertRefused("not_found", () -> compliance.getExportStatus(UUID.randomUUID(), USER));
    }

    /* ---------- deletion ---------- */

    /**
     * EXPORT-05: a user_requested deletion waits 30 days (will_delete_at = requested_at + 30 days) and e-mails a
     * confirmation link. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: it used gdpr_right_to_be_forgotten,
     * which under the amended spec gets no grace period (EXPORT-12, below).
     */
    // EXPORT-05
    @Test
    void deletionRequestWaitsThirtyDaysAndEmailsAConfirmationLink() {
        DataExportCompliance.DeletionReceipt receipt = compliance.requestAccountDeletion(USER, "user_requested");

        assertEquals(DataExportCompliance.DeletionStatus.PENDING, receipt.status());
        assertEquals(START.plus(Duration.ofDays(30)), receipt.willDeleteAt());
        assertEquals("test@example.com", mail.get(0).to());
        assertTrue(mail.get(0).body().contains(
                "https://app.example.com/compliance/delete/" + receipt.deletionId() + "/confirm?token="));
        assertEquals("user_requested", auditOf("deletion_requested").details().get("reason"));
        assertEquals(START.plus(Duration.ofDays(30)), compliance.requestAccountDeletion(USER, "other").willDeleteAt());
    }

    /**
     * EXPORT-12: gdpr_request and gdpr_right_to_be_forgotten are not held for 30 days: will_delete_at = requested_at,
     * and confirm() runs the cascade before it returns (status completed, deleted_at = the returned time = now).
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     */
    // EXPORT-12
    @Test
    void aStatutoryDeletionHasNoGracePeriodAndRunsAtConfirmation() {
        for (String reason : List.of("gdpr_request", "gdpr_right_to_be_forgotten")) {
            erased.clear();
            DataExportCompliance.DeletionReceipt receipt = compliance.requestAccountDeletion(USER, reason);
            assertEquals(START, receipt.willDeleteAt(), reason);
            assertTrue(erased.isEmpty(), "nothing is deleted before confirm");
            Instant scheduled = compliance.confirmDeletion(USER, receipt.deletionId(), tokenFromLastMail());
            assertEquals(START, scheduled);
            assertEquals(List.of(USER), erased);
            DataExportCompliance.DeletionView done = deletion(receipt.deletionId());
            assertEquals(DataExportCompliance.DeletionStatus.COMPLETED, done.status());
            assertEquals(START, done.deletedAt());
        }
    }

    @Test
    void deletionRefusesAnUnknownReason() {
        assertRefused("invalid_reason", () -> compliance.requestAccountDeletion(USER, "bored"));
        assertTrue(mail.isEmpty());
    }

    @Test
    void theConfirmationTokenIsStoredOnlyAsAHash() throws SQLException {
        compliance.requestAccountDeletion(USER, "other");
        String token = tokenFromLastMail();

        try (Connection c = db.getConnection(); Statement s = c.createStatement();
             ResultSet row = s.executeQuery("SELECT confirmation_token_hash FROM deletion_requests")) {
            assertTrue(row.next());
            String saved = row.getString(1);
            assertEquals(64, saved.length());
            assertFalse(saved.contains(token));
        }
    }

    // EXPORT-09
    @Test
    void confirmingWithTheEmailedTokenApprovesTheDeletion() {
        DataExportCompliance.DeletionReceipt receipt = compliance.requestAccountDeletion(USER, "user_requested");

        Instant scheduled = compliance.confirmDeletion(USER, receipt.deletionId(), tokenFromLastMail());

        assertEquals(receipt.willDeleteAt(), scheduled);
        assertEquals(DataExportCompliance.DeletionStatus.APPROVED, deletion(receipt.deletionId()).status());
        assertEquals(USER, auditOf("deletion_confirmed").userId());
    }

    /** A wrong or missing token changes nothing. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: confirm takes the
     *  caller; the code is invalid_confirmation_token (EXPORT-15, Phase B.2 renamed it from invalid_token). */
    // EXPORT-14
    @Test
    void confirmingWithAWrongTokenChangesNothing() {
        UUID id = compliance.requestAccountDeletion(USER, "gdpr_request").deletionId();

        assertRefused("invalid_confirmation_token", () -> compliance.confirmDeletion(USER, id, "wrong"));
        assertRefused("invalid_confirmation_token", () -> compliance.confirmDeletion(USER, id, null));
        assertRefused("not_found", () -> compliance.confirmDeletion(USER, UUID.randomUUID(), "wrong"));
        assertEquals(DataExportCompliance.DeletionStatus.PENDING, deletion(id).status());
        assertTrue(erased.isEmpty(), "nothing is deleted before confirm, even for a statutory reason");
    }

    /**
     * EXPORT-14: the token is single-use and valid 24 hours, and confirm/cancel act only on the caller's own request
     * (anyone else, an admin included, gets not_found, even with the right token). Changed 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP: a reused token was "not_pending" and a late one "grace_period_expired"; under
     * the amended spec both are refused tokens (invalid_token), and expiry is 24 hours, not 30 days. Changed again
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-15, Phase B.2): the code is now invalid_confirmation_token.
     */
    // EXPORT-14
    @Test
    void aDeletionCanBeConfirmedOnlyOnceAndNotAfterTheGracePeriod() {
        UUID id = compliance.requestAccountDeletion(USER, "user_requested").deletionId();
        String token = tokenFromLastMail();
        assertRefused("not_found", () -> compliance.confirmDeletion(STRANGER, id, token));
        assertRefused("not_found", () -> compliance.confirmDeletion(ADMIN, id, token));
        assertEquals(DataExportCompliance.DeletionStatus.PENDING, deletion(id).status());
        compliance.confirmDeletion(USER, id, token);
        assertRefused("invalid_confirmation_token", () -> compliance.confirmDeletion(USER, id, token));

        UUID late = compliance.requestAccountDeletion(USER, "other").deletionId();
        String lateToken = tokenFromLastMail();
        clock.advance(Duration.ofHours(24).plusSeconds(1));
        assertRefused("invalid_confirmation_token", () -> compliance.confirmDeletion(USER, late, lateToken));
        assertEquals(DataExportCompliance.DeletionStatus.PENDING, deletion(late).status());
        assertRefused("not_found", () -> compliance.cancelDeletion(late, STRANGER));

        // Exactly 24 hours is still valid.
        UUID onTime = compliance.requestAccountDeletion(USER, "other").deletionId();
        String onTimeToken = tokenFromLastMail();
        clock.advance(Duration.ofHours(24));
        compliance.confirmDeletion(USER, onTime, onTimeToken);
        assertEquals(DataExportCompliance.DeletionStatus.APPROVED, deletion(onTime).status());
        assertTrue(erased.isEmpty());
    }

    /**
     * EXPORT-15: a wrong, a reused and an expired token all get the same 400 invalid_confirmation_token (same status, code
     * and message) and change nothing; another user's request is 404 not_found; confirm and cancel of a cancelled request
     * get 409 deletion_not_pending, even with the request's still-valid token; a completed request (user_id NULL,
     * EXPORT-13) is 404 not_found to every caller, its former owner included (spec clarification 3abb340).
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase B.2). Touches: test H2 DB.
     */
    // EXPORT-15
    @Test
    void wrongReusedOrExpiredTokensGetOneAnswerAndClosedRequestsAre409() {
        UUID wrong = compliance.requestAccountDeletion(USER, "user_requested").deletionId();
        DataExportCompliance.ComplianceException a = assertRefused(400, "invalid_confirmation_token",
                () -> compliance.confirmDeletion(USER, wrong, "not-the-token"));

        UUID reused = compliance.requestAccountDeletion(USER, "user_requested").deletionId();
        String reusedToken = tokenFromLastMail();
        compliance.confirmDeletion(USER, reused, reusedToken);
        DataExportCompliance.ComplianceException b = assertRefused(400, "invalid_confirmation_token",
                () -> compliance.confirmDeletion(USER, reused, reusedToken));

        UUID expired = compliance.requestAccountDeletion(USER, "user_requested").deletionId();
        String expiredToken = tokenFromLastMail();
        clock.advance(Duration.ofHours(24).plusSeconds(1));
        DataExportCompliance.ComplianceException c = assertRefused(400, "invalid_confirmation_token",
                () -> compliance.confirmDeletion(USER, expired, expiredToken));
        assertEquals(a.getMessage(), b.getMessage());
        assertEquals(a.getMessage(), c.getMessage());
        assertEquals(DataExportCompliance.DeletionStatus.PENDING, deletion(wrong).status());
        assertEquals(DataExportCompliance.DeletionStatus.PENDING, deletion(expired).status());

        UUID theirs = compliance.requestAccountDeletion(USER, "user_requested").deletionId();
        String theirToken = tokenFromLastMail();
        assertRefused(404, "not_found", () -> compliance.confirmDeletion(STRANGER, theirs, theirToken));
        assertRefused(404, "not_found", () -> compliance.cancelDeletion(theirs, STRANGER));

        UUID cancelled = compliance.requestAccountDeletion(USER, "user_requested").deletionId();
        String cancelledToken = tokenFromLastMail();
        compliance.cancelDeletion(cancelled, USER);
        assertRefused(409, "deletion_not_pending", () -> compliance.confirmDeletion(USER, cancelled, cancelledToken));
        assertRefused(409, "deletion_not_pending", () -> compliance.cancelDeletion(cancelled, USER));

        assertTrue(erased.isEmpty(), "no refusal erased anything");

        // A statutory request runs its cascade on confirm, so it is completed with user_id NULL.
        UUID completed = compliance.requestAccountDeletion(USER, "gdpr_request").deletionId();
        String completedToken = tokenFromLastMail();
        compliance.confirmDeletion(USER, completed, completedToken);
        assertEquals(DataExportCompliance.DeletionStatus.COMPLETED, deletion(completed).status());
        assertNull(deletion(completed).userId());
        for (UUID caller : List.of(USER, STRANGER, ADMIN)) {
            assertRefused(404, "not_found", () -> compliance.confirmDeletion(caller, completed, completedToken));
            assertRefused(404, "not_found", () -> compliance.cancelDeletion(completed, caller));
        }
    }

    // EXPORT-06
    @Test
    void cancellingDuringTheGracePeriodStopsTheDeletion() {
        UUID id = confirmedDeletion();
        clock.advance(Duration.ofDays(29));

        assertEquals(DataExportCompliance.DeletionStatus.CANCELLED, compliance.cancelDeletion(id, USER));

        clock.advance(Duration.ofDays(2));
        assertEquals(0, compliance.executeScheduledDeletions());
        assertTrue(erased.isEmpty());
        assertEquals(USER, auditOf("deletion_cancelled").userId());
    }

    @Test
    void cancellingAfterTheGracePeriodIsRefused() {
        UUID id = confirmedDeletion();
        clock.advance(Duration.ofDays(31));

        assertRefused("grace_period_expired", () -> compliance.cancelDeletion(id, USER));
    }

    /**
     * A cancelled request cannot be cancelled again; a completed one is nobody's any more. Changed 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-15, Phase B.2): a cancelled request answers 409 deletion_not_pending
     * (it asserted cannot_cancel, the old code).
     */
    @Test
    void aFinishedOrCancelledDeletionCannotBeCancelled() {
        UUID cancelled = confirmedDeletion();
        compliance.cancelDeletion(cancelled, USER);
        assertRefused(409, "deletion_not_pending", () -> compliance.cancelDeletion(cancelled, USER));

        UUID finished = confirmedDeletion();
        clock.advance(Duration.ofDays(30));
        compliance.executeScheduledDeletions();
        // Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-13): a completed request no longer names its
        // user (user_id NULL), so it is nobody's own request any more: not_found rather than cannot_cancel.
        assertRefused("not_found", () -> compliance.cancelDeletion(finished, USER));
    }

    /**
     * Only the owner can cancel. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-14 amendment: "confirm
     * and cancel act only on the caller's own request; anyone else's is 404"): an admin could cancel before.
     */
    // EXPORT-14
    @Test
    void onlyTheOwnerOrAnAdminCanCancel() {
        UUID id = confirmedDeletion();

        assertRefused("not_found", () -> compliance.cancelDeletion(id, STRANGER));
        assertRefused("not_found", () -> compliance.cancelDeletion(id, ADMIN));
        assertEquals(DataExportCompliance.DeletionStatus.CANCELLED, compliance.cancelDeletion(id, USER));
    }

    /**
     * EXPORT-07: the cascade erases the user's data once the grace period ends. Changed 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP: no "deletion_completed" entry names the user any more (EXPORT-13), so the
     * test checks user_deleted_cascade instead, and that deletion_requests.user_id is NULL once completed.
     */
    // EXPORT-07
    @Test
    void scheduledDeletionErasesConfirmedUsersOnceTheGracePeriodEnds() {
        UUID id = confirmedDeletion();

        assertEquals(0, compliance.executeScheduledDeletions(), "nothing is erased during the grace period");
        assertTrue(erased.isEmpty());

        clock.advance(Duration.ofDays(30));
        assertEquals(1, compliance.executeScheduledDeletions());

        assertEquals(List.of(USER), erased);
        DataExportCompliance.DeletionView done = deletion(id);
        assertEquals(DataExportCompliance.DeletionStatus.COMPLETED, done.status());
        assertNotNull(done.deletedAt());
        assertEquals(USER, auditOf("user_deleted_cascade").userId());
        assertNull(done.userId(), "deletion_requests.user_id is NULL once completed");
        assertEquals(0, compliance.executeScheduledDeletions(), "a finished deletion does not run again");
    }

    /**
     * EXPORT-13: the cascade order is eraseAll (the user's rows), then 'user_deleted_cascade' logged for the user, then
     * the audit eraser's eraseSubject(user) LAST, and nothing is logged for the user after it; user_id is NULL on the
     * completed request. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: in-memory H2 and fakes.
     */
    // EXPORT-13
    @Test
    void theCascadeErasesRowsThenLogsThenErasesTheAuditSubjectLast() {
        UUID id = confirmedDeletion();
        clock.advance(Duration.ofDays(30));
        events.clear();
        assertEquals(1, compliance.executeScheduledDeletions());
        assertEquals(List.of("eraseAll:" + USER, "audit:user_deleted_cascade:" + USER, "eraseSubject:" + USER), events);
        assertNull(deletion(id).userId());
    }

    /**
     * EXPORT-08: the audit log is kept: the deletion never deletes audit entries (the entries written before and
     * during the cascade are all still there); the only audit-store change is the audit system's own eraseSubject.
     * Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     */
    // EXPORT-08
    @Test
    void theAuditLogIsKeptWhenTheUserIsDeleted() {
        confirmedDeletion();
        int before = audit.size();
        clock.advance(Duration.ofDays(30));
        compliance.executeScheduledDeletions();
        assertEquals(before + 1, audit.size(), "only user_deleted_cascade was added and nothing was removed");
        assertEquals(List.of("deletion_requested", "deletion_confirmed", "user_deleted_cascade"),
                audit.stream().map(AuditEntry::action).toList());
        assertEquals(1, events.stream().filter(e -> e.startsWith("eraseSubject:")).count());
    }

    /**
     * EXPORT-11: every export and deletion request is logged with its context (format, reason, deletion id) so a
     * why_chain can be built from the log. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     */
    // EXPORT-11
    @Test
    void everyRequestIsAudited() {
        compliance.requestDataExport(USER, "csv");
        UUID id = compliance.requestAccountDeletion(USER, "other").deletionId();
        compliance.confirmDeletion(USER, id, tokenFromLastMail());
        compliance.cancelDeletion(id, USER);
        assertEquals(List.of("data_export_requested", "deletion_requested", "deletion_confirmed", "deletion_cancelled"),
                audit.stream().map(AuditEntry::action).toList());
        assertEquals("csv", auditOf("data_export_requested").details().get("format"));
        assertEquals("other", auditOf("deletion_requested").details().get("reason"));
        assertEquals(id.toString(), auditOf("deletion_cancelled").details().get("deletion_id"));
        assertTrue(audit.stream().allMatch(a -> USER.equals(a.userId())));
    }

    @Test
    void anUnconfirmedRequestNeverErasesAnything() {
        compliance.requestAccountDeletion(USER, "user_requested");
        clock.advance(Duration.ofDays(60));

        assertEquals(0, compliance.executeScheduledDeletions());
        assertTrue(erased.isEmpty());
    }

    @Test
    void aFailedEraseStaysApprovedAndIsTriedAgain() {
        UUID id = confirmedDeletion();
        clock.advance(Duration.ofDays(30));

        eraseFails = true;
        assertEquals(0, compliance.executeScheduledDeletions());
        assertEquals(DataExportCompliance.DeletionStatus.APPROVED, deletion(id).status());
        assertEquals("IOException", auditOf("deletion_failed").details().get("error"));

        eraseFails = false;
        assertEquals(0, compliance.executeScheduledDeletions(), "the failed run's claim still holds");
        clock.advance(DataExportCompliance.CLAIM_LEASE.plusMinutes(1));
        assertEquals(1, compliance.executeScheduledDeletions());
        assertEquals(DataExportCompliance.DeletionStatus.COMPLETED, deletion(id).status());
    }

    /** Marks a row as claimed now, the way a worker that then stopped would have left it. */
    private void claim(String table, String column, UUID id) throws SQLException {
        try (Connection c = db.getConnection();
             PreparedStatement ps = c.prepareStatement("UPDATE " + table + " SET " + column + " = ? WHERE id = ?")) {
            ps.setObject(1, clock.instant().atOffset(ZoneOffset.UTC));
            ps.setObject(2, id);
            ps.executeUpdate();
        }
    }

    @Test
    void aStalledExportIsTakenOverOnceItsClaimExpires() throws SQLException {
        UUID id = compliance.requestDataExport(USER, "json").exportId();
        claim("export_requests", "claimed_at", id);

        compliance.processExport(id);
        assertEquals(DataExportCompliance.ExportStatus.PENDING, compliance.getExportStatus(id, USER).status(),
                "a fresh claim belongs to a worker that may still be running");

        clock.advance(DataExportCompliance.CLAIM_LEASE.plusMinutes(1));
        compliance.processExport(id);
        assertEquals(DataExportCompliance.ExportStatus.COMPLETED, compliance.getExportStatus(id, USER).status());
    }

    @Test
    void csvKeepsEachListItemApart() {
        userData.put("sessions", List.of(Map.of("ip", "10.0.0.1"), Map.of("device_info", "Phone")));

        UUID id = requestAndProcessExport("csv");

        String body = new String(stored.get("exports/" + id + ".csv"), StandardCharsets.UTF_8);
        assertTrue(body.contains("sessions,[0].ip,10.0.0.1\n"));
        assertTrue(body.contains("sessions,[1].device_info,Phone\n"));
    }

    @Test
    void aCancellationCannotWinOnceTheEraseHasStarted() throws SQLException {
        UUID id = confirmedDeletion();
        clock.advance(Duration.ofDays(30));   // exactly at the deadline, when a cancellation and the eraser may overlap
        claim("deletion_requests", "erase_started_at", id);

        assertRefused("cannot_cancel", () -> compliance.cancelDeletion(id, USER));
        assertEquals(DataExportCompliance.DeletionStatus.APPROVED, deletion(id).status());
    }

    @Test
    void aCancellationAtTheDeadlineStopsTheEraser() {
        UUID id = confirmedDeletion();
        clock.advance(Duration.ofDays(30));

        assertEquals(DataExportCompliance.DeletionStatus.CANCELLED, compliance.cancelDeletion(id, USER));
        assertEquals(0, compliance.executeScheduledDeletions());
        assertTrue(erased.isEmpty());
    }

    /* ---------- admin ---------- */

    // EXPORT-10
    @Test
    void adminsCanListExportsByUserAndStatus() {
        UUID done = requestAndProcessExport("json");
        UUID waiting = compliance.requestDataExport(STRANGER, "csv").exportId();

        assertEquals(2, compliance.listExportRequests(ADMIN, null, null).total());
        DataExportCompliance.Listing<DataExportCompliance.ExportView> mine = compliance.listExportRequests(ADMIN, USER, null);
        assertEquals(Set.of(done), Set.copyOf(mine.items().stream().map(DataExportCompliance.ExportView::exportId).toList()));
        DataExportCompliance.Listing<DataExportCompliance.ExportView> pending =
                compliance.listExportRequests(ADMIN, null, DataExportCompliance.ExportStatus.PENDING);
        assertEquals(1, pending.total());
        assertEquals(waiting, pending.items().get(0).exportId());
    }

    // EXPORT-10
    @Test
    void adminsCanListDeletionsByStatus() {
        UUID approved = confirmedDeletion();
        compliance.requestAccountDeletion(STRANGER, "other");

        assertEquals(2, compliance.listDeletionRequests(ADMIN, null).total());
        DataExportCompliance.Listing<DataExportCompliance.DeletionView> listed =
                compliance.listDeletionRequests(ADMIN, DataExportCompliance.DeletionStatus.APPROVED);
        assertEquals(1, listed.total());
        assertEquals(approved, listed.items().get(0).deletionId());
        assertEquals("user_requested", listed.items().get(0).reason());
    }

    @Test
    void listingsAreForAdminsOnly() {
        assertRefused("forbidden", () -> compliance.listExportRequests(USER, null, null));
        assertRefused("forbidden", () -> compliance.listDeletionRequests(USER, null));
    }
}
