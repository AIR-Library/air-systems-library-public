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
            }
        };
        DataExportCompliance.Services services = new DataExportCompliance.Services(store,
                (to, subject, body) -> mail.add(new Mail(to, subject, body)),
                (action, userId, details) -> audit.add(new AuditEntry(action, userId, details)),
                users, ADMIN::equals, queued::add);
        compliance = new DataExportCompliance(db, services, clock, "https://app.example.com/");
        compliance.createTables();
    }

    /* ---------- helpers ---------- */

    private void assertRefused(String code, Runnable call) {
        DataExportCompliance.ComplianceException e =
                assertThrows(DataExportCompliance.ComplianceException.class, call::run);
        assertEquals(code, e.code());
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
        compliance.confirmDeletion(id, tokenFromLastMail());
        return id;
    }

    private DataExportCompliance.DeletionView deletion(UUID id) {
        return compliance.listDeletionRequests(ADMIN, null).items().stream()
                .filter(d -> d.deletionId().equals(id)).findFirst().orElseThrow();
    }

    /* ---------- export ---------- */

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

    @Test
    void deletionRequestWaitsThirtyDaysAndEmailsAConfirmationLink() {
        DataExportCompliance.DeletionReceipt receipt = compliance.requestAccountDeletion(USER, "gdpr_right_to_be_forgotten");

        assertEquals(DataExportCompliance.DeletionStatus.PENDING, receipt.status());
        assertEquals(START.plus(Duration.ofDays(30)), receipt.willDeleteAt());
        assertEquals("test@example.com", mail.get(0).to());
        assertTrue(mail.get(0).body().contains(
                "https://app.example.com/compliance/delete/" + receipt.deletionId() + "/confirm?token="));
        assertEquals("gdpr_right_to_be_forgotten", auditOf("deletion_requested").details().get("reason"));
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

    @Test
    void confirmingWithTheEmailedTokenApprovesTheDeletion() {
        DataExportCompliance.DeletionReceipt receipt = compliance.requestAccountDeletion(USER, "user_requested");

        Instant scheduled = compliance.confirmDeletion(receipt.deletionId(), tokenFromLastMail());

        assertEquals(receipt.willDeleteAt(), scheduled);
        assertEquals(DataExportCompliance.DeletionStatus.APPROVED, deletion(receipt.deletionId()).status());
        assertEquals(USER, auditOf("deletion_confirmed").userId());
    }

    @Test
    void confirmingWithAWrongTokenChangesNothing() {
        UUID id = compliance.requestAccountDeletion(USER, "user_requested").deletionId();

        assertRefused("invalid_token", () -> compliance.confirmDeletion(id, "wrong"));
        assertRefused("invalid_token", () -> compliance.confirmDeletion(id, null));
        assertRefused("not_found", () -> compliance.confirmDeletion(UUID.randomUUID(), "wrong"));
        assertEquals(DataExportCompliance.DeletionStatus.PENDING, deletion(id).status());
    }

    @Test
    void aDeletionCanBeConfirmedOnlyOnceAndNotAfterTheGracePeriod() {
        UUID id = compliance.requestAccountDeletion(USER, "user_requested").deletionId();
        String token = tokenFromLastMail();
        compliance.confirmDeletion(id, token);
        assertRefused("not_pending", () -> compliance.confirmDeletion(id, token));

        UUID late = compliance.requestAccountDeletion(USER, "other").deletionId();
        String lateToken = tokenFromLastMail();
        clock.advance(Duration.ofDays(31));
        assertRefused("grace_period_expired", () -> compliance.confirmDeletion(late, lateToken));
    }

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

    @Test
    void aFinishedOrCancelledDeletionCannotBeCancelled() {
        UUID cancelled = confirmedDeletion();
        compliance.cancelDeletion(cancelled, USER);
        assertRefused("cannot_cancel", () -> compliance.cancelDeletion(cancelled, USER));

        UUID finished = confirmedDeletion();
        clock.advance(Duration.ofDays(30));
        compliance.executeScheduledDeletions();
        assertRefused("cannot_cancel", () -> compliance.cancelDeletion(finished, USER));
    }

    @Test
    void onlyTheOwnerOrAnAdminCanCancel() {
        UUID id = confirmedDeletion();

        assertRefused("not_found", () -> compliance.cancelDeletion(id, STRANGER));
        assertEquals(DataExportCompliance.DeletionStatus.CANCELLED, compliance.cancelDeletion(id, ADMIN));
    }

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
        assertEquals(USER, auditOf("deletion_completed").userId());
        assertEquals(0, compliance.executeScheduledDeletions(), "a finished deletion does not run again");
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
