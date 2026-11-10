import org.junit.jupiter.api.*;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;

public class OrganizationsTeamsTest {
    private static Connection db;
    private OrganizationsTeams ot;

    @BeforeAll
    static void setupDB() throws Exception {
        db = DriverManager.getConnection("jdbc:h2:mem:test;DB_CLOSE_DELAY=-1", "sa", "");
        OrganizationsTeams.initSchema(db);
    }

    @BeforeEach
    void clean() throws SQLException {
        try (Statement stmt = db.createStatement()) {
            stmt.execute("TRUNCATE TABLE memberships");
            stmt.execute("TRUNCATE TABLE invitations");
            stmt.execute("TRUNCATE TABLE organizations");
            stmt.execute("TRUNCATE TABLE users");
        }
        ot = new OrganizationsTeams(db);
    }

    private long createUser(String email) throws SQLException {
        try (PreparedStatement ps = db.prepareStatement("INSERT INTO users (email) VALUES (?)", Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, email);
            ps.executeUpdate();
            try (ResultSet rs = ps.getGeneratedKeys()) {
                rs.next();
                return rs.getLong(1);
            }
        }
    }

    @Test
    void testCreateOrg() throws Exception {
        long userId = createUser("owner@example.com");
        Map<String, Object> org = ot.createOrg(userId, "Acme Corp");
        assertEquals("Acme Corp", org.get("name"));
        assertEquals("acme-corp", org.get("slug"));
        assertTrue((Long) org.get("id") > 0);
    }

    // ORG-01
    @Test
    void testNonMemberCannotReadMembers() throws Exception {
        long ownerId = createUser("owner@example.com");
        long outsiderId = createUser("outsider@example.com");
        Map<String, Object> org = ot.createOrg(ownerId, "TestOrg");
        long orgId = (Long) org.get("id");
        SecurityException e = assertThrows(SecurityException.class, () -> ot.listMembers(outsiderId, orgId));
        assertEquals("not_found", e.getMessage());
    }

    // ORG-02
    @Test
    void testMemberCannotInvite() throws Exception {
        long ownerId = createUser("owner@example.com");
        long memberId = createUser("member@example.com");
        Map<String, Object> org = ot.createOrg(ownerId, "TestOrg");
        long orgId = (Long) org.get("id");
        String memberToken = ot.invite(ownerId, orgId, "member@example.com", "member");
        ot.acceptInvitation(memberId, memberToken);
        assertThrows(SecurityException.class, () -> ot.invite(memberId, orgId, "test@example.com", "member"));
    }

    // ORG-02
    @Test
    void testAdminCanInvite() throws Exception {
        long ownerId = createUser("owner@example.com");
        long adminId = createUser("admin@example.com");
        Map<String, Object> org = ot.createOrg(ownerId, "TestOrg");
        long orgId = (Long) org.get("id");
        String adminToken = ot.invite(ownerId, orgId, "admin@example.com", "admin");
        ot.acceptInvitation(adminId, adminToken);
        String token = ot.invite(adminId, orgId, "newmember@example.com", "member");
        assertNotNull(token);
        assertTrue(token.length() > 0);
    }

    // ORG-03
    @Test
    void testAdminCannotRemoveOwner() throws Exception {
        long ownerId = createUser("owner@example.com");
        long adminId = createUser("admin@example.com");
        Map<String, Object> org = ot.createOrg(ownerId, "TestOrg");
        long orgId = (Long) org.get("id");
        String adminToken = ot.invite(ownerId, orgId, "admin@example.com", "admin");
        ot.acceptInvitation(adminId, adminToken);
        assertThrows(SecurityException.class, () -> ot.removeMember(adminId, orgId, ownerId));
    }

    // ORG-03
    @Test
    void testLastOwnerCannotLeave() throws Exception {
        long ownerId = createUser("owner@example.com");
        Map<String, Object> org = ot.createOrg(ownerId, "TestOrg");
        long orgId = (Long) org.get("id");
        assertThrows(SecurityException.class, () -> ot.leaveOrg(ownerId, orgId));
    }

    // ORG-04
    @Test
    void testInvitationWorksOnce() throws Exception {
        long ownerId = createUser("owner@example.com");
        Map<String, Object> org = ot.createOrg(ownerId, "TestOrg");
        long orgId = (Long) org.get("id");
        String token = ot.invite(ownerId, orgId, "newuser@example.com", "member");
        long newUserId = createUser("newuser@example.com");
        ot.acceptInvitation(newUserId, token);
        // Second use should fail
        assertThrows(SecurityException.class, () -> ot.acceptInvitation(newUserId, token));
    }

    // ORG-05
    @Test
    void testExpiredInvitationFails() throws Exception {
        long ownerId = createUser("owner@example.com");
        Map<String, Object> org = ot.createOrg(ownerId, "TestOrg");
        long orgId = (Long) org.get("id");
        String token = ot.invite(ownerId, orgId, "expired@example.com", "member");
        try (Statement stmt = db.createStatement()) {
            stmt.execute(
                "UPDATE invitations SET expires_at = DATEADD('SECOND', -1, CURRENT_TIMESTAMP) WHERE token_hash = '" +
                ot.hashTokenPublic(token) + "'");
        }
        long newUserId = createUser("expired@example.com");
        assertThrows(SecurityException.class, () -> ot.acceptInvitation(newUserId, token));
    }

    // ORG-05
    @Test
    void testAcceptingWithDifferentEmailFails() throws Exception {
        long ownerId = createUser("owner@example.com");
        Map<String, Object> org = ot.createOrg(ownerId, "TestOrg");
        long orgId = (Long) org.get("id");
        String token = ot.invite(ownerId, orgId, "correct@example.com", "member");
        long wrongUserId = createUser("wrong@example.com");
        assertThrows(SecurityException.class, () -> ot.acceptInvitation(wrongUserId, token));
    }

    /**
     * ORG-06: the raw invitation token is not stored anywhere in the database. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP: besides the token_hash column it now reads every text column of every table
     * (the row says "anywhere"). Touches: the test's in-memory H2 database (reads only).
     */
    // ORG-06
    @Test
    void testRawTokenNotStored() throws Exception {
        long ownerId = createUser("owner@example.com");
        Map<String, Object> org = ot.createOrg(ownerId, "TestOrg");
        long orgId = (Long) org.get("id");
        String token = ot.invite(ownerId, orgId, "test@example.com", "member");
        try (PreparedStatement ps = db.prepareStatement(
            "SELECT COUNT(*) FROM invitations WHERE token_hash = ?")) {
            ps.setString(1, token);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                assertEquals(0, rs.getInt(1));
            }
        }
        List<String> tables = new ArrayList<>();
        try (ResultSet t = db.getMetaData().getTables(null, null, "%", new String[]{"TABLE"})) {
            while (t.next()) {
                String schema = t.getString("TABLE_SCHEM");
                if (!"INFORMATION_SCHEMA".equalsIgnoreCase(schema)) tables.add(schema + "." + t.getString("TABLE_NAME"));
            }
        }
        assertTrue(tables.size() >= 3, "expected the org tables, found " + tables);
        for (String table : tables) {
            try (Statement st = db.createStatement(); ResultSet rs = st.executeQuery("SELECT * FROM " + table)) {
                int cols = rs.getMetaData().getColumnCount();
                while (rs.next()) {
                    for (int c = 1; c <= cols; c++) {
                        String v = rs.getString(c);
                        assertFalse(v != null && v.contains(token), "raw token found in " + table);
                    }
                }
            }
        }
    }

    @Test
    void testGetOrgNonMember() throws Exception {
        long ownerId = createUser("owner@example.com");
        long outsiderId = createUser("outsider@example.com");
        Map<String, Object> org = ot.createOrg(ownerId, "TestOrg");
        long orgId = (Long) org.get("id");
        assertThrows(SecurityException.class, () -> ot.getOrg(outsiderId, orgId));
    }

    @Test
    void testChangeRoleByMemberFails() throws Exception {
        long ownerId = createUser("owner@example.com");
        long memberId = createUser("member@example.com");
        long targetId = createUser("target@example.com");
        Map<String, Object> org = ot.createOrg(ownerId, "TestOrg");
        long orgId = (Long) org.get("id");
        String memberToken = ot.invite(ownerId, orgId, "member@example.com", "member");
        ot.acceptInvitation(memberId, memberToken);
        String targetToken = ot.invite(ownerId, orgId, "target@example.com", "member");
        ot.acceptInvitation(targetId, targetToken);
        assertThrows(SecurityException.class, () -> ot.changeRole(memberId, orgId, targetId, "admin"));
    }

    @Test
    void testAdminCannotPromoteToOwner() throws Exception {
        long ownerId = createUser("owner@example.com");
        long adminId = createUser("admin@example.com");
        long targetId = createUser("target@example.com");
        Map<String, Object> org = ot.createOrg(ownerId, "TestOrg");
        long orgId = (Long) org.get("id");
        String adminToken = ot.invite(ownerId, orgId, "admin@example.com", "admin");
        ot.acceptInvitation(adminId, adminToken);
        String targetToken = ot.invite(ownerId, orgId, "target@example.com", "member");
        ot.acceptInvitation(targetId, targetToken);
        assertThrows(SecurityException.class, () -> ot.changeRole(adminId, orgId, targetId, "owner"));
    }

    @Test
    void testOwnerCanDemoteAdmin() throws Exception {
        long ownerId = createUser("owner@example.com");
        long adminId = createUser("admin@example.com");
        Map<String, Object> org = ot.createOrg(ownerId, "TestOrg");
        long orgId = (Long) org.get("id");
        String adminToken = ot.invite(ownerId, orgId, "admin@example.com", "admin");
        ot.acceptInvitation(adminId, adminToken);
        ot.changeRole(ownerId, orgId, adminId, "member");
        assertEquals("member", ot.getRolePublic(orgId, adminId));
    }

    @Test
    void testOwnerCanRemoveAdmin() throws Exception {
        long ownerId = createUser("owner@example.com");
        long adminId = createUser("admin@example.com");
        Map<String, Object> org = ot.createOrg(ownerId, "TestOrg");
        long orgId = (Long) org.get("id");
        String adminToken = ot.invite(ownerId, orgId, "admin@example.com", "admin");
        ot.acceptInvitation(adminId, adminToken);
        ot.removeMember(ownerId, orgId, adminId);
        assertFalse(ot.isMemberPublic(orgId, adminId));
    }

    @Test
    void testOwnerCannotBeDemotedByAdmin() throws Exception {
        long ownerId = createUser("owner@example.com");
        long adminId = createUser("admin@example.com");
        Map<String, Object> org = ot.createOrg(ownerId, "TestOrg");
        long orgId = (Long) org.get("id");
        String adminToken = ot.invite(ownerId, orgId, "admin@example.com", "admin");
        ot.acceptInvitation(adminId, adminToken);
        assertThrows(SecurityException.class, () -> ot.changeRole(adminId, orgId, ownerId, "member"));
    }

    @Test
    void testSecondOwnerCanLeave() throws Exception {
        long ownerId = createUser("owner@example.com");
        long secondOwnerId = createUser("secondowner@example.com");
        Map<String, Object> org = ot.createOrg(ownerId, "TestOrg");
        long orgId = (Long) org.get("id");
        String token = ot.invite(ownerId, orgId, "secondowner@example.com", "owner");
        ot.acceptInvitation(secondOwnerId, token);
        ot.leaveOrg(secondOwnerId, orgId);
        assertFalse(ot.isMemberPublic(orgId, secondOwnerId));
    }

    @Test
    void testListMembers() throws Exception {
        long ownerId = createUser("owner@example.com");
        long memberId = createUser("member@example.com");
        Map<String, Object> org = ot.createOrg(ownerId, "TestOrg");
        long orgId = (Long) org.get("id");
        String token = ot.invite(ownerId, orgId, "member@example.com", "member");
        ot.acceptInvitation(memberId, token);
        try (ResultSet rs = ot.listMembers(ownerId, orgId)) {
            int count = 0;
            while (rs.next()) count++;
            assertEquals(2, count);
        }
    }

    @Test
    void testGetOrg() throws Exception {
        long ownerId = createUser("owner@example.com");
        Map<String, Object> org = ot.createOrg(ownerId, "TestOrg");
        long orgId = (Long) org.get("id");
        Map<String, Object> fetched = ot.getOrg(ownerId, orgId);
        assertEquals("TestOrg", fetched.get("name"));
    }

    @Test
    void testSlugUniqueness() throws Exception {
        long ownerId = createUser("owner@example.com");
        ot.createOrg(ownerId, "Test Org");
        assertThrows(SQLException.class, () -> ot.createOrg(ownerId, "Test Org"));
    }
}
