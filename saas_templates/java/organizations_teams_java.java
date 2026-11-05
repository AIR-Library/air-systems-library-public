import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class OrganizationsTeams {
    private final Connection db;

    public OrganizationsTeams(Connection db) {
        this.db = db;
    }

    public static void initSchema(Connection db) throws SQLException {
        db.createStatement().execute(
            "CREATE TABLE IF NOT EXISTS users (" +
            "id BIGINT AUTO_INCREMENT PRIMARY KEY, email VARCHAR(255) UNIQUE NOT NULL)"
        );
        db.createStatement().execute(
            "CREATE TABLE IF NOT EXISTS organizations (" +
            "id BIGINT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255) NOT NULL, " +
            "slug VARCHAR(255) UNIQUE NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        );
        db.createStatement().execute(
            "CREATE TABLE IF NOT EXISTS memberships (" +
            "org_id BIGINT NOT NULL, user_id BIGINT NOT NULL, " +
            "role ENUM('owner','admin','member') NOT NULL, " +
            "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, " +
            "PRIMARY KEY (org_id, user_id))"
        );
        db.createStatement().execute(
            "CREATE TABLE IF NOT EXISTS invitations (" +
            "id BIGINT AUTO_INCREMENT PRIMARY KEY, org_id BIGINT NOT NULL, " +
            "email VARCHAR(255) NOT NULL, role ENUM('owner','admin','member') NOT NULL, " +
            "token_hash VARCHAR(64) NOT NULL UNIQUE, " +
            "expires_at TIMESTAMP NOT NULL, accepted_at TIMESTAMP NULL, " +
            "invited_by BIGINT NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        );
    }

    private String hashToken(String rawToken) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(rawToken.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public String hashTokenPublic(String rawToken) throws NoSuchAlgorithmException {
        return hashToken(rawToken);
    }

    private String generateToken() {
        SecureRandom sr = new SecureRandom();
        byte[] token = new byte[32];
        sr.nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }

    private String generateSlug(String name) {
        return name.toLowerCase().replaceAll("[^a-z0-9]+", "-").replaceAll("^-|-$", "");
    }

    private boolean isMember(long orgId, long userId) throws SQLException {
        try (PreparedStatement ps = db.prepareStatement(
            "SELECT 1 FROM memberships WHERE org_id=? AND user_id=?")) {
            ps.setLong(1, orgId);
            ps.setLong(2, userId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    public boolean isMemberPublic(long orgId, long userId) throws SQLException {
        return isMember(orgId, userId);
    }

    private String getRole(long orgId, long userId) throws SQLException {
        try (PreparedStatement ps = db.prepareStatement(
            "SELECT role FROM memberships WHERE org_id=? AND user_id=?")) {
            ps.setLong(1, orgId);
            ps.setLong(2, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getString("role");
                return null;
            }
        }
    }

    public String getRolePublic(long orgId, long userId) throws SQLException {
        return getRole(orgId, userId);
    }

    private int countOwners(long orgId) throws SQLException {
        try (PreparedStatement ps = db.prepareStatement(
            "SELECT COUNT(*) FROM memberships WHERE org_id=? AND role='owner'")) {
            ps.setLong(1, orgId);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }

    public Map<String, Object> createOrg(long userId, String name) throws SQLException, NoSuchAlgorithmException {
        String slug = generateSlug(name);
        try (PreparedStatement ps = db.prepareStatement(
            "INSERT INTO organizations (name, slug) VALUES (?, ?)", Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, name);
            ps.setString(2, slug);
            ps.executeUpdate();
            try (ResultSet rs = ps.getGeneratedKeys()) {
                rs.next();
                long orgId = rs.getLong(1);
                try (PreparedStatement ms = db.prepareStatement(
                    "INSERT INTO memberships (org_id, user_id, role) VALUES (?, ?, 'owner')")) {
                    ms.setLong(1, orgId);
                    ms.setLong(2, userId);
                    ms.executeUpdate();
                }
                Map<String, Object> org = new HashMap<>();
                org.put("id", orgId);
                org.put("name", name);
                org.put("slug", slug);
                org.put("created_at", Instant.now().toString());
                return org;
            }
        }
    }

    public String invite(long actorId, long orgId, String email, String role) throws SQLException, NoSuchAlgorithmException {
        if (!isMember(orgId, actorId)) throw new SecurityException("not_found");
        String actorRole = getRole(orgId, actorId);
        if (!"admin".equals(actorRole) && !"owner".equals(actorRole)) throw new SecurityException("forbidden");
        if (!"owner".equals(actorRole) && "owner".equals(role)) throw new SecurityException("forbidden");

        String rawToken = generateToken();
        String tokenHash = hashToken(rawToken);
        Timestamp expiresAt = Timestamp.from(Instant.now().plus(7, ChronoUnit.DAYS));

        try (PreparedStatement ps = db.prepareStatement(
            "INSERT INTO invitations (org_id, email, role, token_hash, expires_at, invited_by) VALUES (?, ?, ?, ?, ?, ?)")) {
            ps.setLong(1, orgId);
            ps.setString(2, email);
            ps.setString(3, role);
            ps.setString(4, tokenHash);
            ps.setTimestamp(5, expiresAt);
            ps.setLong(6, actorId);
            ps.executeUpdate();
        }
        return rawToken;
    }

    public Map<String, Object> acceptInvitation(long userId, String rawToken) throws SQLException, NoSuchAlgorithmException {
        String tokenHash = hashToken(rawToken);
        long invId;
        long orgId;
        String email;
        String role;

        try (PreparedStatement ps = db.prepareStatement(
            "SELECT id, org_id, email, role FROM invitations WHERE token_hash=? AND accepted_at IS NULL AND expires_at > ?")) {
            ps.setString(1, tokenHash);
            ps.setTimestamp(2, Timestamp.from(Instant.now()));
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new SecurityException("invalid_or_expired_token");
                invId = rs.getLong("id");
                orgId = rs.getLong("org_id");
                email = rs.getString("email");
                role = rs.getString("role");
            }
        }

        // Verify user's email matches invitation email
        String userEmail;
        try (PreparedStatement ups = db.prepareStatement("SELECT email FROM users WHERE id=?")) {
            ups.setLong(1, userId);
            try (ResultSet urs = ups.executeQuery()) {
                if (!urs.next()) throw new SecurityException("user_not_found");
                userEmail = urs.getString("email");
            }
        }
        if (!email.equalsIgnoreCase(userEmail)) throw new SecurityException("email_mismatch");

        if (isMember(orgId, userId)) throw new SecurityException("already_member");

        try (PreparedStatement us = db.prepareStatement(
            "UPDATE invitations SET accepted_at=? WHERE id=?")) {
            us.setTimestamp(1, Timestamp.from(Instant.now()));
            us.setLong(2, invId);
            us.executeUpdate();
        }

        try (PreparedStatement ms = db.prepareStatement(
            "INSERT INTO memberships (org_id, user_id, role) VALUES (?, ?, ?)")) {
            ms.setLong(1, orgId);
            ms.setLong(2, userId);
            ms.setString(3, role);
            ms.executeUpdate();
        }

        Map<String, Object> membership = new HashMap<>();
        membership.put("org_id", orgId);
        membership.put("user_id", userId);
        membership.put("role", role);
        membership.put("created_at", Instant.now().toString());
        return membership;
    }

    public void changeRole(long actorId, long orgId, long userId, String role) throws SQLException {
        if (!isMember(orgId, actorId)) throw new SecurityException("not_found");
        String actorRole = getRole(orgId, actorId);
        if (!"admin".equals(actorRole) && !"owner".equals(actorRole)) throw new SecurityException("forbidden");
        if (!"owner".equals(actorRole) && "owner".equals(role)) throw new SecurityException("forbidden");
        if ("owner".equals(role) && "owner".equals(getRole(orgId, userId))) throw new SecurityException("forbidden");
        if ("owner".equals(getRole(orgId, userId)) && !"owner".equals(role)) {
            if (countOwners(orgId) <= 1) throw new SecurityException("last_owner_cannot_be_demoted");
        }

        try (PreparedStatement ps = db.prepareStatement(
            "UPDATE memberships SET role=? WHERE org_id=? AND user_id=?")) {
            ps.setString(1, role);
            ps.setLong(2, orgId);
            ps.setLong(3, userId);
            int updated = ps.executeUpdate();
            if (updated == 0) throw new SecurityException("not_found");
        }
    }

    public void removeMember(long actorId, long orgId, long userId) throws SQLException {
        if (!isMember(orgId, actorId)) throw new SecurityException("not_found");
        String actorRole = getRole(orgId, actorId);
        if (!"admin".equals(actorRole) && !"owner".equals(actorRole)) throw new SecurityException("forbidden");
        if ("owner".equals(getRole(orgId, userId))) throw new SecurityException("cannot_remove_owner");

        try (PreparedStatement ps = db.prepareStatement(
            "DELETE FROM memberships WHERE org_id=? AND user_id=?")) {
            ps.setLong(1, orgId);
            ps.setLong(2, userId);
            int updated = ps.executeUpdate();
            if (updated == 0) throw new SecurityException("not_found");
        }
    }

    public void leaveOrg(long userId, long orgId) throws SQLException {
        if (!isMember(orgId, userId)) throw new SecurityException("not_found");
        String role = getRole(orgId, userId);
        if ("owner".equals(role) && countOwners(orgId) <= 1) throw new SecurityException("last_owner_cannot_leave");

        try (PreparedStatement ps = db.prepareStatement(
            "DELETE FROM memberships WHERE org_id=? AND user_id=?")) {
            ps.setLong(1, orgId);
            ps.setLong(2, userId);
            int updated = ps.executeUpdate();
            if (updated == 0) throw new SecurityException("not_found");
        }
    }

    public ResultSet listMembers(long actorId, long orgId) throws SQLException {
        if (!isMember(orgId, actorId)) throw new SecurityException("not_found");
        PreparedStatement ps = db.prepareStatement(
            "SELECT m.user_id, m.role, m.created_at FROM memberships m WHERE m.org_id=? ORDER BY m.created_at");
        ps.setLong(1, orgId);
        return ps.executeQuery();
    }

    public Map<String, Object> getOrg(long actorId, long orgId) throws SQLException {
        if (!isMember(orgId, actorId)) throw new SecurityException("not_found");
        try (PreparedStatement ps = db.prepareStatement(
            "SELECT id, name, slug, created_at FROM organizations WHERE id=?")) {
            ps.setLong(1, orgId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new SecurityException("not_found");
                Map<String, Object> org = new HashMap<>();
                org.put("id", rs.getLong("id"));
                org.put("name", rs.getString("name"));
                org.put("slug", rs.getString("slug"));
                org.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                return org;
            }
        }
    }
}
