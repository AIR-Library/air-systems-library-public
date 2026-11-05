package com.aoi.rbac;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

/**
 * AOI Permissions & RBAC System (Java)
 * Implements Template #6: PERMISSIONS & RBAC
 */
public class PermissionsRbacSystem {

    // --- Tier Hierarchy: public < member < admin < owner ---
    public enum Tier {
        PUBLIC(0), MEMBER(1), ADMIN(2), OWNER(3), SERVICE(4);
        private final int level;
        Tier(int level) { this.level = level; }
        public int getLevel() { return level; }
        public static Tier fromString(String s) {
            if (s == null) return PUBLIC;
            switch (s.toLowerCase()) {
                case "owner": return OWNER;
                case "admin": return ADMIN;
                case "member": return MEMBER;
                case "service": return SERVICE;
                default: return PUBLIC;
            }
        }
    }

    // --- User Model ---
    public static class User {
        public final String id;
        public final String email;
        public final Tier tier;
        public final String organizationId;
        public final Instant createdAt;

        public User(String id, String email, Tier tier, String organizationId, Instant createdAt) {
            this.id = id;
            this.email = email;
            this.tier = tier;
            this.organizationId = organizationId;
            this.createdAt = createdAt;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new HashMap<>();
            m.put("id", id);
            m.put("email", email);
            m.put("tier", tier.name().toLowerCase());
            m.put("organization_id", organizationId);
            m.put("created_at", createdAt.toString());
            return m;
        }
    }

    // --- Audit Log Entry ---
    public static class AuditLogEntry {
        public final String id;
        public final String action;
        public final String userId;
        public final String endpoint;
        public final String requiredTier;
        public final String userTier;
        public final String decision; // "PASS" or "FAIL"
        public final Map<String, Object> metadata;
        public final Instant timestamp;

        public AuditLogEntry(String id, String action, String userId, String endpoint,
                             String requiredTier, String userTier, String decision,
                             Map<String, Object> metadata, Instant timestamp) {
            this.id = id;
            this.action = action;
            this.userId = userId;
            this.endpoint = endpoint;
            this.requiredTier = requiredTier;
            this.userTier = userTier;
            this.decision = decision;
            this.metadata = metadata;
            this.timestamp = timestamp;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new HashMap<>();
            m.put("id", id);
            m.put("action", action);
            m.put("user_id", userId);
            m.put("endpoint", endpoint);
            m.put("required_tier", requiredTier);
            m.put("user_tier", userTier);
            m.put("decision", decision);
            m.put("metadata", metadata);
            m.put("timestamp", timestamp.toString());
            return m;
        }
    }

    // --- Permission Check Result ---
    public static class PermissionResult {
        public final boolean allowed;
        public final int statusCode;
        public final String errorCode;
        public final String message;

        public PermissionResult(boolean allowed, int statusCode, String errorCode, String message) {
            this.allowed = allowed;
            this.statusCode = statusCode;
            this.errorCode = errorCode;
            this.message = message;
        }

        public Map<String, Object> toErrorMap() {
            Map<String, Object> m = new HashMap<>();
            m.put("error", errorCode);
            m.put("code", statusCode);
            m.put("message", message);
            return m;
        }
    }

    // --- Cascade Delete Result ---
    public static class CascadeResult {
        public final boolean success;
        public final Map<String, Integer> deletedItems;
        public final String error;

        public CascadeResult(boolean success, Map<String, Integer> deletedItems, String error) {
            this.success = success;
            this.deletedItems = deletedItems;
            this.error = error;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new HashMap<>();
            m.put("success", success);
            m.put("deleted_items", deletedItems);
            if (error != null) m.put("error", error);
            return m;
        }
    }

    // --- In-Memory Data Stores (simulating database) ---
    private final Map<String, User> users = new ConcurrentHashMap<>();
    private final Map<String, List<String>> userSessions = new ConcurrentHashMap<>();
    private final Map<String, List<String>> userApiKeys = new ConcurrentHashMap<>();
    private final Map<String, List<String>> userFiles = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Object>> userPreferences = new ConcurrentHashMap<>();
    private final Map<String, List<String>> deploymentDnsRecords = new ConcurrentHashMap<>();
    private final Map<String, List<String>> deploymentThemeConfigs = new ConcurrentHashMap<>();
    private final Map<String, List<String>> deploymentLogs = new ConcurrentHashMap<>();
    private final Map<String, List<String>> orgDeployments = new ConcurrentHashMap<>();
    private final Map<String, List<String>> orgUsers = new ConcurrentHashMap<>();
    private final Map<String, List<String>> orgApiKeys = new ConcurrentHashMap<>();
    private final Map<String, List<String>> orgSessions = new ConcurrentHashMap<>();
    private final List<AuditLogEntry> auditLog = new ArrayList<>();
    private final AtomicLong auditIdCounter = new AtomicLong(1);
    private final AtomicLong userIdCounter = new AtomicLong(1);

    // --- Database Schema (DDL) ---
    public static final String DATABASE_SCHEMA = """
        CREATE TABLE IF NOT EXISTS users (
            id VARCHAR(36) PRIMARY KEY,
            email VARCHAR(255) NOT NULL UNIQUE,
            tier VARCHAR(20) NOT NULL DEFAULT 'public',
            organization_id VARCHAR(36),
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id VARCHAR(36) PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL,
            token VARCHAR(512) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id VARCHAR(36) PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL,
            key_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS files (
            id VARCHAR(36) PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL,
            filename VARCHAR(255) NOT NULL,
            storage_path VARCHAR(512) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS preferences (
            user_id VARCHAR(36) PRIMARY KEY,
            settings JSON NOT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS deployments (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL,
            name VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS dns_records (
            id VARCHAR(36) PRIMARY KEY,
            deployment_id VARCHAR(36) NOT NULL,
            record_type VARCHAR(20) NOT NULL,
            value VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (deployment_id) REFERENCES deployments(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS theme_configs (
            id VARCHAR(36) PRIMARY KEY,
            deployment_id VARCHAR(36) NOT NULL,
            config JSON NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (deployment_id) REFERENCES deployments(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS deployment_logs (
            id VARCHAR(36) PRIMARY KEY,
            deployment_id VARCHAR(36) NOT NULL,
            level VARCHAR(20) NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (deployment_id) REFERENCES deployments(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS organizations (
            id VARCHAR(36) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            action VARCHAR(100) NOT NULL,
            user_id VARCHAR(36),
            endpoint VARCHAR(255),
            required_tier VARCHAR(20),
            user_tier VARCHAR(20),
            decision VARCHAR(10) NOT NULL,
            metadata JSON,
            timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX idx_audit_user ON audit_log(user_id);
        CREATE INDEX idx_audit_action ON audit_log(action);
        CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
        """;

    // --- Constructor ---
    public PermissionsRbacSystem() {
        // Initialize in-memory stores
    }

    // --- User Management ---
    public User createUser(String email, Tier tier, String organizationId) {
        String id = "user-" + userIdCounter.incrementAndGet();
        User user = new User(id, email, tier, organizationId, Instant.now());
        users.put(id, user);
        userSessions.put(id, new ArrayList<>());
        userApiKeys.put(id, new ArrayList<>());
        userFiles.put(id, new ArrayList<>());
        userPreferences.put(id, new HashMap<>());
        return user;
    }

    public User getUser(String userId) {
        return users.get(userId);
    }

    public List<User> listUsers() {
        return new ArrayList<>(users.values());
    }

    // --- Session Management ---
    public void addSession(String userId, String sessionId) {
        userSessions.computeIfAbsent(userId, k -> new ArrayList<>()).add(sessionId);
    }

    public List<String> getUserSessions(String userId) {
        return userSessions.getOrDefault(userId, new ArrayList<>());
    }

    // --- API Key Management ---
    public void addApiKey(String userId, String apiKeyId) {
        userApiKeys.computeIfAbsent(userId, k -> new ArrayList<>()).add(apiKeyId);
    }

    public List<String> getUserApiKeys(String userId) {
        return userApiKeys.getOrDefault(userId, new ArrayList<>());
    }

    // --- File Management ---
    public void addFile(String userId, String fileId) {
        userFiles.computeIfAbsent(userId, k -> new ArrayList<>()).add(fileId);
    }

    public List<String> getUserFiles(String userId) {
        return userFiles.getOrDefault(userId, new ArrayList<>());
    }

    // --- Preference Management ---
    public void setPreference(String userId, String key, Object value) {
        userPreferences.computeIfAbsent(userId, k -> new HashMap<>()).put(key, value);
    }

    public Map<String, Object> getUserPreferences(String userId) {
        return userPreferences.getOrDefault(userId, new HashMap<>());
    }

    // --- Deployment Management ---
    public void addDeploymentToOrg(String orgId, String deploymentId) {
        orgDeployments.computeIfAbsent(orgId, k -> new ArrayList<>()).add(deploymentId);
    }

    public List<String> getOrgDeployments(String orgId) {
        return orgDeployments.getOrDefault(orgId, new ArrayList<>());
    }

    public void addDnsRecord(String deploymentId, String recordId) {
        deploymentDnsRecords.computeIfAbsent(deploymentId, k -> new ArrayList<>()).add(recordId);
    }

    public List<String> getDeploymentDnsRecords(String deploymentId) {
        return deploymentDnsRecords.getOrDefault(deploymentId, new ArrayList<>());
    }

    public void addThemeConfig(String deploymentId, String configId) {
        deploymentThemeConfigs.computeIfAbsent(deploymentId, k -> new ArrayList<>()).add(configId);
    }

    public List<String> getDeploymentThemeConfigs(String deploymentId) {
        return deploymentThemeConfigs.getOrDefault(deploymentId, new ArrayList<>());
    }

    public void addDeploymentLog(String deploymentId, String logId) {
        deploymentLogs.computeIfAbsent(deploymentId, k -> new ArrayList<>()).add(logId);
    }

    public List<String> getDeploymentLogs(String deploymentId) {
        return deploymentLogs.getOrDefault(deploymentId, new ArrayList<>());
    }

    // --- Organization Management ---
    public void addUserToOrg(String orgId, String userId) {
        orgUsers.computeIfAbsent(orgId, k -> new ArrayList<>()).add(userId);
    }

    public List<String> getOrgUsers(String orgId) {
        return orgUsers.getOrDefault(orgId, new ArrayList<>());
    }

    public void addApiKeyToOrg(String orgId, String apiKeyId) {
        orgApiKeys.computeIfAbsent(orgId, k -> new ArrayList<>()).add(apiKeyId);
    }

    public List<String> getOrgApiKeys(String orgId) {
        return orgApiKeys.getOrDefault(orgId, new ArrayList<>());
    }

    public void addSessionToOrg(String orgId, String sessionId) {
        orgSessions.computeIfAbsent(orgId, k -> new ArrayList<>()).add(sessionId);
    }

    public List<String> getOrgSessions(String orgId) {
        return orgSessions.getOrDefault(orgId, new ArrayList<>());
    }

    // --- Permission Check Middleware ---

    /**
     * Check if user has OWNER tier
     */
    public PermissionResult requireOwner(User currentUser, String endpoint) {
        String userTier = currentUser != null ? currentUser.tier.name().toLowerCase() : "public";
        String requiredTier = "owner";
        boolean pass = currentUser != null && currentUser.tier == Tier.OWNER;

        // Log permission check
        logPermissionCheck(currentUser, endpoint, requiredTier, userTier, pass);

        if (!pass) {
            return new PermissionResult(false, 403, "owner_only", "Owner access required");
        }
        return new PermissionResult(true, 200, null, null);
    }

    /**
     * Check if user has ADMIN or OWNER tier
     */
    public PermissionResult requireAdmin(User currentUser, String endpoint) {
        String userTier = currentUser != null ? currentUser.tier.name().toLowerCase() : "public";
        String requiredTier = "admin";
        boolean pass = currentUser != null && (currentUser.tier == Tier.ADMIN || currentUser.tier == Tier.OWNER);

        // Log permission check
        logPermissionCheck(currentUser, endpoint, requiredTier, userTier, pass);

        if (!pass) {
            return new PermissionResult(false, 403, "admin_only", "Admin access required");
        }
        return new PermissionResult(true, 200, null, null);
    }

    /**
     * Check if user is authenticated (not public)
     */
    public PermissionResult requireAuthenticated(User currentUser, String endpoint) {
        String userTier = currentUser != null ? currentUser.tier.name().toLowerCase() : "public";
        String requiredTier = "authenticated";
        boolean pass = currentUser != null && currentUser.tier != Tier.PUBLIC;

        // Log permission check
        logPermissionCheck(currentUser, endpoint, requiredTier, userTier, pass);

        if (!pass) {
            return new PermissionResult(false, 401, "authentication_required", "Authentication required");
        }
        return new PermissionResult(true, 200, null, null);
    }

    /**
     * Generic permission check with tier hierarchy
     */
    public PermissionResult checkPermission(User currentUser, Tier requiredTier, String endpoint) {
        String userTier = currentUser != null ? currentUser.tier.name().toLowerCase() : "public";
        String requiredTierStr = requiredTier.name().toLowerCase();
        boolean pass = currentUser != null && currentUser.tier.getLevel() >= requiredTier.getLevel();

        // Log permission check
        logPermissionCheck(currentUser, endpoint, requiredTierStr, userTier, pass);

        if (!pass) {
            String errorCode = "permission_denied";
            if (requiredTier == Tier.OWNER) errorCode = "owner_only";
            else if (requiredTier == Tier.ADMIN) errorCode = "admin_only";
            return new PermissionResult(false, 403, errorCode, "Permission denied: requires " + requiredTierStr + " tier");
        }
        return new PermissionResult(true, 200, null, null);
    }

    /**
     * Log permission check to audit log
     */
    private void logPermissionCheck(User currentUser, String endpoint, String requiredTier, String userTier, boolean pass) {
        String userId = currentUser != null ? currentUser.id : "anonymous";
        String decision = pass ? "PASS" : "FAIL";
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("timestamp", Instant.now().toString());

        AuditLogEntry entry = new AuditLogEntry(
            "audit-" + auditIdCounter.incrementAndGet(),
            "permission_check",
            userId,
            endpoint,
            requiredTier,
            userTier,
            decision,
            metadata,
            Instant.now()
        );
        synchronized (auditLog) {
            auditLog.add(entry);
        }
    }

    // --- Cascade Delete Operations ---

    /**
     * Cascade delete user: sessions, api_keys, files, preferences
     */
    public CascadeResult deleteUserCascade(String userId) {
        Map<String, Integer> deletedItems = new HashMap<>();
        try {
            // Simulate transaction
            int sessionsDeleted = 0;
            int keysDeleted = 0;
            int filesDeleted = 0;
            int prefsCleared = 0;

            List<String> sessions = userSessions.get(userId);
            if (sessions != null) {
                sessionsDeleted = sessions.size();
                sessions.clear();
            }

            List<String> keys = userApiKeys.get(userId);
            if (keys != null) {
                keysDeleted = keys.size();
                keys.clear();
            }

            List<String> files = userFiles.get(userId);
            if (files != null) {
                filesDeleted = files.size();
                files.clear();
            }

            Map<String, Object> prefs = userPreferences.get(userId);
            if (prefs != null) {
                prefsCleared = prefs.size();
                prefs.clear();
            }

            users.remove(userId);

            deletedItems.put("sessions", sessionsDeleted);
            deletedItems.put("keys", keysDeleted);
            deletedItems.put("files", filesDeleted);
            deletedItems.put("preferences", prefsCleared);

            // Log cascade delete
            logCascadeDelete("user_deleted_cascade", userId, deletedItems);

            return new CascadeResult(true, deletedItems, null);

        } catch (Exception e) {
            // Rollback: restore data (simulated)
            return new CascadeResult(false, deletedItems, "Cascade delete failed: " + e.getMessage());
        }
    }

    /**
     * Cascade delete deployment: dns_records, theme_configs, deployment_logs, archive to S3
     */
    public CascadeResult deleteDeploymentCascade(String deploymentId) {
        Map<String, Integer> deletedItems = new HashMap<>();
        try {
            int dnsDeleted = 0;
            int themesDeleted = 0;
            int logsDeleted = 0;

            List<String> dns = deploymentDnsRecords.get(deploymentId);
            if (dns != null) {
                dnsDeleted = dns.size();
                dns.clear();
            }

            List<String> themes = deploymentThemeConfigs.get(deploymentId);
            if (themes != null) {
                themesDeleted = themes.size();
                themes.clear();
            }

            List<String> logs = deploymentLogs.get(deploymentId);
            if (logs != null) {
                logsDeleted = logs.size();
                logs.clear();
            }

            // Archive to S3 (simulated)
            // In production: s3Client.putObject("archive-bucket", deploymentId + "/archive.tar.gz", ...)

            deletedItems.put("dns", dnsDeleted);
            deletedItems.put("theme_configs", themesDeleted);
            deletedItems.put("deployment_logs", logsDeleted);
            deletedItems.put("archived_to_s3", 1);

            // Log cascade delete
            logCascadeDelete("deployment_deleted_cascade", deploymentId, deletedItems);

            return new CascadeResult(true, deletedItems, null);

        } catch (Exception e) {
            return new CascadeResult(false, deletedItems, "Cascade delete failed: " + e.getMessage());
        }
    }

    /**
     * Cascade delete organization: deployments, users, api_keys, sessions
     */
    public CascadeResult deleteOrganizationCascade(String orgId) {
        Map<String, Integer> deletedItems = new HashMap<>();
        try {
            int deploymentsDeleted = 0;
            int usersDeleted = 0;
            int keysDeleted = 0;
            int sessionsRevoked = 0;

            List<String> deployments = orgDeployments.get(orgId);
            if (deployments != null) {
                deploymentsDeleted = deployments.size();
                // Delete each deployment cascade
                for (String depId : deployments) {
                    deleteDeploymentCascade(depId);
                }
                deployments.clear();
            }

            // FIX: rename local variable to avoid shadowing the field 'orgUsers'
            List<String> orgUserList = orgUsers.get(orgId);
            if (orgUserList != null) {
                usersDeleted = orgUserList.size();
                // Delete each user cascade
                for (String userId : orgUserList) {
                    deleteUserCascade(userId);
                }
                orgUserList.clear();
            }

            List<String> keys = orgApiKeys.get(orgId);
            if (keys != null) {
                keysDeleted = keys.size();
                keys.clear();
            }

            List<String> sessions = orgSessions.get(orgId);
            if (sessions != null) {
                sessionsRevoked = sessions.size();
                sessions.clear();
            }

            deletedItems.put("deployments", deploymentsDeleted);
            deletedItems.put("users", usersDeleted);
            deletedItems.put("api_keys", keysDeleted);
            deletedItems.put("sessions", sessionsRevoked);

            // Log cascade delete
            logCascadeDelete("org_deleted_cascade", orgId, deletedItems);

            return new CascadeResult(true, deletedItems, null);

        } catch (Exception e) {
            return new CascadeResult(false, deletedItems, "Cascade delete failed: " + e.getMessage());
        }
    }

    /**
     * Log cascade delete to audit log
     */
    private void logCascadeDelete(String action, String entityId, Map<String, Integer> deletedItems) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("deleted_items", deletedItems);
        metadata.put("timestamp", Instant.now().toString());

        AuditLogEntry entry = new AuditLogEntry(
            "audit-" + auditIdCounter.incrementAndGet(),
            action,
            "system",
            "cascade_delete",
            "owner",
            "system",
            "PASS",
            metadata,
            Instant.now()
        );
        synchronized (auditLog) {
            auditLog.add(entry);
        }
    }

    // --- Audit Log Queries ---

    /**
     * Get all audit log entries
     */
    public List<AuditLogEntry> getAuditLog() {
        synchronized (auditLog) {
            return new ArrayList<>(auditLog);
        }
    }

    /**
     * Get audit log entries for a specific user
     */
    public List<AuditLogEntry> getAuditLogByUser(String userId) {
        synchronized (auditLog) {
            return auditLog.stream()
                .filter(e -> userId.equals(e.userId))
                .collect(java.util.stream.Collectors.toList());
        }
    }

    /**
     * Get audit log entries for a specific action
     */
    public List<AuditLogEntry> getAuditLogByAction(String action) {
        synchronized (auditLog) {
            return auditLog.stream()
                .filter(e -> action.equals(e.action))
                .collect(java.util.stream.Collectors.toList());
        }
    }

    /**
     * Get failed permission checks (forensics)
     */
    public List<AuditLogEntry> getFailedPermissionChecks() {
        synchronized (auditLog) {
            return auditLog.stream()
                .filter(e -> "permission_check".equals(e.action) && "FAIL".equals(e.decision))
                .collect(java.util.stream.Collectors.toList());
        }
    }

    /**
     * Get permission checks for a specific endpoint
     */
    public List<AuditLogEntry> getPermissionChecksByEndpoint(String endpoint) {
        synchronized (auditLog) {
            return auditLog.stream()
                .filter(e -> "permission_check".equals(e.action) && endpoint.equals(e.endpoint))
                .collect(java.util.stream.Collectors.toList());
        }
    }

    // --- Utility Methods ---

    /**
     * Check if tier hierarchy allows access
     */
    public boolean hasTierAccess(Tier userTier, Tier requiredTier) {
        return userTier != null && userTier.getLevel() >= requiredTier.getLevel();
    }

    /**
     * Get tier hierarchy order
     */
    public List<String> getTierHierarchy() {
        return List.of("public", "member", "admin", "owner");
    }

    /**
     * Validate tier string - returns true only for known tier names
     */
    public boolean isValidTier(String tier) {
        if (tier == null) return false;
        String lower = tier.toLowerCase();
        return lower.equals("public") || lower.equals("member") || lower.equals("admin") || lower.equals("owner") || lower.equals("service");
    }

    /**
     * Get current time in UTC ISO 8601
     */
    public String getCurrentUtcTime() {
        return Instant.now().toString();
    }

    /**
     * Clear all data (for testing)
     */
    public void clearAllData() {
        users.clear();
        userSessions.clear();
        userApiKeys.clear();
        userFiles.clear();
        userPreferences.clear();
        deploymentDnsRecords.clear();
        deploymentThemeConfigs.clear();
        deploymentLogs.clear();
        orgDeployments.clear();
        orgUsers.clear();
        orgApiKeys.clear();
        orgSessions.clear();
        synchronized (auditLog) {
            auditLog.clear();
        }
        auditIdCounter.set(1);
        userIdCounter.set(1);
    }
}
