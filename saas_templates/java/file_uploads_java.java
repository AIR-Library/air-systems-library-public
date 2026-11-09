package com.saas.fileuploads;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.sql.DataSource;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.*;
import java.time.Instant;
import java.util.*;
import java.util.Base64.Encoder;

public final class FileUploadService {
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of("pdf", "png", "jpg", "jpeg", "gif", "txt", "csv", "docx", "xlsx");
    private static final Map<String, byte[]> MAGIC_BYTES = Map.of(
        "png", new byte[]{(byte)0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
        "jpg", new byte[]{(byte)0xFF, (byte)0xD8, (byte)0xFF},
        "jpeg", new byte[]{(byte)0xFF, (byte)0xD8, (byte)0xFF},
        "pdf", new byte[]{0x25, 0x50, 0x44, 0x46, 0x2D},
        "docx", new byte[]{0x50, 0x4B, 0x03, 0x04},
        "xlsx", new byte[]{0x50, 0x4B, 0x03, 0x04}
    );
    private static final byte[] GIF87A = new byte[]{0x47, 0x49, 0x46, 0x38, 0x37, 0x61};
    private static final byte[] GIF89A = new byte[]{0x47, 0x49, 0x46, 0x38, 0x39, 0x61};
    private static final int MAX_FILENAME_LENGTH = 255;
    private static final long DEFAULT_MAX_SIZE = 10 * 1024 * 1024L;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private final DataSource dataSource;
    private final Path storageRoot;
    private final long maxFileSize;
    private final byte[] hmacKey;

    public record Config(String jdbcUrl, String storageRoot, long maxFileSize, String hmacKeyBase64) {}
    public record UploadResult(String fileId) {}
    public record DownloadLink(String token) {}
    public record FileMeta(String id, String orgId, String ownerUserId, String storedName, String originalName,
                           String extension, String mimeType, long sizeBytes, String sha256, Instant createdAt,
                           Instant deletedAt) {}

    public FileUploadService(Config config) throws Exception {
        this.dataSource = new SimpleDataSource(config.jdbcUrl);
        this.storageRoot = Paths.get(config.storageRoot).toAbsolutePath().normalize();
        this.maxFileSize = config.maxFileSize > 0 ? config.maxFileSize : DEFAULT_MAX_SIZE;
        this.hmacKey = Base64.getDecoder().decode(config.hmacKeyBase64);
        Files.createDirectories(this.storageRoot);
        initSchema();
    }

    private void initSchema() throws SQLException {
        try (Connection c = dataSource.getConnection(); Statement s = c.createStatement()) {
            s.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id VARCHAR(36) PRIMARY KEY,
                    org_id VARCHAR(36) NOT NULL,
                    owner_user_id VARCHAR(36) NOT NULL,
                    stored_name VARCHAR(255) NOT NULL,
                    original_name VARCHAR(255) NOT NULL,
                    extension VARCHAR(10) NOT NULL,
                    mime_type VARCHAR(100) NOT NULL,
                    size_bytes BIGINT NOT NULL,
                    sha256 VARCHAR(64) NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    deleted_at TIMESTAMP NULL
                );
                CREATE INDEX IF NOT EXISTS idx_files_org ON files(org_id);
                CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_user_id);
                
                CREATE TABLE IF NOT EXISTS org_members (
                    org_id VARCHAR(36) NOT NULL,
                    user_id VARCHAR(36) NOT NULL,
                    PRIMARY KEY (org_id, user_id)
                );
            """);
        }
    }

    public UploadResult upload(String userId, String orgId, String originalFilename, byte[] content, String declaredContentType)
            throws IOException, SQLException, UploadException {
        if (!isOrgMember(userId, orgId)) throw new UploadException("User not a member of organization");
        if (content.length > maxFileSize) throw new UploadException("File exceeds size limit");

        String ext = extractExtension(originalFilename).toLowerCase();
        if (!ALLOWED_EXTENSIONS.contains(ext)) throw new UploadException("Extension not allowed");

        if (!verifyMagicBytes(content, ext)) throw new UploadException("File signature does not match extension");
        if (isTextType(ext) && containsNullBytes(content)) throw new UploadException("Text file contains NUL bytes");

        String sanitizedOriginal = sanitizeFilename(originalFilename);
        if (sanitizedOriginal.length() > MAX_FILENAME_LENGTH) throw new UploadException("Filename too long");

        String fileId = UUID.randomUUID().toString();
        String storedName = fileId + "." + ext;
        String sha256 = computeSha256(content);
        Instant now = Instant.now();

        Path target = storageRoot.resolve(storedName);
        Files.write(target, content, StandardOpenOption.CREATE_NEW);

        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement("""
                 INSERT INTO files (id, org_id, owner_user_id, stored_name, original_name, extension, mime_type, size_bytes, sha256, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             """)) {
            ps.setString(1, fileId);
            ps.setString(2, orgId);
            ps.setString(3, userId);
            ps.setString(4, storedName);
            ps.setString(5, sanitizedOriginal);
            ps.setString(6, ext);
            ps.setString(7, declaredContentType != null ? declaredContentType : "application/octet-stream");
            ps.setLong(8, content.length);
            ps.setString(9, sha256);
            ps.setTimestamp(10, Timestamp.from(now));
            ps.executeUpdate();
        }
        return new UploadResult(fileId);
    }

    public DownloadLink createDownloadLink(String userId, String fileId, int ttlSeconds) throws SQLException, DownloadException {
        FileMeta meta = getFileMeta(fileId);
        if (meta == null || meta.deletedAt() != null) throw new DownloadException("File not found");
        if (!canAccess(userId, meta)) throw new DownloadException("Access denied");

        long expiresAt = Instant.now().getEpochSecond() + ttlSeconds;
        String payload = fileId + "." + expiresAt;
        String signature = hmacSha256(payload);
        String token = URL_ENCODER.encodeToString((payload + "." + signature).getBytes());
        return new DownloadLink(token);
    }

    public byte[] download(String userId, String token) throws IOException, SQLException, DownloadException {
        try {
            String[] parts = new String(Base64.getUrlDecoder().decode(token)).split("\\.", 3);
            if (parts.length != 3) throw new DownloadException("Invalid token format");

            String fileId = parts[0];
            long expiresAt = Long.parseLong(parts[1]);
            String providedSig = parts[2];

            if (Instant.now().getEpochSecond() > expiresAt) throw new DownloadException("Link expired");

            String expectedPayload = fileId + "." + expiresAt;
            String expectedSig = hmacSha256(expectedPayload);
            if (!constantTimeEquals(providedSig, expectedSig)) throw new DownloadException("Invalid signature");

            FileMeta meta = getFileMeta(fileId);
            if (meta == null || meta.deletedAt() != null) throw new DownloadException("File not found");
            if (!canAccess(userId, meta)) throw new DownloadException("Access denied");

            Path filePath = storageRoot.resolve(meta.storedName());
            if (!Files.exists(filePath)) throw new DownloadException("File not found on disk");
            return Files.readAllBytes(filePath);
        } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
            throw new DownloadException("Invalid token format");
        }
    }

    public void deleteFile(String userId, String fileId) throws SQLException, DownloadException {
        FileMeta meta = getFileMeta(fileId);
        if (meta == null || meta.deletedAt() != null) throw new DownloadException("File not found");
        if (!canAccess(userId, meta)) throw new DownloadException("Access denied");

        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement("UPDATE files SET deleted_at = ? WHERE id = ?")) {
            ps.setTimestamp(1, Timestamp.from(Instant.now()));
            ps.setString(2, fileId);
            ps.executeUpdate();
        }
    }

    private boolean isOrgMember(String userId, String orgId) throws SQLException {
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement("SELECT 1 FROM org_members WHERE org_id = ? AND user_id = ?")) {
            ps.setString(1, orgId);
            ps.setString(2, userId);
            return ps.executeQuery().next();
        }
    }

    private boolean canAccess(String userId, FileMeta meta) throws SQLException {
        return meta.ownerUserId().equals(userId) || isOrgMember(userId, meta.orgId());
    }

    private FileMeta getFileMeta(String fileId) throws SQLException {
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement("SELECT * FROM files WHERE id = ?")) {
            ps.setString(1, fileId);
            ResultSet rs = ps.executeQuery();
            if (!rs.next()) return null;
            Timestamp deletedTs = rs.getTimestamp("deleted_at");
            return new FileMeta(
                rs.getString("id"), rs.getString("org_id"), rs.getString("owner_user_id"),
                rs.getString("stored_name"), rs.getString("original_name"), rs.getString("extension"),
                rs.getString("mime_type"), rs.getLong("size_bytes"), rs.getString("sha256"),
                rs.getTimestamp("created_at").toInstant(),
                deletedTs != null ? deletedTs.toInstant() : null
            );
        }
    }

    private String extractExtension(String filename) {
        int dot = filename.lastIndexOf('.');
        return dot > 0 ? filename.substring(dot + 1) : "";
    }

    private boolean verifyMagicBytes(byte[] content, String ext) {
        if (ext.equals("gif")) {
            return checkMagic(content, GIF87A) || checkMagic(content, GIF89A);
        }
        byte[] magic = MAGIC_BYTES.get(ext);
        if (magic == null) return true;
        return checkMagic(content, magic);
    }

    private boolean checkMagic(byte[] content, byte[] magic) {
        if (content.length < magic.length) return false;
        for (int i = 0; i < magic.length; i++) {
            if (content[i] != magic[i]) return false;
        }
        return true;
    }

    private boolean isTextType(String ext) {
        return ext.equals("txt") || ext.equals("csv");
    }

    private boolean containsNullBytes(byte[] content) {
        for (byte b : content) if (b == 0) return true;
        return false;
    }

    private String sanitizeFilename(String name) {
        String base = Paths.get(name).getFileName().toString();
        return base.replaceAll("[\\p{Cntrl}]", "");
    }

    private String computeSha256(byte[] content) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return bytesToHex(md.digest(content));
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    private String hmacSha256(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
            return URL_ENCODER.encodeToString(mac.doFinal(data.getBytes()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) return false;
        int result = 0;
        for (int i = 0; i < a.length(); i++) result |= a.charAt(i) ^ b.charAt(i);
        return result == 0;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static class UploadException extends Exception { public UploadException(String m) { super(m); } }
    public static class DownloadException extends Exception { public DownloadException(String m) { super(m); } }

    private static class SimpleDataSource implements DataSource {
        private final String url;
        SimpleDataSource(String url) { this.url = url; }
        public Connection getConnection() throws SQLException { return DriverManager.getConnection(url); }
        public Connection getConnection(String username, String password) throws SQLException { return DriverManager.getConnection(url, username, password); }
        public PrintWriter getLogWriter() throws SQLException { return null; }
        public void setLogWriter(PrintWriter out) throws SQLException {}
        public void setLoginTimeout(int seconds) throws SQLException {}
        public int getLoginTimeout() throws SQLException { return 0; }
        public java.util.logging.Logger getParentLogger() throws SQLFeatureNotSupportedException { throw new SQLFeatureNotSupportedException(); }
        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException { throw new SQLException("SimpleDataSource wraps nothing"); }
        @Override
        public boolean isWrapperFor(Class<?> iface) throws SQLException { return false; }
    }

    public static String generateHmacKey() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
