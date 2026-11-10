package com.saas.fileuploads;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.file.*;
import java.sql.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class FileUploadServiceTest {
    @TempDir Path tempDir;
    FileUploadService service;
    String hmacKey;
    String orgId = "org-1";
    String userId = "user-1";
    String otherUserId = "user-2";
    String dbUrl;

    @BeforeEach void setup() throws Exception {
        hmacKey = FileUploadService.generateHmacKey();
        dbUrl = "jdbc:h2:mem:test" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1";
        String storage = tempDir.resolve("storage").toString();
        service = new FileUploadService(new FileUploadService.Config(dbUrl, storage, 10 * 1024 * 1024, hmacKey));
        try (Connection c = DriverManager.getConnection(dbUrl); Statement s = c.createStatement()) {
            s.execute("CREATE TABLE IF NOT EXISTS org_members (org_id VARCHAR(36), user_id VARCHAR(36), PRIMARY KEY (org_id, user_id))");
            s.execute("DELETE FROM org_members");
            s.execute("INSERT INTO org_members VALUES ('org-1', 'user-1')");
        }
    }

    private byte[] pngBytes() {
        return new byte[]{(byte)0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52};
    }

    private byte[] exeBytes() {
        return "MZ".getBytes();
    }

    // UPLOAD-01
    @Test void exeRejected() {
        assertThrows(FileUploadService.UploadException.class, () ->
            service.upload(userId, orgId, "malware.exe", exeBytes(), "application/octet-stream"));
    }

    // UPLOAD-01
    @Test void exeRenamedToPngRejectedByMagic() {
        assertThrows(FileUploadService.UploadException.class, () ->
            service.upload(userId, orgId, "malware.png", exeBytes(), "image/png"));
    }

    // UPLOAD-02
    @Test void realPngAcceptedStoredUnderGeneratedName() throws Exception {
        FileUploadService.UploadResult result = service.upload(userId, orgId, "image.png", pngBytes(), "image/png");
        assertNotNull(result.fileId());
        assertTrue(result.fileId().matches("[0-9a-f-]{36}"));
        Path stored = tempDir.resolve("storage").resolve(result.fileId() + ".png");
        assertTrue(Files.exists(stored));
        assertArrayEquals(pngBytes(), Files.readAllBytes(stored));
    }

    // UPLOAD-03
    @Test void pathTraversalInFilenameStoredSafely() throws Exception {
        FileUploadService.UploadResult result = service.upload(userId, orgId, "../../etc/passwd.png", pngBytes(), "image/png");
        FileUploadService.FileMeta meta = getMeta(result.fileId());
        assertEquals("passwd.png", meta.originalName());
        assertFalse(meta.originalName().contains(".."));
        assertFalse(meta.originalName().contains("/"));
    }

    // UPLOAD-04
    @Test void fileOverSizeLimitRejected() throws Exception {
        byte[] large = new byte[11 * 1024 * 1024];
        assertThrows(FileUploadService.UploadException.class, () ->
            service.upload(userId, orgId, "large.png", large, "image/png"));
    }

    // UPLOAD-05
    @Test void nonMemberCannotUpload() {
        assertThrows(FileUploadService.UploadException.class, () ->
            service.upload(otherUserId, orgId, "test.png", pngBytes(), "image/png"));
    }

    // UPLOAD-05
    @Test void nonMemberCannotDownload() throws Exception {
        FileUploadService.UploadResult result = service.upload(userId, orgId, "test.png", pngBytes(), "image/png");
        FileUploadService.DownloadLink link = service.createDownloadLink(userId, result.fileId(), 300);
        assertThrows(FileUploadService.DownloadException.class, () ->
            service.download(otherUserId, link.token()));
    }

    // UPLOAD-06
    @Test void expiredLinkRejected() throws Exception {
        FileUploadService.UploadResult result = service.upload(userId, orgId, "test.png", pngBytes(), "image/png");
        FileUploadService.DownloadLink link = service.createDownloadLink(userId, result.fileId(), -10);
        assertThrows(FileUploadService.DownloadException.class, () ->
            service.download(userId, link.token()));
    }

    /**
     * A link whose signature part was altered is refused. Changed 2026-11-10, session
     * session_012zDydZCZ4AChqhEZ4oVtaP: it replaced the token's last base64url character with "X", but that
     * character also carries unused padding bits, so for several values (and always when it already was "X")
     * the "tampered" token decoded to the same bytes and the download succeeded: a random failure (seen once in
     * this session's runs). It now changes a character five from the end, which always alters the signature.
     * Touches: the test's temporary database and storage.
     */
    // UPLOAD-06
    @Test void tamperedLinkRejected() throws Exception {
        FileUploadService.UploadResult result = service.upload(userId, orgId, "test.png", pngBytes(), "image/png");
        FileUploadService.DownloadLink link = service.createDownloadLink(userId, result.fileId(), 300);
        String token = link.token();
        int i = token.length() - 5;
        char replacement = token.charAt(i) == 'A' ? 'B' : 'A';
        String tampered = token.substring(0, i) + replacement + token.substring(i + 1);
        assertThrows(FileUploadService.DownloadException.class, () ->
            service.download(userId, tampered));
    }

    @Test void downloadRechecksAccess() throws Exception {
        FileUploadService.UploadResult result = service.upload(userId, orgId, "test.png", pngBytes(), "image/png");
        FileUploadService.DownloadLink link = service.createDownloadLink(userId, result.fileId(), 300);
        byte[] downloaded = service.download(userId, link.token());
        assertArrayEquals(pngBytes(), downloaded);
    }

    // UPLOAD-07
    @Test void softDeleteWorks() throws Exception {
        FileUploadService.UploadResult result = service.upload(userId, orgId, "test.png", pngBytes(), "image/png");
        FileUploadService.DownloadLink linkBeforeDelete = service.createDownloadLink(userId, result.fileId(), 300);
        service.deleteFile(userId, result.fileId());
        FileUploadService.FileMeta meta = getMeta(result.fileId());
        assertNotNull(meta);
        assertNotNull(meta.deletedAt());
        assertThrows(FileUploadService.DownloadException.class, () ->
            service.createDownloadLink(userId, result.fileId(), 300));
        assertThrows(FileUploadService.DownloadException.class, () ->
            service.download(userId, linkBeforeDelete.token()));
    }

    private FileUploadService.FileMeta getMeta(String fileId) throws SQLException {
        try (Connection c = DriverManager.getConnection(dbUrl);
             PreparedStatement ps = c.prepareStatement("SELECT * FROM files WHERE id = ?")) {
            ps.setString(1, fileId);
            ResultSet rs = ps.executeQuery();
            if (!rs.next()) return null;
            Timestamp deletedTs = rs.getTimestamp("deleted_at");
            return new FileUploadService.FileMeta(
                rs.getString("id"), rs.getString("org_id"), rs.getString("owner_user_id"),
                rs.getString("stored_name"), rs.getString("original_name"), rs.getString("extension"),
                rs.getString("mime_type"), rs.getLong("size_bytes"), rs.getString("sha256"),
                rs.getTimestamp("created_at").toInstant(),
                deletedTs != null ? deletedTs.toInstant() : null
            );
        }
    }
}
