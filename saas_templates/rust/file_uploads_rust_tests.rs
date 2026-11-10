//! Tests for the file uploads template (TIER 3 spec, system 3).
//!
//! What: the eight spec tests, run against `InMemoryFileStore`, a temp directory per test and a
//! manual clock. Why: these bodies used to live in a private `#[cfg(test)] mod tests` inside the
//! implementation, which this file could not reach (`file_uploads_rust::tests::...` was private and not
//! in scope), so nothing compiled. Moved here with names and assertions kept; corrections are listed per
//! test. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: temp directories only.

mod file_uploads_rust;

#[cfg(test)]
mod tests {
    use super::file_uploads_rust::*;
    use std::collections::HashSet;
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    /// What: a fresh, empty storage directory for one test. In: the test's name. Out: its path.
    /// Why: one shared directory, removed by every test, raced between parallel tests.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the OS temp directory.
    fn setup_test_dir(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("file_uploads_test_{}_{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): UPLOAD-01 also needs a plain .exe refused;
    /// that assertion was added.
    // UPLOAD-01
    #[test]
    fn test_exe_rejected_by_magic_bytes() {
        let storage_dir = setup_test_dir("exe");
        let store = InMemoryFileStore::new();
        let authorizer = AlwaysAuthorizer;
        let secret = [0u8; 32];
        let max_size = 10 * 1024 * 1024;
        let mut allowlist = HashSet::new();
        allowlist.insert("png".to_string());
        let uploader = FileUploads::new(store, authorizer, secret, storage_dir.clone(), max_size, allowlist);

        let exe_bytes = b"MZ\x90\x00"; // DOS header
        let res = uploader.upload("user1", "org1", "malicious.png", exe_bytes, "image/png");
        assert_eq!(res.err().unwrap(), FileUploadError::InvalidMagicBytes);
        let res = uploader.upload("user1", "org1", "malicious.exe", exe_bytes, "application/octet-stream");
        assert_eq!(res.err().unwrap(), FileUploadError::InvalidExtension);
    }

    // UPLOAD-02
    #[test]
    fn test_png_accepted_and_stored_under_generated_name() {
        let storage_dir = setup_test_dir("png");
        let store = InMemoryFileStore::new();
        let authorizer = AlwaysAuthorizer;
        let secret = [1u8; 32];
        let max_size = 10 * 1024 * 1024;
        let mut allowlist = HashSet::new();
        allowlist.insert("png".to_string());
        let uploader = FileUploads::new(store.clone(), authorizer, secret, storage_dir.clone(), max_size, allowlist);

        let png_bytes = [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
            0x00, 0x00, 0x00, 0x0D, // IHDR chunk length
            0x49, 0x48, 0x44, 0x52, // "IHDR"
            0x00, 0x00, 0x00, 0x01, // width: 1
            0x00, 0x00, 0x00, 0x01, // height: 1
            0x08, 0x02, 0x00, 0x00, 0x00, // bit depth, color type, compression, filter, interlace
            0x90, 0x77, 0x53, 0xDE, // CRC
        ];
        let file_id = uploader.upload("user1", "org1", "image.png", &png_bytes, "image/png").unwrap();
        assert_ne!(file_id, "image.png");

        let record = store.get_file(&file_id).unwrap();
        assert_eq!(record.original_name, "image.png");
        assert_eq!(record.extension, "png");
        assert_eq!(record.mime_type, "image/png");
        assert_eq!(record.size_bytes, png_bytes.len() as u64);
        assert!(!record.stored_name.is_empty());
        assert_eq!(record.deleted_at, None);

        let storage_path = storage_dir.join(&record.stored_name);
        assert!(storage_path.exists());
        let stored_bytes = fs::read(storage_path).unwrap();
        assert_eq!(stored_bytes, png_bytes);
    }

    /// Changed 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): UPLOAD-03 "stored safely" is now asserted
    /// (the stored file sits directly in the storage directory under a generated name).
    // UPLOAD-03
    #[test]
    fn test_path_traversal_sanitized() {
        let storage_dir = setup_test_dir("traversal");
        let store = InMemoryFileStore::new();
        let authorizer = AlwaysAuthorizer;
        let secret = [2u8; 32];
        let max_size = 10 * 1024 * 1024;
        let mut allowlist = HashSet::new();
        allowlist.insert("png".to_string());
        let uploader = FileUploads::new(store.clone(), authorizer, secret, storage_dir.clone(), max_size, allowlist);

        let png_bytes = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let file_id = uploader.upload("user1", "org1", "../../etc/passwd.png", &png_bytes, "image/png").unwrap();

        let record = store.get_file(&file_id).unwrap();
        assert_eq!(record.original_name, "etc_passwd.png");
        assert!(!record.stored_name.contains('/') && !record.stored_name.contains("..") && !record.stored_name.contains("passwd"));
        assert!(storage_dir.join(&record.stored_name).exists());
    }

    // UPLOAD-04
    #[test]
    fn test_file_over_size_limit_rejected() {
        let storage_dir = setup_test_dir("size");
        let store = InMemoryFileStore::new();
        let authorizer = AlwaysAuthorizer;
        let secret = [3u8; 32];
        let max_size = 10; // 10 bytes
        let mut allowlist = HashSet::new();
        allowlist.insert("txt".to_string());
        let uploader = FileUploads::new(store.clone(), authorizer, secret, storage_dir.clone(), max_size, allowlist);

        let bytes = b"0123456789A"; // 11 bytes
        let res = uploader.upload("user1", "org1", "big.txt", bytes, "text/plain");
        assert_eq!(res.err().unwrap(), FileUploadError::SizeLimitExceeded);
    }

    /// Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): `download` now takes the caller (spec
    /// amendment 2026-09-26), the member and non-member services share one store (with two separate
    /// stores the non-member could never even find the file, so the membership check was not tested),
    /// and the allowlist is cloned instead of used after a move.
    // UPLOAD-05
    #[test]
    fn test_non_member_cannot_upload_or_download() {
        let storage_dir = setup_test_dir("nonmember");
        let store = InMemoryFileStore::new();
        let authorizer = NeverAuthorizer;
        let secret = [4u8; 32];
        let max_size = 10 * 1024 * 1024;
        let mut allowlist = HashSet::new();
        allowlist.insert("txt".to_string());
        let uploader =
            FileUploads::new(store.clone(), authorizer, secret, storage_dir.clone(), max_size, allowlist.clone());

        let txt_bytes = b"hello";
        let res = uploader.upload("user1", "org1", "test.txt", txt_bytes, "text/plain");
        assert_eq!(res.err().unwrap(), FileUploadError::Unauthorized);

        // First upload as member to have a file
        let authorizer2 = AlwaysAuthorizer;
        let uploader2 = FileUploads::new(store.clone(), authorizer2, secret, storage_dir.clone(), max_size, allowlist);
        let file_id = uploader2.upload("user1", "org1", "test.txt", txt_bytes, "text/plain").unwrap();

        // Try to download as non-member
        let token = uploader2.create_download_link("user1", "org1", &file_id, 300).unwrap();
        let res = uploader.download("user2", &token);
        assert_eq!(res.err().unwrap(), FileUploadError::Unauthorized);
    }

    /// Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): a manual clock advanced by 2 s replaces
    /// `thread::sleep(2 s)` on the wall clock (rule: no dependence on wall-clock timing); `download`
    /// takes the caller.
    // UPLOAD-06
    #[test]
    fn test_expired_link_rejected() {
        let storage_dir = setup_test_dir("expired");
        let store = InMemoryFileStore::new();
        let authorizer = AlwaysAuthorizer;
        let secret = [5u8; 32];
        let max_size = 10 * 1024 * 1024;
        let mut allowlist = HashSet::new();
        allowlist.insert("txt".to_string());
        let clock = ManualClock::new(1_000);
        let uploader = FileUploads::new(store.clone(), authorizer, secret, storage_dir.clone(), max_size, allowlist)
            .with_clock(clock.clone());

        let txt_bytes = b"hello";
        let file_id = uploader.upload("user1", "org1", "test.txt", txt_bytes, "text/plain").unwrap();

        // Create link with 1 second TTL
        let token = uploader.create_download_link("user1", "org1", &file_id, 1).unwrap();
        clock.advance(2);
        let res = uploader.download("user1", &token);
        assert_eq!(res.err().unwrap(), FileUploadError::TokenExpired);
    }

    /// Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): `download` takes the caller.
    // UPLOAD-06
    #[test]
    fn test_link_with_changed_character_rejected() {
        let storage_dir = setup_test_dir("tampered");
        let store = InMemoryFileStore::new();
        let authorizer = AlwaysAuthorizer;
        let secret = [6u8; 32];
        let max_size = 10 * 1024 * 1024;
        let mut allowlist = HashSet::new();
        allowlist.insert("txt".to_string());
        let uploader = FileUploads::new(store.clone(), authorizer, secret, storage_dir.clone(), max_size, allowlist);

        let txt_bytes = b"hello";
        let file_id = uploader.upload("user1", "org1", "test.txt", txt_bytes, "text/plain").unwrap();

        let token = uploader.create_download_link("user1", "org1", &file_id, 300).unwrap();
        let mut token_bytes = token.into_bytes();
        token_bytes[0] = if token_bytes[0] == 0 { 1 } else { token_bytes[0] - 1 };
        let corrupted_token = String::from_utf8(token_bytes).unwrap();
        let res = uploader.download("user1", &corrupted_token);
        assert_eq!(res.err().unwrap(), FileUploadError::InvalidToken);
    }

    /// Corrected 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP): the old body deleted the file, asserted
    /// that a link can no longer be created, then called `create_download_link(...).unwrap()` on the same
    /// deleted file, which contradicts the assertion just above it. The "pre-delete link" is now created
    /// before the delete, as its comment intended; the second delete of an already-deleted file is
    /// asserted to fail instead of unwrapped.
    // UPLOAD-07
    #[test]
    fn test_after_delete_file_can_no_longer_be_linked_or_downloaded() {
        let storage_dir = setup_test_dir("deleted");
        let store = InMemoryFileStore::new();
        let authorizer = AlwaysAuthorizer;
        let secret = [7u8; 32];
        let max_size = 10 * 1024 * 1024;
        let mut allowlist = HashSet::new();
        allowlist.insert("txt".to_string());
        let uploader = FileUploads::new(store.clone(), authorizer, secret, storage_dir.clone(), max_size, allowlist);

        let txt_bytes = b"hello";
        let file_id = uploader.upload("user1", "org1", "test.txt", txt_bytes, "text/plain").unwrap();

        // First, create a link before deletion
        let token = uploader.create_download_link("user1", "org1", &file_id, 300).unwrap();

        // Delete the file
        uploader.delete_file("user1", "org1", &file_id).unwrap();

        // Try to create a download link
        let res = uploader.create_download_link("user1", "org1", &file_id, 300);
        assert_eq!(res.err().unwrap(), FileUploadError::FileDeleted);

        // Deleting again fails: the file is already gone
        let res = uploader.delete_file("user1", "org1", &file_id);
        assert_eq!(res.err().unwrap(), FileUploadError::FileDeleted);

        // Try to download using the pre-delete link
        let res = uploader.download("user1", &token);
        assert_eq!(res.err().unwrap(), FileUploadError::FileDeleted);
    }
}
