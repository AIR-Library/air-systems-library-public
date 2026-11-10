package fileuploads

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupTest(t *testing.T) (*FileUploads, *InMemoryStore, string) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "fileuploads_test")
	if err != nil {
		t.Fatal(err)
	}
	hmacKey := make([]byte, 32)
	rand.Read(hmacKey)
	config := DefaultConfig(tmpDir, hmacKey)
	store := NewInMemoryStore()
	fu := NewFileUploads(config, store)
	return fu, store, tmpDir
}

// UPLOAD-01
func TestExeRejected(t *testing.T) {
	fu, store, _ := setupTest(t)
	store.AddOrgMember("org1", "user1")

	exeData := []byte("MZ\x90\x00")
	_, err := fu.Upload("user1", "org1", "malware.exe", exeData, "application/x-msdownload")
	if err != ErrInvalidExtension {
		t.Errorf("expected ErrInvalidExtension, got %v", err)
	}

	// exe renamed to .png should be rejected by magic bytes (uses exe magic bytes, not png)
	_, err = fu.Upload("user1", "org1", "malware.png", exeData, "image/png")
	if err != ErrInvalidMagicBytes {
		t.Errorf("expected ErrInvalidMagicBytes for exe renamed to png, got %v", err)
	}
}

// UPLOAD-02
func TestRealPNGAcceptedGeneratedName(t *testing.T) {
	fu, store, tmpDir := setupTest(t)
	store.AddOrgMember("org1", "user1")

	pngData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	fileID, err := fu.Upload("user1", "org1", "image.png", pngData, "image/png")
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}

	file, err := store.GetFileByID(fileID)
	if err != nil {
		t.Fatalf("get file failed: %v", err)
	}

	if file.OriginalName != "image.png" {
		t.Errorf("original name not preserved: %s", file.OriginalName)
	}
	if file.StoredName == "image.png" {
		t.Error("stored name should be generated, not original")
	}
	if !strings.HasSuffix(file.StoredName, ".png") {
		t.Errorf("stored name should keep extension: %s", file.StoredName)
	}

	storagePath := filepath.Join(tmpDir, file.StoredName)
	if _, err := os.Stat(storagePath); os.IsNotExist(err) {
		t.Error("file not found in storage directory")
	}
}

// UPLOAD-03
func TestPathTraversalStoredSafely(t *testing.T) {
	fu, store, tmpDir := setupTest(t)
	store.AddOrgMember("org1", "user1")

	pngData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	fileID, err := fu.Upload("user1", "org1", "../../etc/passwd.png", pngData, "image/png")
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}

	file, err := store.GetFileByID(fileID)
	if err != nil {
		t.Fatalf("get file failed: %v", err)
	}

	if strings.Contains(file.OriginalName, "..") || strings.Contains(file.OriginalName, "/") {
		t.Errorf("original name contains path parts: %s", file.OriginalName)
	}

	storagePath := filepath.Join(tmpDir, file.StoredName)
	if _, err := os.Stat(storagePath); os.IsNotExist(err) {
		t.Error("file not found in storage directory")
	}
}

// UPLOAD-04
func TestFileOverSizeLimitRejected(t *testing.T) {
	fu, store, _ := setupTest(t)
	store.AddOrgMember("org1", "user1")

	config := fu.config
	config.MaxFileSize = 100
	fu.config = config

	largeData := make([]byte, 200)
	_, err := fu.Upload("user1", "org1", "large.txt", largeData, "text/plain")
	if err != ErrFileTooLarge {
		t.Errorf("expected ErrFileTooLarge, got %v", err)
	}
}

// UPLOAD-05
func TestNonMemberCannotUploadOrDownload(t *testing.T) {
	fu, store, _ := setupTest(t)
	store.AddOrgMember("org1", "user1")

	pngData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

	_, err := fu.Upload("user2", "org1", "test.png", pngData, "image/png")
	if err != ErrUnauthorized {
		t.Errorf("non-member upload should fail: %v", err)
	}

	fileID, err := fu.Upload("user1", "org1", "test.png", pngData, "image/png")
	if err != nil {
		t.Fatalf("member upload failed: %v", err)
	}

	_, err = fu.CreateDownloadLink("user2", fileID, 300)
	if err != ErrUnauthorized {
		t.Errorf("non-member create link should fail: %v", err)
	}

	token, err := fu.CreateDownloadLink("user1", fileID, 300)
	if err != nil {
		t.Fatalf("member create link failed: %v", err)
	}

	_, err = fu.Download("user1", token)
	if err != nil {
		t.Fatalf("member download failed: %v", err)
	}

	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: download(user, token) re-checks the caller (spec
	// UPLOAD-05); a non-member holding a valid link is refused.
	_, err = fu.Download("user2", token)
	if err != ErrUnauthorized {
		t.Errorf("non-member download with a valid link should fail: %v", err)
	}
}

// UPLOAD-06
func TestExpiredAndTamperedLinkRejected(t *testing.T) {
	fu, store, _ := setupTest(t)
	store.AddOrgMember("org1", "user1")

	pngData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	fileID, err := fu.Upload("user1", "org1", "test.png", pngData, "image/png")
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}

	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: an injectable clock replaces the 2 s sleep (spec
	// README: time comes from an injectable clock); the link is 1 s old past its 300 s expiry.
	now := time.Unix(1_700_000_000, 0)
	fu.config.Now = func() time.Time { return now }
	token, err := fu.CreateDownloadLink("user1", fileID, 300)
	if err != nil {
		t.Fatalf("create link failed: %v", err)
	}
	if _, err = fu.Download("user1", token); err != nil {
		t.Fatalf("link inside its lifetime should work: %v", err)
	}

	now = now.Add(301 * time.Second)
	_, err = fu.Download("user1", token)
	if err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}

	token2, err := fu.CreateDownloadLink("user1", fileID, 300)
	if err != nil {
		t.Fatalf("create link failed: %v", err)
	}

	tampered := token2[:len(token2)-1] + "X"
	_, err = fu.Download("user1", tampered)
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken for tampered link, got %v", err)
	}
}

// UPLOAD-07
func TestAfterDeleteFileCannotLinkOrDownload(t *testing.T) {
	fu, store, _ := setupTest(t)
	store.AddOrgMember("org1", "user1")

	pngData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	fileID, err := fu.Upload("user1", "org1", "test.png", pngData, "image/png")
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}

	// Create download link BEFORE delete
	token, err := fu.CreateDownloadLink("user1", fileID, 300)
	if err != nil {
		t.Fatalf("create link before delete failed: %v", err)
	}

	err = fu.DeleteFile("user1", fileID)
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	// CreateDownloadLink after delete should fail
	_, err = fu.CreateDownloadLink("user1", fileID, 300)
	if err != ErrFileNotFound {
		t.Errorf("expected ErrFileNotFound after delete, got %v", err)
	}

	// Download with pre-delete token should fail with ErrFileNotFound
	_, err = fu.Download("user1", token)
	if err != ErrFileNotFound {
		t.Errorf("expected ErrFileNotFound on download after delete, got %v", err)
	}
}

func TestTextFileWithNULRejected(t *testing.T) {
	fu, store, _ := setupTest(t)
	store.AddOrgMember("org1", "user1")

	txtData := []byte("hello\x00world")
	_, err := fu.Upload("user1", "org1", "test.txt", txtData, "text/plain")
	if err != ErrInvalidMagicBytes {
		t.Errorf("expected ErrInvalidMagicBytes for NUL in text, got %v", err)
	}
}

func TestCSVAccepted(t *testing.T) {
	fu, store, _ := setupTest(t)
	store.AddOrgMember("org1", "user1")

	csvData := []byte("a,b,c\n1,2,3\n")
	fileID, err := fu.Upload("user1", "org1", "data.csv", csvData, "text/csv")
	if err != nil {
		t.Fatalf("csv upload failed: %v", err)
	}

	file, _ := store.GetFileByID(fileID)
	if file.Extension != "csv" {
		t.Errorf("extension not preserved: %s", file.Extension)
	}
}

func TestPDFMagicBytesValidated(t *testing.T) {
	fu, store, _ := setupTest(t)
	store.AddOrgMember("org1", "user1")

	pdfData := []byte{0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34}
	fileID, err := fu.Upload("user1", "org1", "doc.pdf", pdfData, "application/pdf")
	if err != nil {
		t.Fatalf("pdf upload failed: %v", err)
	}

	file, _ := store.GetFileByID(fileID)
	if file.Extension != "pdf" {
		t.Errorf("extension not preserved: %s", file.Extension)
	}
}

func TestDOCXMagicBytesValidated(t *testing.T) {
	fu, store, _ := setupTest(t)
	store.AddOrgMember("org1", "user1")

	docxData := []byte{0x50, 0x4B, 0x03, 0x04}
	fileID, err := fu.Upload("user1", "org1", "doc.docx", docxData, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	if err != nil {
		t.Fatalf("docx upload failed: %v", err)
	}

	file, _ := store.GetFileByID(fileID)
	if file.Extension != "docx" {
		t.Errorf("extension not preserved: %s", file.Extension)
	}
}

func TestXLSXMagicBytesValidated(t *testing.T) {
	fu, store, _ := setupTest(t)
	store.AddOrgMember("org1", "user1")

	xlsxData := []byte{0x50, 0x4B, 0x03, 0x04}
	fileID, err := fu.Upload("user1", "org1", "sheet.xlsx", xlsxData, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	if err != nil {
		t.Fatalf("xlsx upload failed: %v", err)
	}

	file, _ := store.GetFileByID(fileID)
	if file.Extension != "xlsx" {
		t.Errorf("extension not preserved: %s", file.Extension)
	}
}

func TestJPEGMagicBytesValidated(t *testing.T) {
	fu, store, _ := setupTest(t)
	store.AddOrgMember("org1", "user1")

	jpegData := []byte{0xFF, 0xD8, 0xFF, 0xE0}
	fileID, err := fu.Upload("user1", "org1", "photo.jpg", jpegData, "image/jpeg")
	if err != nil {
		t.Fatalf("jpeg upload failed: %v", err)
	}

	file, _ := store.GetFileByID(fileID)
	if file.Extension != "jpg" {
		t.Errorf("extension not preserved: %s", file.Extension)
	}
}

func TestGIFMagicBytesValidated(t *testing.T) {
	fu, store, _ := setupTest(t)
	store.AddOrgMember("org1", "user1")

	gifData := []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}
	fileID, err := fu.Upload("user1", "org1", "anim.gif", gifData, "image/gif")
	if err != nil {
		t.Fatalf("gif upload failed: %v", err)
	}

	file, _ := store.GetFileByID(fileID)
	if file.Extension != "gif" {
		t.Errorf("extension not preserved: %s", file.Extension)
	}
}

func TestFilenameLengthLimit(t *testing.T) {
	fu, store, _ := setupTest(t)
	store.AddOrgMember("org1", "user1")

	longName := strings.Repeat("a", 300) + ".txt"
	txtData := []byte("hello world")
	fileID, err := fu.Upload("user1", "org1", longName, txtData, "text/plain")
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}

	file, _ := store.GetFileByID(fileID)
	if len(file.OriginalName) > 255 {
		t.Errorf("original name not truncated: %d", len(file.OriginalName))
	}
}

func TestDeleteByNonOwnerFails(t *testing.T) {
	fu, store, _ := setupTest(t)
	store.AddOrgMember("org1", "user1")
	store.AddOrgMember("org1", "user2")

	pngData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	fileID, err := fu.Upload("user1", "org1", "test.png", pngData, "image/png")
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}

	err = fu.DeleteFile("user2", fileID)
	if err != ErrUnauthorized {
		t.Errorf("expected ErrUnauthorized for non-owner delete, got %v", err)
	}
}

func TestMalformedTokenHandledGracefully(t *testing.T) {
	fu, _, _ := setupTest(t)

	_, err := fu.Download("user1", "not-base64!@#")
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken for bad base64, got %v", err)
	}

	_, err = fu.Download("user1", "dGhpcyBpcyBub3QgYSB2YWxpZCB0b2tlbg==")
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken for wrong parts, got %v", err)
	}

	_, err = fu.Download("user1", "ZmlsZTEuMTIzLmludmFsaWQ=")
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken for bad sig, got %v", err)
	}
}

func TestDownloadRechecksOrgMembership(t *testing.T) {
	fu, store, _ := setupTest(t)
	store.AddOrgMember("org1", "user1")
	store.AddOrgMember("org2", "user2")

	pngData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	fileID, err := fu.Upload("user1", "org1", "test.png", pngData, "image/png")
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}

	token, err := fu.CreateDownloadLink("user1", fileID, 300)
	if err != nil {
		t.Fatalf("create link failed: %v", err)
	}

	_, err = fu.Download("user1", token)
	if err != nil {
		t.Fatalf("owner download failed: %v", err)
	}

	store2 := NewInMemoryStore()
	store2.AddOrgMember("org1", "user1")
	fu2 := NewFileUploads(fu.config, store2)

	_, err = fu2.Download("user1", token)
	if err != ErrFileNotFound {
		t.Errorf("expected ErrFileNotFound when file not in store, got %v", err)
	}
}
// TestFullSignaturesRequired proves the spec's FULL magic-byte signatures: a 4-byte PNG prefix, "GIF8"
// without "7a"/"9a", and "%PDF" without "-" are rejected. Why: file_uploads spec (amended 2026-09-26);
// Go checked 4-byte prefixes. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: a temp dir.
func TestFullSignaturesRequired(t *testing.T) {
	fu, store, _ := setupTest(t)
	store.AddOrgMember("org1", "user1")
	cases := map[string][]byte{
		"a.png": {0x89, 0x50, 0x4E, 0x47, 0x00, 0x00, 0x00, 0x00},
		"a.gif": []byte("GIF8xx"),
		"a.pdf": []byte("%PDF1.4"),
	}
	for name, data := range cases {
		if _, err := fu.Upload("user1", "org1", name, data, "application/octet-stream"); err != ErrInvalidMagicBytes {
			t.Errorf("%s with a partial signature: want ErrInvalidMagicBytes, got %v", name, err)
		}
	}
	if _, err := fu.Upload("user1", "org1", "a.gif", []byte("GIF87a"), "image/gif"); err != nil {
		t.Errorf("GIF87a should be accepted: %v", err)
	}
}
