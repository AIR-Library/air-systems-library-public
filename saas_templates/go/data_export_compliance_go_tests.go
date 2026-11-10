package compliance

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeMailer records what would be emailed (no network in tests).
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-03, EXPORT-09).
type fakeMailer struct {
	links  map[int]string
	tokens map[string]string // deletion id -> token
}

func (f *fakeMailer) SendExportReady(userID int, downloadURL string) error {
	f.links[userID] = downloadURL
	return nil
}

func (f *fakeMailer) SendDeletionConfirmation(_ int, deletionID, token string) error {
	f.tokens[deletionID] = token
	return nil
}

// fakeEraser records erase_subject calls with the audit log length at the time, so a test can prove the
// call came last. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-13).
type fakeEraser struct {
	svc      *ComplianceService
	erased   []int
	logsAt   []int
	failWith error
}

func (f *fakeEraser) EraseSubject(userID int) error {
	if f.failWith != nil {
		return f.failWith
	}
	f.erased = append(f.erased, userID)
	f.logsAt = append(f.logsAt, len(f.svc.auditLogs)) // the service holds its lock while calling
	return nil
}

// newFixedService creates a service with a fixed clock, a fake mailer and a fake eraser.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: export and deletion now need a mailer and the
// cascade an audit eraser.
func newFixedService(fixed time.Time) (*ComplianceService, *fakeMailer, *fakeEraser) {
	m := &fakeMailer{links: map[int]string{}, tokens: map[string]string{}}
	e := &fakeEraser{}
	s, _ := NewComplianceServiceWith(Options{Mailer: m, Eraser: e})
	s.nowFunc = func() time.Time { return fixed }
	e.svc = s
	return s, m, e
}

var t0 = time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC)

// EXPORT-01
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the files are now generated, so the test parses them.
func TestExportFormatsWork(t *testing.T) {
	svc, _, _ := newFixedService(t0)
	svc.AddSession(1, "sess-1")
	expJSON, err := svc.RequestExport(1, "json")
	if err != nil {
		t.Fatalf("json export request failed: %v", err)
	}
	var parsed map[string]interface{}
	if expJSON.Format != "json" || json.Unmarshal(expJSON.Content, &parsed) != nil || parsed["sessions"] == nil {
		t.Errorf("json export is not valid JSON with the user's data: %s", expJSON.Content)
	}
	expCSV, err := svc.RequestExport(1, "csv")
	if err != nil {
		t.Fatalf("csv export request failed: %v", err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(expCSV.Content))).ReadAll()
	if expCSV.Format != "csv" || err != nil || len(rows) < 2 || rows[0][0] != "category" {
		t.Errorf("csv export is not valid CSV with a header and rows: %q (%v)", expCSV.Content, err)
	}
	if _, err := svc.RequestExport(1, "xml"); !errors.Is(err, ErrUnsupportedFormat) {
		t.Errorf("xml should be refused, got %v", err)
	}
}

// EXPORT-02
func TestExportIncludesAllCategories(t *testing.T) {
	svc, _, _ := newFixedService(t0)
	svc.SetProfile(10, map[string]string{"email": "u10@example.com"})
	svc.AddActivity(10, "login")
	svc.AddFile(10, "report.pdf")
	exp, _ := svc.RequestExport(10, "json")
	expected := []string{
		"profile", "sessions", "activity", "files",
		"preferences", "transactions", "audit_trail",
	}
	if len(exp.DataCategories) != len(expected) {
		t.Fatalf("expected %d categories, got %d", len(expected), len(exp.DataCategories))
	}
	var parsed map[string]json.RawMessage
	_ = json.Unmarshal(exp.Content, &parsed)
	for i, cat := range expected {
		if exp.DataCategories[i] != cat {
			t.Errorf("category %d expected %s, got %s", i, cat, exp.DataCategories[i])
		}
		if _, ok := parsed[cat]; !ok {
			t.Errorf("the file has no %s section", cat)
		}
	}
	if !strings.Contains(string(exp.Content), "report.pdf") || !strings.Contains(string(exp.Content), "u10@example.com") {
		t.Errorf("the file is missing the user's data: %s", exp.Content)
	}
}

// EXPORT-03
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the email is really sent (to the fake mailer).
func TestExportEmailSent(t *testing.T) {
	svc, mailer, _ := newFixedService(t0)
	exp, _ := svc.RequestExport(5, "json")
	if !exp.EmailSent || exp.FileURL == "" {
		t.Errorf("expected EmailSent and a file URL: %+v", exp)
	}
	if mailer.links[5] != exp.FileURL {
		t.Errorf("the email did not carry the download link: %q", mailer.links[5])
	}
	bare := NewComplianceService()
	if _, err := bare.RequestExport(5, "json"); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("without a mailer the export must not claim an email was sent: %v", err)
	}
}

// EXPORT-04
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the link is signed; it works until 7 days and is
// refused after, and a tampered link is refused.
func TestExportSignedURLExpiry(t *testing.T) {
	svc, _, _ := newFixedService(t0)
	exp, _ := svc.RequestExport(7, "csv")
	if exp.ExpiresAt == nil || !exp.ExpiresAt.Equal(t0.Add(7*24*time.Hour)) {
		t.Fatalf("expected expiry after 7 days, got %v", exp.ExpiresAt)
	}
	svc.nowFunc = func() time.Time { return t0.Add(7*24*time.Hour - time.Second) }
	if body, err := svc.Download(exp.FileURL); err != nil || string(body) != string(exp.Content) {
		t.Fatalf("the signed link should work inside 7 days: %v", err)
	}
	if _, err := svc.Download(strings.Replace(exp.FileURL, "sig=", "sig=0", 1)); !errors.Is(err, ErrInvalidLink) {
		t.Errorf("a tampered link should be refused, got %v", err)
	}
	svc.nowFunc = func() time.Time { return t0.Add(7 * 24 * time.Hour) }
	if _, err := svc.Download(exp.FileURL); !errors.Is(err, ErrLinkExpired) {
		t.Errorf("the link should expire after 7 days, got %v", err)
	}
}

// EXPORT-05
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the amended spec gives the 30-day grace period to
// user_requested (and other); this test used gdpr_request, which now has none (EXPORT-12).
func TestDeletionGracePeriod(t *testing.T) {
	svc, mailer, _ := newFixedService(t0)
	svc.AddSession(3, "s")
	del, _ := svc.RequestDeletion(3, "user_requested")
	if !del.WillDeleteAt.Equal(t0.Add(30 * 24 * time.Hour)) {
		t.Errorf("expected will_delete_at = requested_at + 30 days, got %v", del.WillDeleteAt)
	}
	if _, err := svc.ConfirmDeletion(3, del.ID, mailer.tokens[del.ID]); err != nil {
		t.Fatal(err)
	}
	svc.nowFunc = func() time.Time { return t0.Add(30*24*time.Hour - time.Second) }
	if n, _ := svc.PerformDueDeletions(); n != 0 || len(svc.sessions[3]) != 1 {
		t.Fatalf("nothing may be deleted inside the grace period")
	}
	svc.nowFunc = func() time.Time { return t0.Add(30 * 24 * time.Hour) }
	if n, _ := svc.PerformDueDeletions(); n != 1 || len(svc.sessions[3]) != 0 {
		t.Fatalf("the deletion should run once the grace period ends")
	}
}

// EXPORT-06
func TestDeletionCancelWithinGrace(t *testing.T) {
	svc, _, _ := newFixedService(t0)
	del, _ := svc.RequestDeletion(4, "user_requested")
	svc.nowFunc = func() time.Time { return t0.Add(29 * 24 * time.Hour) }
	_, err := svc.CancelDeletion(4, del.ID)
	if err != nil {
		t.Fatalf("cancel failed: %v", err)
	}
	if del.Status != "cancelled" {
		t.Errorf("expected status cancelled, got %s", del.Status)
	}
}

// TestDeletionCancelAfterGrace proves the Phase B.3 ruling: cancelling after will_delete_at has passed (the
// deletion is due but not yet run) is 409 grace_period_over, and the request stays as it was.
// In: none. Out: test failures. Why: data_export_compliance spec endpoint 5, amended by commit d4f4ed7.
// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
// EXPORT-06
func TestDeletionCancelAfterGrace(t *testing.T) {
	svc, _, _ := newFixedService(t0)
	del, _ := svc.RequestDeletion(4, "user_requested")
	before := del.Status
	svc.nowFunc = func() time.Time { return del.WillDeleteAt.Add(time.Second) }
	_, err := svc.CancelDeletion(4, del.ID)
	if !errors.Is(err, ErrGraceElapsed) || err.Error() != "grace_period_over" || HTTPStatus(err) != 409 {
		t.Fatalf("cancel after will_delete_at: expected 409 grace_period_over, got %v (%d)", err, HTTPStatus(err))
	}
	if del.Status != before {
		t.Fatalf("a refused cancel changed the status to %s", del.Status)
	}
}

// EXPORT-07
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: confirmed with the emailed token (any string used to
// do), API keys and exports added, and the audit trail must now be KEPT (the old assertion required it to
// be cleared while its message said it should be preserved; EXPORT-08).
func TestDeletionCascade(t *testing.T) {
	svc, mailer, _ := newFixedService(t0)
	uid := 8
	svc.SetProfile(uid, map[string]string{"email": "u8@example.com"})
	svc.AddSession(uid, "sess1")
	svc.AddAPIKey(uid, "key1")
	svc.AddActivity(uid, "login")
	svc.AddFile(uid, "file1")
	svc.SetPreference(uid, true)
	svc.AddTransaction(uid, "txn1")
	svc.AddAuditTrailEntry(uid, "login")
	svc.AddSession(99, "other-user-session")
	exp, _ := svc.RequestExport(uid, "json")

	del, _ := svc.RequestDeletion(uid, "user_requested")
	if _, err := svc.ConfirmDeletion(uid, del.ID, mailer.tokens[del.ID]); err != nil {
		t.Fatal(err)
	}
	svc.nowFunc = func() time.Time { return t0.Add(31 * 24 * time.Hour) }
	if err := svc.PerformDeletionNow(del.ID); err != nil {
		t.Fatalf("perform deletion failed: %v", err)
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	for name, gone := range map[string]bool{
		"profile": svc.profiles[uid] == nil, "sessions": svc.sessions[uid] == nil, "api_keys": svc.apiKeys[uid] == nil,
		"activity": svc.activity[uid] == nil, "files": svc.files[uid] == nil, "transactions": svc.transactions[uid] == nil,
		"export": svc.exports[exp.ID] == nil,
	} {
		if !gone {
			t.Errorf("%s not cleared", name)
		}
	}
	if _, ok := svc.preferences[uid]; ok {
		t.Errorf("preferences not cleared")
	}
	if len(svc.auditTrail[uid]) != 1 {
		t.Errorf("the cascade must not touch the audit trail")
	}
	if len(svc.sessions[99]) != 1 {
		t.Errorf("another user's data was deleted")
	}
}

// EXPORT-08
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the completion entry is 'user_deleted_cascade'.
func TestAuditLogPreserved(t *testing.T) {
	svc, mailer, _ := newFixedService(t0)
	uid := 9
	svc.AddAuditTrailEntry(uid, "some action")
	del, _ := svc.RequestDeletion(uid, "gdpr_request")
	if _, err := svc.ConfirmDeletion(uid, del.ID, mailer.tokens[del.ID]); err != nil {
		t.Fatal(err)
	}
	if len(svc.auditTrail[uid]) != 1 {
		t.Errorf("the user's audit trail must be kept by the cascade")
	}
	found := map[string]bool{}
	for _, a := range svc.GetAuditLogs() {
		if a.UserID == uid {
			found[a.Action] = true
		}
	}
	for _, action := range []string{"deletion_requested", "deletion_confirmed", "user_deleted_cascade"} {
		if !found[action] {
			t.Errorf("expected %s audit log for user %d", action, uid)
		}
	}
}

// EXPORT-09
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: only the emailed token confirms ("nonempty" used to).
func TestDeletionConfirmationToken(t *testing.T) {
	svc, mailer, _ := newFixedService(t0)
	del, _ := svc.RequestDeletion(11, "user_requested")
	token := mailer.tokens[del.ID]
	if len(token) != 64 {
		t.Fatalf("expected a 32-byte hex token in the email, got %q", token)
	}
	if strings.Contains(del.tokenHash, token) || del.tokenHash == token {
		t.Fatalf("the raw token must not be stored")
	}
	for _, bad := range []string{"", "nonempty"} {
		if _, err := svc.ConfirmDeletion(11, del.ID, bad); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("token %q: expected ErrInvalidToken, got %v", bad, err)
		}
	}
	if _, err := svc.ConfirmDeletion(11, del.ID, token); err != nil {
		t.Fatalf("confirmation with the emailed token failed: %v", err)
	}
	if del.Status != "approved" {
		t.Errorf("expected status approved, got %s", del.Status)
	}
	for _, a := range svc.GetAuditLogs() {
		if strings.Contains(a.Details, token) {
			t.Errorf("the token was written to the audit log")
		}
	}
}

// EXPORT-10
func TestAdminListRequests(t *testing.T) {
	svc, _, _ := newFixedService(t0)
	svc.RequestExport(20, "json")
	svc.RequestExport(21, "csv")
	svc.RequestDeletion(20, "gdpr_request")
	svc.RequestDeletion(22, "user_requested")

	exports := svc.ListExports(nil, nil)
	if len(exports) != 2 || exports[0].UserID != 20 || exports[1].UserID != 21 {
		t.Errorf("expected 2 exports in creation order, got %d", len(exports))
	}
	deletions := svc.ListDeletions(nil, nil)
	if len(deletions) != 2 || *deletions[0].UserID != 20 || *deletions[1].UserID != 22 {
		t.Errorf("expected 2 deletions in creation order, got %d", len(deletions))
	}
}

// EXPORT-11
func TestAuditLogging(t *testing.T) {
	svc, _, _ := newFixedService(t0)
	svc.RequestExport(30, "json")
	svc.RequestDeletion(30, "gdpr_right_to_be_forgotten")
	logs := svc.GetAuditLogs()
	if len(logs) != 2 {
		t.Fatalf("expected 2 audit logs, got %d", len(logs))
	}
	if logs[0].Action != "data_export_requested" {
		t.Errorf("first log action expected data_export_requested, got %s", logs[0].Action)
	}
	if logs[1].Action != "deletion_requested" {
		t.Errorf("second log action expected deletion_requested, got %s", logs[1].Action)
	}
	for _, l := range logs {
		if len(l.WhyChain) == 0 {
			t.Errorf("%s has no why_chain", l.Action)
		}
	}
}

// EXPORT-12 proves a statutory request has no grace period and confirm runs the cascade before it returns.
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
func TestStatutoryDeletionHasNoGrace(t *testing.T) {
	for _, reason := range []string{"gdpr_request", "gdpr_right_to_be_forgotten"} {
		svc, mailer, eraser := newFixedService(t0)
		svc.AddSession(40, "s")
		del, err := svc.RequestDeletion(40, reason)
		if err != nil {
			t.Fatal(err)
		}
		if !del.WillDeleteAt.Equal(del.RequestedAt) {
			t.Errorf("%s: expected will_delete_at = requested_at, got %v", reason, del.WillDeleteAt)
		}
		if len(svc.sessions[40]) != 1 {
			t.Errorf("%s: nothing may be deleted before confirm", reason)
		}
		got, err := svc.ConfirmDeletion(40, del.ID, mailer.tokens[del.ID])
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != "completed" || got.DeletedAt == nil || !got.DeletedAt.Equal(t0) || len(svc.sessions[40]) != 0 || len(eraser.erased) != 1 {
			t.Errorf("%s: confirm should have completed the deletion: %+v", reason, got)
		}
	}
	if _, err := newFixedServiceReason(t0, "because"); !errors.Is(err, ErrInvalidReason) {
		t.Errorf("an unknown reason should be refused, got %v", err)
	}
}

func newFixedServiceReason(now time.Time, reason string) (*DeletionRequest, error) {
	svc, _, _ := newFixedService(now)
	return svc.RequestDeletion(1, reason)
}

// EXPORT-13 proves the cascade order: rows deleted, 'user_deleted_cascade' logged, erase_subject called
// LAST with nothing logged for the user after it, deletion_requests.user_id NULL; and an eraser failure
// rolls everything back. Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
func TestDeletionCascadeOrder(t *testing.T) {
	svc, mailer, eraser := newFixedService(t0)
	svc.AddSession(50, "s")
	del, _ := svc.RequestDeletion(50, "gdpr_request")
	if _, err := svc.ConfirmDeletion(50, del.ID, mailer.tokens[del.ID]); err != nil {
		t.Fatal(err)
	}
	logs := svc.GetAuditLogs()
	if len(eraser.erased) != 1 || eraser.erased[0] != 50 {
		t.Fatalf("erase_subject(50) not called: %v", eraser.erased)
	}
	if eraser.logsAt[0] != len(logs) {
		t.Fatalf("something was logged after erase_subject: %d entries then, %d now", eraser.logsAt[0], len(logs))
	}
	if last := logs[len(logs)-1]; last.Action != "user_deleted_cascade" || last.UserID != 50 {
		t.Fatalf("the last entry before the erasure must be user_deleted_cascade, got %+v", last)
	}
	if del.UserID != nil || del.Status != "completed" {
		t.Fatalf("completed deletion must have user_id NULL: %+v", del)
	}

	// An eraser failure undoes the cascade.
	svc2, mailer2, eraser2 := newFixedService(t0)
	eraser2.failWith = errors.New("audit store down")
	svc2.AddSession(51, "s")
	del2, _ := svc2.RequestDeletion(51, "gdpr_request")
	if _, err := svc2.ConfirmDeletion(51, del2.ID, mailer2.tokens[del2.ID]); err == nil {
		t.Fatal("expected the eraser's failure")
	}
	if len(svc2.sessions[51]) != 1 || del2.UserID == nil || del2.Status == "completed" {
		t.Fatalf("a failed erasure must roll the cascade back: %+v", del2)
	}
	for _, l := range svc2.GetAuditLogs() {
		if l.Action == "user_deleted_cascade" {
			t.Fatalf("a rolled-back cascade must not stay logged")
		}
	}
}

// EXPORT-14 proves confirmation rules: nothing deleted before confirm; wrong, reused and expired tokens are
// refused; another user's request is not found for confirm and cancel; a token is bound to its request.
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
func TestDeletionConfirmationRules(t *testing.T) {
	svc, mailer, _ := newFixedService(t0)
	svc.AddSession(60, "s")
	del, _ := svc.RequestDeletion(60, "user_requested")
	other, _ := svc.RequestDeletion(61, "user_requested")
	token := mailer.tokens[del.ID]

	if _, err := svc.ConfirmDeletion(61, del.ID, token); !errors.Is(err, ErrNotFound) {
		t.Errorf("another user's confirm: expected ErrNotFound, got %v", err)
	}
	if _, err := svc.CancelDeletion(61, del.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("another user's cancel: expected ErrNotFound, got %v", err)
	}
	if _, err := svc.ConfirmDeletion(61, other.ID, token); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("a token for another request: expected ErrInvalidToken, got %v", err)
	}
	if _, err := svc.ConfirmDeletion(60, del.ID, strings.Repeat("0", 64)); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("a wrong token: expected ErrInvalidToken, got %v", err)
	}
	if len(svc.sessions[60]) != 1 {
		t.Fatal("nothing may be deleted before confirm")
	}

	svc.nowFunc = func() time.Time { return t0.Add(24*time.Hour + time.Second) }
	if _, err := svc.ConfirmDeletion(60, del.ID, token); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("a token over 24h old: expected ErrInvalidToken, got %v", err)
	}

	svc.nowFunc = func() time.Time { return t0.Add(time.Hour) }
	if _, err := svc.ConfirmDeletion(61, other.ID, mailer.tokens[other.ID]); err != nil {
		t.Fatalf("the right token: %v", err)
	}
	if _, err := svc.ConfirmDeletion(61, other.ID, mailer.tokens[other.ID]); err == nil {
		t.Errorf("a reused token must be refused")
	}
}

// TestDeletionRefusalCodes proves EXPORT-15: a wrong, a reused and an expired confirmation token all get the
// same 400 invalid_confirmation_token; confirm or cancel of a cancelled request gets 409 deletion_not_pending;
// another user's request is 404 not_found; and a refused call changes nothing. A completed request's
// user_id is NULL (EXPORT-13), so the ownership check answers 404 for it before any status check: see the
// last block. Input: none; output: test failures. Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
// (Phase B.2). Touches: memory only (fake mailer and eraser).
// EXPORT-15
func TestDeletionRefusalCodes(t *testing.T) {
	svc, mailer, _ := newFixedService(t0)

	// wrong, reused and expired tokens: one error, one status.
	wrongReq, _ := svc.RequestDeletion(70, "user_requested")
	_, wrongErr := svc.ConfirmDeletion(70, wrongReq.ID, strings.Repeat("a", 64))

	reusedReq, _ := svc.RequestDeletion(71, "user_requested")
	if _, err := svc.ConfirmDeletion(71, reusedReq.ID, mailer.tokens[reusedReq.ID]); err != nil {
		t.Fatalf("first confirm: %v", err)
	}
	_, reusedErr := svc.ConfirmDeletion(71, reusedReq.ID, mailer.tokens[reusedReq.ID])

	expiredReq, _ := svc.RequestDeletion(72, "user_requested")
	svc.nowFunc = func() time.Time { return t0.Add(tokenTTL) }
	_, expiredErr := svc.ConfirmDeletion(72, expiredReq.ID, mailer.tokens[expiredReq.ID])
	svc.nowFunc = func() time.Time { return t0 }

	for name, err := range map[string]error{"wrong": wrongErr, "reused": reusedErr, "expired": expiredErr} {
		if !errors.Is(err, ErrInvalidToken) || err.Error() != "invalid_confirmation_token" || HTTPStatus(err) != 400 {
			t.Errorf("%s token: expected 400 invalid_confirmation_token, got %d %v", name, HTTPStatus(err), err)
		}
	}
	if wrongReq.Status != "pending" || expiredReq.Status != "pending" || reusedReq.Status != "approved" {
		t.Errorf("a refused confirm must change nothing: %s %s %s", wrongReq.Status, expiredReq.Status, reusedReq.Status)
	}

	// a cancelled request: confirm (even with its valid, unused token) and cancel are 409.
	cancelled, _ := svc.RequestDeletion(73, "user_requested")
	if _, err := svc.CancelDeletion(73, cancelled.ID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	_, confirmErr := svc.ConfirmDeletion(73, cancelled.ID, mailer.tokens[cancelled.ID])
	_, cancelErr := svc.CancelDeletion(73, cancelled.ID)
	for name, err := range map[string]error{"confirm": confirmErr, "cancel": cancelErr} {
		if !errors.Is(err, ErrNotPending) || err.Error() != "deletion_not_pending" || HTTPStatus(err) != 409 {
			t.Errorf("%s of a cancelled request: expected 409 deletion_not_pending, got %d %v", name, HTTPStatus(err), err)
		}
	}
	if cancelled.Status != "cancelled" {
		t.Errorf("a refused call must leave the request cancelled, got %s", cancelled.Status)
	}

	// another user's request: 404 not_found for confirm and cancel, whatever the token.
	_, otherConfirm := svc.ConfirmDeletion(99, wrongReq.ID, mailer.tokens[wrongReq.ID])
	_, otherCancel := svc.CancelDeletion(99, wrongReq.ID)
	for name, err := range map[string]error{"confirm": otherConfirm, "cancel": otherCancel} {
		if !errors.Is(err, ErrNotFound) || err.Error() != "not_found" || HTTPStatus(err) != 404 {
			t.Errorf("another user's %s: expected 404 not_found, got %d %v", name, HTTPStatus(err), err)
		}
	}
	if wrongReq.Status != "pending" {
		t.Errorf("another user's call must change nothing, got %s", wrongReq.Status)
	}

	// a completed (statutory) request: refused for confirm and cancel and left completed. Its user_id is
	// NULL once completed (EXPORT-13), so the ownership check answers first with 404 not_found; see the
	// report for this spec point (EXPORT-13 vs EXPORT-15).
	done, _ := svc.RequestDeletion(74, "gdpr_request")
	if _, err := svc.ConfirmDeletion(74, done.ID, mailer.tokens[done.ID]); err != nil || done.Status != "completed" {
		t.Fatalf("statutory confirm: %v %s", err, done.Status)
	}
	_, doneConfirm := svc.ConfirmDeletion(74, done.ID, mailer.tokens[done.ID])
	_, doneCancel := svc.CancelDeletion(74, done.ID)
	for name, err := range map[string]error{"confirm": doneConfirm, "cancel": doneCancel} {
		if HTTPStatus(err) != 404 {
			t.Errorf("%s of a completed request: expected 404 (user_id is NULL), got %d %v", name, HTTPStatus(err), err)
		}
	}
	if done.Status != "completed" || done.UserID != nil {
		t.Errorf("a completed request must stay completed with no user id, got %s %v", done.Status, done.UserID)
	}
}
