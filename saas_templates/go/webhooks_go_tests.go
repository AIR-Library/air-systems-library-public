package webhooks

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newTestWebhook() *Webhook {
	store := NewInMemoryStore()
	if err := store.InitSchema(); err != nil {
		panic(err)
	}
	return NewWebhook(store)
}

// HOOK-01
func TestWebhook_SignVerifyRoundtrip(t *testing.T) {
	w := newTestWebhook()
	_, secret, err := w.CreateEndpoint(1, "https://example.com", []string{"test"})
	if err != nil {
		t.Fatal(err)
	}
	msgID := "msg_123"
	timestamp := time.Now().Unix()
	body := []byte(`{"foo":1}`)
	sig, err := Sign(secret, msgID, timestamp, body)
	if err != nil {
		t.Fatal(err)
	}
	header := http.Header{}
	header.Set("webhook-id", msgID)
	header.Set("webhook-timestamp", strconv.FormatInt(timestamp, 10))
	header.Set("webhook-signature", sig)
	ok, err := Verify(secret, header, body, 300)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected verify to succeed")
	}
}

// HOOK-02
func TestWebhook_VerifyFailsOnChangedBody(t *testing.T) {
	w := newTestWebhook()
	_, secret, err := w.CreateEndpoint(1, "https://example.com", []string{"test"})
	if err != nil {
		t.Fatal(err)
	}
	msgID := "msg_456"
	timestamp := time.Now().Unix()
	body := []byte(`{"foo":1}`)
	sig, _ := Sign(secret, msgID, timestamp, body)
	// tamper body
	tampered := []byte(`{"foo":2}`)
	header := http.Header{}
	header.Set("webhook-id", msgID)
	header.Set("webhook-timestamp", strconv.FormatInt(timestamp, 10))
	header.Set("webhook-signature", sig)
	ok, err := Verify(secret, header, tampered, 300)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected verify to fail on changed body")
	}
}

// HOOK-02
func TestWebhook_VerifyFailsOnChangedTimestamp(t *testing.T) {
	w := newTestWebhook()
	_, secret, err := w.CreateEndpoint(1, "https://example.com", []string{"test"})
	if err != nil {
		t.Fatal(err)
	}
	msgID := "msg_789"
	timestamp := time.Now().Unix()
	body := []byte(`{"foo":1}`)
	sig, _ := Sign(secret, msgID, timestamp, body)
	header := http.Header{}
	header.Set("webhook-id", msgID)
	header.Set("webhook-timestamp", strconv.FormatInt(timestamp+1, 10)) // changed
	header.Set("webhook-signature", sig)
	ok, err := Verify(secret, header, body, 300)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected verify to fail on changed timestamp")
	}
}

// HOOK-03
func TestWebhook_VerifyRejectsOldTimestamp(t *testing.T) {
	w := newTestWebhook()
	_, secret, err := w.CreateEndpoint(1, "https://example.com", []string{"test"})
	if err != nil {
		t.Fatal(err)
	}
	msgID := "msg_old"
	now := time.Now().Unix()
	old := now - 400 // older than tolerance 300
	body := []byte(`{}`)
	sig, _ := Sign(secret, msgID, old, body)
	header := http.Header{}
	header.Set("webhook-id", msgID)
	header.Set("webhook-timestamp", strconv.FormatInt(old, 10))
	header.Set("webhook-signature", sig)
	ok, err := Verify(secret, header, body, 300)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected verify to reject old timestamp")
	}
}

// HOOK-04
func TestWebhook_VerifyAcceptsOneOfMultipleSignatures(t *testing.T) {
	w := newTestWebhook()
	_, secret1, err := w.CreateEndpoint(1, "https://example.com", []string{"test"})
	if err != nil {
		t.Fatal(err)
	}
	_, secret2, err := w.CreateEndpoint(2, "https://example.com", []string{"test"})
	if err != nil {
		t.Fatal(err)
	}
	msgID := "msg_multi"
	timestamp := time.Now().Unix()
	body := []byte(`{}`)
	sig1, _ := Sign(secret1, msgID, timestamp, body)
	sig2, _ := Sign(secret2, msgID, timestamp, body)
	header := http.Header{}
	header.Set("webhook-id", msgID)
	header.Set("webhook-timestamp", strconv.FormatInt(timestamp, 10))
	header.Set("webhook-signature", sig1+" "+sig2) // space-separated
	ok, err := Verify(secret1, header, body, 300)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected verify to succeed with first signature")
	}
	// verify with secret2 should also succeed
	ok, err = Verify(secret2, header, body, 300)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected verify to succeed with second signature")
	}
}

// HOOK-05
func TestWebhook_DeliverSuccessAndRetry(t *testing.T) {
	w := newTestWebhook()

	// Success case: sender returns 200
	successSender := func(url string, headers http.Header, body []byte) (int, error) {
		return http.StatusOK, nil
	}
	epID, _, err := w.CreateEndpoint(1, "https://example.com/success", []string{"ev1"})
	if err != nil {
		t.Fatal(err)
	}
	msgID, err := w.SendEvent(1, "ev1", map[string]string{"hello": "world"})
	if err != nil {
		t.Fatal(err)
	}
	var deliveryID int64
	// Get delivery ID from store directly since we're using in-memory
	store := w.store.(*InMemoryStore)
	store.mu.RLock()
	for id, d := range store.deliveries {
		if d.MessageID == msgID && d.EndpointID == epID {
			deliveryID = id
			break
		}
	}
	store.mu.RUnlock()
	if deliveryID == 0 {
		t.Fatal("delivery not found")
	}
	ok, err := w.Deliver(deliveryID, successSender)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected delivery to succeed")
	}
	ep, err := w.store.GetEndpoint(epID)
	if err != nil {
		t.Fatal(err)
	}
	if ep.FailureCount != 0 {
		t.Error("expected failure_count to be 0 after success")
	}
	d, err := w.store.GetDelivery(deliveryID)
	if err != nil {
		t.Fatal(err)
	}
	if d.NextAttemptAt != nil {
		t.Error("expected no next attempt after success")
	}

	// Failure case: sender returns 500
	failSender := func(url string, headers http.Header, body []byte) (int, error) {
		return http.StatusInternalServerError, nil
	}
	epID2, _, err := w.CreateEndpoint(2, "https://example.com/fail", []string{"ev1"})
	if err != nil {
		t.Fatal(err)
	}
	msgID2, err := w.SendEvent(2, "ev1", map[string]string{"hello": "world"})
	if err != nil {
		t.Fatal(err)
	}
	var deliveryID2 int64
	store.mu.RLock()
	for id, d := range store.deliveries {
		if d.MessageID == msgID2 && d.EndpointID == epID2 {
			deliveryID2 = id
			break
		}
	}
	store.mu.RUnlock()
	if deliveryID2 == 0 {
		t.Fatal("delivery not found")
	}
	ok, err = w.Deliver(deliveryID2, failSender)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected delivery to fail")
	}
	ep2, err := w.store.GetEndpoint(epID2)
	if err != nil {
		t.Fatal(err)
	}
	if ep2.FailureCount != 1 {
		t.Error("expected failure_count to be 1 after first failure")
	}
	d2, err := w.store.GetDelivery(deliveryID2)
	if err != nil {
		t.Fatal(err)
	}
	if d2.NextAttemptAt == nil {
		t.Error("expected next attempt to be scheduled")
	}

	// Test 301, 400 also schedule retry
	for _, code := range []int{http.StatusMovedPermanently, http.StatusBadRequest} {
		code := code
		sender := func(url string, headers http.Header, body []byte) (int, error) {
			return code, nil
		}
		epID3, _, err := w.CreateEndpoint(3, "https://example.com/code", []string{"ev1"})
		if err != nil {
			t.Fatal(err)
		}
		msgID3, err := w.SendEvent(3, "ev1", map[string]string{})
		if err != nil {
			t.Fatal(err)
		}
		var deliveryID3 int64
		store.mu.RLock()
		for id, d := range store.deliveries {
			if d.MessageID == msgID3 && d.EndpointID == epID3 {
				deliveryID3 = id
				break
			}
		}
		store.mu.RUnlock()
		if deliveryID3 == 0 {
			t.Fatal("delivery not found")
		}
		ok, err = w.Deliver(deliveryID3, sender)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Errorf("expected delivery to fail for status %d", code)
		}
		ep3, err := w.store.GetEndpoint(epID3)
		if err != nil {
			t.Fatal(err)
		}
		if ep3.FailureCount != 1 {
			t.Errorf("expected failure_count 1 for status %d", code)
		}
		d3, err := w.store.GetDelivery(deliveryID3)
		if err != nil {
			t.Fatal(err)
		}
		if d3.NextAttemptAt == nil {
			t.Errorf("expected next attempt scheduled for status %d", code)
		}
	}
}

// HOOK-07
func TestWebhook_DeliverWebhookIDConsistent(t *testing.T) {
	w := newTestWebhook()

	var capturedIDs []string
	sender := func(url string, headers http.Header, body []byte) (int, error) {
		capturedIDs = append(capturedIDs, headers.Get("webhook-id"))
		if len(capturedIDs) == 1 {
			return http.StatusInternalServerError, nil
		}
		return http.StatusOK, nil
	}
	epID, _, err := w.CreateEndpoint(1, "https://example.com", []string{"ev2"})
	if err != nil {
		t.Fatal(err)
	}
	msgID, err := w.SendEvent(1, "ev2", map[string]int{"n": 5})
	if err != nil {
		t.Fatal(err)
	}
	var deliveryID int64
	store := w.store.(*InMemoryStore)
	store.mu.RLock()
	for id, d := range store.deliveries {
		if d.MessageID == msgID && d.EndpointID == epID {
			deliveryID = id
			break
		}
	}
	store.mu.RUnlock()
	if deliveryID == 0 {
		t.Fatal("delivery not found")
	}
	// First attempt (fails)
	_, err = w.Deliver(deliveryID, sender)
	if err != nil {
		t.Fatal(err)
	}
	// Second attempt (succeeds)
	_, err = w.Deliver(deliveryID, sender)
	if err != nil {
		t.Fatal(err)
	}
	if len(capturedIDs) != 2 {
		t.Error("expected two captured webhook-ids")
	}
	if capturedIDs[0] != capturedIDs[1] {
		t.Error("webhook-id differed between retries")
	}
	if capturedIDs[0] != msgID {
		t.Error("webhook-id does not match message id")
	}
}

// HOOK-08
func TestWebhook_SecretGeneration(t *testing.T) {
	w := newTestWebhook()
	_, secret, err := w.CreateEndpoint(999, "https://example.com", []string{"any"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, "whsec_") {
		t.Error("secret does not start with whsec_")
	}
	b64 := secret[6:]
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Error("secret base64 decode failed")
	}
	if len(decoded) < 24 || len(decoded) > 64 {
		t.Error("secret decoded length out of range 24-64")
	}
}

func TestWebhook_RotateSecret(t *testing.T) {
	w := newTestWebhook()
	epID, oldSecret, err := w.CreateEndpoint(1, "https://example.com", []string{"evx"})
	if err != nil {
		t.Fatal(err)
	}
	newSecret, err := w.RotateSecret(epID)
	if err != nil {
		t.Fatal(err)
	}
	if newSecret == oldSecret {
		t.Error("rotate_secret did not change secret")
	}
	ep, err := w.store.GetEndpoint(epID)
	if err != nil {
		t.Fatal(err)
	}
	if ep.Secret != newSecret {
		t.Error("secret not persisted after rotation")
	}
}

// HOOK-06
func TestWebhook_OrgIsolation(t *testing.T) {
	w := newTestWebhook()

	// Org 1 endpoint subscribed to "ev1"
	epID1, _, err := w.CreateEndpoint(1, "https://org1.example.com", []string{"ev1"})
	if err != nil {
		t.Fatal(err)
	}
	// Org 2 endpoint subscribed to "ev1"
	epID2, _, err := w.CreateEndpoint(2, "https://org2.example.com", []string{"ev1"})
	if err != nil {
		t.Fatal(err)
	}

	// Send event for org 1
	msgID, err := w.SendEvent(1, "ev1", map[string]string{"data": "org1"})
	if err != nil {
		t.Fatal(err)
	}

	// Check deliveries: only org 1's endpoint should have a delivery
	store := w.store.(*InMemoryStore)
	store.mu.RLock()
	count1 := 0
	count2 := 0
	for _, d := range store.deliveries {
		if d.MessageID == msgID && d.EndpointID == epID1 {
			count1++
		}
		if d.MessageID == msgID && d.EndpointID == epID2 {
			count2++
		}
	}
	store.mu.RUnlock()
	if count1 != 1 {
		t.Error("expected 1 delivery for org 1 endpoint")
	}
	if count2 != 0 {
		t.Error("expected 0 deliveries for org 2 endpoint")
	}

	// Send event for org 2
	msgID2, err := w.SendEvent(2, "ev1", map[string]string{"data": "org2"})
	if err != nil {
		t.Fatal(err)
	}
	store.mu.RLock()
	count1 = 0
	count2 = 0
	for _, d := range store.deliveries {
		if d.MessageID == msgID2 && d.EndpointID == epID1 {
			count1++
		}
		if d.MessageID == msgID2 && d.EndpointID == epID2 {
			count2++
		}
	}
	store.mu.RUnlock()
	if count1 != 0 {
		t.Error("expected 0 deliveries for org 1 endpoint on org 2 event")
	}
	if count2 != 1 {
		t.Error("expected 1 delivery for org 2 endpoint on org 2 event")
	}
}
