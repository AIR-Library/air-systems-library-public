package webhooks

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Store defines the storage interface for webhooks.
type Store interface {
	InitSchema() error
	CreateEndpoint(orgID int64, url, secret, eventTypesJSON string) (int64, error)
	GetEndpoint(id int64) (*Endpoint, error)
	UpdateEndpointSecret(id int64, secret string) error
	UpdateEndpointFailureCount(id int64, count int, active bool) error
	GetActiveEndpointsByOrgAndEvent(orgID int64, eventType string) ([]*Endpoint, error)
	CreateMessage(id, payload string, orgID int64, eventType string) error
	GetMessage(id string) (*Message, error)
	CreateDelivery(messageID string, endpointID int64) (int64, error)
	GetDelivery(id int64) (*Delivery, error)
	UpdateDelivery(deliveryID int64, statusCode int, success bool, errMsg string, deliveredAt time.Time, nextAttemptAt *time.Time, nextAttemptNum int) error
}

// Endpoint represents a webhook endpoint.
type Endpoint struct {
	ID            int64
	OrgID         int64
	URL           string
	Secret        string
	EventTypes    []string
	Active        bool
	FailureCount  int
	CreatedAt     time.Time
}

// Message represents a webhook message.
type Message struct {
	ID        string
	OrgID     int64
	EventType string
	Payload   []byte
	CreatedAt time.Time
}

// Delivery represents a webhook delivery attempt.
type Delivery struct {
	ID             int64
	MessageID      string
	EndpointID     int64
	Attempt        int
	StatusCode     *int
	Success        *bool
	Error          *string
	NextAttemptAt  *time.Time
	DeliveredAt    *time.Time
	CreatedAt      time.Time
}

// InMemoryStore is an in-memory implementation of Store for testing.
type InMemoryStore struct {
	mu             sync.RWMutex
	endpoints      map[int64]*Endpoint
	messages       map[string]*Message
	deliveries     map[int64]*Delivery
	nextEndpointID int64
	nextDeliveryID int64
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		endpoints:  make(map[int64]*Endpoint),
		messages:   make(map[string]*Message),
		deliveries: make(map[int64]*Delivery),
	}
}

func (s *InMemoryStore) InitSchema() error {
	return nil
}

func (s *InMemoryStore) CreateEndpoint(orgID int64, url, secret, eventTypesJSON string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextEndpointID++
	id := s.nextEndpointID
	var eventTypes []string
	if err := json.Unmarshal([]byte(eventTypesJSON), &eventTypes); err != nil {
		return 0, err
	}
	ep := &Endpoint{
		ID:           id,
		OrgID:        orgID,
		URL:          url,
		Secret:       secret,
		EventTypes:   eventTypes,
		Active:       true,
		FailureCount: 0,
		CreatedAt:    time.Now(),
	}
	s.endpoints[id] = ep
	return id, nil
}

func (s *InMemoryStore) GetEndpoint(id int64) (*Endpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ep, ok := s.endpoints[id]
	if !ok {
		return nil, errors.New("endpoint not found")
	}
	return ep, nil
}

func (s *InMemoryStore) UpdateEndpointSecret(id int64, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ep, ok := s.endpoints[id]
	if !ok {
		return errors.New("endpoint not found")
	}
	ep.Secret = secret
	return nil
}

func (s *InMemoryStore) UpdateEndpointFailureCount(id int64, count int, active bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ep, ok := s.endpoints[id]
	if !ok {
		return errors.New("endpoint not found")
	}
	ep.FailureCount = count
	ep.Active = active
	return nil
}

func (s *InMemoryStore) GetActiveEndpointsByOrgAndEvent(orgID int64, eventType string) ([]*Endpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Endpoint
	for _, ep := range s.endpoints {
		if ep.OrgID == orgID && ep.Active {
			for _, t := range ep.EventTypes {
				if t == eventType {
					result = append(result, ep)
					break
				}
			}
		}
	}
	return result, nil
}

func (s *InMemoryStore) CreateMessage(id, payload string, orgID int64, eventType string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	msg := &Message{
		ID:        id,
		OrgID:     orgID,
		EventType: eventType,
		Payload:   []byte(payload),
		CreatedAt: time.Now(),
	}
	s.messages[id] = msg
	return nil
}

func (s *InMemoryStore) GetMessage(id string) (*Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	msg, ok := s.messages[id]
	if !ok {
		return nil, errors.New("message not found")
	}
	return msg, nil
}

func (s *InMemoryStore) CreateDelivery(messageID string, endpointID int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextDeliveryID++
	id := s.nextDeliveryID
	d := &Delivery{
		ID:         id,
		MessageID:  messageID,
		EndpointID: endpointID,
		Attempt:    1,
		CreatedAt:  time.Now(),
	}
	s.deliveries[id] = d
	return id, nil
}

func (s *InMemoryStore) GetDelivery(id int64) (*Delivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.deliveries[id]
	if !ok {
		return nil, errors.New("delivery not found")
	}
	return d, nil
}

func (s *InMemoryStore) UpdateDelivery(deliveryID int64, statusCode int, success bool, errMsg string, deliveredAt time.Time, nextAttemptAt *time.Time, nextAttemptNum int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.deliveries[deliveryID]
	if !ok {
		return errors.New("delivery not found")
	}
	d.StatusCode = &statusCode
	d.Success = &success
	if errMsg != "" {
		d.Error = &errMsg
	}
	d.DeliveredAt = &deliveredAt
	d.NextAttemptAt = nextAttemptAt
	d.Attempt = nextAttemptNum
	return nil
}

// SQLStore is a production SQL implementation of Store using database/sql.
type SQLStore struct {
	db *sql.DB
}

func NewSQLStore(db *sql.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) InitSchema() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS webhook_endpoints (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			org_id INTEGER NOT NULL,
			url TEXT NOT NULL,
			secret TEXT NOT NULL,
			event_types TEXT NOT NULL,
			active BOOLEAN NOT NULL DEFAULT 1,
			failure_count INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS webhook_messages (
			id TEXT PRIMARY KEY,
			org_id INTEGER NOT NULL,
			event_type TEXT NOT NULL,
			payload TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS webhook_deliveries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			message_id TEXT NOT NULL,
			endpoint_id INTEGER NOT NULL,
			attempt INTEGER NOT NULL,
			status_code INTEGER,
			success BOOLEAN,
			error TEXT,
			next_attempt_at TIMESTAMP,
			delivered_at TIMESTAMP,
			FOREIGN KEY (message_id) REFERENCES webhook_messages(id),
			FOREIGN KEY (endpoint_id) REFERENCES webhook_endpoints(id)
		);`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLStore) CreateEndpoint(orgID int64, url, secret, eventTypesJSON string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO webhook_endpoints (org_id, url, secret, event_types, active, failure_count) VALUES (?, ?, ?, ?, 1, 0)`,
		orgID, url, secret, eventTypesJSON,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *SQLStore) GetEndpoint(id int64) (*Endpoint, error) {
	var ep Endpoint
	var eventTypesJSON string
	err := s.db.QueryRow(
		`SELECT id, org_id, url, secret, event_types, active, failure_count, created_at FROM webhook_endpoints WHERE id = ?`,
		id,
	).Scan(&ep.ID, &ep.OrgID, &ep.URL, &ep.Secret, &eventTypesJSON, &ep.Active, &ep.FailureCount, &ep.CreatedAt)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(eventTypesJSON), &ep.EventTypes); err != nil {
		return nil, err
	}
	return &ep, nil
}

func (s *SQLStore) UpdateEndpointSecret(id int64, secret string) error {
	_, err := s.db.Exec(`UPDATE webhook_endpoints SET secret = ? WHERE id = ?`, secret, id)
	return err
}

func (s *SQLStore) UpdateEndpointFailureCount(id int64, count int, active bool) error {
	_, err := s.db.Exec(`UPDATE webhook_endpoints SET failure_count = ?, active = ? WHERE id = ?`, count, active, id)
	return err
}

func (s *SQLStore) GetActiveEndpointsByOrgAndEvent(orgID int64, eventType string) ([]*Endpoint, error) {
	rows, err := s.db.Query(`SELECT id, org_id, url, secret, event_types, active, failure_count, created_at FROM webhook_endpoints WHERE active = 1 AND org_id = ?`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*Endpoint
	for rows.Next() {
		var ep Endpoint
		var eventTypesJSON string
		if err := rows.Scan(&ep.ID, &ep.OrgID, &ep.URL, &ep.Secret, &eventTypesJSON, &ep.Active, &ep.FailureCount, &ep.CreatedAt); err != nil {
			continue
		}
		if err := json.Unmarshal([]byte(eventTypesJSON), &ep.EventTypes); err != nil {
			continue
		}
		for _, t := range ep.EventTypes {
			if t == eventType {
				result = append(result, &ep)
				break
			}
		}
	}
	return result, rows.Err()
}

func (s *SQLStore) CreateMessage(id, payload string, orgID int64, eventType string) error {
	_, err := s.db.Exec(
		`INSERT INTO webhook_messages (id, org_id, event_type, payload) VALUES (?, ?, ?, ?)`,
		id, orgID, eventType, payload,
	)
	return err
}

func (s *SQLStore) GetMessage(id string) (*Message, error) {
	var msg Message
	var payloadJSON string
	err := s.db.QueryRow(`SELECT id, org_id, event_type, payload, created_at FROM webhook_messages WHERE id = ?`, id).
		Scan(&msg.ID, &msg.OrgID, &msg.EventType, &payloadJSON, &msg.CreatedAt)
	if err != nil {
		return nil, err
	}
	msg.Payload = []byte(payloadJSON)
	return &msg, nil
}

func (s *SQLStore) CreateDelivery(messageID string, endpointID int64) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO webhook_deliveries (message_id, endpoint_id, attempt, status_code, success, error, next_attempt_at, delivered_at) VALUES (?, ?, 1, NULL, NULL, NULL, NULL, NULL)`,
		messageID, endpointID,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *SQLStore) GetDelivery(id int64) (*Delivery, error) {
	var d Delivery
	var statusCode, success sql.NullInt64
	var errMsg, nextAttemptAt, deliveredAt sql.NullString
	err := s.db.QueryRow(
		`SELECT id, message_id, endpoint_id, attempt, status_code, success, error, next_attempt_at, delivered_at FROM webhook_deliveries WHERE id = ?`,
		id,
	).Scan(&d.ID, &d.MessageID, &d.EndpointID, &d.Attempt, &statusCode, &success, &errMsg, &nextAttemptAt, &deliveredAt)
	if err != nil {
		return nil, err
	}
	if statusCode.Valid {
		v := int(statusCode.Int64)
		d.StatusCode = &v
	}
	if success.Valid {
		v := success.Int64 == 1
		d.Success = &v
	}
	if errMsg.Valid {
		d.Error = &errMsg.String
	}
	if nextAttemptAt.Valid {
		if t, err := time.Parse(time.RFC3339, nextAttemptAt.String); err == nil {
			d.NextAttemptAt = &t
		}
	}
	if deliveredAt.Valid {
		if t, err := time.Parse(time.RFC3339, deliveredAt.String); err == nil {
			d.DeliveredAt = &t
		}
	}
	return &d, nil
}

func (s *SQLStore) UpdateDelivery(deliveryID int64, statusCode int, success bool, errMsg string, deliveredAt time.Time, nextAttemptAt *time.Time, nextAttemptNum int) error {
	var nextAttemptStr *string
	if nextAttemptAt != nil {
		s := nextAttemptAt.Format(time.RFC3339)
		nextAttemptStr = &s
	}
	_, err := s.db.Exec(
		`UPDATE webhook_deliveries SET status_code = ?, success = ?, error = ?, delivered_at = ?, next_attempt_at = ?, attempt = ? WHERE id = ?`,
		statusCode, success, errMsg, deliveredAt.Format(time.RFC3339), nextAttemptStr, nextAttemptNum, deliveryID,
	)
	return err
}

// Webhook holds a Store and provides the API.
type Webhook struct {
	store Store
}

// NewWebhook creates a Webhook instance with the given store.
func NewWebhook(store Store) *Webhook {
	return &Webhook{store: store}
}

// generateSecret creates a whsec_ prefixed base64-encoded 32-byte secret.
func generateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "whsec_" + base64.StdEncoding.EncodeToString(b), nil
}

// generateMessageID creates a msg_ prefixed URL-safe base64 random ID.
func generateMessageID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "msg_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// Sign returns a v1,base64(hmac-sha256) signature.
// The content signed is exactly "msg_id.timestamp.payload" (raw body bytes).
func Sign(secret string, msgID string, timestamp int64, body []byte) (string, error) {
	if len(secret) < 7 || !strings.HasPrefix(secret, "whsec_") {
		return "", errors.New("invalid secret format")
	}
	keyB64 := secret[6:]
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	var buf bytes.Buffer
	buf.WriteString(msgID)
	buf.WriteByte('.')
	buf.WriteString(strconv.FormatInt(timestamp, 10))
	buf.WriteByte('.')
	buf.Write(body)
	if _, err := mac.Write(buf.Bytes()); err != nil {
		return "", err
	}
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return "v1," + sig, nil
}

// Verify checks the signature(s) in the header against the secret.
// Returns true if any signature matches and timestamp is within tolerance.
func Verify(secret string, header http.Header, rawBody []byte, toleranceSeconds int) (bool, error) {
	id := header.Get("webhook-id")
	ts := header.Get("webhook-timestamp")
	sigHeader := header.Get("webhook-signature")
	if id == "" || ts == "" || sigHeader == "" {
		return false, errors.New("missing required headers")
	}
	timestamp, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false, err
	}
	now := time.Now().Unix()
	if now-timestamp > int64(toleranceSeconds) || timestamp-now > int64(toleranceSeconds) {
		return false, nil
	}
	if len(secret) < 7 || !strings.HasPrefix(secret, "whsec_") {
		return false, errors.New("invalid secret format")
	}
	keyB64 := secret[6:]
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return false, err
	}
	var buf bytes.Buffer
	buf.WriteString(id)
	buf.WriteByte('.')
	buf.WriteString(strconv.FormatInt(timestamp, 10))
	buf.WriteByte('.')
	buf.Write(rawBody)
	data := buf.Bytes()
	for _, s := range strings.Fields(sigHeader) {
		if !strings.HasPrefix(s, "v1,") {
			continue
		}
		sigB64 := s[3:]
		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			continue
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		expected := mac.Sum(nil)
		if hmac.Equal(sig, expected) {
			return true, nil
		}
	}
	return false, nil
}

// CreateEndpoint registers a new webhook endpoint.
func (w *Webhook) CreateEndpoint(orgID int64, url string, eventTypes []string) (int64, string, error) {
	if !strings.HasPrefix(url, "https://") && url != "http://localhost" {
		return 0, "", errors.New("URL must be https:// or http://localhost for dev")
	}
	secret, err := generateSecret()
	if err != nil {
		return 0, "", err
	}
	eventTypesJSON, err := json.Marshal(eventTypes)
	if err != nil {
		return 0, "", err
	}
	id, err := w.store.CreateEndpoint(orgID, url, secret, string(eventTypesJSON))
	if err != nil {
		return 0, "", err
	}
	return id, secret, nil
}

// SendEvent creates a message and a pending delivery for each active endpoint subscribed to eventType for the given org.
func (w *Webhook) SendEvent(orgID int64, eventType string, payload interface{}) (string, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	msgID, err := generateMessageID()
	if err != nil {
		return "", err
	}
	if err := w.store.CreateMessage(msgID, string(payloadBytes), orgID, eventType); err != nil {
		return "", err
	}
	endpoints, err := w.store.GetActiveEndpointsByOrgAndEvent(orgID, eventType)
	if err != nil {
		return "", err
	}
	for _, ep := range endpoints {
		if _, err := w.store.CreateDelivery(msgID, ep.ID); err != nil {
			return "", err
		}
	}
	return msgID, nil
}

// RotateSecret replaces the secret for an endpoint.
func (w *Webhook) RotateSecret(endpointID int64) (string, error) {
	secret, err := generateSecret()
	if err != nil {
		return "", err
	}
	if err := w.store.UpdateEndpointSecret(endpointID, secret); err != nil {
		return "", err
	}
	return secret, nil
}

// Deliver attempts a single delivery for the given delivery record using the provided sender.
// Sender signature: func(url string, headers http.Header, body []byte) (statusCode int, err error)
// Returns true on success (2xx), false on failure (with retry scheduled).
func (w *Webhook) Deliver(deliveryID int64, sender func(string, http.Header, []byte) (int, error)) (bool, error) {
	delivery, err := w.store.GetDelivery(deliveryID)
	if err != nil {
		return false, err
	}
	endpoint, err := w.store.GetEndpoint(delivery.EndpointID)
	if err != nil {
		return false, err
	}
	if !endpoint.Active {
		return false, errors.New("endpoint inactive")
	}
	msg, err := w.store.GetMessage(delivery.MessageID)
	if err != nil {
		return false, err
	}
	timestamp := time.Now().Unix()
	signature, err := Sign(endpoint.Secret, msg.ID, timestamp, msg.Payload)
	if err != nil {
		return false, err
	}
	headers := http.Header{}
	headers.Set("Content-Type", "application/json")
	headers.Set("webhook-id", msg.ID)
	headers.Set("webhook-timestamp", strconv.FormatInt(timestamp, 10))
	headers.Set("webhook-signature", signature)
	statusCode, err := sender(endpoint.URL, headers, msg.Payload)
	var errMsg string
	if err != nil {
		statusCode = 0
		errMsg = err.Error()
	}
	success := statusCode >= 200 && statusCode <= 299
	now := time.Now()
	if err := w.store.UpdateDelivery(deliveryID, statusCode, success, errMsg, now, nil, delivery.Attempt); err != nil {
		return false, err
	}
	if success {
		if err := w.store.UpdateEndpointFailureCount(delivery.EndpointID, 0, true); err != nil {
			return false, err
		}
		return true, nil
	}
	newFailureCount := endpoint.FailureCount + 1
	newActive := endpoint.Active
	if newFailureCount >= 5 {
		newActive = false
	}
	if err := w.store.UpdateEndpointFailureCount(delivery.EndpointID, newFailureCount, newActive); err != nil {
		return false, err
	}
	backoff := []time.Duration{
		5 * time.Second,
		5 * time.Minute,
		30 * time.Minute,
		2 * time.Hour,
		5 * time.Hour,
		10 * time.Hour,
		10 * time.Hour,
	}
	var nextAttemptAt *time.Time
	idx := delivery.Attempt - 1
	if idx >= 0 && idx < len(backoff) {
		t := now.Add(backoff[idx])
		nextAttemptAt = &t
	}
	nextAttemptNum := delivery.Attempt + 1
	if err := w.store.UpdateDelivery(deliveryID, statusCode, success, errMsg, now, nextAttemptAt, nextAttemptNum); err != nil {
		return false, err
	}
	return false, nil
}
