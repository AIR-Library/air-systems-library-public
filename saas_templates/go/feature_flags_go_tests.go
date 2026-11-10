package featureflags

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"
)

// FLAG-01
func TestUnknownFlagReturnsDefault(t *testing.T) {
	store := NewMemoryStore()
	client := NewClient(store)
	ctx := context.Background()

	detail := client.GetBooleanDetails(ctx, "unknown_flag", true, EvaluationContext{TargetingKey: "user1"})

	if detail.Value != true {
		t.Errorf("expected default value true, got %v", detail.Value)
	}
	if detail.Reason != ReasonError {
		t.Errorf("expected reason ERROR, got %s", detail.Reason)
	}
	if detail.ErrorCode != ErrorCodeFlagNotFound {
		t.Errorf("expected error code FLAG_NOT_FOUND, got %s", detail.ErrorCode)
	}
}

// FLAG-02
func TestTypeMismatch(t *testing.T) {
	store := NewMemoryStore()
	client := NewClient(store)
	ctx := context.Background()

	err := client.SetFlag(ctx, "admin", "bool_flag", TypeBoolean, false, true, []Rule{})
	if err != nil {
		t.Fatalf("SetFlag failed: %v", err)
	}

	detail := client.GetStringDetails(ctx, "bool_flag", "default", EvaluationContext{TargetingKey: "user1"})

	if detail.Value != "default" {
		t.Errorf("expected default value 'default', got %v", detail.Value)
	}
	if detail.Reason != ReasonError {
		t.Errorf("expected reason ERROR, got %s", detail.Reason)
	}
	if detail.ErrorCode != ErrorCodeTypeMismatch {
		t.Errorf("expected error code TYPE_MISMATCH, got %s", detail.ErrorCode)
	}
}

// FLAG-03
func TestDisabledFlagReturnsDefault(t *testing.T) {
	store := NewMemoryStore()
	client := NewClient(store)
	ctx := context.Background()

	err := client.SetFlag(ctx, "admin", "disabled_flag", TypeBoolean, true, false, []Rule{})
	if err != nil {
		t.Fatalf("SetFlag failed: %v", err)
	}

	detail := client.GetBooleanDetails(ctx, "disabled_flag", false, EvaluationContext{TargetingKey: "user1"})

	if detail.Value != false {
		t.Errorf("expected default value false, got %v", detail.Value)
	}
	if detail.Reason != ReasonDisabled {
		t.Errorf("expected reason DISABLED, got %s", detail.Reason)
	}
}

// FLAG-04
func TestMatchingRuleReturnsValue(t *testing.T) {
	store := NewMemoryStore()
	client := NewClient(store)
	ctx := context.Background()

	rules := []Rule{
		{
			Conditions: []Condition{
				{Attribute: "email", Operator: "ends_with", Value: "@acme.com"},
			},
			Variant: "on",
			Value:   true,
			Rollout: nil,
		},
	}
	err := client.SetFlag(ctx, "admin", "targeted_flag", TypeBoolean, false, true, rules)
	if err != nil {
		t.Fatalf("SetFlag failed: %v", err)
	}

	detail := client.GetBooleanDetails(ctx, "targeted_flag", false, EvaluationContext{
		TargetingKey: "user1",
		Email:        "test@acme.com",
	})

	if detail.Value != true {
		t.Errorf("expected value true, got %v", detail.Value)
	}
	if detail.Variant != "on" {
		t.Errorf("expected variant 'on', got %s", detail.Variant)
	}
	if detail.Reason != ReasonTargetingMatch {
		t.Errorf("expected reason TARGETING_MATCH, got %s", detail.Reason)
	}

	detail2 := client.GetBooleanDetails(ctx, "targeted_flag", false, EvaluationContext{
		TargetingKey: "user2",
		Email:        "test@example.com",
	})

	if detail2.Value != false {
		t.Errorf("expected default value false for non-matching, got %v", detail2.Value)
	}
	if detail2.Reason != ReasonDefault {
		t.Errorf("expected reason DEFAULT for non-matching, got %s", detail2.Reason)
	}
}

// FLAG-05
func TestRolloutDeterministic(t *testing.T) {
	store := NewMemoryStore()
	client := NewClient(store)
	ctx := context.Background()

	rules := []Rule{
		{
			Conditions: []Condition{},
			Variant:    "beta",
			Value:      true,
			Rollout:    &Rollout{Percentage: 30},
		},
	}
	err := client.SetFlag(ctx, "admin", "rollout_flag", TypeBoolean, false, true, rules)
	if err != nil {
		t.Fatalf("SetFlag failed: %v", err)
	}

	for i := 0; i < 100; i++ {
		detail1 := client.GetBooleanDetails(ctx, "rollout_flag", false, EvaluationContext{TargetingKey: "user_consistent"})
		detail2 := client.GetBooleanDetails(ctx, "rollout_flag", false, EvaluationContext{TargetingKey: "user_consistent"})
		if detail1.Value != detail2.Value {
			t.Errorf("rollout not deterministic: got %v then %v", detail1.Value, detail2.Value)
		}
	}

	trueCount := 0
	for i := 0; i < 10000; i++ {
		key := string(rune(i%1000)) + string(rune(i/1000))
		detail := client.GetBooleanDetails(ctx, "rollout_flag", false, EvaluationContext{TargetingKey: key})
		if detail.Value == true {
			trueCount++
		}
	}

	if trueCount < 2500 || trueCount > 3500 {
		t.Errorf("rollout distribution out of range: got %d true out of 10000 (expected 2500-3500)", trueCount)
	}
}

// FLAG-06
func TestRolloutFallsThrough(t *testing.T) {
	store := NewMemoryStore()
	client := NewClient(store)
	ctx := context.Background()

	rules := []Rule{
		{
			Conditions: []Condition{},
			Variant:    "beta",
			Value:      true,
			Rollout:    &Rollout{Percentage: 30},
		},
		{
			Conditions: []Condition{},
			Variant:    "stable",
			Value:      false,
			Rollout:    nil,
		},
	}
	err := client.SetFlag(ctx, "admin", "fallthrough_flag", TypeBoolean, false, true, rules)
	if err != nil {
		t.Fatalf("SetFlag failed: %v", err)
	}

	foundFallback := false
	for i := 0; i < 1000; i++ {
		key := string(rune(i%1000)) + string(rune(i/1000))
		detail := client.GetBooleanDetails(ctx, "fallthrough_flag", false, EvaluationContext{TargetingKey: key})
		if detail.Value == false && detail.Variant == "stable" && detail.Reason == ReasonTargetingMatch {
			foundFallback = true
			break
		}
	}

	if !foundFallback {
		t.Error("no user fell through to the second rule; rollout may be applying to everyone")
	}
}

// FLAG-07
func TestCorruptRulesReturnsParseError(t *testing.T) {
	store := NewMemoryStore()
	client := NewClient(store)
	ctx := context.Background()

	flag := &Flag{
		Key:          "corrupt_flag",
		Type:         TypeBoolean,
		DefaultValue: json.RawMessage(`false`),
		Enabled:      true,
		Rules:        json.RawMessage(`{ not valid json }`),
		UpdatedAt:    time.Now().UTC(),
		UpdatedBy:    "test",
	}
	store.SetFlag(ctx, flag)

	detail := client.GetBooleanDetails(ctx, "corrupt_flag", true, EvaluationContext{TargetingKey: "user1"})

	if detail.Value != true {
		t.Errorf("expected default value true, got %v", detail.Value)
	}
	if detail.Reason != ReasonError {
		t.Errorf("expected reason ERROR, got %s", detail.Reason)
	}
	if detail.ErrorCode != ErrorCodeParseError {
		t.Errorf("expected error code PARSE_ERROR, got %s", detail.ErrorCode)
	}
}

// FLAG-08
func TestSetFlagWritesAudit(t *testing.T) {
	store := NewMemoryStore()
	client := NewClient(store)
	ctx := context.Background()

	err := client.SetFlag(ctx, "admin", "audit_flag", TypeBoolean, false, true, []Rule{})
	if err != nil {
		t.Fatalf("SetFlag failed: %v", err)
	}

	err = client.SetFlag(ctx, "admin2", "audit_flag", TypeBoolean, true, false, []Rule{
		{Conditions: []Condition{}, Variant: "new", Value: true, Rollout: nil},
	})
	if err != nil {
		t.Fatalf("SetFlag update failed: %v", err)
	}

	auditLog, err := store.GetAuditLog(ctx, "audit_flag")
	if err != nil {
		t.Fatalf("GetAuditLog failed: %v", err)
	}

	if len(auditLog) != 2 {
		t.Errorf("expected 2 audit entries, got %d", len(auditLog))
	}

	if auditLog[0].Action != "set_flag" {
		t.Errorf("first audit action: expected 'set_flag', got %s", auditLog[0].Action)
	}
	if auditLog[0].ActorID != "admin" {
		t.Errorf("first audit actor: expected 'admin', got %s", auditLog[0].ActorID)
	}
	var oldVal1 map[string]interface{}
	json.Unmarshal(auditLog[0].OldValue, &oldVal1)
	if oldVal1 != nil {
		t.Errorf("first audit old_value should be null, got %v", oldVal1)
	}

	if auditLog[1].ActorID != "admin2" {
		t.Errorf("second audit actor: expected 'admin2', got %s", auditLog[1].ActorID)
	}
	var oldVal2 map[string]interface{}
	json.Unmarshal(auditLog[1].OldValue, &oldVal2)
	if oldVal2 == nil {
		t.Error("second audit old_value should not be null")
	} else if oldVal2["enabled"] != true {
		t.Errorf("second audit old_value enabled should be true, got %v", oldVal2["enabled"])
	}
}

func TestSQLStore(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Skip("sqlite3 driver not available, skipping SQL store test")
	}
	defer db.Close()

	store := NewSQLStore(db)
	ctx := context.Background()

	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema failed: %v", err)
	}

	client := NewClient(store)

	err = client.SetFlag(ctx, "admin", "sql_flag", TypeString, "default_val", true, []Rule{})
	if err != nil {
		t.Fatalf("SetFlag failed: %v", err)
	}

	detail := client.GetStringDetails(ctx, "sql_flag", "fallback", EvaluationContext{TargetingKey: "user1"})
	if detail.Value != "default_val" {
		t.Errorf("expected 'default_val', got %v", detail.Value)
	}
	if detail.Reason != ReasonDefault {
		t.Errorf("expected reason DEFAULT, got %s", detail.Reason)
	}

	auditLog, err := store.GetAuditLog(ctx, "sql_flag")
	if err != nil {
		t.Fatalf("GetAuditLog failed: %v", err)
	}
	if len(auditLog) != 1 {
		t.Errorf("expected 1 audit entry, got %d", len(auditLog))
	}

	detail2 := client.GetStringDetails(ctx, "nonexistent", "fallback", EvaluationContext{TargetingKey: "user1"})
	if detail2.Value != "fallback" {
		t.Errorf("expected fallback, got %v", detail2.Value)
	}
	if detail2.ErrorCode != ErrorCodeFlagNotFound {
		t.Errorf("expected FLAG_NOT_FOUND, got %s", detail2.ErrorCode)
	}
}

func TestNumberAndObjectTypes(t *testing.T) {
	store := NewMemoryStore()
	client := NewClient(store)
	ctx := context.Background()

	err := client.SetFlag(ctx, "admin", "num_flag", TypeNumber, 42.5, true, []Rule{})
	if err != nil {
		t.Fatalf("SetFlag failed: %v", err)
	}

	numDetail := client.GetNumberDetails(ctx, "num_flag", 0, EvaluationContext{TargetingKey: "user1"})
	if numDetail.Value != 42.5 {
		t.Errorf("expected 42.5, got %v", numDetail.Value)
	}

	objDefault := map[string]interface{}{"key": "value", "nested": map[string]interface{}{"a": 1}}
	err = client.SetFlag(ctx, "admin", "obj_flag", TypeObject, objDefault, true, []Rule{})
	if err != nil {
		t.Fatalf("SetFlag failed: %v", err)
	}

	objDetail := client.GetObjectDetails(ctx, "obj_flag", map[string]interface{}{}, EvaluationContext{TargetingKey: "user1"})
	objVal, ok := objDetail.Value.(map[string]interface{})
	if !ok {
		t.Errorf("expected map, got %T", objDetail.Value)
	} else if objVal["key"] != "value" {
		t.Errorf("expected key=value, got %v", objVal["key"])
	}
}

func TestOperators(t *testing.T) {
	store := NewMemoryStore()
	client := NewClient(store)
	ctx := context.Background()

	rules := []Rule{
		{Conditions: []Condition{{Attribute: "tier", Operator: "equals", Value: "premium"}}, Variant: "premium", Value: true, Rollout: nil},
	}
	client.SetFlag(ctx, "admin", "ops_flag", TypeBoolean, false, true, rules)

	detail := client.GetBooleanDetails(ctx, "ops_flag", false, EvaluationContext{TargetingKey: "u1", Tier: "premium"})
	if detail.Value != true || detail.Reason != ReasonTargetingMatch {
		t.Errorf("equals failed: %v %s", detail.Value, detail.Reason)
	}

	detail = client.GetBooleanDetails(ctx, "ops_flag", false, EvaluationContext{TargetingKey: "u2", Tier: "free"})
	if detail.Value != false || detail.Reason != ReasonDefault {
		t.Errorf("equals non-match failed: %v %s", detail.Value, detail.Reason)
	}

	rules = []Rule{
		{Conditions: []Condition{{Attribute: "tier", Operator: "not_equals", Value: "free"}}, Variant: "paid", Value: true, Rollout: nil},
	}
	client.SetFlag(ctx, "admin", "ops_flag2", TypeBoolean, false, true, rules)

	detail = client.GetBooleanDetails(ctx, "ops_flag2", false, EvaluationContext{TargetingKey: "u1", Tier: "premium"})
	if detail.Value != true || detail.Reason != ReasonTargetingMatch {
		t.Errorf("not_equals failed: %v %s", detail.Value, detail.Reason)
	}

	detail = client.GetBooleanDetails(ctx, "ops_flag2", false, EvaluationContext{TargetingKey: "u2", Tier: "free"})
	if detail.Value != false || detail.Reason != ReasonDefault {
		t.Errorf("not_equals non-match failed: %v %s", detail.Value, detail.Reason)
	}

	rules = []Rule{
		{Conditions: []Condition{{Attribute: "org_id", Operator: "in_list", Value: []interface{}{"org1", "org2"}}}, Variant: "allowed", Value: true, Rollout: nil},
	}
	client.SetFlag(ctx, "admin", "ops_flag3", TypeBoolean, false, true, rules)

	detail = client.GetBooleanDetails(ctx, "ops_flag3", false, EvaluationContext{TargetingKey: "u1", OrgID: "org1"})
	if detail.Value != true || detail.Reason != ReasonTargetingMatch {
		t.Errorf("in_list failed: %v %s", detail.Value, detail.Reason)
	}

	detail = client.GetBooleanDetails(ctx, "ops_flag3", false, EvaluationContext{TargetingKey: "u2", OrgID: "org3"})
	if detail.Value != false || detail.Reason != ReasonDefault {
		t.Errorf("in_list non-match failed: %v %s", detail.Value, detail.Reason)
	}

	rules = []Rule{
		{Conditions: []Condition{{Attribute: "email", Operator: "ends_with", Value: "@company.com"}}, Variant: "employee", Value: true, Rollout: nil},
	}
	client.SetFlag(ctx, "admin", "ops_flag4", TypeBoolean, false, true, rules)

	detail = client.GetBooleanDetails(ctx, "ops_flag4", false, EvaluationContext{TargetingKey: "u1", Email: "john@company.com"})
	if detail.Value != true || detail.Reason != ReasonTargetingMatch {
		t.Errorf("ends_with failed: %v %s", detail.Value, detail.Reason)
	}

	detail = client.GetBooleanDetails(ctx, "ops_flag4", false, EvaluationContext{TargetingKey: "u2", Email: "john@gmail.com"})
	if detail.Value != false || detail.Reason != ReasonDefault {
		t.Errorf("ends_with non-match failed: %v %s", detail.Value, detail.Reason)
	}
}

func TestCustomAttributes(t *testing.T) {
	store := NewMemoryStore()
	client := NewClient(store)
	ctx := context.Background()

	rules := []Rule{
		{Conditions: []Condition{{Attribute: "custom_field", Operator: "equals", Value: "special"}}, Variant: "custom", Value: true, Rollout: nil},
	}
	client.SetFlag(ctx, "admin", "custom_flag", TypeBoolean, false, true, rules)

	detail := client.GetBooleanDetails(ctx, "custom_flag", false, EvaluationContext{
		TargetingKey: "u1",
		Attributes:   map[string]interface{}{"custom_field": "special"},
	})
	if detail.Value != true || detail.Reason != ReasonTargetingMatch {
		t.Errorf("custom attribute failed: %v %s", detail.Value, detail.Reason)
	}

	detail = client.GetBooleanDetails(ctx, "custom_flag", false, EvaluationContext{
		TargetingKey: "u2",
		Attributes:   map[string]interface{}{"custom_field": "other"},
	})
	if detail.Value != false || detail.Reason != ReasonDefault {
		t.Errorf("custom attribute non-match failed: %v %s", detail.Value, detail.Reason)
	}
}

func TestNeverThrows(t *testing.T) {
	store := NewMemoryStore()
	client := NewClient(store)
	ctx := context.Background()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("evaluation panicked: %v", r)
		}
	}()

	client.GetBooleanDetails(ctx, "unknown", true, EvaluationContext{})

	flag := &Flag{
		Key:          "corrupt",
		Type:         TypeBoolean,
		DefaultValue: json.RawMessage(`false`),
		Enabled:      true,
		Rules:        json.RawMessage(`{ invalid }`),
		UpdatedAt:    time.Now().UTC(),
		UpdatedBy:    "test",
	}
	store.SetFlag(ctx, flag)
	client.GetBooleanDetails(ctx, "corrupt", true, EvaluationContext{})

	flag2 := &Flag{
		Key:          "bool_flag",
		Type:         TypeBoolean,
		DefaultValue: json.RawMessage(`true`),
		Enabled:      true,
		Rules:        json.RawMessage(`[]`),
		UpdatedAt:    time.Now().UTC(),
		UpdatedBy:    "test",
	}
	store.SetFlag(ctx, flag2)
	client.GetStringDetails(ctx, "bool_flag", "default", EvaluationContext{})
}