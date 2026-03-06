package domain

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sufield/stave/internal/domain/kernel"
)

func TestNewSanitizableMap(t *testing.T) {
	m := kernel.NewSanitizableMap(map[string]string{"a": "1", "b": "2"})
	if m.Len() != 2 {
		t.Errorf("Len() = %d, want 2", m.Len())
	}
	if v, ok := m.Get("a"); !ok || v != "1" {
		t.Errorf("Get(a) = (%q, %v), want (\"1\", true)", v, ok)
	}
}

func TestSanitizableMap_SetAndGet(t *testing.T) {
	var m kernel.SanitizableMap
	m.Set("key", "value")

	v, ok := m.Get("key")
	if !ok || v != "value" {
		t.Errorf("Get(key) = (%q, %v), want (\"value\", true)", v, ok)
	}
}

func TestSanitizableMap_SetSensitive(t *testing.T) {
	m := kernel.NewSanitizableMap(map[string]string{"public": "data"})
	m.SetSensitive("secret", "hunter2")

	// Get always returns raw
	if v, _ := m.Get("secret"); v != "hunter2" {
		t.Errorf("Get(secret) = %q, want \"hunter2\"", v)
	}

	// Sanitized sanitizes sensitive keys
	if got := m.Sanitized("secret"); got != kernel.SanitizedValue {
		t.Errorf("Sanitized(secret) = %q, want %q", got, kernel.SanitizedValue)
	}

	// Non-sensitive keys pass through
	if got := m.Sanitized("public"); got != "data" {
		t.Errorf("Sanitized(public) = %q, want \"data\"", got)
	}
}

func TestSanitizableMap_Keys_Sorted(t *testing.T) {
	m := kernel.NewSanitizableMap(map[string]string{"c": "3", "a": "1", "b": "2"})
	keys := m.Keys()
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("Keys() = %v, want %v", keys, want)
	}
}

func TestSanitizableMap_MarshalJSON(t *testing.T) {
	m := kernel.NewSanitizableMap(map[string]string{"public": "data"})
	m.SetSensitive("secret", "hunter2")

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}

	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if raw["public"] != "data" {
		t.Errorf("public = %q, want \"data\"", raw["public"])
	}
	if raw["secret"] != kernel.SanitizedValue {
		t.Errorf("secret = %q, want %q", raw["secret"], kernel.SanitizedValue)
	}
}

func TestSanitizableMap_MarshalJSON_Empty(t *testing.T) {
	var m kernel.SanitizableMap
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	if string(data) != "{}" {
		t.Errorf("empty MarshalJSON() = %s, want {}", data)
	}
}

func TestSanitizableMap_UnmarshalJSON(t *testing.T) {
	input := `{"key":"value","other":"data"}`
	var m kernel.SanitizableMap
	if err := json.Unmarshal([]byte(input), &m); err != nil {
		t.Fatalf("UnmarshalJSON error: %v", err)
	}

	if v, ok := m.Get("key"); !ok || v != "value" {
		t.Errorf("Get(key) = (%q, %v), want (\"value\", true)", v, ok)
	}

	// Deserialized keys are non-sensitive
	if got := m.Sanitized("key"); got != "value" {
		t.Errorf("Sanitized(key) after unmarshal = %q, want \"value\"", got)
	}
}

func TestSanitizableMap_JSONRoundTrip(t *testing.T) {
	original := kernel.NewSanitizableMap(map[string]string{
		"control_id": "CTL.EXP.STATE.001",
		"asset_id":   "arn:aws:s3:::bucket",
	})

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	// Compare with plain map marshal
	plainData, err := json.Marshal(map[string]string{
		"control_id": "CTL.EXP.STATE.001",
		"asset_id":   "arn:aws:s3:::bucket",
	})
	if err != nil {
		t.Fatalf("Marshal plain error: %v", err)
	}

	// Both should unmarshal to the same thing
	var fromRedactable, fromPlain map[string]string
	if err := json.Unmarshal(data, &fromRedactable); err != nil {
		t.Fatalf("Unmarshal redactable error: %v", err)
	}
	if err := json.Unmarshal(plainData, &fromPlain); err != nil {
		t.Fatalf("Unmarshal plain error: %v", err)
	}

	if !reflect.DeepEqual(fromRedactable, fromPlain) {
		t.Errorf("round-trip mismatch: redactable=%v, plain=%v", fromRedactable, fromPlain)
	}
}

func TestSanitizableMap_ZeroValue(t *testing.T) {
	var m kernel.SanitizableMap

	// Zero value should work without panics
	if m.Len() != 0 {
		t.Errorf("Len() = %d, want 0", m.Len())
	}
	if _, ok := m.Get("any"); ok {
		t.Error("Get on zero value should return false")
	}
	if got := m.Sanitized("any"); got != "" {
		t.Errorf("Sanitized on zero value = %q, want empty", got)
	}
	if keys := m.Keys(); keys != nil {
		t.Errorf("Keys on zero value = %v, want nil", keys)
	}
}

func TestSanitizableMap_MarshalJSON_Deterministic(t *testing.T) {
	// Build a map with multiple keys; marshal 100 times and verify byte-identical output.
	m := kernel.NewSanitizableMap(map[string]string{
		"z_last":  "val-z",
		"a_first": "val-a",
		"m_mid":   "val-m",
	})
	m.SetSensitive("secret", "hunter2")

	first, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("first marshal: %v", err)
	}
	// Verify key order is alphabetical in the raw JSON
	want := `{"a_first":"val-a","m_mid":"val-m","secret":"[SANITIZED]","z_last":"val-z"}`
	if string(first) != want {
		t.Fatalf("unexpected JSON:\ngot:  %s\nwant: %s", first, want)
	}
	for i := range 100 {
		got, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal iteration %d: %v", i, err)
		}
		if string(got) != string(first) {
			t.Fatalf("nondeterministic at iteration %d:\nfirst: %s\ngot:   %s", i, first, got)
		}
	}
}

func TestSanitizableMap_Clone_IsolatedCopy(t *testing.T) {
	original := kernel.NewSanitizableMap(map[string]string{
		"public": "value",
	})
	original.SetSensitive("secret", "hunter2")

	cloned := original.Clone()
	cloned.Set("public", "updated")
	cloned.SetSensitive("secret", "changed")
	cloned.Set("new_key", "new_value")

	if got, _ := original.Get("public"); got != "value" {
		t.Fatalf("original public = %q, want value", got)
	}
	if got, _ := original.Get("secret"); got != "hunter2" {
		t.Fatalf("original secret = %q, want hunter2", got)
	}
	if _, ok := original.Get("new_key"); ok {
		t.Fatal("original unexpectedly contains new_key after clone mutation")
	}
	if got := original.Sanitized("secret"); got != kernel.SanitizedValue {
		t.Fatalf("original sanitized secret = %q, want %q", got, kernel.SanitizedValue)
	}
}
