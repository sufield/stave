package kernel

import (
	"encoding/json"
	"testing"
)

func TestNewSanitizableMap(t *testing.T) {
	m := NewSanitizableMap(map[string]string{"a": "1", "b": "2"})
	if m.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", m.Len())
	}
}

func TestSanitizableMap_SetAndGet(t *testing.T) {
	var m SanitizableMap
	m.Set("key1", "val1")
	got, ok := m.Get("key1")
	if !ok || got != "val1" {
		t.Fatalf("Get(key1) = %q, %v; want %q, true", got, ok, "val1")
	}

	// Missing key.
	_, ok = m.Get("missing")
	if ok {
		t.Error("Get(missing) should return false")
	}
}

func TestSanitizableMap_SetSensitiveAndSanitized(t *testing.T) {
	var m SanitizableMap
	m.SetSensitive("secret", "hunter2")
	m.Set("public", "hello")

	// Raw Get still returns the real value.
	got, ok := m.Get("secret")
	if !ok || got != "hunter2" {
		t.Fatalf("Get(secret) = %q, %v; want %q, true", got, ok, "hunter2")
	}

	// Sanitized returns redacted for sensitive keys.
	if s := m.Sanitized("secret"); s != Redacted {
		t.Errorf("Sanitized(secret) = %q, want %q", s, Redacted)
	}

	// Sanitized returns the value for non-sensitive keys.
	if s := m.Sanitized("public"); s != "hello" {
		t.Errorf("Sanitized(public) = %q, want %q", s, "hello")
	}

	// Sanitized returns empty for missing keys.
	if s := m.Sanitized("missing"); s != "" {
		t.Errorf("Sanitized(missing) = %q, want empty", s)
	}
}

func TestSanitizableMap_Set_ClearsSensitive(t *testing.T) {
	var m SanitizableMap
	m.SetSensitive("key", "secret")
	if s := m.Sanitized("key"); s != Redacted {
		t.Fatalf("expected redacted, got %q", s)
	}

	// Set (non-sensitive) should clear the sensitive flag.
	m.Set("key", "not-secret")
	if s := m.Sanitized("key"); s != "not-secret" {
		t.Errorf("after Set, Sanitized(key) = %q, want %q", s, "not-secret")
	}
}

func TestSanitizableMap_Keys(t *testing.T) {
	m := NewSanitizableMap(map[string]string{"z": "1", "a": "2", "m": "3"})
	keys := m.Keys()
	want := []string{"a", "m", "z"}
	if len(keys) != len(want) {
		t.Fatalf("Keys() length = %d, want %d", len(keys), len(want))
	}
	for i, k := range keys {
		if k != want[i] {
			t.Errorf("Keys()[%d] = %q, want %q", i, k, want[i])
		}
	}
}

func TestSanitizableMap_Keys_Empty(t *testing.T) {
	var m SanitizableMap
	if keys := m.Keys(); keys != nil {
		t.Errorf("Keys() on empty map = %v, want nil", keys)
	}
}

func TestSanitizableMap_Len(t *testing.T) {
	var m SanitizableMap
	if m.Len() != 0 {
		t.Errorf("Len() on zero value = %d, want 0", m.Len())
	}
	m.Set("a", "b")
	if m.Len() != 1 {
		t.Errorf("Len() after one Set = %d, want 1", m.Len())
	}
}

func TestSanitizableMap_Clone(t *testing.T) {
	m := NewSanitizableMap(map[string]string{"a": "1"})
	m.SetSensitive("secret", "x")

	c := m.Clone()

	// Clone should have the same data.
	if got, _ := c.Get("a"); got != "1" {
		t.Errorf("Clone Get(a) = %q, want %q", got, "1")
	}
	if s := c.Sanitized("secret"); s != Redacted {
		t.Errorf("Clone Sanitized(secret) = %q, want %q", s, Redacted)
	}

	// Mutating the clone should not affect the original.
	c.Set("a", "mutated")
	if got, _ := m.Get("a"); got != "1" {
		t.Error("mutation of clone affected original")
	}
}

func TestSanitizableMap_MarshalJSON(t *testing.T) {
	t.Run("empty map", func(t *testing.T) {
		var m SanitizableMap
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("MarshalJSON error: %v", err)
		}
		if string(data) != "{}" {
			t.Errorf("got %s, want {}", data)
		}
	})

	t.Run("no sensitive keys", func(t *testing.T) {
		m := NewSanitizableMap(map[string]string{"key": "val"})
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("MarshalJSON error: %v", err)
		}
		var decoded map[string]string
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if decoded["key"] != "val" {
			t.Errorf("key = %q, want %q", decoded["key"], "val")
		}
	})

	t.Run("with sensitive keys", func(t *testing.T) {
		m := NewSanitizableMap(map[string]string{"public": "hello"})
		m.SetSensitive("secret", "hunter2")
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("MarshalJSON error: %v", err)
		}
		var decoded map[string]string
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if decoded["secret"] != Redacted {
			t.Errorf("secret = %q, want %q", decoded["secret"], Redacted)
		}
		if decoded["public"] != "hello" {
			t.Errorf("public = %q, want %q", decoded["public"], "hello")
		}
	})
}

func TestSanitizableMap_UnmarshalJSON(t *testing.T) {
	input := `{"a":"1","b":"2"}`
	var m SanitizableMap
	if err := json.Unmarshal([]byte(input), &m); err != nil {
		t.Fatalf("UnmarshalJSON error: %v", err)
	}
	if m.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", m.Len())
	}
	got, ok := m.Get("a")
	if !ok || got != "1" {
		t.Errorf("Get(a) = %q, %v; want %q, true", got, ok, "1")
	}

	// After unmarshal, all keys are non-sensitive.
	if s := m.Sanitized("a"); s != "1" {
		t.Errorf("Sanitized(a) = %q, want %q (non-sensitive after unmarshal)", s, "1")
	}
}

func TestSanitizableMap_UnmarshalJSON_Error(t *testing.T) {
	var m SanitizableMap
	if err := json.Unmarshal([]byte(`not json`), &m); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestSanitizableMap_EnsureInit(t *testing.T) {
	// Test that operations on zero-value map don't panic.
	var m SanitizableMap
	m.Set("a", "1")
	m.SetSensitive("b", "2")
	if m.Len() != 2 {
		t.Errorf("Len() = %d, want 2", m.Len())
	}
}
