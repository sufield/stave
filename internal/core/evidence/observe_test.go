package evidence

import (
	"strings"
	"testing"
)

func neverSensitive(string) bool { return false }

// sensitiveTokens mimics the real isSensitiveKey logic: splits on _ and
// checks each segment against known sensitive tokens.
func sensitiveTokens(key string) bool {
	tokens := strings.FieldsFunc(key, func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == ':'
	})
	for _, t := range tokens {
		switch t {
		case "secret", "password", "token", "credential", "auth":
			return true
		}
	}
	return false
}

func TestExtractObservationProperties_HappyPath(t *testing.T) {
	props := map[string]any{
		"enabled":    true,
		"bucket_acl": "private",
	}
	fields := []string{"enabled", "bucket_acl"}

	got := ExtractObservationProperties(props, fields, neverSensitive)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	// Sorted: bucket_acl < enabled
	if got[0].Field != "bucket_acl" || got[0].Value != "private" {
		t.Errorf("got[0] = %+v", got[0])
	}
	if got[1].Field != "enabled" || got[1].Value != "true" {
		t.Errorf("got[1] = %+v", got[1])
	}
}

func TestExtractObservationProperties_NestedPath(t *testing.T) {
	props := map[string]any{
		"storage": map[string]any{
			"access": map[string]any{
				"public_read": false,
			},
		},
	}
	fields := []string{"storage.access.public_read"}

	got := ExtractObservationProperties(props, fields, neverSensitive)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Value != "false" {
		t.Errorf("Value = %q, want %q", got[0].Value, "false")
	}
}

func TestExtractObservationProperties_MissingField(t *testing.T) {
	props := map[string]any{"enabled": true}
	fields := []string{"nonexistent", "also.missing"}

	got := ExtractObservationProperties(props, fields, neverSensitive)
	if len(got) != 0 {
		t.Errorf("len = %d, want 0 for missing fields", len(got))
	}
}

func TestExtractObservationProperties_SensitiveRedaction(t *testing.T) {
	props := map[string]any{
		"db_password": "hunter2",
		"region":      "us-east-1",
	}
	fields := []string{"db_password", "region"}

	got := ExtractObservationProperties(props, fields, sensitiveTokens)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	// Sorted: db_password < region
	if got[0].Field != "db_password" || got[0].Value != RedactedValue {
		t.Errorf("expected redacted db_password, got %+v", got[0])
	}
	if got[1].Field != "region" || got[1].Value != "us-east-1" {
		t.Errorf("expected plain region, got %+v", got[1])
	}
}

func TestExtractObservationProperties_NestedSensitivePath(t *testing.T) {
	props := map[string]any{
		"auth": map[string]any{
			"secret": "abc123",
		},
	}
	fields := []string{"auth.secret"}

	got := ExtractObservationProperties(props, fields, sensitiveTokens)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Value != RedactedValue {
		t.Errorf("expected redacted, got %q", got[0].Value)
	}
}

func TestExtractObservationProperties_NilInputs(t *testing.T) {
	if got := ExtractObservationProperties(nil, []string{"a"}, neverSensitive); got != nil {
		t.Errorf("nil properties: got %v, want nil", got)
	}
	if got := ExtractObservationProperties(map[string]any{"a": 1}, nil, neverSensitive); got != nil {
		t.Errorf("nil fields: got %v, want nil", got)
	}
	if got := ExtractObservationProperties(map[string]any{"a": 1}, []string{}, neverSensitive); got != nil {
		t.Errorf("empty fields: got %v, want nil", got)
	}
}

func TestExtractObservationProperties_NilSensitiveCallback(t *testing.T) {
	props := map[string]any{"secret": "value"}
	got := ExtractObservationProperties(props, []string{"secret"}, nil)
	if len(got) != 1 || got[0].Value != "value" {
		t.Errorf("nil callback should not redact: got %+v", got)
	}
}
