package observations

import (
	"testing"
)

func TestNormalizeProperties_BooleanStrings(t *testing.T) {
	m := map[string]any{
		"enabled":  "true",
		"disabled": "false",
		"upper":    "TRUE",
		"mixed":    "False",
		"padded":   "  true  ",
	}
	normalizeProperties(m)

	for _, tc := range []struct {
		key  string
		want bool
	}{
		{"enabled", true},
		{"disabled", false},
		{"upper", true},
		{"mixed", false},
		{"padded", true},
	} {
		got, ok := m[tc.key].(bool)
		if !ok {
			t.Errorf("%s: expected bool, got %T (%v)", tc.key, m[tc.key], m[tc.key])
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.key, got, tc.want)
		}
	}
}

func TestNormalizeProperties_NumericStrings(t *testing.T) {
	m := map[string]any{
		"count":    "42",
		"fraction": "3.14",
		"negative": "-1",
		"zero":     "0",
		"padded":   "  100  ",
	}
	normalizeProperties(m)

	for _, tc := range []struct {
		key  string
		want float64
	}{
		{"count", 42},
		{"fraction", 3.14},
		{"negative", -1},
		{"zero", 0},
		{"padded", 100},
	} {
		got, ok := m[tc.key].(float64)
		if !ok {
			t.Errorf("%s: expected float64, got %T (%v)", tc.key, m[tc.key], m[tc.key])
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.key, got, tc.want)
		}
	}
}

func TestNormalizeProperties_PreservesNonStringTypes(t *testing.T) {
	m := map[string]any{
		"already_bool":  true,
		"already_float": 3.14,
		"already_nil":   nil,
		"already_int":   42, // unlikely from JSON but possible from test fixtures
	}
	normalizeProperties(m)

	if m["already_bool"] != true {
		t.Errorf("already_bool changed: %v", m["already_bool"])
	}
	if m["already_float"] != 3.14 {
		t.Errorf("already_float changed: %v", m["already_float"])
	}
	if m["already_nil"] != nil {
		t.Errorf("already_nil changed: %v", m["already_nil"])
	}
	if m["already_int"] != 42 {
		t.Errorf("already_int changed: %v", m["already_int"])
	}
}

func TestNormalizeProperties_NestedMaps(t *testing.T) {
	m := map[string]any{
		"block_public_access": map[string]any{
			"block_public_acls":       "true",
			"ignore_public_acls":      "false",
			"restrict_public_buckets": "true",
			"block_public_policy":     "true",
		},
		"versioning": map[string]any{
			"status":     "Enabled",
			"mfa_delete": "false",
		},
	}
	normalizeProperties(m)

	bpa := m["block_public_access"].(map[string]any)
	if bpa["block_public_acls"] != true {
		t.Errorf("nested bool not coerced: %v (%T)", bpa["block_public_acls"], bpa["block_public_acls"])
	}
	if bpa["ignore_public_acls"] != false {
		t.Errorf("nested bool not coerced: %v", bpa["ignore_public_acls"])
	}

	ver := m["versioning"].(map[string]any)
	if ver["status"] != "Enabled" {
		t.Errorf("non-boolean string should be preserved: %v", ver["status"])
	}
	if ver["mfa_delete"] != false {
		t.Errorf("nested bool not coerced: %v", ver["mfa_delete"])
	}
}

func TestNormalizeProperties_Slices(t *testing.T) {
	m := map[string]any{
		"tags": []any{"true", "false", "hello", "42"},
	}
	normalizeProperties(m)

	tags := m["tags"].([]any)
	if tags[0] != true {
		t.Errorf("slice[0]: expected true, got %v (%T)", tags[0], tags[0])
	}
	if tags[1] != false {
		t.Errorf("slice[1]: expected false, got %v (%T)", tags[1], tags[1])
	}
	if tags[2] != "hello" {
		t.Errorf("slice[2]: expected 'hello', got %v", tags[2])
	}
	if tags[3] != float64(42) {
		t.Errorf("slice[3]: expected 42.0, got %v (%T)", tags[3], tags[3])
	}
}

func TestNormalizeProperties_PreservesNonNumericStrings(t *testing.T) {
	m := map[string]any{
		"bucket_name": "s3://my-bucket",
		"arn":         "arn:aws:s3:::my-bucket",
		"empty":       "",
		"whitespace":  "   ",
		"hex":         "0xFF",
		"octal":       "0o777",
		"binary":      "0b1010",
		"region":      "us-east-1",
	}
	normalizeProperties(m)

	for key, want := range map[string]string{
		"bucket_name": "s3://my-bucket",
		"arn":         "arn:aws:s3:::my-bucket",
		"empty":       "",
		"whitespace":  "   ",
		"hex":         "0xFF",
		"octal":       "0o777",
		"binary":      "0b1010",
		"region":      "us-east-1",
	} {
		got, ok := m[key].(string)
		if !ok {
			t.Errorf("%s: expected string, got %T (%v)", key, m[key], m[key])
			continue
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", key, got, want)
		}
	}
}

func TestNormalizeProperties_Idempotent(t *testing.T) {
	m := map[string]any{
		"enabled": "true",
		"count":   "42",
		"name":    "test",
		"nested": map[string]any{
			"flag": "false",
		},
	}

	normalizeProperties(m)
	// Run again — should produce identical result
	normalizeProperties(m)

	if m["enabled"] != true {
		t.Errorf("enabled: %v (%T)", m["enabled"], m["enabled"])
	}
	if m["count"] != float64(42) {
		t.Errorf("count: %v (%T)", m["count"], m["count"])
	}
	if m["name"] != "test" {
		t.Errorf("name: %v", m["name"])
	}
	nested := m["nested"].(map[string]any)
	if nested["flag"] != false {
		t.Errorf("nested.flag: %v (%T)", nested["flag"], nested["flag"])
	}
}

func TestNormalizeProperties_EmptyMap(t *testing.T) {
	m := map[string]any{}
	normalizeProperties(m) // should not panic
	if len(m) != 0 {
		t.Errorf("empty map should stay empty")
	}
}
