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

func TestNormalizeValue_TableDriven(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want any
	}{
		// Booleans
		{"true lowercase", "true", true},
		{"false lowercase", "false", false},
		{"TRUE uppercase", "TRUE", true},
		{"FALSE uppercase", "FALSE", false},
		{"true padded", "  true  ", true},
		{"false padded", " false ", false},
		{"true trailing space", "true ", true},

		// Numbers — standard
		{"integer", "42", float64(42)},
		{"negative integer", "-1", float64(-1)},
		{"zero", "0", float64(0)},
		{"decimal", "3.14", float64(3.14)},
		{"negative decimal", "-0.5", float64(-0.5)},
		{"padded number", "  100  ", float64(100)},

		// Numbers — scientific notation
		{"scientific 1e10", "1e10", float64(1e10)},
		{"scientific 2.5E3", "2.5E3", float64(2.5e3)},
		{"scientific negative", "-1.5e-3", float64(-1.5e-3)},

		// Numbers — leading zero (JSON-style, not octal)
		{"leading zero 08", "08", float64(8)},
		{"leading zero 007", "007", float64(7)},
		{"dot prefix", ".5", float64(0.5)},

		// Strings preserved — not numeric
		{"s3 uri", "s3://my-bucket", "s3://my-bucket"},
		{"arn", "arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket"},
		{"region", "us-east-1", "us-east-1"},
		{"empty", "", ""},
		{"whitespace only", "   ", "   "},
		{"hex rejected", "0xFF", "0xFF"},
		{"octal rejected", "0o777", "0o777"},
		{"binary rejected", "0b1010", "0b1010"},
		{"version string", "v1.2.3", "v1.2.3"},
		{"uuid", "550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440000"},
		{"ip address", "192.168.1.1", "192.168.1.1"},
		{"date", "2026-01-15", "2026-01-15"},
		{"mixed text", "bucket-42-prod", "bucket-42-prod"},

		// Already typed — pass through
		{"already bool true", true, true},
		{"already bool false", false, false},
		{"already float64", float64(3.14), float64(3.14)},
		{"already int", 42, 42},
		{"nil preserved", nil, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeValue(tc.in)
			if got != tc.want {
				t.Errorf("normalizeValue(%v [%T]) = %v [%T], want %v [%T]",
					tc.in, tc.in, got, got, tc.want, tc.want)
			}
		})
	}
}

func TestNormalizeValue_DeepNesting(t *testing.T) {
	// 4 levels deep — ensures recursion works correctly
	m := map[string]any{
		"l1": map[string]any{
			"l2": map[string]any{
				"l3": map[string]any{
					"flag":  "true",
					"count": "99",
					"name":  "deep",
				},
			},
		},
	}
	normalizeProperties(m)

	deep := m["l1"].(map[string]any)["l2"].(map[string]any)["l3"].(map[string]any)
	if deep["flag"] != true {
		t.Errorf("deep flag: got %v (%T), want true", deep["flag"], deep["flag"])
	}
	if deep["count"] != float64(99) {
		t.Errorf("deep count: got %v (%T), want 99", deep["count"], deep["count"])
	}
	if deep["name"] != "deep" {
		t.Errorf("deep name: got %v, want 'deep'", deep["name"])
	}
}

func TestNormalizeValue_SliceOfMaps(t *testing.T) {
	m := map[string]any{
		"items": []any{
			map[string]any{"enabled": "true", "count": "5"},
			map[string]any{"enabled": "false", "count": "0"},
		},
	}
	normalizeProperties(m)

	items := m["items"].([]any)
	first := items[0].(map[string]any)
	if first["enabled"] != true {
		t.Errorf("items[0].enabled: got %v (%T)", first["enabled"], first["enabled"])
	}
	if first["count"] != float64(5) {
		t.Errorf("items[0].count: got %v (%T)", first["count"], first["count"])
	}
	second := items[1].(map[string]any)
	if second["enabled"] != false {
		t.Errorf("items[1].enabled: got %v (%T)", second["enabled"], second["enabled"])
	}
}

func TestIsNumericCandidate_EdgeCases(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"", false},
		{"0", true},
		{"-1", true},
		{".5", true},
		{"0xFF", false},
		{"0o777", false},
		{"0b1010", false},
		{"0X1A", false},
		{"0O755", false},
		{"0B1111", false},
		{"42", true},
		{"3.14", true},
		{"-0.5", true},
		{"1e10", true},
		{"abc", false},
		{"s3://bucket", false},
		{"us-east-1", false},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := isNumericCandidate(tc.input)
			if got != tc.want {
				t.Errorf("isNumericCandidate(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
