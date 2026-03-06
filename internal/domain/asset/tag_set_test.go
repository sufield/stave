package asset

import "testing"

func TestTagSetMatches(t *testing.T) {
	ts := NewTagSet(map[string]string{
		"environment": " Production ",
		"empty":       "   ",
	})

	if !ts.Matches(" environment ", nil) {
		t.Fatalf("expected key match when allowed values are empty")
	}

	if !ts.Matches("environment", map[string]struct{}{"production": {}}) {
		t.Fatalf("expected normalized value match")
	}

	if ts.Matches("environment", map[string]struct{}{"dev": {}}) {
		t.Fatalf("expected mismatch for non-allowed value")
	}

	if ts.Matches("empty", nil) {
		t.Fatalf("expected empty normalized value to be ignored")
	}

	if ts.Matches("missing", nil) {
		t.Fatalf("expected missing key not to match")
	}
}

func TestNewTagSetCopiesInput(t *testing.T) {
	raw := map[string]string{"env": "prod"}
	ts := NewTagSet(raw)

	raw["env"] = "dev"

	if !ts.Matches("env", map[string]struct{}{"prod": {}}) {
		t.Fatalf("expected tag set to be independent from source map mutation")
	}
	if ts.Matches("env", map[string]struct{}{"dev": {}}) {
		t.Fatalf("expected copied tag set to retain original value")
	}
}

func TestTagSetCaseInsensitiveKeysAndConflictDetection(t *testing.T) {
	ts := NewTagSet(map[string]string{
		"Owner": "security",
		"owner": "platform",
		"Env":   "prod",
	})

	if !ts.HasConflicts() {
		t.Fatalf("expected case-insensitive key conflict to be detected")
	}

	conflicts := ts.Conflicts()
	if len(conflicts) != 1 || conflicts[0] != "owner" {
		t.Fatalf("conflicts = %v, want [owner]", conflicts)
	}

	// Conflict detection should not break case-insensitive matching.
	if !ts.Matches("OWNER", nil) {
		t.Fatalf("expected case-insensitive key lookup to match")
	}
}

func TestTagSetConflictsReturnsCopy(t *testing.T) {
	ts := NewTagSet(map[string]string{
		"Env": "prod",
		"env": "dev",
	})

	conflicts := ts.Conflicts()
	if len(conflicts) == 0 {
		t.Fatalf("expected conflicts")
	}
	conflicts[0] = "mutated"

	got := ts.Conflicts()
	if got[0] != "env" {
		t.Fatalf("expected immutable conflict output, got %v", got)
	}
}

func TestResourceHasTagMatchDelegatesToTagSet(t *testing.T) {
	r := Asset{
		ID: "r1",
		Properties: map[string]any{
			"storage": map[string]any{
				"tags": map[string]any{
					" Environment ": " Production ",
					"":              "ignored",
					"num":           123,
				},
			},
		},
	}

	if !r.HasTagMatch("environment", map[string]struct{}{"production": {}}) {
		t.Fatalf("expected normalized key/value tag match")
	}
	if r.HasTagMatch("environment", map[string]struct{}{"dev": {}}) {
		t.Fatalf("expected mismatch for non-allowed tag value")
	}
	if r.HasTagMatch("missing", nil) {
		t.Fatalf("expected missing tag key not to match")
	}
}
