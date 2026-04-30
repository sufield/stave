package exception

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/profile"
)

func TestDate_MarshalJSON_ZeroValue(t *testing.T) {
	d := Date{}
	data, err := d.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON zero value error: %v", err)
	}
	if string(data) != `""` {
		t.Errorf("zero Date MarshalJSON = %q, want %q", data, `""`)
	}
}

func TestDate_MarshalJSON_NonZero(t *testing.T) {
	d := Date{}
	if err := d.UnmarshalYAML(func(v any) error {
		*(v.(*string)) = "2026-03-28"
		return nil
	}); err != nil {
		t.Fatalf("UnmarshalYAML: %v", err)
	}
	data, err := d.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	want := `"2026-03-28"`
	if string(data) != want {
		t.Errorf("MarshalJSON = %q, want %q", data, want)
	}
}

func TestDate_MarshalJSON_InJSONObject(t *testing.T) {
	type wrapper struct {
		Date Date `json:"date"`
	}
	d := Date{}
	_ = d.UnmarshalYAML(func(v any) error {
		*(v.(*string)) = "2026-01-15"
		return nil
	})
	w := wrapper{Date: d}
	data, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}
	if !strings.Contains(string(data), `"2026-01-15"`) {
		t.Errorf("JSON does not contain expected date: %s", data)
	}
}

func TestDate_UnmarshalYAML_EmptyString(t *testing.T) {
	d := Date{}
	err := d.UnmarshalYAML(func(v any) error {
		*(v.(*string)) = ""
		return nil
	})
	if err != nil {
		t.Fatalf("UnmarshalYAML empty string error: %v", err)
	}
	if !d.IsZero() {
		t.Error("empty string should result in zero time")
	}
}

func TestDate_UnmarshalYAML_RFC3339(t *testing.T) {
	d := Date{}
	err := d.UnmarshalYAML(func(v any) error {
		*(v.(*string)) = "2026-03-28T15:04:05Z"
		return nil
	})
	if err != nil {
		t.Fatalf("UnmarshalYAML RFC3339 error: %v", err)
	}
	if d.IsZero() {
		t.Error("RFC3339 date should not be zero")
	}
	if d.Year() != 2026 {
		t.Errorf("year = %d, want 2026", d.Year())
	}
}

func TestDate_UnmarshalYAML_InvalidFormat(t *testing.T) {
	d := Date{}
	err := d.UnmarshalYAML(func(v any) error {
		*(v.(*string)) = "not-a-date"
		return nil
	})
	if err == nil {
		t.Fatal("expected error for invalid date format")
	}
	if !strings.Contains(err.Error(), "invalid date") {
		t.Errorf("error message = %q, want to contain 'invalid date'", err.Error())
	}
}

func TestDate_String_Zero(t *testing.T) {
	d := Date{}
	if got := d.String(); got != "" {
		t.Errorf("String() for zero date = %q, want empty", got)
	}
}

func TestDate_String_NonZero(t *testing.T) {
	d := Date{}
	_ = d.UnmarshalYAML(func(v any) error {
		*(v.(*string)) = "2026-03-28"
		return nil
	})
	if got := d.String(); got != "2026-03-28" {
		t.Errorf("String() = %q, want 2026-03-28", got)
	}
}

func TestLoadExceptions_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := writeYAML(t, dir, `not: valid: yaml: [`)
	_, err := LoadExceptions(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadExceptions_MissingControlID(t *testing.T) {
	dir := t.TempDir()
	path := writeYAML(t, dir, `
exceptions:
  - bucket: my-bucket
    rationale: "Some reason"
    requires_passing:
      - CONTROLS.001
`)
	_, err := LoadExceptions(path)
	if err == nil {
		t.Fatal("expected error for missing control_id")
	}
	if !strings.Contains(err.Error(), "control_id") {
		t.Errorf("error should mention control_id: %v", err)
	}
}

func TestApplyExceptions_ExceptionForUnknownControl(t *testing.T) {
	// Exception for a control that is not in the results should produce no ack.
	results := []profile.Result{} // empty results
	excs := []Config{{
		ControlID:       "UNKNOWN.001",
		Rationale:       "test",
		RequiresPassing: []kernel.ControlID{"COMP.001"},
	}}
	acks := ApplyExceptions(excs, results, "", time.Time{})
	if len(acks) != 0 {
		t.Errorf("expected 0 acks for unknown control, got %d", len(acks))
	}
}
