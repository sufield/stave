package catalog

import (
	"context"
	"testing"

	"fmt"

	policy "github.com/sufield/stave/internal/core/controldef"
)

type stubProvider struct {
	controls []policy.ControlDefinition
	err      error
}

func (s *stubProvider) Load(_ context.Context) ([]policy.ControlDefinition, error) {
	return s.controls, s.err
}

func sampleControls() []policy.ControlDefinition {
	return []policy.ControlDefinition{
		{
			ID:       "CTL.S3.PUBLIC.001",
			Name:     "Public Read Disabled",
			Type:     policy.TypeUnsafeState,
			Severity: policy.SeverityCritical,
			Domain:   "storage",
		},
		{
			ID:       "CTL.S3.ENCRYPT.001",
			Name:     "At-Rest Encryption",
			Type:     policy.TypeUnsafeState,
			Severity: policy.SeverityHigh,
			Domain:   "encryption",
		},
		{
			ID:       "CTL.S3.LOG.001",
			Name:     "Access Logging",
			Type:     policy.TypeUnsafeDuration,
			Severity: policy.SeverityMedium,
			Domain:   "logging",
		},
	}
}

func TestToRows(t *testing.T) {
	controls := sampleControls()
	rows := ToRows(controls)

	if len(rows) != 3 {
		t.Fatalf("len = %d, want 3", len(rows))
	}
	if rows[0].ID != "CTL.S3.PUBLIC.001" {
		t.Errorf("row[0].ID = %q", rows[0].ID)
	}
	if rows[0].Domain != "storage" {
		t.Errorf("row[0].Domain = %q, want storage", rows[0].Domain)
	}
}

func TestToRows_Empty(t *testing.T) {
	rows := ToRows(nil)
	if len(rows) != 0 {
		t.Errorf("expected empty, got %d rows", len(rows))
	}
}

func TestSortRows(t *testing.T) {
	tests := []struct {
		sortBy    string
		wantFirst string
	}{
		{"id", "CTL.S3.ENCRYPT.001"},
		{"name", "Access Logging"},
		{"domain", "encryption"},
		{"severity", policy.SeverityCritical.String()},
	}

	for _, tt := range tests {
		t.Run(tt.sortBy, func(t *testing.T) {
			rows := ToRows(sampleControls())
			if err := SortRows(rows, tt.sortBy); err != nil {
				t.Fatalf("SortRows error: %v", err)
			}
			var got string
			switch tt.sortBy {
			case "id":
				got = rows[0].ID
			case "name":
				got = rows[0].Name
			case "domain":
				got = rows[0].Domain
			case "severity":
				got = rows[0].Severity
			}
			if got != tt.wantFirst {
				t.Errorf("first row %s = %q, want %q", tt.sortBy, got, tt.wantFirst)
			}
		})
	}
}

func TestSortRows_InvalidColumn(t *testing.T) {
	rows := ToRows(sampleControls())
	if err := SortRows(rows, "nonexistent"); err == nil {
		t.Error("expected error for invalid sort column")
	}
}

func TestParseColumns(t *testing.T) {
	t.Run("valid columns", func(t *testing.T) {
		cols, err := ParseColumns("id,name,type")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cols) != 3 {
			t.Fatalf("len = %d, want 3", len(cols))
		}
		if cols[0] != "id" || cols[1] != "name" || cols[2] != "type" {
			t.Errorf("cols = %v", cols)
		}
	})

	t.Run("deduplicates", func(t *testing.T) {
		cols, err := ParseColumns("id,id,name")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cols) != 2 {
			t.Errorf("len = %d, want 2 (deduped)", len(cols))
		}
	})

	t.Run("normalizes case and whitespace", func(t *testing.T) {
		cols, err := ParseColumns(" ID , Name ")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cols[0] != "id" || cols[1] != "name" {
			t.Errorf("cols = %v", cols)
		}
	})

	t.Run("invalid column", func(t *testing.T) {
		_, err := ParseColumns("id,invalid")
		if err == nil {
			t.Error("expected error for invalid column")
		}
	})

	t.Run("empty string", func(t *testing.T) {
		_, err := ParseColumns("")
		if err == nil {
			t.Error("expected error for empty columns")
		}
	})

	t.Run("all five columns", func(t *testing.T) {
		cols, err := ParseColumns("id,name,type,severity,domain")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cols) != 5 {
			t.Errorf("len = %d, want 5", len(cols))
		}
	})
}

func TestFieldValue(t *testing.T) {
	row := ControlRow{
		ID:       "CTL.001",
		Name:     "Test",
		Type:     "unsafe_state",
		Severity: "critical",
		Domain:   "storage",
	}

	tests := []struct {
		col  string
		want string
	}{
		{"id", "CTL.001"},
		{"name", "Test"},
		{"type", "unsafe_state"},
		{"severity", "critical"},
		{"domain", "storage"},
		{"unknown", ""},
	}

	for _, tt := range tests {
		if got := FieldValue(row, tt.col); got != tt.want {
			t.Errorf("FieldValue(%q) = %q, want %q", tt.col, got, tt.want)
		}
	}
}

func TestListRunner_Run(t *testing.T) {
	provider := &stubProvider{controls: sampleControls()}
	runner := &ListRunner{Provider: provider}

	rows, err := runner.Run(context.Background(), ListConfig{Dir: "controls", SortBy: "id"})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("len = %d, want 3", len(rows))
	}
	// Should be sorted by ID
	if rows[0].ID != "CTL.S3.ENCRYPT.001" {
		t.Errorf("first row ID = %q, want CTL.S3.ENCRYPT.001", rows[0].ID)
	}
}

func TestListRunner_RunError(t *testing.T) {
	provider := &stubProvider{err: fmt.Errorf("not found")}
	runner := &ListRunner{Provider: provider}

	_, err := runner.Run(context.Background(), ListConfig{Dir: "bad", SortBy: "id"})
	if err == nil {
		t.Error("expected error from repo failure")
	}
}
