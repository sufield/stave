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

func (s *stubProvider) Fetch(_ context.Context) ([]policy.ControlDefinition, error) {
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

func TestSummarizePolicies(t *testing.T) {
	controls := sampleControls()
	rows := SummarizePolicies(controls)

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

func TestSummarizePolicies_Empty(t *testing.T) {
	rows := SummarizePolicies(nil)
	if len(rows) != 0 {
		t.Errorf("expected empty, got %d rows", len(rows))
	}
}

func TestOrderEntries(t *testing.T) {
	tests := []struct {
		sortBy    string
		wantFirst string
	}{
		{"id", "CTL.S3.ENCRYPT.001"},
		{"name", "Access Logging"},
		{"domain", "encryption"},
		{"risk", policy.SeverityCritical.String()},
	}

	for _, tt := range tests {
		t.Run(tt.sortBy, func(t *testing.T) {
			rows := SummarizePolicies(sampleControls())
			if err := OrderEntries(rows, tt.sortBy); err != nil {
				t.Fatalf("OrderEntries error: %v", err)
			}
			var got string
			switch tt.sortBy {
			case "id":
				got = rows[0].ID
			case "name":
				got = rows[0].Name
			case "domain":
				got = rows[0].Domain
			case "risk":
				got = rows[0].Risk
			}
			if got != tt.wantFirst {
				t.Errorf("first row %s = %q, want %q", tt.sortBy, got, tt.wantFirst)
			}
		})
	}
}

func TestOrderEntries_InvalidColumn(t *testing.T) {
	rows := SummarizePolicies(sampleControls())
	if err := OrderEntries(rows, "nonexistent"); err == nil {
		t.Error("expected error for invalid sort column")
	}
}

func TestSelectFields(t *testing.T) {
	t.Run("valid columns", func(t *testing.T) {
		cols, err := SelectFields("id,name,type")
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
		cols, err := SelectFields("id,id,name")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cols) != 2 {
			t.Errorf("len = %d, want 2 (deduped)", len(cols))
		}
	})

	t.Run("normalizes case and whitespace", func(t *testing.T) {
		cols, err := SelectFields(" ID , Name ")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cols[0] != "id" || cols[1] != "name" {
			t.Errorf("cols = %v", cols)
		}
	})

	t.Run("invalid column", func(t *testing.T) {
		_, err := SelectFields("id,invalid")
		if err == nil {
			t.Error("expected error for invalid column")
		}
	})

	t.Run("empty string", func(t *testing.T) {
		_, err := SelectFields("")
		if err == nil {
			t.Error("expected error for empty columns")
		}
	})

	t.Run("all five columns", func(t *testing.T) {
		cols, err := SelectFields("id,name,type,risk,domain")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cols) != 5 {
			t.Errorf("len = %d, want 5", len(cols))
		}
	})
}

func TestGetAttribute(t *testing.T) {
	row := PolicyEntry{
		ID:     "CTL.001",
		Name:   "Test",
		Type:   "unsafe_state",
		Risk:   "critical",
		Domain: "storage",
	}

	tests := []struct {
		col  string
		want string
	}{
		{"id", "CTL.001"},
		{"name", "Test"},
		{"type", "unsafe_state"},
		{"risk", "critical"},
		{"domain", "storage"},
		{"unknown", ""},
	}

	for _, tt := range tests {
		if got := GetAttribute(row, tt.col); got != tt.want {
			t.Errorf("GetAttribute(%q) = %q, want %q", tt.col, got, tt.want)
		}
	}
}

func TestCatalogBrowser_Browse(t *testing.T) {
	provider := &stubProvider{controls: sampleControls()}
	runner := &CatalogBrowser{Provider: provider}

	rows, err := runner.Browse(context.Background(), DiscoveryRequest{PolicySource: "controls", OrderBy: "id"})
	if err != nil {
		t.Fatalf("Browse error: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("len = %d, want 3", len(rows))
	}
	// Should be sorted by ID
	if rows[0].ID != "CTL.S3.ENCRYPT.001" {
		t.Errorf("first row ID = %q, want CTL.S3.ENCRYPT.001", rows[0].ID)
	}
}

func TestCatalogBrowser_BrowseError(t *testing.T) {
	provider := &stubProvider{err: fmt.Errorf("not found")}
	runner := &CatalogBrowser{Provider: provider}

	_, err := runner.Browse(context.Background(), DiscoveryRequest{PolicySource: "bad", OrderBy: "id"})
	if err == nil {
		t.Error("expected error from repo failure")
	}
}
