package securityaudit

import (
	"testing"

	"github.com/sufield/stave/internal/core/outcome"
)

func TestAllReportFormats(t *testing.T) {
	formats := AllReportFormats()
	if len(formats) != 3 {
		t.Fatalf("AllReportFormats() len=%d, want 3", len(formats))
	}
	want := []string{"json", "markdown", "sarif"}
	for i, f := range formats {
		if f != want[i] {
			t.Fatalf("AllReportFormats()[%d]=%q, want %q", i, f, want[i])
		}
	}
}

func TestStatus_String(t *testing.T) {
	tests := []struct {
		s    outcome.Status
		want string
	}{
		{outcome.Pass, "PASS"},
		{outcome.Warn, "WARN"},
		{outcome.Fail, "FAIL"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Fatalf("Status(%q).String()=%q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestCheckID_String(t *testing.T) {
	if got := CheckBuildInfoPresent.String(); got != "SC.BUILDINFO.PRESENT" {
		t.Fatalf("got %q", got)
	}
}

func TestAllCheckIDs(t *testing.T) {
	ids := AllCheckIDs()
	if len(ids) == 0 {
		t.Fatal("AllCheckIDs() returned empty")
	}
	if len(ids) != len(allChecks) {
		t.Fatalf("len=%d, want %d", len(ids), len(allChecks))
	}
	// Verify defensive copy: mutating returned slice should not affect internal registry.
	ids[0] = "MUTATED"
	fresh := AllCheckIDs()
	if fresh[0] == "MUTATED" {
		t.Fatal("AllCheckIDs did not return a defensive copy")
	}
}
