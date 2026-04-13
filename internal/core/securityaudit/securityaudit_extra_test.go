package securityaudit

import (
	"strings"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
)

func TestDisplayFailOn(t *testing.T) {
	tests := []struct {
		failOn policy.Severity
		want   string
	}{
		{policy.SeverityCritical, "CRITICAL"},
		{policy.SeverityHigh, "HIGH"},
		{policy.SeverityMedium, "MEDIUM"},
		{policy.SeverityLow, "LOW"},
		// SeverityNone has an empty String() so DisplayFailOn returns "".
		{policy.SeverityNone, ""},
	}
	for _, tt := range tests {
		name := tt.failOn.String()
		if name == "" {
			name = "none"
		}
		t.Run(name, func(t *testing.T) {
			g := GatingInfo{FailOn: tt.failOn}
			got := g.DisplayFailOn()
			if got != tt.want {
				t.Errorf("DisplayFailOn() = %q, want %q", got, tt.want)
			}
			// Non-empty result must be all uppercase.
			if got != "" && got != strings.ToUpper(got) {
				t.Errorf("DisplayFailOn() %q is not uppercase", got)
			}
		})
	}
}

func TestParseSeverityList_Empty(t *testing.T) {
	sevs, err := ParseSeverityList("")
	if err != nil {
		t.Fatalf("ParseSeverityList(\"\") error: %v", err)
	}
	if len(sevs) != 2 {
		t.Fatalf("empty input should return [CRITICAL, HIGH], got %v", sevs)
	}
	if sevs[0] != policy.SeverityCritical {
		t.Errorf("sevs[0] = %q, want CRITICAL", sevs[0])
	}
	if sevs[1] != policy.SeverityHigh {
		t.Errorf("sevs[1] = %q, want HIGH", sevs[1])
	}
}

func TestParseSeverityList_Whitespace(t *testing.T) {
	sevs, err := ParseSeverityList("   ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sevs) != 2 {
		t.Fatalf("whitespace-only input should return default [CRITICAL, HIGH], got %v", sevs)
	}
}

func TestParseSeverityList_Single(t *testing.T) {
	sevs, err := ParseSeverityList("critical")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sevs) != 1 || sevs[0] != policy.SeverityCritical {
		t.Fatalf("got %v, want [CRITICAL]", sevs)
	}
}

func TestParseSeverityList_Multiple(t *testing.T) {
	sevs, err := ParseSeverityList("critical,high,medium")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sevs) != 3 {
		t.Fatalf("expected 3 severities, got %d: %v", len(sevs), sevs)
	}
	if sevs[0] != policy.SeverityCritical || sevs[1] != policy.SeverityHigh || sevs[2] != policy.SeverityMedium {
		t.Errorf("unexpected order: %v", sevs)
	}
}

func TestParseSeverityList_Deduplicates(t *testing.T) {
	sevs, err := ParseSeverityList("critical,high,critical")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sevs) != 2 {
		t.Fatalf("expected 2 unique severities, got %d: %v", len(sevs), sevs)
	}
}

func TestParseSeverityList_Invalid(t *testing.T) {
	_, err := ParseSeverityList("invalid_severity")
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

func TestParseSeverityList_MixedCase(t *testing.T) {
	sevs, err := ParseSeverityList("CRITICAL,high,Medium")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sevs) != 3 {
		t.Fatalf("expected 3 severities, got %v", sevs)
	}
}
