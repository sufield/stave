package builtin

import (
	"testing"

	"github.com/sufield/stave/internal/domain/policy"
)

func TestParseSelector(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantTags []string
		wantSev  policy.Severity
		wantErr  bool
	}{
		{"simple tags", "aws/s3", []string{"aws", "s3"}, policy.SeverityNone, false},
		{"single tag", "aws", []string{"aws"}, policy.SeverityNone, false},
		{"with severity", "aws/s3/severity:high+", []string{"aws", "s3"}, policy.SeverityHigh, false},
		{"severity only", "severity:critical+", nil, policy.SeverityCritical, false},
		{"empty", "", nil, policy.SeverityNone, true},
		{"invalid severity", "severity:extreme+", nil, policy.SeverityNone, true},
		{"case insensitive", "AWS/S3/severity:HIGH+", []string{"aws", "s3"}, policy.SeverityHigh, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sel, err := ParseSelector(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(sel.Tags) != len(tt.wantTags) {
				t.Fatalf("scope_tags: got %v, want %v", sel.Tags, tt.wantTags)
			}
			for i := range tt.wantTags {
				if sel.Tags[i] != tt.wantTags[i] {
					t.Errorf("scope_tags[%d]: got %q, want %q", i, sel.Tags[i], tt.wantTags[i])
				}
			}
			if sel.MinSeverity != tt.wantSev {
				t.Errorf("min_severity: got %v, want %v", sel.MinSeverity, tt.wantSev)
			}
		})
	}
}

func TestSelector_Matches(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:        "CTL.S3.PUBLIC.001",
		Name:      "No Public S3 Bucket Read",
		Severity:  policy.SeverityHigh,
		Domain:    "exposure",
		ScopeTags: []string{"aws", "s3"},
	}
	invNoSeverity := policy.ControlDefinition{
		ID:        "CTL.S3.LOG.001",
		Name:      "S3 Logging Enabled",
		Domain:    "compliance",
		ScopeTags: []string{"aws", "s3"},
	}

	tests := []struct {
		name     string
		selector Selector
		ctl      policy.ControlDefinition
		want     bool
	}{
		{"match all tags", Selector{Tags: []string{"aws", "s3"}}, ctl, true},
		{"match subset tag", Selector{Tags: []string{"aws"}}, ctl, true},
		{"no match missing tag", Selector{Tags: []string{"aws", "gcp"}}, ctl, false},
		{"no tags = match all", Selector{}, ctl, true},
		{"severity exact", Selector{MinSeverity: policy.SeverityHigh}, ctl, true},
		{"severity lower passes", Selector{MinSeverity: policy.SeverityMedium}, ctl, true},
		{"severity higher fails", Selector{MinSeverity: policy.SeverityCritical}, ctl, false},
		{"severity filter no sev on ctl", Selector{MinSeverity: policy.SeverityLow}, invNoSeverity, false},
		{"both tags and severity", Selector{Tags: []string{"aws", "s3"}, MinSeverity: policy.SeverityHigh}, ctl, true},
		{"tags match severity fails", Selector{Tags: []string{"aws"}, MinSeverity: policy.SeverityCritical}, ctl, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.selector.Matches(tt.ctl)
			if got != tt.want {
				t.Errorf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesAny(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:        "CTL.S3.PUBLIC.001",
		Severity:  policy.SeverityHigh,
		ScopeTags: []string{"aws", "s3"},
	}

	t.Run("empty selectors matches all", func(t *testing.T) {
		if !MatchesAny(ctl, nil) {
			t.Error("expected true for nil selectors")
		}
	})

	t.Run("one matches", func(t *testing.T) {
		sels := []Selector{
			{Tags: []string{"gcp"}},
			{Tags: []string{"aws"}},
		}
		if !MatchesAny(ctl, sels) {
			t.Error("expected true when one selector matches")
		}
	})

	t.Run("none match", func(t *testing.T) {
		sels := []Selector{
			{Tags: []string{"gcp"}},
			{MinSeverity: policy.SeverityCritical},
		}
		if MatchesAny(ctl, sels) {
			t.Error("expected false when no selectors match")
		}
	})
}
