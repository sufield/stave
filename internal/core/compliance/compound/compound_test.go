package compound

import (
	"testing"

	"github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
)

func fail(id string) compliance.Result {
	return compliance.Result{ControlID: id, Pass: false, Severity: policy.SeverityHigh}
}

func pass(id string) compliance.Result {
	return compliance.Result{ControlID: id, Pass: true, Severity: policy.SeverityHigh}
}

func TestCompound001(t *testing.T) {
	rule := compound001()

	tests := []struct {
		name    string
		results []compliance.Result
		want    bool
	}{
		{
			name:    "both fail — triggers",
			results: []compliance.Result{fail("ACCESS.001"), fail("ACCESS.002")},
			want:    true,
		},
		{
			name:    "only ACCESS.001 fails",
			results: []compliance.Result{fail("ACCESS.001"), pass("ACCESS.002")},
			want:    false,
		},
		{
			name:    "only ACCESS.002 fails",
			results: []compliance.Result{pass("ACCESS.001"), fail("ACCESS.002")},
			want:    false,
		},
		{
			name:    "both pass",
			results: []compliance.Result{pass("ACCESS.001"), pass("ACCESS.002")},
			want:    false,
		},
		{
			name:    "neither present",
			results: []compliance.Result{fail("CONTROLS.001")},
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := rule.Matches(tc.results); got != tc.want {
				t.Errorf("Matches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCompound002(t *testing.T) {
	rule := compound002()

	tests := []struct {
		name    string
		results []compliance.Result
		want    bool
	}{
		{
			name:    "access fail + encryption pass — triggers",
			results: []compliance.Result{fail("ACCESS.001"), pass("CONTROLS.001")},
			want:    true,
		},
		{
			name:    "both fail",
			results: []compliance.Result{fail("ACCESS.001"), fail("CONTROLS.001")},
			want:    false,
		},
		{
			name:    "both pass",
			results: []compliance.Result{pass("ACCESS.001"), pass("CONTROLS.001")},
			want:    false,
		},
		{
			name:    "access pass + encryption fail",
			results: []compliance.Result{pass("ACCESS.001"), fail("CONTROLS.001")},
			want:    false,
		},
		{
			name:    "neither present",
			results: []compliance.Result{},
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := rule.Matches(tc.results); got != tc.want {
				t.Errorf("Matches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCompound003(t *testing.T) {
	rule := compound003()

	tests := []struct {
		name    string
		results []compliance.Result
		want    bool
	}{
		{
			name:    "VPC pass + endpoint policy fail — triggers",
			results: []compliance.Result{pass("ACCESS.003"), fail("ACCESS.006")},
			want:    true,
		},
		{
			name:    "both pass",
			results: []compliance.Result{pass("ACCESS.003"), pass("ACCESS.006")},
			want:    false,
		},
		{
			name:    "both fail",
			results: []compliance.Result{fail("ACCESS.003"), fail("ACCESS.006")},
			want:    false,
		},
		{
			name:    "VPC fail + endpoint policy pass",
			results: []compliance.Result{fail("ACCESS.003"), pass("ACCESS.006")},
			want:    false,
		},
		{
			name:    "neither present",
			results: []compliance.Result{fail("AUDIT.001")},
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := rule.Matches(tc.results); got != tc.want {
				t.Errorf("Matches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDetect(t *testing.T) {
	rules := DefaultRules()

	t.Run("two compounds fire", func(t *testing.T) {
		results := []compliance.Result{
			fail("ACCESS.001"),
			fail("ACCESS.002"),
			pass("CONTROLS.001"),
		}
		findings := Detect(rules, results)
		if len(findings) != 2 {
			t.Fatalf("got %d findings, want 2", len(findings))
		}
		ids := map[string]bool{}
		for _, f := range findings {
			ids[f.ID] = true
		}
		if !ids["COMPOUND.001"] {
			t.Error("expected COMPOUND.001")
		}
		if !ids["COMPOUND.002"] {
			t.Error("expected COMPOUND.002")
		}
	})

	t.Run("no compounds fire", func(t *testing.T) {
		results := []compliance.Result{
			pass("ACCESS.001"),
			pass("ACCESS.002"),
			pass("CONTROLS.001"),
		}
		findings := Detect(rules, results)
		if len(findings) != 0 {
			t.Errorf("got %d findings, want 0", len(findings))
		}
	})
}
