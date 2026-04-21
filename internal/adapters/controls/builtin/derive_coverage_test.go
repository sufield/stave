package builtin

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
)

func TestDeriveDefectCoverage(t *testing.T) {
	store := testRegistry()
	controls, err := store.All()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	overrides, derived, empty := 0, 0, 0
	for _, ctl := range controls {
		if ctl.Defect != "" {
			overrides++
			continue
		}
		d := policy.DeriveDefect(&ctl.UnsafePredicate)
		if d != "" {
			derived++
		} else {
			empty++
		}
	}

	total := len(controls)
	t.Logf("Total controls: %d", total)
	t.Logf("With defect already (override+triage+derived): %d", overrides)
	t.Logf("Derivable but not yet applied: %d", derived)
	t.Logf("Not derivable: %d", empty)
	t.Logf("Coverage: %.1f%% (%d/%d)", float64(overrides)/float64(total)*100, overrides, total)
}
