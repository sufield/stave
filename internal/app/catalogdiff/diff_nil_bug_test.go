package catalogdiff

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
)

func TestFormatTable_NilDeltaHandledSafely(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("FormatTable panicked on nil delta: %v", rec)
		}
	}()

	res := FormatTable(nil)
	if res != "" {
		t.Errorf("expected empty string for nil delta, got %q", res)
	}
}

func TestSeverityChanges_CollectionMethods(t *testing.T) {
	scs := SeverityChanges{
		{ControlID: "CTL-1", Before: policy.SeverityMedium, After: policy.SeverityHigh},
		{ControlID: "CTL-2", Before: policy.SeverityHigh, After: policy.SeverityLow},
	}

	if scs.Len() != 2 {
		t.Errorf("scs.Len() = %d, want 2", scs.Len())
	}

	if scs.Escalated().Len() != 1 {
		t.Errorf("Escalated len = %d, want 1", scs.Escalated().Len())
	}

	if scs.Deescalated().Len() != 1 {
		t.Errorf("Deescalated len = %d, want 1", scs.Deescalated().Len())
	}
}
