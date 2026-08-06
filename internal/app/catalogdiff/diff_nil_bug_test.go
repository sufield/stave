package catalogdiff

import (
	"testing"
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
