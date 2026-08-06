package exemptionsuggest

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/report"
)

func TestSuggest_NilHistoryHandledSafely(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("Suggest panicked on nil history entry: %v", rec)
		}
	}()

	in := Input{
		History:  []*report.Assessment{nil},
		Window:   30 * 24 * time.Hour,
		MinDwell: 14 * 24 * time.Hour,
		EvalTime: time.Now(),
	}

	res := Suggest(in)
	if res == nil {
		t.Fatalf("expected non-nil result")
	}
}
