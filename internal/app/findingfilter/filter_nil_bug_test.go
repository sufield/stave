package findingfilter

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/report"
)

func TestClassify_NilHistoryHandledSafely(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("Classify panicked on nil history entry: %v", rec)
		}
	}()

	in := Input{
		History:  []*report.Assessment{nil},
		EvalTime: time.Now(),
	}

	res := Classify(in)
	if res == nil {
		t.Fatalf("expected non-nil result")
	}
}
