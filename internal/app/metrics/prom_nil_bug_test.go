package metrics

import (
	"testing"
)

func TestWrite_NilWriterHandledSafely(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("Write panicked on nil writer: %v", rec)
		}
	}()

	Write(nil, Input{PostureScore: 90.0})
}
