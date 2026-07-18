package metrics

import (
	"bytes"
	"testing"
)

func TestBugHunt_Write_NilAssessmentDoesNotPanic(t *testing.T) {
	// Under buggy code, passing a nil Assessment inside Input to Write panics.
	// We assert that it does not panic and handles it gracefully.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Write panicked on nil Assessment: %v", r)
		}
	}()

	var buf bytes.Buffer
	Write(&buf, Input{
		Assessment:   nil,
		PostureScore: 95.5,
	})

	output := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("stave_posture_score 95.5")) {
		t.Errorf("expected stave_posture_score to be printed, got: %q", output)
	}
}
