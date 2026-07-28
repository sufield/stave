package sanitize

import (
	"testing"
)

func TestSanitizer_ScrubMap_NilReceiverDoesNotPanic(t *testing.T) {
	t.Parallel()

	var s *Sanitizer = nil
	props := map[string]any{
		"bucket_name": "my-secret-bucket",
	}

	got := s.ScrubMap(props, AssetProfile())
	if got == nil {
		t.Error("expected non-nil map returned when calling ScrubMap on nil *Sanitizer")
	}
	if got["bucket_name"] != "my-secret-bucket" {
		t.Errorf("expected original value retained on nil *Sanitizer, got %v", got["bucket_name"])
	}
}
