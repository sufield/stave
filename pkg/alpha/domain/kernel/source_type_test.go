package kernel

import "testing"

func TestObservationSourceTypeIsEmpty(t *testing.T) {
	if !ObservationSourceType("").IsEmpty() {
		t.Error("empty string should be empty")
	}
}
