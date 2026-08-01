package translation

import (
	"testing"
)

func TestRenderClause_PresentOperatorWithNilObservedValue(t *testing.T) {
	c := Clause{
		ObservationKey: "storage.access.public_read",
		Operator:       "present",
		ExpectedValue:  true,
		ObservedValue:  nil,
	}

	got := RenderClause(c, GetDefaultFieldRegistry())
	want := "the bucket allows anonymous read is set"
	if got != want {
		t.Errorf("RenderClause(present with nil observed) = %q, want %q", got, want)
	}
}
