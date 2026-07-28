package predicate

import (
	"testing"
)

func TestFieldPath_HasPrefix_SegmentBoundary(t *testing.T) {
	t.Parallel()

	fp := NewFieldPath("properties.storage_account.kind")

	if fp.HasPrefix("properties.storage") {
		t.Error("CRITICAL BUG: HasPrefix(\"properties.storage\") returned true for \"properties.storage_account.kind\"; must enforce segment dot-boundary")
	}

	trimmed := fp.TrimPrefix("properties.storage")
	if trimmed != "properties.storage_account.kind" {
		t.Errorf("CRITICAL BUG: TrimPrefix(\"properties.storage\") on \"properties.storage_account.kind\" returned %q; expected original string %q", trimmed, "properties.storage_account.kind")
	}
}
