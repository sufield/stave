package lint

import (
	"testing"
)

func TestBugHunt_Linter_IsSortedSequence_MixedArray(t *testing.T) {
	l := NewLinter()
	// An array with a scalar first, followed by a map without sortable keys (id/name/key/type).
	// Under the buggy code, the scalar element causes isSortedSequence to return true immediately,
	// ignoring the map element completely.
	root := mustParse(t, `
id: CTL.AWS.PUBLIC.001
name: Test
description: Test description
remediation:
  action: Fix
some_array:
  - 1
  - value: 2
`)
	diags := l.walkOrdering("test.yaml", root)

	// We expect the CTL_ORDERING_HINT warning to be triggered because of the second item.
	foundHint := false
	for _, d := range diags {
		if d.RuleID == "CTL_ORDERING_HINT" {
			foundHint = true
		}
	}
	if !foundHint {
		t.Errorf("expected CTL_ORDERING_HINT warning for mapping in mixed array, but none was found")
	}
}
