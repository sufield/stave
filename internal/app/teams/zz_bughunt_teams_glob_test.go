package teams

import (
	"testing"
)

func TestBugHunt_GlobMatch_Wildcards(t *testing.T) {
	// A pattern like "*abc*" should match "xyzabc123".
	// Under the buggy code, it strips the trailing "*" leaving "*abc",
	// then calls strings.HasPrefix("xyzabc123", "*abc") which returns false
	// because "xyzabc123" does not start with a literal asterisk.
	if !globMatch("*abc*", "xyzabc123") {
		t.Error("expected '*abc*' to match 'xyzabc123'")
	}
}
