package reachability

import (
	"testing"

	"github.com/sufield/stave/internal/core/access"
)

func TestBuildContext_DeterministicHighestPrivilegePrincipal(t *testing.T) {
	// Two entries with equal max score (privileged internal roles)
	entries := []access.ResourceAccessEntry{
		{
			PrincipalARN: "arn:aws:iam::123456789012:role/RoleZ",
			Actions:      []string{"*"},
		},
		{
			PrincipalARN: "arn:aws:iam::123456789012:role/RoleA",
			Actions:      []string{"*"},
		},
	}

	// Run BuildContext multiple times. HighestPrivilegePrincipal must be consistently "arn:aws:iam::123456789012:role/RoleA"
	first := BuildContext(entries)
	want := "arn:aws:iam::123456789012:role/RoleA"

	for range 100 {
		ctx := BuildContext(entries)
		if string(ctx.HighestPrivilegePrincipal) != want {
			t.Fatalf("non-deterministic HighestPrivilegePrincipal selection: got %s, want %s (first got %s)", ctx.HighestPrivilegePrincipal, want, first.HighestPrivilegePrincipal)
		}
	}
}
