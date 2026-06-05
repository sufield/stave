package diagnose

import (
	"context"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

// TestBugHunt_FindingPreRunNilResolver proves that NewFindingCmd's PreRunE
// panics when no governance resolver is injected into the command context.
//
// cmdctx.ResolverFromCmd is documented to return nil when no resolver was set
// (e.g. test harnesses that drive the command without bootstrap). finding_cmd.go
// line 86-88 calls `eval := cmdctx.ResolverFromCmd(cmd)` and immediately invokes
// `eval.MaxUnsafeDuration()` with no nil guard. That dereferences the nil
// *GovernanceResolver receiver inside mergeLayers (resolver.go:112, `r.Getenv`),
// causing a nil-pointer panic.
//
// Correct behavior (asserted here): with a nil resolver, PreRunE must skip
// config-default resolution and return without panicking — exactly like
// cmd/apply/cmd.go:43 (`if eval == nil { return }`) and
// cmd/enforce/gate/options.go:55-57.
func TestBugHunt_FindingPreRunNilResolver(t *testing.T) {
	// Factories are not invoked during PreRunE; trivial stubs suffice.
	newObsRepo := func() (appcontracts.ObservationRepository, error) { return nil, nil }
	newCtlRepo := func() (appcontracts.ControlRepository, error) { return nil, nil }

	cmd := NewFindingCmd(newObsRepo, newCtlRepo)

	// Background context carries no resolver, so cmdctx.ResolverFromCmd
	// returns nil — the documented "no resolver injected" condition.
	cmd.SetContext(context.Background())

	// Satisfy PreRunE's required-flag check so we reach the resolver call.
	if err := cmd.Flags().Set("control-id", "CTL.S3.PUBLIC.001"); err != nil {
		t.Fatalf("set control-id: %v", err)
	}
	if err := cmd.Flags().Set("asset-id", "res:aws:s3:bucket:my-bucket"); err != nil {
		t.Fatalf("set asset-id: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PreRunE panicked with a nil resolver (unguarded nil deref at finding_cmd.go:88): %v", r)
		}
	}()

	if err := cmd.PreRunE(cmd, nil); err != nil {
		t.Fatalf("PreRunE returned an unexpected error with a nil resolver: %v", err)
	}
}
