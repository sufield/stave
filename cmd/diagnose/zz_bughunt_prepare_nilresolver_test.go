package diagnose

import (
	"context"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

// TestBugHunt_PrepareNilResolver proves that the diagnose command's PreRunE
// (diagnoseOptions.Prepare) panics when no governance resolver is injected
// into the command context.
//
// cmdctx.ResolverFromCmd is documented to return nil when no resolver was set
// (e.g. tolerant commands or test harnesses that drive the command without
// bootstrap). options.go:60 calls `eval := cmdctx.ResolverFromCmd(cmd)` and,
// when --max-unsafe was not changed, immediately invokes
// `eval.MaxUnsafeDuration()` at options.go:62 with no nil guard. That
// dereferences the nil *GovernanceResolver receiver inside mergeLayers
// (resolver.go:112, `r.Getenv`), causing a nil-pointer panic.
//
// Correct behavior (asserted here): with a nil resolver, Prepare must skip
// config-default resolution and return without panicking — exactly like
// cmd/apply/cmd.go:43 (`if eval == nil { return }`) and
// cmd/enforce/gate/options.go:55-57. A missing resolver must leave
// MaxUnsafeDuration at its flag default ("") instead of panicking.
func TestBugHunt_PrepareNilResolver(t *testing.T) {
	// Factories are not invoked during PreRunE; trivial stubs suffice.
	newObsRepo := func() (appcontracts.ObservationRepository, error) { return nil, nil }
	newCtlRepo := func() (appcontracts.ControlRepository, error) { return nil, nil }

	cmd := NewDiagnoseCmd(newObsRepo, newCtlRepo)

	// Background context carries no resolver, so cmdctx.ResolverFromCmd
	// returns nil — the documented "no resolver injected" condition.
	cmd.SetContext(context.Background())

	// --max-unsafe is left unchanged so Prepare takes the branch that
	// calls eval.MaxUnsafeDuration() at options.go:62.

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PreRunE panicked with a nil resolver (unguarded nil deref at options.go:62): %v", r)
		}
	}()

	if err := cmd.PreRunE(cmd, nil); err != nil {
		t.Fatalf("PreRunE returned an unexpected error with a nil resolver: %v", err)
	}
}
