package apply

import (
	"testing"

	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/core/kernel"
)

// Test_Mut_BuildProjectConfigInput_HappyPath pins the success path of
// buildProjectConfigInput (deps_project.go), the shared helper the fix
// extracted so both the standard apply path and buildStaveConfig translate
// stave.yaml the same way.
//
// On the happy path pack.NewEmbeddedRegistry() succeeds, so the
// `if err != nil` guard at deps_project.go:47 must be FALSE: the helper
// returns a nil error and a fully-populated input whose PackRegistry was
// assigned. Negating that guard to `if err == nil` (the surviving
// CONDITIONALS_NEGATION at deps_project.go:47:9) inverts the path — on a
// successful registry build the mutant returns early with a non-nil error
// and leaves input.PackRegistry nil, dropping every enabled-control-pack /
// exclude / exception setting before the evaluator sees it.
func Test_Mut_BuildProjectConfigInput_HappyPath(t *testing.T) {
	projCfg := &appconfig.WorkspacePolicy{
		Exceptions: []appconfig.PolicyException{
			{ControlID: "CTL.S3.PUBLIC.001", AssetID: "my-bucket", Reason: "risk-accepted"},
		},
		EnabledControlPacks: []string{"aws-foundational"},
		ExcludeControls:     []kernel.ControlID{"CTL.S3.LOGGING.001"},
	}

	input, err := buildProjectConfigInput(projCfg, true)
	if err != nil {
		t.Fatalf("buildProjectConfigInput returned error on the happy path (embedded registry builds successfully): %v", err)
	}

	// The embedded pack registry built successfully, so the helper must
	// have assigned it. A nil PackRegistry means the err-guard branch was
	// taken on a successful build (the mutant), dropping pack resolution.
	if input.PackRegistry == nil {
		t.Fatalf("input.PackRegistry is nil after a successful registry build; the success path must assign the embedded registry so enabled_control_packs resolve")
	}

	// The non-registry settings carry through regardless, proving the
	// returned input is the real translated config, not an empty zero
	// value the mutant's early-return error path would force callers to
	// discard.
	if len(input.Exceptions) != 1 {
		t.Fatalf("input.Exceptions = %d, want 1 (exception must survive translation)", len(input.Exceptions))
	}
	if len(input.ExcludeControls) != 1 {
		t.Fatalf("input.ExcludeControls = %d, want 1", len(input.ExcludeControls))
	}
	if !input.ControlsFlagSet {
		t.Fatalf("input.ControlsFlagSet = false, want true (controlsSet arg must propagate)")
	}
}
