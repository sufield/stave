package enforce

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/enforce/baseline"
	"github.com/sufield/stave/cmd/enforce/cidiff"
	"github.com/sufield/stave/cmd/enforce/diff"
	"github.com/sufield/stave/cmd/enforce/fix"
	"github.com/sufield/stave/cmd/enforce/gate"
	"github.com/sufield/stave/cmd/enforce/generate"
	"github.com/sufield/stave/cmd/enforce/graph"
	"github.com/sufield/stave/cmd/enforce/status"
	appstatus "github.com/sufield/stave/internal/app/status"
)

// Factory functions for individual enforcement commands.

// NewGenerateCmd constructs the generatecmd component.
func NewGenerateCmd() *cobra.Command { return generate.NewCmd() }

// NewDiffCmd constructs the diffcmd component.
func NewDiffCmd(loadSnapshots compose.SnapshotLoader) *cobra.Command {
	return diff.NewCmd(loadSnapshots)
}

// NewFixCmd constructs the fixcmd component.
func NewFixCmd(deps fix.Deps) *cobra.Command {
	return fix.NewFixCmd(deps)
}

// NewFixLoopCmd constructs the fixloopcmd component.
func NewFixLoopCmd(deps fix.LoopDeps) *cobra.Command {
	return fix.NewFixLoopCmd(deps)
}

// NewGateCmd constructs the gatecmd component.
func NewGateCmd(deps gate.Deps) *cobra.Command {
	return gate.NewCmd(deps)
}

// NewCiDiffCmd constructs the cidiffcmd component.
func NewCiDiffCmd() *cobra.Command { return cidiff.NewCmd() }

// NewBaselineCmd constructs the baselinecmd component.
func NewBaselineCmd() *cobra.Command { return baseline.NewCmd() }

// NewStatusCmd constructs the statuscmd component.
func NewStatusCmd() *cobra.Command { return status.NewCmd() }

// NewGraphCmd constructs the graphcmd component.
func NewGraphCmd(newCtlRepo compose.CtlRepoFactory, loadSnapshots compose.SnapshotLoader) *cobra.Command {
	return graph.NewCmd(newCtlRepo, loadSnapshots)
}

// NextCommandForProject provides a high-level recommendation for the next
// action to take in a project. It delegates to the app-layer inspector.
func NextCommandForProject(projectRoot string) (string, error) {
	inspector := appstatus.NewInspector()
	state, err := inspector.Inspect(projectRoot)
	if err != nil {
		return "", fmt.Errorf("inspect project: %w", err)
	}
	return state.RecommendNext(), nil
}
