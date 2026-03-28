package enforce

import (
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

func NewGenerateCmd() *cobra.Command { return generate.NewCmd() }
func NewDiffCmd(loadSnapshots compose.SnapshotLoader) *cobra.Command {
	return diff.NewCmd(loadSnapshots)
}
func NewFixCmd(deps fix.FixDeps) *cobra.Command {
	return fix.NewFixCmd(deps)
}
func NewFixLoopCmd(deps fix.FixLoopDeps) *cobra.Command {
	return fix.NewFixLoopCmd(deps)
}
func NewGateCmd(deps gate.Deps) *cobra.Command {
	return gate.NewCmd(deps)
}
func NewCiDiffCmd(deps cidiff.Deps) *cobra.Command     { return cidiff.NewCmd(deps) }
func NewBaselineCmd(deps baseline.Deps) *cobra.Command { return baseline.NewCmd(deps) }
func NewStatusCmd() *cobra.Command                     { return status.NewCmd() }
func NewGraphCmd(newCtlRepo compose.CtlRepoFactory, loadSnapshots compose.SnapshotLoader) *cobra.Command {
	return graph.NewCmd(newCtlRepo, loadSnapshots)
}

// NextCommandForProject provides a high-level recommendation for the next
// action to take in a project. It delegates to the app-layer scanner.
func NextCommandForProject(projectRoot string) (string, error) {
	scanner := appstatus.NewScanner()
	state, err := scanner.Scan(projectRoot)
	if err != nil {
		return "", err
	}
	return state.RecommendNext(), nil
}
