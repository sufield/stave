package enforce

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/cmd/enforce/baseline"
	"github.com/sufield/stave/cmd/enforce/cidiff"
	"github.com/sufield/stave/cmd/enforce/diff"
	"github.com/sufield/stave/cmd/enforce/fix"
	"github.com/sufield/stave/cmd/enforce/gate"
	"github.com/sufield/stave/cmd/enforce/generate"
	"github.com/sufield/stave/cmd/enforce/graph"
	"github.com/sufield/stave/cmd/enforce/status"
)

// Factory functions for individual enforcement commands.

func NewGenerateCmd() *cobra.Command { return generate.NewCmd() }
func NewDiffCmd() *cobra.Command     { return diff.NewCmd() }
func NewFixCmd() *cobra.Command      { return fix.NewFixCmd() }
func NewFixLoopCmd() *cobra.Command  { return fix.NewFixLoopCmd() }
func NewGateCmd() *cobra.Command     { return gate.NewCmd() }
func NewCiDiffCmd() *cobra.Command   { return cidiff.NewCmd() }
func NewBaselineCmd() *cobra.Command { return baseline.NewCmd() }
func NewGraphCmd() *cobra.Command    { return graph.NewCmd() }
func NewStatusCmd() *cobra.Command   { return status.NewCmd() }

// NextCommandForProject provides a high-level recommendation for the next
// action to take in a project. It delegates to the status Runner.
func NextCommandForProject(projectRoot string) (string, error) {
	resolver := &projctx.Resolver{WorkingDir: projectRoot}
	runner := status.NewRunner(resolver)
	state, err := runner.Scan(projectRoot)
	if err != nil {
		return "", err
	}
	return state.RecommendNext(), nil
}
