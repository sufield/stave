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

func NewGenerateCmd() *cobra.Command                   { return generate.NewCmd() }
func NewDiffCmd(p *compose.Provider) *cobra.Command    { return diff.NewCmd(p) }
func NewFixCmd(p *compose.Provider) *cobra.Command     { return fix.NewFixCmd(p) }
func NewFixLoopCmd(p *compose.Provider) *cobra.Command { return fix.NewFixLoopCmd(p) }
func NewGateCmd(p *compose.Provider) *cobra.Command    { return gate.NewCmd(p) }
func NewCiDiffCmd() *cobra.Command                     { return cidiff.NewCmd() }
func NewBaselineCmd() *cobra.Command                   { return baseline.NewCmd() }
func NewStatusCmd() *cobra.Command                     { return status.NewCmd() }
func NewGraphCmd(p *compose.Provider) *cobra.Command   { return graph.NewCmd(p) }

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
