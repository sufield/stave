package enforce

import (
	"github.com/spf13/cobra"
	enfbaseline "github.com/sufield/stave/cmd/enforce/baseline"
	enfcidiff "github.com/sufield/stave/cmd/enforce/cidiff"
	enfdiff "github.com/sufield/stave/cmd/enforce/diff"
	enffix "github.com/sufield/stave/cmd/enforce/fix"
	enfgate "github.com/sufield/stave/cmd/enforce/gate"
	enfgenerate "github.com/sufield/stave/cmd/enforce/generate"
	enfgraph "github.com/sufield/stave/cmd/enforce/graph"
	enfstatus "github.com/sufield/stave/cmd/enforce/status"
)

func NewEnforceCmd() *cobra.Command  { return enfgenerate.NewCmd() }
func NewDiffCmd() *cobra.Command     { return enfdiff.NewCmd() }
func NewFixCmd() *cobra.Command      { return enffix.NewFixCmd() }
func NewFixLoopCmd() *cobra.Command  { return enffix.NewFixLoopCmd() }
func NewGateCmd() *cobra.Command     { return enfgate.NewCmd() }
func NewCiDiffCmd() *cobra.Command   { return enfcidiff.NewCmd() }
func NewBaselineCmd() *cobra.Command { return enfbaseline.NewCmd() }
func NewGraphCmd() *cobra.Command    { return enfgraph.NewCmd() }
func NewStatusCmd() *cobra.Command   { return enfstatus.NewCmd() }

func NextCommandForProject(projectRoot string) (string, error) {
	return enfstatus.NextCommandForProject(projectRoot)
}
