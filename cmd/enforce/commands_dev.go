package enforce

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/enforce/graph"
)

func NewGraphCmd(p *compose.Provider) *cobra.Command { return graph.NewCmd(p) }
