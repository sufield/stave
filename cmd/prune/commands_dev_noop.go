//go:build !stavedev

package prune

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
)

// DevCommands returns nil in production builds.
func DevCommands(_ *compose.Provider) []*cobra.Command { return nil }
