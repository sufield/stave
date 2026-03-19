//go:build stavedev

package cmd

import "github.com/spf13/cobra"

// GetDevRootCmd returns a fully-wired root cobra command with all dev commands.
func GetDevRootCmd() *cobra.Command {
	return NewApp(WithDevCommands()).Root
}
