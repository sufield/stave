//go:build !stavedev

package cmd

// WireDevCommands is a no-op in production builds.
// The dev binary (stave-dev) is built with -tags stavedev to include
// all developer-only commands.
func WireDevCommands(_ *App) {}
