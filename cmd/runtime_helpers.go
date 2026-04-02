package cmd

import (
	"fmt"
	"os"
	"slices"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/platform/shlex"
)

// expandAliasIfMatch checks if os.Args[1] matches a user-defined alias.
// If so, it replaces the command arguments with the expanded alias tokens
// followed by any extra arguments the user passed.
//
// Alias values are tokenized with a POSIX shell-aware parser that respects
// single quotes, double quotes, and backslash escapes, so alias values like
// 'apply --controls "path with spaces/controls"' expand correctly.
func (a *App) expandAliasIfMatch() {
	if len(os.Args) < 2 || os.Args[1][0] == '-' {
		return
	}
	aliases := projconfig.LoadUserAliases()
	if len(aliases) == 0 {
		return
	}
	expanded, ok := aliases[os.Args[1]]
	if !ok {
		return
	}
	tokens, err := shlex.Split(expanded)
	if err != nil {
		// Malformed alias value: surface the error via stderr and leave
		// os.Args unchanged so the CLI produces a "command not found" error
		// rather than silently misexpanding.
		fmt.Fprintf(a.Root.ErrOrStderr(), "stave: alias %q: %v\n", os.Args[1], err)
		return
	}
	newArgs := slices.Concat(tokens, os.Args[2:])
	a.Root.SetArgs(newArgs)
}
