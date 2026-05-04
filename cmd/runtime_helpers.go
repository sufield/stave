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
//
// Returns the post-expansion argv slice so callers can keep their own
// `args` variable in sync with what Cobra actually parsed. The earlier
// shape called Root.SetArgs() in-place but left the caller's `args`
// pointing at the pre-expansion form, which made downstream consumers
// (writeCommandError, prepareFirstRunHint, ensureFirstRunRunHint)
// look at the alias name rather than the resolved command — the
// first-run hint then misclassified `stave myalias` invocations.
// When no expansion happens the function returns os.Args unchanged.
func (a *App) expandAliasIfMatch() []string {
	// Empty-string guard: os.Args[1] could be the empty string when
	// the binary is invoked via exec with an explicit empty argv
	// slot. Indexing [0] on an empty string panics; the existing
	// `[0] == '-'` check assumed at least one byte. Equivalent to
	// "treat empty as not-an-alias".
	if len(os.Args) < 2 || os.Args[1] == "" || os.Args[1][0] == '-' {
		return append([]string(nil), os.Args...)
	}
	aliases, err := projconfig.LoadUserAliases()
	if err != nil {
		// Surface user-config load failure rather than silently
		// treating it as "no aliases" — a corrupted user config
		// would otherwise hide every alias miss behind the
		// "command not found" message Cobra produces below.
		fmt.Fprintf(a.Root.ErrOrStderr(), "stave: load user aliases: %v\n", err)
		return append([]string(nil), os.Args...)
	}
	if len(aliases) == 0 {
		return append([]string(nil), os.Args...)
	}
	expanded, ok := aliases[os.Args[1]]
	if !ok {
		return append([]string(nil), os.Args...)
	}
	tokens, err := shlex.Split(expanded)
	if err != nil {
		// Malformed alias value: surface the error via stderr and leave
		// os.Args unchanged so the CLI produces a "command not found" error
		// rather than silently misexpanding.
		fmt.Fprintf(a.Root.ErrOrStderr(), "stave: alias %q: %v\n", os.Args[1], err)
		return append([]string(nil), os.Args...)
	}
	newArgs := slices.Concat(tokens, os.Args[2:])
	a.Root.SetArgs(newArgs)
	// The caller's `args` slice typically excludes argv[0] (binary
	// name), so synthesise the same shape: the resolved arguments
	// minus the binary name. Cobra's SetArgs receives the same
	// shape (no binary-name prefix), so downstream callers comparing
	// args[0] now see the expanded command name.
	return append([]string{os.Args[0]}, newArgs...)
}
