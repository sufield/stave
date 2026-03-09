package cmd

import (
	"os"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/platform/logging"
)

// expandAliasIfMatch checks if os.Args[1] matches a user-defined alias.
// If so, it replaces the command arguments with the expanded alias tokens
// followed by any extra arguments the user passed.
func (a *App) expandAliasIfMatch() {
	if len(os.Args) < 2 || strings.HasPrefix(os.Args[1], "-") {
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
	// Note: strings.Fields splits on whitespace without respecting shell quoting.
	// Alias values with quoted arguments containing spaces won't tokenize correctly.
	tokens := strings.Fields(expanded)
	newArgs := append(tokens, os.Args[2:]...)
	a.Root.SetArgs(newArgs)
}

func (a *App) attachRunIDFromPlan(plan *appeval.EvaluationPlan) {
	logging.SetDefaultLogger(a.Logger)
	cmdutil.AttachRunIDFromPlan(plan)
	a.Logger = logging.DefaultLogger()
}
