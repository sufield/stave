package test

import "github.com/sufield/stave/cmd/cmdutil/compose"

// Deps holds the adapter factories required by the test command.
// Constructed at registration time in cmd/commands.go.
type Deps struct {
	NewCtlRepo      compose.CtlRepoFactory
	NewCELEvaluator compose.CELEvaluatorFactory
}
