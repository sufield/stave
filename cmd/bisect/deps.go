package bisect

import "github.com/sufield/stave/cmd/cmdutil/compose"

// Deps holds the adapter factories required by the bisect command.
// Constructed at registration time in cmd/commands.go.
type Deps struct {
	NewCtlRepo      compose.CtlRepoFactory
	NewCELEvaluator compose.CELEvaluatorFactory
}
