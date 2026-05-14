package mapcmd

import "github.com/sufield/stave/cmd/cmdutil/compose"

// Deps holds the adapter factories required by the map command.
// Constructed at registration time in cmd/commands.go.
type Deps struct {
	NewCtlRepo compose.CtlRepoFactory
}
