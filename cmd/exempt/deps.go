package exempt

import "github.com/sufield/stave/cmd/cmdutil/compose"

// Deps holds the adapter factories the exempt command group needs.
// Currently only the validate subcommand depends on a factory; the
// others read or write the acceptance file via the appexempt
// app-layer service. Constructed at registration time in cmd/commands.go.
type Deps struct {
	NewBuiltinControlStore compose.BuiltinControlStoreFactory
}
