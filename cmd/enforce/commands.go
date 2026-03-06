package enforce

import (
	enfbaseline "github.com/sufield/stave/cmd/enforce/baseline"
	enfcidiff "github.com/sufield/stave/cmd/enforce/cidiff"
	enfdiff "github.com/sufield/stave/cmd/enforce/diff"
	enffix "github.com/sufield/stave/cmd/enforce/fix"
	enfgate "github.com/sufield/stave/cmd/enforce/gate"
	enfgenerate "github.com/sufield/stave/cmd/enforce/generate"
	enfgraph "github.com/sufield/stave/cmd/enforce/graph"
	enfstatus "github.com/sufield/stave/cmd/enforce/status"
)

var EnforceCmd = enfgenerate.NewCmd()

var DiffCmd = enfdiff.NewCmd()

var FixCmd = enffix.NewFixCmd()

var FixLoopCmd = enffix.NewFixLoopCmd()

var GateCmd = enfgate.NewCmd()

var CiDiffCmd = enfcidiff.NewCmd()

var BaselineCmd = enfbaseline.NewCmd()

var GraphCmd = enfgraph.NewCmd()

var StatusCmd = enfstatus.NewCmd()

func NextCommandForProject(projectRoot string) (string, error) {
	return enfstatus.NextCommandForProject(projectRoot)
}
