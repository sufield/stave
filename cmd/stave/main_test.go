package main

import (
	"os"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/sufield/stave/cmd"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"stave": staveMain,
	})
}

// staveMain runs the stave CLI without calling os.Exit directly.
// testscript intercepts os.Exit to capture the exit code.
func staveMain() {
	app := cmd.NewApp()
	err := app.Root.Execute()
	if err != nil {
		os.Exit(cmd.ExitCode(err))
	}
}

func TestScripts(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir:                 "testdata/scripts",
		RequireExplicitExec: true,
	})
}
