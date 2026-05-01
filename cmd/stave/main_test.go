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
	app, err := cmd.NewApp()
	if err != nil {
		os.Exit(cmd.ExitCode(err))
	}
	if err := app.Root.Execute(); err != nil {
		os.Exit(cmd.ExitCode(err))
	}
}

func TestScripts(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		// Each testscript fixture spawns the stave binary in
		// process; the suite collectively dominates the cmd/stave
		// package runtime. Skip under -short for the fast feedback
		// loop. Run via `make test` (or drop -short) before merge.
		t.Skip("skipping: testscript fixtures spawn the stave binary; run without -short for full coverage")
	}
	testscript.Run(t, testscript.Params{
		Dir:                 "testdata/scripts",
		RequireExplicitExec: true,
	})
}
