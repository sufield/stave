// cli_schema_test.go — golden test of the CLI's *structure* (commands, flags,
// types, nesting). Catches drift a behavior test misses: a flag changing
// String->StringSlice, a required flag dropped, or a subcommand reparented. Run
// after any change that touches the command tree.
//
//	go test ./cmd -run TestCLISchema             # verify
//	go test ./cmd -run TestCLISchema -update     # accept intended changes
package cmd

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var updateSchema = flag.Bool("update", false, "rewrite the CLI schema golden files")

func TestCLISchema(t *testing.T) {
	const golden = "testdata/cli-schema"

	root := getRootCmd() // a FRESH root (not the shared cache) so GenYamlTree's
	// in-tree mutations can't leak into other cmd tests.
	// Critical for stable goldens: the doc generators otherwise append a dated
	// "auto generated" tag that would make every run diff.
	disableAutoGenTagTree(root)

	tmp := t.TempDir()
	if err := doc.GenYamlTree(root, tmp); err != nil {
		t.Fatalf("GenYamlTree: %v", err)
	}

	// Honor BOTH the local -update flag and the repo-wide UPDATE_GOLDEN env var
	// (set by `make golden-update-all`), so this golden regenerates alongside the
	// others instead of failing the bulk regeneration on a mismatch.
	if *updateSchema || os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.RemoveAll(golden); err != nil {
			t.Fatal(err)
		}
		if err := os.CopyFS(golden, os.DirFS(tmp)); err != nil { // Go 1.23+
			t.Fatal(err)
		}
		t.Logf("updated golden: %s", golden)
		return
	}

	got, _ := os.ReadDir(tmp)
	for _, e := range got {
		gotBytes, err := os.ReadFile(filepath.Join(tmp, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		wantBytes, err := os.ReadFile(filepath.Join(golden, e.Name()))
		if err != nil {
			t.Errorf("%s: new command file (command added or reparented); run -update if intended", e.Name())
			continue
		}
		if string(gotBytes) != string(wantBytes) {
			t.Errorf("%s: CLI schema drift (a flag type, requiredness, or structure changed); run -update if intended", e.Name())
		}
	}
	// Catch removals/renames too.
	want, _ := os.ReadDir(golden)
	for _, e := range want {
		if _, err := os.Stat(filepath.Join(tmp, e.Name())); err != nil {
			t.Errorf("%s: command disappeared (removed or renamed)", e.Name())
		}
	}
}

func disableAutoGenTagTree(c *cobra.Command) {
	c.DisableAutoGenTag = true
	for _, sub := range c.Commands() {
		disableAutoGenTagTree(sub)
	}
}
