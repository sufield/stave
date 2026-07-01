// facade_ratchet_test.go — Phase 4 of the pkg/stave facade migration
// (docs/architecture/pkg-stave-facade.md), started as a RATCHET rather
// than the final flip.
//
// The doc's Phase 4 is "scan all of cmd/ and drop the per-command opt-in
// list" — but that can only be the END state, once every command is
// migrated. Today ~64 leaf command packages still import internal/
// directly, so a blanket deny-all would fail on all of them at once.
//
// This test is the incremental form: it walks every leaf command package
// under cmd/ and maintains facadeCleanBaseline — the set that is ALREADY
// facade-clean (imports no non-exempt internal package). It enforces a
// one-way ratchet:
//
//  1. No baseline package may regress (gain a non-exempt internal import).
//  2. Any package that BECOMES clean must be added to the baseline
//     (progress is locked in; you cannot clean a package and forget it).
//
// So the baseline only ever grows. When it covers every command package,
// the leaky set is empty and this test can be flipped to the pure
// deny-all that the doc's Phase 4 describes — at which point the
// per-command architecture_test.go files and the baseline both become
// redundant and can be deleted.
//
// "Facade-clean" here is the exemption bar: a package may import the four
// CLI-shaped shared helpers (cli/ui, platform/fsutil, platform/metadata,
// util/jsonutil) but no other internal/ package. The cmd/cmdutil subtree
// is excluded entirely — it is the wrapper layer that legitimately owns
// the internal helpers.
package cmd

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// facadeCleanBaseline is the set of leaf command packages (paths relative
// to cmd/) that import no non-exempt internal/ package. It is a ratchet:
// add packages as they migrate; never remove one (that would be a
// regression the test should have caught).
var facadeCleanBaseline = map[string]struct{}{
	"apply":              {},
	"apply/validate":     {},
	"apply/verify":       {},
	"attest":             {},
	"bisect":             {},
	"bundle":             {},
	"catalog":            {},
	"enforce/cidiff":     {},
	"enforce/diff":       {},
	"enforce/fix":        {},
	"enforce/gate":       {},
	"enforce/generate":   {},
	"enforce/graph":      {},
	"exportsir":          {},
	"cel":                {},
	"compare":            {},
	"contract":           {},
	"coverage":           {},
	"enforce/baseline":   {},
	"doctor":             {},
	"exempt":             {},
	"expand":             {},
	"export":             {},
	"export/compliance":  {},
	"exportinvariants":   {},
	"features":           {},
	"fingerprint":        {},
	"forge":              {},
	"gaps":               {},
	"initcmd":            {},
	"initcmd/alias":      {},
	"initcmd/env":        {},
	"inspect":            {},
	"inspect/acl":        {},
	"inspect/aliases":    {},
	"inspect/compliance": {},
	"inspect/exposure":   {},
	"inspect/policy":     {},
	"inspect/risk":       {},
	"map":                {},
	"mcp":                {},
	"metrics":            {},
	"nep":                {},
	"path":               {},
	"profile":            {},
	"readiness":          {},
	"report":             {},
	"sanitize":           {},
	"score":              {},
	"scorecard":          {},
	"search":             {},
	"services":           {},
	"snapshotdiff":       {},
	"stave":              {},
	"stave-dev":          {},
	"telemetry":          {},
	"test":               {},
	"trend":              {},
	"validatemapping":    {},
}

func TestFacadeRatchet(t *testing.T) {
	exemptHelpers := []string{
		`"github.com/sufield/stave/internal/cli/ui"`,
		`"github.com/sufield/stave/internal/platform/fsutil"`,
		`"github.com/sufield/stave/internal/platform/metadata"`,
		`"github.com/sufield/stave/internal/util/jsonutil"`,
	}
	const internalPrefix = `"github.com/sufield/stave/internal/`

	fset := token.NewFileSet()
	cleanNow := map[string]struct{}{}

	walkErr := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(path)
		if rel == "." {
			return nil
		}
		// cmd/cmdutil is the wrapper layer that legitimately owns the
		// internal helpers; testdata holds fixtures, not packages.
		if rel == "cmdutil" || strings.HasPrefix(rel, "cmdutil/") || d.Name() == "testdata" {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}

		entries, err := os.ReadDir(path)
		if err != nil {
			return fmt.Errorf("read dir %s: %w", path, err)
		}
		hasProd, leaks := false, false
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			hasProd = true
			f, perr := parser.ParseFile(fset, filepath.Join(path, name), nil, parser.ImportsOnly)
			if perr != nil {
				return fmt.Errorf("parse %s: %w", filepath.Join(path, name), perr)
			}
			for _, imp := range f.Imports {
				if strings.HasPrefix(imp.Path.Value, internalPrefix) && !slices.Contains(exemptHelpers, imp.Path.Value) {
					leaks = true
				}
			}
		}
		if hasProd && !leaks {
			cleanNow[rel] = struct{}{}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}

	// 1. Regression: a baseline package that is no longer clean.
	var regressed []string
	for pkg := range facadeCleanBaseline {
		if _, ok := cleanNow[pkg]; !ok {
			regressed = append(regressed, pkg)
		}
	}
	slices.Sort(regressed)
	if len(regressed) > 0 {
		t.Errorf("facade regression — these packages were facade-clean and now import a non-exempt internal/ package:\n  cmd/%s\n\n"+
			"Move the new dependency behind pkg/stave (see docs/architecture/pkg-stave-facade.md); do not import internal/ directly.",
			strings.Join(regressed, "\n  cmd/"))
	}

	// 2. Un-enrolled progress: a clean package missing from the baseline.
	var unenrolled []string
	for pkg := range cleanNow {
		if _, ok := facadeCleanBaseline[pkg]; !ok {
			unenrolled = append(unenrolled, pkg)
		}
	}
	slices.Sort(unenrolled)
	if len(unenrolled) > 0 {
		t.Errorf("facade ratchet — these packages are now facade-clean but missing from facadeCleanBaseline:\n  %q\n\n"+
			"Add them to the baseline in cmd/facade_ratchet_test.go so the progress is locked in and cannot regress.",
			unenrolled)
	}
}
