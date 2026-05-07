// Command z3prove demonstrates Z3-based reachability reasoning
// over the s3-broad-write-scope pattern. Where the iter-4 CEL
// example (sibling main.go) detects the unsafe configuration
// state ("the policy is in prefix mode"), this program answers
// the deeper question: *given the prefix the policy admits, is
// there a concrete object key that the policy permits AND that
// the application's intended-key pattern excludes?*
//
// CEL evaluates a state predicate. Z3 enumerates a witness over
// a search space. They answer different questions about the
// same configuration.
//
// # Modelling note
//
// The aclements/go-z3 binding does not expose Z3's string theory.
// A faithful model of "string K starts with prefix P AND key K
// matches narrower pattern Q" is therefore not available. This
// program models the search space as a finite enum of named
// keys, encoded as integer constants:
//
//   0 = "files/abc-uuid/photo.png"   (intended)
//   1 = "files/admin.html"            (admitted by prefix, NOT intended)
//   2 = "files/../etc/passwd"         (admitted, path traversal)
//
// The constraint set encodes:
//   - admitted = (key in admitted_set), the set the bucket policy
//     permits.
//   - intended = (key in intended_set), the set the application's
//     key generator produces.
//
// The unsafe predicate the solver discharges:
//   admitted AND NOT intended
//
// SAT → at least one concrete key the policy admits is outside
// the intended set; the solver returns its index, and the program
// prints the corresponding label.
// UNSAT → every admitted key is intended (the remediated case
// where the policy binds an exact key).
//
// A real production model would parse the policy's Resource
// pattern as a finite-state automaton or use Z3's string theory
// (via a different binding). The demo here keeps the encoding
// legible.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/aclements/go-z3/z3"
)

// witnessLabels are the named keys the model enumerates over.
// Indices match the integer constants the solver uses.
var witnessLabels = []string{
	"files/abc-uuid/photo.png",
	"files/admin.html",
	"files/../etc/passwd",
}

const (
	idxIntended    = 0 // the only key the application actually wants
	idxFlatNoUUID  = 1 // admitted by prefix; missing UUID layer
	idxTraversal   = 2 // admitted by prefix; classic path traversal
	witnessCount   = 3
)

func main() {
	root, err := exampleRoot()
	if err != nil {
		log.Fatalf("locate example root: %v", err)
	}

	phase := "both"
	if len(os.Args) > 1 {
		phase = os.Args[1]
	}

	ok := true
	if phase == "before" || phase == "both" {
		ok = runProof(filepath.Join(root, "fixtures/before/observations"), "before (prefix-mode)") && ok
	}
	if phase == "both" {
		fmt.Println()
	}
	if phase == "after" || phase == "both" {
		ok = runProof(filepath.Join(root, "fixtures/after/observations"), "after  (exact-mode)") && ok
	}
	if !ok {
		os.Exit(1)
	}
}

// runProof loads the upload policy from the fixture, encodes the
// admitted/intended sets into Z3, and discharges the
// "admitted AND NOT intended" conjecture. Returns false (without
// exiting) on assertion failure so main can report both phases.
func runProof(snapshotsDir, label string) bool {
	mode, exemplar, err := loadUploadPolicy(snapshotsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] load: %v\n", label, err)
		return false
	}

	ctx := z3.NewContext(nil)
	intSort := ctx.IntSort()
	key := ctx.IntConst("key")

	// admitted = key in admittedIndices.
	admittedIndices := indicesAdmittedBy(mode)
	admitted := disjunction(ctx, key, admittedIndices, intSort)

	// intended = key == idxIntended (the single key the
	// application's UUID-prefixed naming convention produces).
	intendedKey := ctx.FromInt(int64(idxIntended), intSort).(z3.Int)
	intended := key.Eq(intendedKey)

	unsafe := admitted.And(intended.Not())

	s := z3.NewSolver(ctx)
	s.Assert(unsafe)
	sat, err := s.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] z3 check: %v\n", label, err)
		return false
	}

	fmt.Printf("=== %s ===\n", label)
	fmt.Printf("  policy mode: %s   exemplar: %s\n", mode, exemplar)
	fmt.Printf("  admitted set: %v\n", labelsForIndices(admittedIndices))
	fmt.Printf("  intended set: [%q]\n", witnessLabels[idxIntended])

	if sat {
		m := s.Model()
		v := m.Eval(key, true)
		idx, isLit, ok := v.(z3.Int).AsInt64()
		switch {
		case !ok || !isLit:
			fmt.Printf("  verdict: SAT — admitted key falls outside intended set (witness not extractable)\n")
		case idx >= 0 && int(idx) < witnessCount:
			fmt.Printf("  verdict: SAT — witness key %q is admitted but unintended\n", witnessLabels[idx])
		default:
			fmt.Printf("  verdict: SAT — witness index=%d (out of label range)\n", idx)
		}
		return mode == "prefix" // expected SAT for prefix mode
	}
	fmt.Printf("  verdict: UNSAT — every admitted key is intended\n")
	return mode == "exact" // expected UNSAT for exact mode
}

// indicesAdmittedBy returns the witness indices the policy admits
// under the given mode. Prefix mode admits every key whose label
// starts with "files/" (all three witnesses); exact mode admits
// only the single intended key.
func indicesAdmittedBy(mode string) []int {
	switch mode {
	case "prefix":
		return []int{idxIntended, idxFlatNoUUID, idxTraversal}
	case "exact":
		return []int{idxIntended}
	default:
		return nil
	}
}

// disjunction builds (key == i_0 OR key == i_1 OR …) over the
// supplied indices. Returns FromBool(false) for an empty set so
// the result composes correctly with .And.
func disjunction(ctx *z3.Context, key z3.Int, indices []int, sort z3.Sort) z3.Bool {
	if len(indices) == 0 {
		return ctx.FromBool(false)
	}
	first := key.Eq(ctx.FromInt(int64(indices[0]), sort).(z3.Int))
	if len(indices) == 1 {
		return first
	}
	rest := make([]z3.Bool, 0, len(indices)-1)
	for _, i := range indices[1:] {
		rest = append(rest, key.Eq(ctx.FromInt(int64(i), sort).(z3.Int)))
	}
	return first.Or(rest...)
}

func labelsForIndices(idxs []int) []string {
	out := make([]string, 0, len(idxs))
	for _, i := range idxs {
		out = append(out, witnessLabels[i])
	}
	return out
}

// loadUploadPolicy reads the snapshot directory and returns the
// upload policy's mode ("prefix" or "exact") plus an exemplar key
// for human-readable output (the prefix string or exact key).
//
// The reader is intentionally Stave-free: this program decodes
// obs.v0.1 JSON directly so it can ship as a separate Go module
// (the CGO libz3 link stays out of Stave's vendored tree). The
// schema is self-describing — Stave is not the only reasoner
// that can read it.
func loadUploadPolicy(snapshotsDir string) (mode, exemplar string, err error) {
	entries, err := os.ReadDir(snapshotsDir)
	if err != nil {
		return "", "", fmt.Errorf("read dir %s: %w", snapshotsDir, err)
	}
	// Latest snapshot wins on duplicates: sort filenames
	// (timestamp-named) so the last one read is the most recent.
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(snapshotsDir, name))
		if err != nil {
			return "", "", err
		}
		var snap struct {
			Assets []struct {
				Type       string                 `json:"type"`
				Properties map[string]interface{} `json:"properties"`
			} `json:"assets"`
		}
		if err := json.Unmarshal(raw, &snap); err != nil {
			return "", "", fmt.Errorf("parse %s: %w", name, err)
		}
		for _, a := range snap.Assets {
			if a.Type != "s3_upload_policy" {
				continue
			}
			upload, _ := a.Properties["s3_upload"].(map[string]interface{})
			if upload == nil {
				continue
			}
			mode, _ = upload["allowed_key_mode"].(string)
			if v, ok := upload["allowed_prefix"].(string); ok && v != "" {
				exemplar = v + "*"
			} else if v, ok := upload["allowed_key"].(string); ok && v != "" {
				exemplar = v
			}
			return mode, exemplar, nil
		}
	}
	return "", "", fmt.Errorf("no s3_upload_policy asset found in %s", snapshotsDir)
}

// exampleRoot resolves the sibling fixtures/ directory by walking
// up from this file's package directory (z3prove/) to the parent
// example directory. runtime.Caller anchors the lookup so the
// program works regardless of cwd.
func exampleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller(0) unavailable")
	}
	return filepath.Dir(filepath.Dir(file)), nil
}

