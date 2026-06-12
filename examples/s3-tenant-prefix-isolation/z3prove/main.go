// Command z3prove demonstrates Z3-based reachability reasoning
// over the s3-tenant-prefix-isolation pattern. The CEL example
// at the parent directory's main.go detects the unsafe
// configuration ("the app-signer doesn't enforce per-tenant
// prefix"); this program enumerates a concrete cross-tenant
// request the signer admits but the application's intended
// access pattern excludes.
//
// # Modelling note
//
// Same constraint as the other go-z3 provers in examples/: the aclements/go-z3 binding does
// not expose Z3's string theory, so the search space is encoded
// as a finite enum of named witness requests. Each request is a
// (requesting_tenant, target_key) pair encoded as an integer:
//
//	0 = (tenant=A, target="tenants/A/photo.png")        intended
//	1 = (tenant=A, target="tenants/B/photo.png")        cross-tenant
//	2 = (tenant=A, target="tenants/A/../B/secret.json") path traversal
//
// Constraint encoding:
//
//	admitted = key ∈ admitted_set            depends on signer flags
//	intended = (key == 0)                    each tenant only its own prefix
//	unsafe   = admitted AND NOT intended
//
// Permissive signer (enforce_prefix=false OR allow_traversal=true):
// admitted_set = {0, 1, 2}, so unsafe is SAT.
// Strict signer (enforce_prefix=true allow_traversal=false):
// admitted_set = {0}, so unsafe is UNSAT.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/aclements/go-z3/z3"
)

var witnessLabels = []string{
	"tenant=A → tenants/A/photo.png",
	"tenant=A → tenants/B/photo.png",
	"tenant=A → tenants/A/../B/secret.json",
}

const (
	idxOwnPrefix   = 0
	idxCrossTenant = 1
	idxTraversal   = 2
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
		ok = runProof(filepath.Join(root, "fixtures/before/observations"), "before (signer permissive)") && ok
	}
	if phase == "both" {
		fmt.Println()
	}
	if phase == "after" || phase == "both" {
		ok = runProof(filepath.Join(root, "fixtures/after/observations"), "after  (signer enforced)") && ok
	}
	if !ok {
		os.Exit(1)
	}
}

func runProof(snapshotsDir, label string) bool {
	purpose, err := loadSignerPurpose(snapshotsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] load: %v\n", label, err)
		return false
	}
	enforcePrefix := !strings.Contains(purpose, "enforce_prefix=false")
	allowTraversal := strings.Contains(purpose, "allow_traversal=true")

	ctx := z3.NewContext(nil)
	intSort := ctx.IntSort()
	key := ctx.IntConst("request")

	admittedIndices := indicesAdmittedBy(enforcePrefix, allowTraversal)
	admitted := disjunction(ctx, key, admittedIndices, intSort)

	intendedKey := ctx.FromInt(int64(idxOwnPrefix), intSort).(z3.Int)
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
	fmt.Printf("  signer purpose: %s\n", purpose)
	fmt.Printf("  flags: enforce_prefix=%v   allow_traversal=%v\n",
		enforcePrefix, allowTraversal)
	fmt.Printf("  admitted set: %v\n", labelsForIndices(admittedIndices))
	fmt.Printf("  intended set: [%q]\n", witnessLabels[idxOwnPrefix])

	expectSAT := !enforcePrefix || allowTraversal

	if sat {
		m := s.Model()
		v := m.Eval(key, true)
		idx, isLit, ok := v.(z3.Int).AsInt64()
		switch {
		case !ok || !isLit:
			fmt.Printf("  verdict: SAT — admitted request falls outside intended set (witness not extractable)\n")
		case idx >= 0 && int(idx) < witnessCount:
			fmt.Printf("  verdict: SAT — witness request: %s\n", witnessLabels[idx])
		default:
			fmt.Printf("  verdict: SAT — witness index=%d (out of label range)\n", idx)
		}
		return expectSAT
	}
	fmt.Printf("  verdict: UNSAT — every admitted request is intended\n")
	return !expectSAT
}

func indicesAdmittedBy(enforcePrefix, allowTraversal bool) []int {
	switch {
	case !enforcePrefix:
		// Signer does not check the request's target prefix at
		// all — every witness is admitted.
		return []int{idxOwnPrefix, idxCrossTenant, idxTraversal}
	case allowTraversal:
		// Signer enforces the requesting tenant's prefix at
		// signing time, but does not normalize ".." — the
		// traversal request is still signed cleanly.
		return []int{idxOwnPrefix, idxTraversal}
	default:
		return []int{idxOwnPrefix}
	}
}

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

// loadSignerPurpose reads the snapshot directory and returns
// the app_signer identity's purpose string. The reader decodes
// obs.v0.1 JSON directly so the program can ship as a separate
// Go module with no Stave dependency.
func loadSignerPurpose(snapshotsDir string) (string, error) {
	entries, err := os.ReadDir(snapshotsDir)
	if err != nil {
		return "", fmt.Errorf("read dir %s: %w", snapshotsDir, err)
	}
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
			return "", err
		}
		var snap struct {
			Identities []struct {
				Type       string         `json:"type"`
				Properties map[string]any `json:"properties"`
			} `json:"identities"`
		}
		if err := json.Unmarshal(raw, &snap); err != nil {
			return "", fmt.Errorf("parse %s: %w", name, err)
		}
		for _, idn := range snap.Identities {
			if idn.Type != "app_signer" {
				continue
			}
			if p, ok := idn.Properties["purpose"].(string); ok {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("no app_signer identity found in %s", snapshotsDir)
}

func exampleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller(0) unavailable")
	}
	return filepath.Dir(filepath.Dir(file)), nil
}
