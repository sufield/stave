// Command z3prove demonstrates Z3-based reachability reasoning
// over the s3-public-list-policy pattern. The CEL example at
// the parent main.go detects the unsafe state ("the bucket's
// public_list fold is true"); this program reads the raw
// bucket policy from storage.policy_json and enumerates
// concrete (principal, action, resource) requests the policy
// admits that fall outside the application's intended access.
//
// # Modelling note
//
// Same int-enum encoding pattern as the other Z3 provers in examples/ (and
// the rest of the Z3-suited iterations). The witnesses are
// named (principal, action, resource) triples encoded as
// integer constants:
//
//	0 = (AppRole,    s3:ListBucket,        bucket)             intended
//	1 = (Principal:*, s3:ListBucket,        bucket)             DANGEROUS (key inventory leak)
//	2 = (Principal:*, s3:ListBucketVersions, bucket)            DANGEROUS (version-history inventory)
//	3 = (Principal:*, s3:GetBucketLocation, bucket)             DANGEROUS (region/metadata leak)
//
// The bucket-level Resource ARN is the bucket itself, not
// `bucket/*` — see the README's authoring note. ListBucket-
// family actions reject statements whose Resource has a
// trailing `/*`; the matcher in this program respects that.
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

type witness struct {
	principal string
	action    string
	resource  string
	intended  bool
	dangerous bool
}

const (
	roleAppARN = "arn:aws:iam::111122223333:role/AcmeArchiveReader"
	bucket     = "arn:aws:s3:::acme-public-archive"
)

var witnesses = []witness{
	{principal: roleAppARN, action: "s3:ListBucket", resource: bucket, intended: true},
	{principal: "*", action: "s3:ListBucket", resource: bucket, dangerous: true},
	{principal: "*", action: "s3:ListBucketVersions", resource: bucket, dangerous: true},
	{principal: "*", action: "s3:GetBucketLocation", resource: bucket, dangerous: true},
}

type statement struct {
	Effect    string `json:"Effect"`
	Principal any    `json:"Principal"`
	Action    any    `json:"Action"`
	Resource  any    `json:"Resource"`
}

type policyDoc struct {
	Statement []statement `json:"Statement"`
}

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
		ok = runProof(filepath.Join(root, "fixtures/before/observations"), "before (Principal:*)") && ok
	}
	if phase == "both" {
		fmt.Println()
	}
	if phase == "after" || phase == "both" {
		ok = runProof(filepath.Join(root, "fixtures/after/observations"), "after  (scoped Principal)") && ok
	}
	if !ok {
		os.Exit(1)
	}
}

func runProof(snapshotsDir, label string) bool {
	statements, err := loadPolicy(snapshotsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] load: %v\n", label, err)
		return false
	}

	admittedIndices := admittedByStatements(statements)

	ctx := z3.NewContext(nil)
	intSort := ctx.IntSort()
	req := ctx.IntConst("request")

	admitted := disjunction(ctx, req, admittedIndices, intSort)
	dangerous := disjunction(ctx, req, dangerousIndices(), intSort)
	intended := disjunction(ctx, req, intendedIndices(), intSort)

	unsafe := admitted.And(dangerous).And(intended.Not())

	s := z3.NewSolver(ctx)
	s.Assert(unsafe)
	sat, err := s.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] z3 check: %v\n", label, err)
		return false
	}

	fmt.Printf("=== %s ===\n", label)
	fmt.Printf("  policy statements: %d\n", len(statements))
	for i, st := range statements {
		fmt.Printf("    [%d] Effect=%s Principal=%v Action=%v Resource=%v\n",
			i, st.Effect, st.Principal, st.Action, st.Resource)
	}
	fmt.Printf("  admitted requests: %d / %d\n", len(admittedIndices), len(witnesses))
	fmt.Printf("  intended scope:    %v\n", indexLabels(intendedIndices()))

	expectSAT := false
	for _, idx := range admittedIndices {
		w := witnesses[idx]
		if w.dangerous && !w.intended {
			expectSAT = true
			break
		}
	}

	if sat {
		m := s.Model()
		v := m.Eval(req, true)
		idx, isLit, ok := v.(z3.Int).AsInt64()
		switch {
		case !ok || !isLit:
			fmt.Printf("  verdict: SAT — anonymous list admitted (witness not extractable)\n")
		case idx >= 0 && int(idx) < len(witnesses):
			w := witnesses[idx]
			fmt.Printf("  verdict: SAT — witness: Principal=%q  Action=%s  Resource=%s\n",
				w.principal, w.action, w.resource)
		default:
			fmt.Printf("  verdict: SAT — witness index=%d (out of label range)\n", idx)
		}
		return expectSAT
	}
	fmt.Printf("  verdict: UNSAT — no anonymous list admitted outside the intended scope\n")
	return !expectSAT
}

func admittedByStatements(statements []statement) []int {
	seen := map[int]struct{}{}
	for _, st := range statements {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		actions := stringList(st.Action)
		resources := stringList(st.Resource)
		for i, w := range witnesses {
			if !principalMatches(st.Principal, w.principal) {
				continue
			}
			if !actionMatches(actions, w.action) {
				continue
			}
			if !resourceMatches(resources, w.resource) {
				continue
			}
			seen[i] = struct{}{}
		}
	}
	out := make([]int, 0, len(seen))
	for i := range seen {
		out = append(out, i)
	}
	sort.Ints(out)
	return out
}

func principalMatches(stmtPrincipal any, witnessPrincipal string) bool {
	switch p := stmtPrincipal.(type) {
	case string:
		return p == "*" || p == witnessPrincipal
	case map[string]any:
		if aws, ok := p["AWS"]; ok {
			for _, arn := range stringList(aws) {
				if arn == "*" || arn == witnessPrincipal {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
}

func actionMatches(stmtActions []string, witness string) bool {
	for _, a := range stmtActions {
		if a == "*" || a == witness {
			return true
		}
		if strings.HasSuffix(a, ":*") {
			service := strings.TrimSuffix(a, ":*")
			if strings.HasPrefix(witness, service+":") {
				return true
			}
		}
	}
	return false
}

// resourceMatches handles the bucket-vs-object ARN distinction
// that ListBucket-family actions impose. ListBucket targets the
// bucket itself (no `/*` suffix); statements written with
// `bucket/*` silently fail to grant listing. The matcher
// rejects a trailing `/*` suffix when the witness Resource
// equals the bucket exactly.
func resourceMatches(stmtResources []string, witness string) bool {
	for _, r := range stmtResources {
		if r == "*" || r == witness {
			return true
		}
		if strings.HasSuffix(r, "/*") {
			prefix := strings.TrimSuffix(r, "/*")
			if strings.HasPrefix(witness, prefix+"/") {
				return true
			}
			// Statements with `bucket/*` do NOT match bucket-level
			// witnesses (the bucket ARN itself).
		}
	}
	return false
}

func intendedIndices() []int {
	out := []int{}
	for i, w := range witnesses {
		if w.intended {
			out = append(out, i)
		}
	}
	return out
}

func dangerousIndices() []int {
	out := []int{}
	for i, w := range witnesses {
		if w.dangerous {
			out = append(out, i)
		}
	}
	return out
}

func indexLabels(idxs []int) []string {
	out := make([]string, 0, len(idxs))
	for _, i := range idxs {
		w := witnesses[i]
		out = append(out, fmt.Sprintf("%s %s %s", w.principal, w.action, w.resource))
	}
	return out
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

func stringList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func loadPolicy(snapshotsDir string) ([]statement, error) {
	entries, err := os.ReadDir(snapshotsDir)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", snapshotsDir, err)
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
			return nil, err
		}
		var snap struct {
			Assets []struct {
				Type       string `json:"type"`
				Properties struct {
					Storage struct {
						PolicyJSON string `json:"policy_json"`
					} `json:"storage"`
				} `json:"properties"`
			} `json:"assets"`
		}
		if err := json.Unmarshal(raw, &snap); err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		for _, a := range snap.Assets {
			if a.Type != "aws_s3_bucket" {
				continue
			}
			if a.Properties.Storage.PolicyJSON == "" {
				continue
			}
			var pol policyDoc
			if err := json.Unmarshal([]byte(a.Properties.Storage.PolicyJSON), &pol); err != nil {
				return nil, fmt.Errorf("parse policy_json: %w", err)
			}
			return pol.Statement, nil
		}
	}
	return nil, fmt.Errorf("no aws_s3_bucket with policy_json found in %s", snapshotsDir)
}

func exampleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller(0) unavailable")
	}
	return filepath.Dir(filepath.Dir(file)), nil
}
