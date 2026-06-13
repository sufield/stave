// Command z3prove demonstrates Z3-based reachability reasoning
// over the iam-overpermission-wildcard pattern. The CEL example
// at the parent main.go detects the unsafe state ("the role's
// attached policy has a wildcard action on a wildcard
// resource"); this program reads the raw policy statements,
// computes the admitted (action, resource) set, and enumerates
// the specific dangerous-action witnesses the wildcard admits
// outside the role's intended scope.
//
// # Modelling note
//
// Same structural pattern as the other Z3 provers in examples/: aclements/go-z3
// has no string theory, so the search space is encoded as a
// finite enum of named (action, resource) pairs as integer
// constants:
//
//	0 = (s3:GetObject,        app-data-production/input/file.csv)   intended
//	1 = (s3:PutObject,        app-data-production/output/result.json) intended
//	2 = (s3:PutBucketPolicy,  customer-pii-bucket)                   DANGEROUS
//	3 = (s3:DeleteObject,     billing-archives/jan-2026.csv)         DANGEROUS
//	4 = (s3:PutBucketAcl,     audit-logs-bucket)                     DANGEROUS
//
// Constraint encoding:
//
//	admitted_by_policy(req)    derived from the role's statements
//	in_intended_scope(req)     req in {0, 1}
//	is_dangerous(req)          req in {2, 3, 4}
//	unsafe = admitted ∧ is_dangerous ∧ ¬in_intended_scope
//
// SAT → there exists a dangerous action the role can perform
// outside its intended scope; the model returns the witness
// index, the program prints the (action, resource) pair.
// UNSAT → every admitted action is in the intended scope.
//
// The "admitted" predicate is computed from the policy's actual
// statements:
//   - Action "s3:*" admits every s3:* witness (broad).
//   - Specific actions admit only matching witnesses.
//   - Resource "*" admits every resource; specific ARNs admit
//     only resources whose ARN starts with the prefix.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/aclements/go-z3/z3"
)

type witness struct {
	action      string
	resource    string
	resourceArn string // ARN form for prefix matching
	dangerous   bool
	intended    bool
}

var witnesses = []witness{
	{
		action:      "s3:GetObject",
		resource:    "app-data-production/input/file.csv",
		resourceArn: "arn:aws:s3:::app-data-production/input/file.csv",
		intended:    true,
	},
	{
		action:      "s3:PutObject",
		resource:    "app-data-production/output/result.json",
		resourceArn: "arn:aws:s3:::app-data-production/output/result.json",
		intended:    true,
	},
	{
		action:      "s3:PutBucketPolicy",
		resource:    "customer-pii-bucket",
		resourceArn: "arn:aws:s3:::customer-pii-bucket",
		dangerous:   true,
	},
	{
		action:      "s3:DeleteObject",
		resource:    "billing-archives/jan-2026.csv",
		resourceArn: "arn:aws:s3:::billing-archives/jan-2026.csv",
		dangerous:   true,
	},
	{
		action:      "s3:PutBucketAcl",
		resource:    "audit-logs-bucket",
		resourceArn: "arn:aws:s3:::audit-logs-bucket",
		dangerous:   true,
	},
}

type statement struct {
	Effect   string `json:"Effect"`
	Action   any    `json:"Action"`   // string OR []string
	Resource any    `json:"Resource"` // string OR []string
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
		ok = runProof(filepath.Join(root, "fixtures/before/observations"), "before (s3:* on *)") && ok
	}
	if phase == "both" {
		fmt.Println()
	}
	if phase == "after" || phase == "both" {
		ok = runProof(filepath.Join(root, "fixtures/after/observations"), "after  (scoped actions + ARNs)") && ok
	}
	if phase == "both" {
		fmt.Println()
	}
	if phase == "bybit-pattern-before" || phase == "both" {
		ok = runBybitProof(filepath.Join(root, "fixtures/bybit-pattern-before/observations"),
			"bybit-pattern-before (developer with s3:PutObject on company-frontend-*)",
			true) && ok
	}
	if phase == "both" {
		fmt.Println()
	}
	if phase == "bybit-pattern-after" || phase == "both" {
		ok = runBybitProof(filepath.Join(root, "fixtures/bybit-pattern-after/observations"),
			"bybit-pattern-after  (developer split: read-only on prod, full on dev)",
			false) && ok
	}
	if !ok {
		os.Exit(1)
	}
}

func runProof(snapshotsDir, label string) bool {
	statements, err := loadStatements(snapshotsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] load: %v\n", label, err)
		return false
	}

	// Compute which witness indices the policy admits, by walking
	// each statement and checking action+resource match.
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
		fmt.Printf("    [%d] Effect=%s Action=%v Resource=%v\n",
			i, st.Effect, st.Action, st.Resource)
	}
	fmt.Printf("  admitted requests: %d / %d\n", len(admittedIndices), len(witnesses))
	fmt.Printf("  intended scope:    %v\n", indexLabels(intendedIndices()))
	fmt.Printf("  dangerous set:     %v\n", indexLabels(dangerousIndices()))

	expectSAT := false
	for _, idx := range admittedIndices {
		if witnesses[idx].dangerous && !witnesses[idx].intended {
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
			fmt.Printf("  verdict: SAT — dangerous request admitted (witness not extractable)\n")
		case idx >= 0 && int(idx) < len(witnesses):
			w := witnesses[idx]
			fmt.Printf("  verdict: SAT — witness: %s on %s\n", w.action, w.resource)
		default:
			fmt.Printf("  verdict: SAT — witness index=%d (out of label range)\n", idx)
		}
		return expectSAT
	}
	fmt.Printf("  verdict: UNSAT — no dangerous action admitted outside intended scope\n")
	return !expectSAT
}

// admittedByStatements walks each Allow statement and collects
// the witness indices whose action + resource match.
func admittedByStatements(statements []statement) []int {
	seen := map[int]struct{}{}
	for _, st := range statements {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		actions := stringList(st.Action)
		resources := stringList(st.Resource)
		for i, w := range witnesses {
			if !actionMatches(actions, w.action) {
				continue
			}
			if !resourceMatches(resources, w.resourceArn) {
				continue
			}
			seen[i] = struct{}{}
		}
	}
	out := make([]int, 0, len(seen))
	for i := range seen {
		out = append(out, i)
	}
	slices.Sort(out)
	return out
}

// actionMatches returns true if any of the statement's actions
// covers the witness action. Handles "s3:*" / "*" wildcards.
func actionMatches(stmtActions []string, witness string) bool {
	for _, a := range stmtActions {
		if a == "*" || a == witness {
			return true
		}
		// service:* form, e.g. "s3:*" matches any "s3:Foo".
		if strings.HasSuffix(a, ":*") {
			service := strings.TrimSuffix(a, ":*")
			if strings.HasPrefix(witness, service+":") {
				return true
			}
		}
	}
	return false
}

// resourceMatches returns true if any of the statement's
// resource patterns covers the witness ARN. Handles "*" and
// trailing-"*" wildcards (e.g. "arn:aws:s3:::bucket/*").
func resourceMatches(stmtResources []string, witness string) bool {
	for _, r := range stmtResources {
		if r == "*" {
			return true
		}
		if strings.HasSuffix(r, "/*") {
			prefix := strings.TrimSuffix(r, "/*")
			if strings.HasPrefix(witness, prefix+"/") {
				return true
			}
		}
		if r == witness {
			return true
		}
	}
	return false
}

func dangerousIndices() []int {
	var out []int
	for i, w := range witnesses {
		if w.dangerous {
			out = append(out, i)
		}
	}
	return out
}

func intendedIndices() []int {
	var out []int
	for i, w := range witnesses {
		if w.intended {
			out = append(out, i)
		}
	}
	return out
}

func indexLabels(idxs []int) []string {
	out := make([]string, 0, len(idxs))
	for _, i := range idxs {
		out = append(out, witnesses[i].action+" → "+witnesses[i].resource)
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

// loadStatements reads the snapshot directory and returns the
// concatenated Allow statements from every attached_policy on
// the IAM role asset. Decodes obs.v0.1 JSON directly so the
// program runs as a separate Go module (libz3 stays out of the
// stave vendored tree).
func loadStatements(snapshotsDir string) ([]statement, error) {
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
	slices.Sort(names)

	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(snapshotsDir, name))
		if err != nil {
			return nil, err
		}
		var snap struct {
			Assets []struct {
				Type       string `json:"type"`
				Properties struct {
					Identity struct {
						Policies struct {
							AttachedPolicies []struct {
								Name       string      `json:"name"`
								Statements []statement `json:"statements"`
							} `json:"attached_policies"`
						} `json:"policies"`
					} `json:"identity"`
				} `json:"properties"`
			} `json:"assets"`
		}
		if err := json.Unmarshal(raw, &snap); err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		for _, a := range snap.Assets {
			if a.Type != "aws_iam_role" && a.Type != "aws_iam_user" {
				continue
			}
			var out []statement
			for _, p := range a.Properties.Identity.Policies.AttachedPolicies {
				out = append(out, p.Statements...)
			}
			if len(out) > 0 {
				return out, nil
			}
		}
	}
	return nil, fmt.Errorf("no IAM role with attached_policies found in %s", snapshotsDir)
}

func exampleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller(0) unavailable")
	}
	return filepath.Dir(filepath.Dir(file)), nil
}
