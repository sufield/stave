// Command z3prove demonstrates Z3-based reachability reasoning
// over Rhino Security Labs' privilege-escalation technique #1
// (iam:AttachUserPolicy self-attach). The CEL example at the
// parent main.go detects the unsafe state ("the user has
// iam:AttachUserPolicy on its own ARN"); this program reads the
// raw policy statements, decides whether self-attach is
// admitted, then enumerates the specific managed policies whose
// attachment turns the user into an admin.
//
// # Modelling note
//
// Same int-enum encoding pattern as the other Z3 provers in examples/.
// The witnesses here are AWS managed policy ARNs the user could
// attach to itself if iam:AttachUserPolicy on self is admitted:
//
//	0 = arn:aws:iam::aws:policy/ReadOnlyAccess         intended (no privesc)
//	1 = arn:aws:iam::aws:policy/AdministratorAccess    DANGEROUS (full admin)
//	2 = arn:aws:iam::aws:policy/IAMFullAccess          DANGEROUS (escalate further)
//	3 = arn:aws:iam::aws:policy/PowerUserAccess        DANGEROUS (near-admin)
//
// The Go side walks each Allow statement to decide whether
// iam:AttachUserPolicy with the user's own ARN as Resource is
// admitted. If yes, every witness is admittable (the user can
// attach any managed policy to itself); if no, none are.
//
// Z3 then discharges:
//
//	admitted    = self_attach_admitted ∧ (witness ∈ all_indices)
//	dangerous   = witness ∈ {1, 2, 3}
//	intended    = witness == 0
//	unsafe      = admitted ∧ dangerous ∧ ¬intended
//
// SAT → there exists an admin-granting policy the user can
// attach. The witness is the specific ARN.
// UNSAT → either self-attach is not admitted, or only the
// non-dangerous witness (ReadOnlyAccess) would be admittable.
//
// The model intentionally treats "any managed policy" as the
// admitted set when self-attach is allowed: the full AWS
// managed-policy catalog is in the millions of bytes; a
// production analyser would parse the actual managed-policy
// docs and check which grant admin. The fixture's three named
// AWS-managed admin-granting policies are the demonstration
// surface.
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
	arn       string
	dangerous bool
	intended  bool
}

var witnesses = []witness{
	{arn: "arn:aws:iam::aws:policy/ReadOnlyAccess", intended: true},
	{arn: "arn:aws:iam::aws:policy/AdministratorAccess", dangerous: true},
	{arn: "arn:aws:iam::aws:policy/IAMFullAccess", dangerous: true},
	{arn: "arn:aws:iam::aws:policy/PowerUserAccess", dangerous: true},
}

type statement struct {
	Effect   string `json:"Effect"`
	Action   any    `json:"Action"`
	Resource any    `json:"Resource"`
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
		ok = runProof(filepath.Join(root, "fixtures/before/observations"), "before (self-attach allowed)") && ok
	}
	if phase == "both" {
		fmt.Println()
	}
	if phase == "after" || phase == "both" {
		ok = runProof(filepath.Join(root, "fixtures/after/observations"), "after  (self-attach removed)") && ok
	}
	if !ok {
		os.Exit(1)
	}
}

func runProof(snapshotsDir, label string) bool {
	userArn, statements, err := loadUserPolicies(snapshotsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] load: %v\n", label, err)
		return false
	}

	selfAttach := selfAttachAdmitted(statements, userArn)

	ctx := z3.NewContext(nil)
	intSort := ctx.IntSort()
	pol := ctx.IntConst("policy")

	allIndices := allWitnessIndices()
	dangerous := disjunction(ctx, pol, dangerousIndices(), intSort)
	intended := pol.Eq(ctx.FromInt(0, intSort).(z3.Int))

	var admitted z3.Bool
	if selfAttach {
		admitted = disjunction(ctx, pol, allIndices, intSort)
	} else {
		admitted = ctx.FromBool(false)
	}

	unsafe := admitted.And(dangerous).And(intended.Not())

	s := z3.NewSolver(ctx)
	s.Assert(unsafe)
	sat, err := s.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] z3 check: %v\n", label, err)
		return false
	}

	fmt.Printf("=== %s ===\n", label)
	fmt.Printf("  user: %s\n", userArn)
	fmt.Printf("  policy statements: %d\n", len(statements))
	for i, st := range statements {
		fmt.Printf("    [%d] Effect=%s Action=%v Resource=%v\n",
			i, st.Effect, st.Action, st.Resource)
	}
	fmt.Printf("  iam:AttachUserPolicy on self admitted: %v\n", selfAttach)
	fmt.Printf("  dangerous witnesses: %v\n", arnLabels(dangerousIndices()))

	expectSAT := selfAttach

	if sat {
		m := s.Model()
		v := m.Eval(pol, true)
		idx, isLit, ok := v.(z3.Int).AsInt64()
		switch {
		case !ok || !isLit:
			fmt.Printf("  verdict: SAT — admin-granting policy reachable (witness not extractable)\n")
		case idx >= 0 && int(idx) < len(witnesses):
			fmt.Printf("  verdict: SAT — witness: attach %s → user becomes admin\n", witnesses[idx].arn)
		default:
			fmt.Printf("  verdict: SAT — witness index=%d (out of label range)\n", idx)
		}
		return expectSAT
	}
	fmt.Printf("  verdict: UNSAT — no admin-granting policy is attachable\n")
	return !expectSAT
}

// selfAttachAdmitted returns true if any Allow statement grants
// iam:AttachUserPolicy with a Resource that includes the user's
// own ARN (exact match or wildcard).
func selfAttachAdmitted(statements []statement, userArn string) bool {
	for _, st := range statements {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		if !actionMatches(stringList(st.Action), "iam:AttachUserPolicy") {
			continue
		}
		if !resourceMatches(stringList(st.Resource), userArn) {
			continue
		}
		return true
	}
	return false
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
		}
	}
	return false
}

func allWitnessIndices() []int {
	out := make([]int, len(witnesses))
	for i := range witnesses {
		out[i] = i
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

func arnLabels(idxs []int) []string {
	out := make([]string, 0, len(idxs))
	for _, i := range idxs {
		out = append(out, witnesses[i].arn)
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

// loadUserPolicies returns the IAM user's ARN plus the
// concatenated Allow statements from every attached_policy on
// the user. Decodes obs.v0.1 JSON directly so the program
// runs as a separate Go module.
func loadUserPolicies(snapshotsDir string) (userArn string, statements []statement, err error) {
	entries, err := os.ReadDir(snapshotsDir)
	if err != nil {
		return "", nil, fmt.Errorf("read dir %s: %w", snapshotsDir, err)
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
			return "", nil, err
		}
		var snap struct {
			Assets []struct {
				ID         string `json:"id"`
				Type       string `json:"type"`
				Properties struct {
					Identity struct {
						Kind     string `json:"kind"`
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
			return "", nil, fmt.Errorf("parse %s: %w", name, err)
		}
		for _, a := range snap.Assets {
			if a.Type != "aws_iam_user" {
				continue
			}
			var out []statement
			for _, p := range a.Properties.Identity.Policies.AttachedPolicies {
				out = append(out, p.Statements...)
			}
			return a.ID, out, nil
		}
	}
	return "", nil, fmt.Errorf("no aws_iam_user asset found in %s", snapshotsDir)
}

func exampleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller(0) unavailable")
	}
	return filepath.Dir(filepath.Dir(file)), nil
}
