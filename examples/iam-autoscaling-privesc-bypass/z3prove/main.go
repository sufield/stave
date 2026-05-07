// Command z3prove runs three Z3 queries against a
// DataScientist + EMR + DenyPrivEscs IAM configuration
// (the writeup-config) and a remediated version (the deny
// expanded to cover all 9 known compute-launch vectors).
//
// # Three queries
//
// Finding 1 — *Deny coverage gap.* For each of 9 known
// compute-launch vectors, are all the vector's required
// actions effectively permitted (in Allow, not in Deny)?
// The query returns SAT when at least one vector is
// reachable.
//
// Finding 2 — *PassRole reaches an admin role.* The EMR
// policy grants iam:PassRole conditioned on
// `iam:PassedToService` (a service list) but NOT scoped
// to specific role ARNs. Any role that trusts a service
// in that list is passable. demo-EC2Admin trusts
// ec2.amazonaws.com and has AdministratorAccess. Z3 finds
// a witness role.
//
// Finding 3 — *Compound privesc path.* The conjunction of
// Finding 1 (a launch vector available) and Finding 2 (an
// admin-equivalent role passable) and the role's trust
// relationship matching the vector's PassedToService.
//
// # The residual
//
// On the remediated config:
//   Finding 1: UNSAT — all 9 vectors blocked.
//   Finding 2: SAT   — PassRole still scoped only by service.
//   Finding 3: UNSAT — no compound path open today.
//
// Finding 2's residual SAT is the article's central
// teaching beat. The remediated config closes today's
// known vectors but does not address the underlying
// architectural issue: PassRole granted by service is
// vulnerable to every new compute service AWS introduces
// until the deny list is expanded again. Scoping
// PassRole by *role ARN* — not by service — is the
// architecturally sound fix.
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

const (
	dataScientistARN = "arn:aws:iam::111122223333:user/demo-DataScientist"
	adminRoleARN     = "arn:aws:iam::111122223333:role/demo-EC2Admin"
)

type statement struct {
	Effect    string         `json:"Effect"`
	Action    any            `json:"Action"`
	Resource  any            `json:"Resource"`
	Condition map[string]any `json:"Condition,omitempty"`
}

type apiState struct {
	allow         []statement
	deny          []statement
	passRoleStmts []statement
	adminRole     adminRoleInfo
}

type adminRoleInfo struct {
	arn             string
	trustedServices []string
	hasAdmin        bool
}

func main() {
	root, err := exampleRoot()
	if err != nil {
		log.Fatalf("locate example root: %v", err)
	}

	configs := []struct {
		key   string
		label string
		dir   string
	}{
		{"writeup", "writeup-config (DataScientist + EMR + DenyPrivEscs)",
			filepath.Join(root, "fixtures/writeup-config/observations")},
		{"remediated", "remediated-config (deny expanded to all 9 known vectors)",
			filepath.Join(root, "fixtures/remediated-config/observations")},
	}

	allOK := true
	for i, c := range configs {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("========== %s ==========\n", c.label)
		state, err := loadState(c.dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] load: %v\n", c.key, err)
			os.Exit(1)
		}
		ok1 := finding1DenyCoverage(c.key, state)
		fmt.Println()
		ok2 := finding2PassRoleReachesAdmin(c.key, state)
		fmt.Println()
		ok3 := finding3CompoundPath(c.key, state)
		fmt.Println()
		printDenyCoverage(state)
		allOK = allOK && ok1 && ok2 && ok3
	}

	if !allOK {
		os.Exit(1)
	}
}

// finding1DenyCoverage walks every compute-launch vector
// in the registry and asks: "is there a vector whose
// required actions are all in Allow and none in Deny?"
// Z3 search over the vector index.
func finding1DenyCoverage(key string, state apiState) bool {
	available := []int{}
	for i, v := range computeLaunchVectors {
		if vectorEffectivelyAvailable(v, state) {
			available = append(available, i)
		}
	}

	ctx := z3.NewContext(nil)
	intSort := ctx.IntSort()
	req := ctx.IntConst("vector_idx")

	availZ := disjunction(ctx, req, available, intSort)

	s := z3.NewSolver(ctx)
	s.Assert(availZ)
	sat, err := s.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s F1] z3: %v\n", key, err)
		return false
	}

	fmt.Println("--- Finding 1: deny coverage gap ---")
	fmt.Printf("  query:    among %d known compute-launch vectors, is any one\n", len(computeLaunchVectors))
	fmt.Printf("            effectively permitted (Allow ∧ ¬Deny)?\n")
	fmt.Printf("  vectors available: %d / %d\n", len(available), len(computeLaunchVectors))

	expectedSAT := key == "writeup"

	if sat {
		m := s.Model()
		v := m.Eval(req, true)
		idx, _, _ := v.(z3.Int).AsInt64()
		w := computeLaunchVectors[idx]
		fmt.Printf("  verdict:  SAT — witness: %s — %s\n", w.Service, w.Description)
		fmt.Printf("            actions: %v\n", w.RequiredActions)
		fmt.Printf("            (deny does not cover these actions; the path is open)\n")
		return expectedSAT
	}
	fmt.Printf("  verdict:  UNSAT — every known compute-launch vector is denied\n")
	if key == "remediated" {
		fmt.Printf("            (the expanded deny list covers all 9 known vectors today;\n")
		fmt.Printf("             see Finding 2 for the residual structural risk)\n")
	}
	return !expectedSAT
}

// finding2PassRoleReachesAdmin asks: "does the principal's
// PassRole grant reach an admin-equivalent role?"
//
// Witness set: candidate target roles. For each, check
// whether the PassRole condition admits the role's trust
// relationship AND the role has admin permissions.
func finding2PassRoleReachesAdmin(key string, state apiState) bool {
	type witness struct {
		arn      string
		hasAdmin bool
		trusted  []string
	}

	// Single witness — the demo-EC2Admin role from the
	// fixture. A production analyser would enumerate every
	// role in the account; the demo's single witness is
	// sufficient to show the structural issue.
	witnesses := []witness{
		{
			arn:      state.adminRole.arn,
			hasAdmin: state.adminRole.hasAdmin,
			trusted:  state.adminRole.trustedServices,
		},
	}

	reachable := []int{}
	for i, w := range witnesses {
		if !w.hasAdmin {
			continue
		}
		if !passRoleAdmitsTrust(state.passRoleStmts, state.deny, w.trusted) {
			continue
		}
		reachable = append(reachable, i)
	}

	ctx := z3.NewContext(nil)
	intSort := ctx.IntSort()
	req := ctx.IntConst("role_idx")

	reachableZ := disjunction(ctx, req, reachable, intSort)

	s := z3.NewSolver(ctx)
	s.Assert(reachableZ)
	sat, err := s.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s F2] z3: %v\n", key, err)
		return false
	}

	fmt.Println("--- Finding 2: PassRole reaches an admin-equivalent role ---")
	fmt.Printf("  query:    is there an admin role whose trust matches the principal's\n")
	fmt.Printf("            PassRole `iam:PassedToService` condition?\n")
	fmt.Printf("  reachable admin roles: %d / %d\n", len(reachable), len(witnesses))

	// This finding is SAT in BOTH writeup and remediated —
	// the deny expansion does not address the PassRole
	// scoping issue.
	if sat {
		m := s.Model()
		v := m.Eval(req, true)
		idx, _, _ := v.(z3.Int).AsInt64()
		w := witnesses[idx]
		fmt.Printf("  verdict:  SAT — witness: %s\n", w.arn)
		fmt.Printf("            (trusts %v; has AdministratorAccess; PassRole condition\n", w.trusted)
		fmt.Printf("             admits any role trusting one of those services)\n")
		if key == "remediated" {
			fmt.Printf("            **RESIDUAL** — the remediated config closes today's launch\n")
			fmt.Printf("            vectors but does not scope PassRole by role ARN. Any new\n")
			fmt.Printf("            compute service AWS adds becomes an immediate exploit\n")
			fmt.Printf("            path until the deny list is expanded.\n")
		}
		return true
	}
	fmt.Printf("  verdict:  UNSAT — no admin role is reachable via PassRole\n")
	return false
}

// finding3CompoundPath asks: "does there exist a complete
// privesc chain — a launch vector that is available AND
// passes a role trusted by that vector's service AND that
// role is admin?" This is the conjunction of Findings 1
// and 2 with the trust-relationship gate.
func finding3CompoundPath(key string, state apiState) bool {
	// Build a list of (vector, role) pairs that satisfy all
	// three conditions: vector available, role trusts the
	// vector's service, role is admin and PassRole-reachable.
	type compoundIdx struct {
		vectorIdx int
	}
	available := []compoundIdx{}
	for i, v := range computeLaunchVectors {
		if !vectorEffectivelyAvailable(v, state) {
			continue
		}
		if !state.adminRole.hasAdmin {
			continue
		}
		if !contains(state.adminRole.trustedServices, v.PassedToService) {
			continue
		}
		if !passRoleAdmitsTrust(state.passRoleStmts, state.deny, []string{v.PassedToService}) {
			continue
		}
		available = append(available, compoundIdx{vectorIdx: i})
	}

	ctx := z3.NewContext(nil)
	intSort := ctx.IntSort()
	req := ctx.IntConst("compound_idx")

	indices := make([]int, len(available))
	for i := range available {
		indices[i] = i
	}
	availZ := disjunction(ctx, req, indices, intSort)

	s := z3.NewSolver(ctx)
	s.Assert(availZ)
	sat, err := s.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s F3] z3: %v\n", key, err)
		return false
	}

	fmt.Println("--- Finding 3: complete privesc chain ---")
	fmt.Printf("  query:    is there an available compute-launch vector + an admin\n")
	fmt.Printf("            role + a trust relationship that all line up?\n")
	fmt.Printf("  compound paths: %d\n", len(available))

	expectedSAT := key == "writeup"

	if sat {
		m := s.Model()
		v := m.Eval(req, true)
		idx, _, _ := v.(z3.Int).AsInt64()
		c := available[idx]
		vec := computeLaunchVectors[c.vectorIdx]
		fmt.Printf("  verdict:  SAT — witness: vector=%s role=%s\n", vec.Service, state.adminRole.arn)
		fmt.Printf("            chain: %v → role with AdministratorAccess assumed by EC2 →\n",
			vec.RequiredActions)
		fmt.Printf("            principal reads IMDS credentials → admin\n")
		return expectedSAT
	}
	fmt.Printf("  verdict:  UNSAT — no compound privesc path open\n")
	if key == "remediated" {
		fmt.Printf("            (Finding 1 closed all launch vectors; without one of those,\n")
		fmt.Printf("             the PassRole reachability in Finding 2 has nowhere to land)\n")
	}
	return !expectedSAT
}

// printDenyCoverage prints the per-vector verdict matrix
// so the article can quote it directly.
func printDenyCoverage(state apiState) {
	fmt.Println("--- Deny coverage analysis ---")
	for _, v := range computeLaunchVectors {
		denied := actionsAllDenied(v.RequiredActions, state.deny)
		status := "BLOCKED   "
		if !denied {
			status = "NOT BLOCKED"
		}
		fmt.Printf("  %-15s %s : %s\n", v.Service, status, v.Description)
	}
}

// vectorEffectivelyAvailable returns true if every
// required action of the vector is in some Allow statement
// and not in any Deny statement, AND the principal has a
// PassRole grant for the vector's PassedToService.
func vectorEffectivelyAvailable(v computeLaunchVector, state apiState) bool {
	for _, action := range v.RequiredActions {
		if !actionEffectivelyAllowed(action, state) {
			return false
		}
	}
	if !passRoleAdmitsTrust(state.passRoleStmts, state.deny, []string{v.PassedToService}) {
		return false
	}
	return true
}

// actionEffectivelyAllowed returns true if the action is
// permitted by some Allow statement and not blocked by
// any Deny statement.
func actionEffectivelyAllowed(action string, state apiState) bool {
	allowed := false
	for _, st := range state.allow {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		if actionMatches(stringList(st.Action), action) {
			allowed = true
			break
		}
	}
	if !allowed {
		return false
	}
	for _, st := range state.deny {
		if !strings.EqualFold(st.Effect, "Deny") {
			continue
		}
		if actionMatches(stringList(st.Action), action) {
			return false
		}
	}
	return true
}

// actionsAllDenied returns true if every action is
// covered by some Deny statement.
func actionsAllDenied(actions []string, deny []statement) bool {
	for _, action := range actions {
		denied := false
		for _, st := range deny {
			if actionMatches(stringList(st.Action), action) {
				denied = true
				break
			}
		}
		if !denied {
			return false
		}
	}
	return true
}

// passRoleAdmitsTrust returns true if some PassRole Allow
// statement admits a role whose trust relationship
// includes one of the candidate services.
func passRoleAdmitsTrust(passStmts []statement, deny []statement, candidateServices []string) bool {
	// First, ensure iam:PassRole is not denied.
	for _, st := range deny {
		if actionMatches(stringList(st.Action), "iam:PassRole") {
			return false
		}
	}
	for _, st := range passStmts {
		if !actionMatches(stringList(st.Action), "iam:PassRole") {
			continue
		}
		// Check the iam:PassedToService condition (if any).
		condServices := extractPassedToServices(st.Condition)
		if len(condServices) == 0 {
			// Unconditional PassRole admits any service.
			return true
		}
		for _, candidate := range candidateServices {
			for _, cond := range condServices {
				if cond == candidate {
					return true
				}
			}
		}
	}
	return false
}

// extractPassedToServices reads the iam:PassedToService
// service list from a Condition block, if present.
func extractPassedToServices(condition map[string]any) []string {
	if condition == nil {
		return nil
	}
	stringEq, _ := condition["StringEquals"].(map[string]any)
	if stringEq == nil {
		return nil
	}
	v, ok := stringEq["iam:PassedToService"]
	if !ok {
		return nil
	}
	return stringList(v)
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
		if star := strings.Index(a, "*"); star > 0 {
			prefix := a[:star]
			if strings.HasPrefix(witness, prefix) {
				return true
			}
		}
	}
	return false
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

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// loadState reads the snapshot dir, finds the principal
// (aws_iam_user) and the admin role (aws_iam_role),
// extracts and partitions the principal's policy
// statements into allow / deny / passRole sets.
func loadState(snapshotsDir string) (apiState, error) {
	var state apiState
	entries, err := os.ReadDir(snapshotsDir)
	if err != nil {
		return state, err
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
			return state, err
		}
		var snap struct {
			Assets []struct {
				ID         string `json:"id"`
				Type       string `json:"type"`
				Properties struct {
					Identity struct {
						Kind            string   `json:"kind"`
						TrustedServices []string `json:"trusted_services"`
						Policies        struct {
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
			return state, err
		}

		for _, a := range snap.Assets {
			if a.Type == "aws_iam_user" && a.ID == dataScientistARN {
				for _, p := range a.Properties.Identity.Policies.AttachedPolicies {
					for _, st := range p.Statements {
						switch strings.ToUpper(st.Effect) {
						case "ALLOW":
							if actionMatches(stringList(st.Action), "iam:PassRole") {
								state.passRoleStmts = append(state.passRoleStmts, st)
							}
							state.allow = append(state.allow, st)
						case "DENY":
							state.deny = append(state.deny, st)
						}
					}
				}
			}
			if a.Type == "aws_iam_role" && a.ID == adminRoleARN {
				state.adminRole.arn = a.ID
				state.adminRole.trustedServices = a.Properties.Identity.TrustedServices
				for _, p := range a.Properties.Identity.Policies.AttachedPolicies {
					for _, st := range p.Statements {
						actions := stringList(st.Action)
						resources := stringList(st.Resource)
						if strings.EqualFold(st.Effect, "Allow") {
							for _, ac := range actions {
								for _, rc := range resources {
									if ac == "*" && rc == "*" {
										state.adminRole.hasAdmin = true
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return state, nil
}

func exampleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller(0) unavailable")
	}
	return filepath.Dir(filepath.Dir(file)), nil
}
