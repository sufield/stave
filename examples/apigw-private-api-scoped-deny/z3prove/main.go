// Command z3prove runs four Z3 queries against the private
// API Gateway configuration from a published tutorial
// (writeup-config) plus a "broadened-allow" variant that
// demonstrates how a single common developer change turns
// the writeup's safe-but-fragile design into an unsafe one.
//
// # Four queries
//
// Finding 1a — *Resource pattern alignment* on the writeup
// config. The Allow and Deny statements both use
// `execute-api:/prod/GET/*`. Z3 asks: is there a
// (stage, method) pair that the Allow covers but the Deny
// does not? Expected: UNSAT (patterns are aligned).
//
// Finding 1b — *Resource pattern alignment* on the
// broadened-allow variant. A developer adds a new stage and
// widens the Allow to `execute-api:/*` but leaves the Deny
// at `execute-api:/prod/GET/*`. Z3 finds a witness:
// `execute-api:/dev/POST/...` is allowed without any VPC
// restriction. Expected: SAT.
//
// Finding 2 — *VPC-wide vs endpoint-specific*. The Deny
// condition uses `aws:sourceVpc` instead of
// `aws:sourceVpce`. Z3 asks: is there a VPC endpoint in the
// same VPC that is NOT the intended endpoint, but reaches
// the API anyway? Expected: SAT — any other endpoint in the
// VPC satisfies `aws:sourceVpc`, so the Deny does not apply
// and the Allow does.
//
// Finding 3 — *No authorization + VPC-wide*. The API method
// uses `--authorization-type NONE`. Combined with Finding 2,
// this means any workload in the VPC reaches the API
// without any auth check. Expected: SAT, witness identical
// to Finding 2 plus auth=NONE.
//
// All four queries return UNSAT on the remediated config:
// patterns aligned, sourceVpce instead of sourceVpc, and
// AWS_IAM authorization.
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
	intendedVpc        = "vpc-0b52ca08e7db8531f"
	intendedVpcEndpoint = "vpce-0abc123def456789"
)

type statement struct {
	Effect    string         `json:"Effect"`
	Sid       string         `json:"Sid,omitempty"`
	Principal any            `json:"Principal"`
	Action    any            `json:"Action"`
	Resource  any            `json:"Resource"`
	Condition map[string]any `json:"Condition,omitempty"`
}

type policyDoc struct {
	Statement []statement `json:"Statement"`
}

func main() {
	root, err := exampleRoot()
	if err != nil {
		log.Fatalf("locate example root: %v", err)
	}

	allOK := true

	configs := []struct {
		key   string
		label string
		dir   string
	}{
		{"writeup", "writeup-config (sourceVpc + identical Resource patterns)",
			filepath.Join(root, "fixtures/writeup-config/observations")},
		{"broadened", "broadened-allow (developer widens Allow)",
			filepath.Join(root, "fixtures/broadened-allow/observations")},
		{"remediated", "remediated-config (sourceVpce + aligned + IAM auth)",
			filepath.Join(root, "fixtures/remediated-config/observations")},
	}

	for i, c := range configs {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("========== %s ==========\n", c.label)
		state, err := loadAPIConfig(c.dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] load: %v\n", c.key, err)
			os.Exit(1)
		}

		ok1 := finding1ResourcePatternMismatch(c.key, state)
		fmt.Println()
		ok2 := finding2VpcWideAccess(c.key, state)
		fmt.Println()
		ok3 := finding3NoAuthCompound(c.key, state)

		allOK = allOK && ok1 && ok2 && ok3
	}

	if !allOK {
		os.Exit(1)
	}
}

type apiState struct {
	statements         []statement
	authorizationType  string
}

// finding1ResourcePatternMismatch asks: "is there a (stage,
// method, path) tuple that the Allow statement covers but
// the Deny statement does not?"
//
// Witness set: enumerated (stage, method) tuples spanning
// the common shapes a developer might add (prod GET,
// dev POST, prod POST, etc.). Each witness's resource is
// constructed as `execute-api:/STAGE/METHOD/...`.
func finding1ResourcePatternMismatch(key string, state apiState) bool {
	type witness struct {
		stage    string
		method   string
		resource string
	}
	witnesses := []witness{
		{"prod", "GET", "execute-api:/prod/GET/time"},
		{"prod", "POST", "execute-api:/prod/POST/users"},
		{"dev", "GET", "execute-api:/dev/GET/health"},
		{"dev", "POST", "execute-api:/dev/POST/users/create"},
		{"staging", "PUT", "execute-api:/staging/PUT/config"},
	}

	// Find the Allow and Deny statements. We treat the first
	// matching statement of each effect; the writeup's policy
	// is small enough that this is exact.
	var allowResources, denyResources []string
	for _, st := range state.statements {
		switch strings.ToUpper(st.Effect) {
		case "ALLOW":
			if allowResources == nil {
				allowResources = stringList(st.Resource)
			}
		case "DENY":
			if denyResources == nil {
				denyResources = stringList(st.Resource)
			}
		}
	}

	allowedIdx := []int{}
	deniedIdx := []int{}
	for i, w := range witnesses {
		if resourceMatches(allowResources, w.resource) {
			allowedIdx = append(allowedIdx, i)
		}
		if resourceMatches(denyResources, w.resource) {
			deniedIdx = append(deniedIdx, i)
		}
	}

	ctx := z3.NewContext(nil)
	intSort := ctx.IntSort()
	req := ctx.IntConst("witness_idx")

	allowedZ := disjunction(ctx, req, allowedIdx, intSort)
	deniedZ := disjunction(ctx, req, deniedIdx, intSort)
	unsafe := allowedZ.And(deniedZ.Not())

	s := z3.NewSolver(ctx)
	s.Assert(unsafe)
	sat, err := s.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s F1] z3: %v\n", key, err)
		return false
	}

	label := "1a"
	if key == "broadened" {
		label = "1b"
	}
	fmt.Printf("--- Finding %s: Allow/Deny resource pattern alignment ---\n", label)
	fmt.Printf("  query:    is there a witness the Allow admits but the Deny does not?\n")
	fmt.Printf("  Allow Resource: %v\n", allowResources)
	fmt.Printf("  Deny  Resource: %v\n", denyResources)
	fmt.Printf("  admitted by Allow: %d / %d   blocked by Deny: %d / %d\n",
		len(allowedIdx), len(witnesses), len(deniedIdx), len(witnesses))

	expectedSAT := key == "broadened"

	if sat {
		m := s.Model()
		v := m.Eval(req, true)
		idx, _, _ := v.(z3.Int).AsInt64()
		w := witnesses[idx]
		fmt.Printf("  verdict:  SAT — witness: stage=%s method=%s resource=%s\n",
			w.stage, w.method, w.resource)
		if key == "broadened" {
			fmt.Printf("            (Allow widened to execute-api:/* — Deny still scoped\n")
			fmt.Printf("             to /prod/GET/*, so this resource is allowed without\n")
			fmt.Printf("             any VPC restriction)\n")
		}
		return expectedSAT
	}
	fmt.Printf("  verdict:  UNSAT — every witness the Allow admits is also blocked by the Deny\n")
	if key == "writeup" {
		fmt.Printf("            (patterns are currently aligned; this becomes a SAT the\n")
		fmt.Printf("             moment either pattern is changed independently — see the\n")
		fmt.Printf("             broadened-allow variant below)\n")
	}
	return !expectedSAT
}

// finding2VpcWideAccess asks: "is there a VPC endpoint in
// the same VPC that is NOT the intended endpoint, but the
// resource policy admits it (because the Deny condition
// uses aws:sourceVpc which any endpoint in the VPC
// satisfies)?"
func finding2VpcWideAccess(key string, state apiState) bool {
	type witness struct {
		vpcEndpoint string
		intended    bool
	}
	witnesses := []witness{
		{vpcEndpoint: intendedVpcEndpoint, intended: true},
		{vpcEndpoint: "vpce-0999888777666555"},
		{vpcEndpoint: "vpce-0abcdefabcdefabcd"},
		{vpcEndpoint: "vpce-0deadbeef00112233"},
	}

	// All these endpoints are in the same VPC
	// (vpc-0b52ca08e7db8531f). For each, check whether the
	// Deny statement's condition fails to apply (i.e., the
	// endpoint is NOT denied). If the Deny doesn't apply, the
	// unconditional Allow does, and the witness reaches the
	// API.

	denyByes := []int{} // witnesses NOT denied
	for i, w := range witnesses {
		denied := false
		for _, st := range state.statements {
			if !strings.EqualFold(st.Effect, "Deny") {
				continue
			}
			if !appliesToWitness(st.Condition, w.vpcEndpoint, intendedVpc) {
				continue
			}
			denied = true
			break
		}
		if !denied {
			denyByes = append(denyByes, i)
		}
	}

	ctx := z3.NewContext(nil)
	intSort := ctx.IntSort()
	req := ctx.IntConst("vpce_idx")

	intendedIdx := []int{}
	for i, w := range witnesses {
		if w.intended {
			intendedIdx = append(intendedIdx, i)
		}
	}

	notDeniedZ := disjunction(ctx, req, denyByes, intSort)
	intendedZ := disjunction(ctx, req, intendedIdx, intSort)
	unsafe := notDeniedZ.And(intendedZ.Not())

	s := z3.NewSolver(ctx)
	s.Assert(unsafe)
	sat, err := s.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s F2] z3: %v\n", key, err)
		return false
	}

	fmt.Println("--- Finding 2: aws:sourceVpc vs aws:sourceVpce ---")
	fmt.Printf("  query:    is there a non-intended VPC endpoint in vpc that the\n")
	fmt.Printf("            policy still admits (Deny does not apply)?\n")
	fmt.Printf("  endpoints not blocked by Deny: %d / %d\n",
		len(denyByes), len(witnesses))

	expectedSAT := key != "remediated"

	if sat {
		m := s.Model()
		v := m.Eval(req, true)
		idx, _, _ := v.(z3.Int).AsInt64()
		w := witnesses[idx]
		fmt.Printf("  verdict:  SAT — witness: %s (in %s, NOT %s)\n",
			w.vpcEndpoint, intendedVpc, intendedVpcEndpoint)
		fmt.Printf("            (Deny condition uses aws:sourceVpc which matches every\n")
		fmt.Printf("             endpoint in the VPC, not just the intended one)\n")
		return expectedSAT
	}
	fmt.Printf("  verdict:  UNSAT — only the intended endpoint reaches the API\n")
	if key == "remediated" {
		fmt.Printf("            (Deny condition uses aws:sourceVpce, scoping to the\n")
		fmt.Printf("             specific endpoint ID)\n")
	}
	return !expectedSAT
}

// finding3NoAuthCompound asks: "is there a request with no
// authorization (auth_type=NONE) AND a non-intended VPC
// endpoint that reaches the API?" This is the compound of
// Finding 2 with the lack of an authorization layer.
func finding3NoAuthCompound(key string, state apiState) bool {
	hasNoAuth := strings.EqualFold(state.authorizationType, "NONE")

	fmt.Println("--- Finding 3: no authorization + VPC-wide access (compound) ---")
	fmt.Printf("  query:    is there a request that reaches the API with no auth\n")
	fmt.Printf("            check AND from a non-intended VPC endpoint?\n")
	fmt.Printf("  authorization_type: %s\n", state.authorizationType)

	if !hasNoAuth {
		// IAM auth is enforced; even if Finding 2 had been SAT,
		// requests must be SigV4-signed by an authorized
		// principal. For the demo we treat the compound
		// finding as gated on hasNoAuth.
		fmt.Printf("  verdict:  UNSAT — authorization requires SigV4-signed callers\n")
		fmt.Printf("            (the resource policy is no longer the sole control)\n")
		return key == "remediated"
	}

	// hasNoAuth is true → reduces to Finding 2. Re-encode in
	// Z3 and look for a witness.
	type witness struct {
		vpcEndpoint string
		intended    bool
	}
	witnesses := []witness{
		{vpcEndpoint: intendedVpcEndpoint, intended: true},
		{vpcEndpoint: "vpce-0999888777666555"},
		{vpcEndpoint: "vpce-0abcdefabcdefabcd"},
	}
	denyByes := []int{}
	for i, w := range witnesses {
		denied := false
		for _, st := range state.statements {
			if !strings.EqualFold(st.Effect, "Deny") {
				continue
			}
			if !appliesToWitness(st.Condition, w.vpcEndpoint, intendedVpc) {
				continue
			}
			denied = true
			break
		}
		if !denied {
			denyByes = append(denyByes, i)
		}
	}

	ctx := z3.NewContext(nil)
	intSort := ctx.IntSort()
	req := ctx.IntConst("vpce_idx_compound")

	intendedIdx := []int{}
	for i, w := range witnesses {
		if w.intended {
			intendedIdx = append(intendedIdx, i)
		}
	}

	notDeniedZ := disjunction(ctx, req, denyByes, intSort)
	intendedZ := disjunction(ctx, req, intendedIdx, intSort)
	unsafe := notDeniedZ.And(intendedZ.Not())

	s := z3.NewSolver(ctx)
	s.Assert(unsafe)
	sat, err := s.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s F3] z3: %v\n", key, err)
		return false
	}

	expectedSAT := key != "remediated"

	if sat {
		m := s.Model()
		v := m.Eval(req, true)
		idx, _, _ := v.(z3.Int).AsInt64()
		w := witnesses[idx]
		fmt.Printf("  verdict:  SAT — witness: %s reaches the API with auth=NONE\n",
			w.vpcEndpoint)
		fmt.Printf("            (no IAM/Lambda authorizer to catch the resource-policy gap)\n")
		return expectedSAT
	}
	fmt.Printf("  verdict:  UNSAT — no compound path open\n")
	return !expectedSAT
}

// appliesToWitness returns true if the Deny statement's
// Condition causes the deny to fire for a request from
// `witnessVpce` in `witnessVpc`. The Condition is a
// `StringNotEquals` map keyed by either `aws:sourceVpc`
// (which fails to fire when the request IS from that VPC)
// or `aws:sourceVpce` (which fails to fire only when the
// request IS from that specific endpoint).
//
// Returns true when the Deny applies (request is denied);
// false when the condition doesn't trigger and the Deny is
// inert.
func appliesToWitness(condition map[string]any, witnessVpce, witnessVpc string) bool {
	if condition == nil {
		// Unconditional Deny applies to every request.
		return true
	}
	stringNotEq, _ := condition["StringNotEquals"].(map[string]any)
	if stringNotEq == nil {
		return true
	}
	if v, ok := stringNotEq["aws:sourceVpc"]; ok {
		expected, _ := v.(string)
		// StringNotEquals: deny applies when sourceVpc !=
		// expected. The witness's source vpc is witnessVpc.
		return witnessVpc != expected
	}
	if v, ok := stringNotEq["aws:sourceVpce"]; ok {
		expected, _ := v.(string)
		return witnessVpce != expected
	}
	return true
}

// --- Shared matcher helpers ---

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
		// Glob with embedded star: "execute-api:/prod/GET/*"
		if star := strings.Index(r, "*"); star > 0 {
			prefix := r[:star]
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

// loadAPIConfig reads the snapshot directory, finds the
// aws_apigateway_rest_api asset, parses the resource policy
// and reads the authorization type.
func loadAPIConfig(snapshotsDir string) (apiState, error) {
	var state apiState
	entries, err := os.ReadDir(snapshotsDir)
	if err != nil {
		return state, fmt.Errorf("read dir %s: %w", snapshotsDir, err)
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
				Type       string `json:"type"`
				Properties struct {
					API struct {
						Network struct {
							ResourcePolicyJSON       string `json:"resource_policy_json"`
							DefaultAuthorizationType string `json:"default_authorization_type"`
						} `json:"network"`
					} `json:"api"`
				} `json:"properties"`
			} `json:"assets"`
		}
		if err := json.Unmarshal(raw, &snap); err != nil {
			return state, fmt.Errorf("parse %s: %w", name, err)
		}
		for _, a := range snap.Assets {
			if a.Type != "aws_apigateway_rest_api" {
				continue
			}
			n := a.Properties.API.Network
			if n.ResourcePolicyJSON == "" {
				continue
			}
			var pol policyDoc
			if err := json.Unmarshal([]byte(n.ResourcePolicyJSON), &pol); err != nil {
				return state, fmt.Errorf("parse resource_policy_json: %w", err)
			}
			state.statements = pol.Statement
			state.authorizationType = n.DefaultAuthorizationType
			return state, nil
		}
	}
	return state, fmt.Errorf("no aws_apigateway_rest_api with resource_policy_json found")
}

func exampleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller(0) unavailable")
	}
	return filepath.Dir(filepath.Dir(file)), nil
}
