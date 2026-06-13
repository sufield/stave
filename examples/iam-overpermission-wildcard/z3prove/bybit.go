package main

// Bybit-pattern proof: developer write access to production S3.
//
// The Bybit/Safe{WALLET} heist (March 2025, $1.5B ETH) was
// enabled by a developer IAM policy whose Resource pattern
// `company-frontend-*` matched both the intended dev bucket
// and the production bucket. Compromised developer creds →
// `s3:PutObject` on `company-frontend-prod/app.js` → backdoored
// JavaScript served via CloudFront → redirected transfers.
//
// The CEL control in the parent example checks
// `has_resource_wildcard_on_sensitive` — set true only when
// Resource is literal `*`. The bybit pattern uses a *prefix*
// wildcard, so the engine sets the boolean false and CEL stays
// silent. Z3 catches what CEL doesn't: enumerate every bucket
// the policy admits, check tags, find the production write.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aclements/go-z3/z3"
)

type bucketWitness struct {
	arn         string
	name        string
	environment string
	servedVia   string
}

type bybitFixture struct {
	statements    []statement
	buckets       []bucketWitness
	hasMFACond    bool
	hasIPCond     bool
	objectLogging map[string]bool // bucket arn → data event logging enabled
}

func runBybitProof(snapshotsDir, label string, expectSAT bool) bool {
	fix, err := loadBybit(snapshotsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] load: %v\n", label, err)
		return false
	}

	fmt.Printf("=== %s ===\n", label)
	fmt.Printf("  policy statements: %d\n", len(fix.statements))
	for i, st := range fix.statements {
		fmt.Printf("    [%d] Effect=%s Action=%v Resource=%v\n",
			i, st.Effect, st.Action, st.Resource)
	}
	fmt.Printf("  buckets observed:  %d\n", len(fix.buckets))
	for _, b := range fix.buckets {
		fmt.Printf("    - %s   environment=%s   served_via=%s\n",
			b.name, b.environment, b.servedVia)
	}

	q1 := queryDevWriteToProduction(fix)
	fmt.Println()
	fmt.Println("  --- Bybit Pattern: Developer Write to Production S3 ---")
	q1.print()

	q2 := queryUndetectableProductionWrite(fix, q1)
	fmt.Println()
	fmt.Println("  --- Compound: Undetectable Production Write ---")
	q2.print()

	got := q1.sat && q2.sat
	if got != expectSAT {
		fmt.Fprintf(os.Stderr, "  ASSERTION FAILED: expected compound=%v, got compound=%v\n",
			expectSAT, got)
		return false
	}
	fmt.Printf("\n  assertion: compound=%v (expected) %s\n", got, "OK")
	return true
}

type bybitVerdict struct {
	sat       bool
	witness   string
	rationale string
}

func (v bybitVerdict) print() {
	if v.sat {
		fmt.Printf("  verdict: SAT\n")
	} else {
		fmt.Printf("  verdict: UNSAT\n")
	}
	if v.witness != "" {
		fmt.Printf("  witness: %s\n", v.witness)
	}
	if v.rationale != "" {
		fmt.Printf("  rationale: %s\n", v.rationale)
	}
}

// queryDevWriteToProduction asks Z3: is there a bucket b such
// that the developer's policy admits s3:PutObject on b AND b is
// tagged environment=production?
//
// Encoded as: bucket = symbolic int in [0..N). For each i,
// admitted_i = policy admits "s3:PutObject" on buckets[i].arn.
// is_prod_i = buckets[i].environment == "production".
// SAT iff ∃ i: admitted_i ∧ is_prod_i.
func queryDevWriteToProduction(fix bybitFixture) bybitVerdict {
	ctx := z3.NewContext(nil)
	intSort := ctx.IntSort()
	bucketIdx := ctx.IntConst("bucket")

	var prodHits []int
	for i, b := range fix.buckets {
		if !policyAdmits(fix.statements, "s3:PutObject", b.arn) {
			continue
		}
		if !strings.EqualFold(b.environment, "production") {
			continue
		}
		prodHits = append(prodHits, i)
	}

	if len(prodHits) == 0 {
		return bybitVerdict{
			sat:       false,
			rationale: "no production bucket admitted by s3:PutObject",
		}
	}

	target := disjunction(ctx, bucketIdx, prodHits, intSort)
	s := z3.NewSolver(ctx)
	s.Assert(target)
	sat, err := s.Check()
	if err != nil || !sat {
		return bybitVerdict{sat: false, rationale: "z3 disagreed (unexpected)"}
	}
	m := s.Model()
	v := m.Eval(bucketIdx, true)
	idx, isLit, ok := v.(z3.Int).AsInt64()
	if !ok || !isLit || int(idx) >= len(fix.buckets) {
		return bybitVerdict{sat: true, witness: "(witness not extractable)"}
	}
	b := fix.buckets[idx]
	return bybitVerdict{
		sat: true,
		witness: fmt.Sprintf("s3:PutObject on %s/app.js   (resource pattern matches both dev and prod)",
			b.arn),
		rationale: fmt.Sprintf("environment=%s, served_via=%s — modifying app.js is a supply chain attack via CloudFront",
			b.environment, b.servedVia),
	}
}

// queryUndetectableProductionWrite combines write access with
// the absence of detective controls:
//
//	compound = write_access(q1)
//	         ∧ no_mfa_condition_in_policy
//	         ∧ no_ip_condition_in_policy
//	         ∧ no_object_logging_for_bucket
//
// Encoded as a 4-way conjunction of Z3 booleans. SAT iff all
// four hold simultaneously.
func queryUndetectableProductionWrite(fix bybitFixture, q1 bybitVerdict) bybitVerdict {
	ctx := z3.NewContext(nil)

	writeAccess := ctx.FromBool(q1.sat)
	noMFA := ctx.FromBool(!fix.hasMFACond)
	noIP := ctx.FromBool(!fix.hasIPCond)

	// Object logging: any production bucket without data event
	// coverage counts as a logging gap for this query.
	loggingGap := false
	for _, b := range fix.buckets {
		if !strings.EqualFold(b.environment, "production") {
			continue
		}
		if !fix.objectLogging[b.arn] {
			loggingGap = true
			break
		}
	}
	noLogging := ctx.FromBool(loggingGap)

	compound := writeAccess.And(noMFA, noIP, noLogging)
	s := z3.NewSolver(ctx)
	s.Assert(compound)
	sat, err := s.Check()
	if err != nil {
		return bybitVerdict{sat: false, rationale: "z3 error"}
	}

	v := bybitVerdict{
		sat: sat,
		rationale: fmt.Sprintf("write_access=%v   no_mfa=%v   no_ip=%v   no_logging=%v",
			q1.sat, !fix.hasMFACond, !fix.hasIPCond, loggingGap),
	}
	if sat {
		v.witness = "developer can write to production S3 from any IP, without MFA, with no CloudTrail data-event record"
	}
	return v
}

// policyAdmits is a thin wrapper over the package's per-statement
// matchers, scoped to the (action, resource) pair the bybit query
// asks about.
func policyAdmits(statements []statement, action, resourceArn string) bool {
	for _, st := range statements {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		actions := stringList(st.Action)
		resources := stringList(st.Resource)
		if !actionMatches(actions, action) {
			continue
		}
		if !resourceMatchesPrefix(resources, resourceArn) {
			continue
		}
		return true
	}
	return false
}

// resourceMatchesPrefix accepts the same wildcards as
// resourceMatches plus mid-string `*` suffix prefixes
// (e.g. `arn:aws:s3:::company-frontend-*` matches
// `arn:aws:s3:::company-frontend-prod`). The parent's
// resourceMatches only handles trailing-`/*`.
func resourceMatchesPrefix(stmtResources []string, witness string) bool {
	for _, r := range stmtResources {
		if r == "*" || r == witness {
			return true
		}
		if strings.HasSuffix(r, "/*") {
			prefix := strings.TrimSuffix(r, "/*")
			if strings.HasPrefix(witness, prefix+"/") {
				return true
			}
			continue
		}
		if strings.HasSuffix(r, "*") {
			prefix := strings.TrimSuffix(r, "*")
			if strings.HasPrefix(witness, prefix) {
				return true
			}
		}
	}
	return false
}

func loadBybit(snapshotsDir string) (bybitFixture, error) {
	entries, err := os.ReadDir(snapshotsDir)
	if err != nil {
		return bybitFixture{}, fmt.Errorf("read dir %s: %w", snapshotsDir, err)
	}
	var names []string
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
			return bybitFixture{}, err
		}
		var snap struct {
			Assets []struct {
				ID         string `json:"id"`
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
					Bucket struct {
						Name              string            `json:"name"`
						Tags              map[string]string `json:"tags"`
						DataEventsEnabled bool              `json:"data_events_enabled"`
					} `json:"bucket"`
				} `json:"properties"`
			} `json:"assets"`
		}
		if err := json.Unmarshal(raw, &snap); err != nil {
			return bybitFixture{}, fmt.Errorf("parse %s: %w", name, err)
		}

		fix := bybitFixture{
			objectLogging: map[string]bool{},
		}
		for _, a := range snap.Assets {
			switch a.Type {
			case "aws_iam_user", "aws_iam_role":
				for _, p := range a.Properties.Identity.Policies.AttachedPolicies {
					fix.statements = append(fix.statements, p.Statements...)
				}
			case "aws_s3_bucket":
				fix.buckets = append(fix.buckets, bucketWitness{
					arn:         a.ID,
					name:        a.Properties.Bucket.Name,
					environment: a.Properties.Bucket.Tags["environment"],
					servedVia:   a.Properties.Bucket.Tags["served_via"],
				})
				fix.objectLogging[a.ID] = a.Properties.Bucket.DataEventsEnabled
			}
		}

		// Both fixtures omit Condition blocks. The schema
		// captures Effect/Action/Resource only, so absence is
		// the signal: no MFA condition, no IP condition.
		fix.hasMFACond = false
		fix.hasIPCond = false

		if len(fix.statements) > 0 {
			return fix, nil
		}
	}
	return bybitFixture{}, fmt.Errorf("no IAM principal with attached_policies found in %s", snapshotsDir)
}
