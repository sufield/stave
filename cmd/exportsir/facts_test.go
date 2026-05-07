package exportsir

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/sir"
)

// fixtureDoc returns a small SIR document covering each fact
// category the projection emits. Stable across calls so tests
// can assert byte-identical output.
func fixtureDoc() *sir.Document {
	t := time.Date(2026, 5, 7, 0, 0, 0, 0, time.UTC)
	return &sir.Document{
		Controls: []sir.ControlFact{
			{
				ID:              "CTL.S3.PUBLIC.005",
				Type:            "unsafe_state",
				Severity:        "medium",
				IntentRationale: "Latent public read is a misconfiguration that becomes a breach when PAB is removed.",
				ForbiddenState: &sir.PredicateFact{
					Logic: "all",
					Rules: []sir.RuleFact{{Field: "properties.storage.access.public_read", Operator: "eq", Value: true}},
				},
			},
			{
				ID:       "CTL.IAM.POLICY.RESOURCE.WILDCARD.001",
				Type:     "unsafe_state",
				Severity: "high",
			},
		},
		Assets: []sir.AssetFact{
			{
				ID:     "arn:aws:s3:::company-data",
				Type:   "aws_s3_bucket",
				Vendor: "aws",
				Lifecycle: &sir.AssetLifecycleFact{
					FirstSeen:   t,
					LastSeen:    t.Add(168 * time.Hour),
					Provisioned: true,
				},
			},
		},
		Identities: []sir.IdentityFact{
			{
				PrincipalID: "arn:aws:iam::111122223333:role/AppRole",
				RoleChains: []sir.RoleChainFact{
					{
						FinalRoleARN:    "arn:aws:iam::444455556666:role/Admin",
						TransitiveLevel: "admin",
						Hops: []sir.RoleHopFact{
							{
								From:         "arn:aws:iam::111122223333:role/AppRole",
								To:           "arn:aws:iam::444455556666:role/Admin",
								CrossAccount: true,
								HopType:      "assume_role",
							},
						},
					},
				},
			},
		},
		Temporal: sir.TemporalFacts{
			Windows: []sir.ExposureWindow{
				{
					AssetID:                "arn:aws:s3:::company-data",
					Start:                  t,
					End:                    t.Add(168 * time.Hour),
					UnsafePredicateMatched: true,
					ContributingControls:   []string{"CTL.S3.PUBLIC.005"},
				},
			},
		},
		EvaluatedAt: t.Add(168 * time.Hour),
	}
}

// TestExtractFacts_CoversAllCategories asserts that the
// projection emits at least one fact per category (control,
// asset, lifecycle, role_chain, exposure). When new SIR fact
// kinds land they should produce new triples here.
func TestExtractFacts_CoversAllCategories(t *testing.T) {
	t.Parallel()
	facts := extractFacts(fixtureDoc())

	categories := make(map[string]int)
	for _, f := range facts {
		categories[f.Source]++
	}
	for _, want := range []string{"control", "asset", "lifecycle", "role_chain", "exposure"} {
		if categories[want] == 0 {
			t.Errorf("no facts emitted for category %q (counts=%v)", want, categories)
		}
	}
}

// TestExtractFacts_EmitsCrossAccountTriple confirms the role
// chain hop projection emits the cross-account flag as its own
// triple — Datalog/ASP consumers can branch on it directly.
func TestExtractFacts_EmitsCrossAccountTriple(t *testing.T) {
	t.Parallel()
	facts := extractFacts(fixtureDoc())
	for _, f := range facts {
		if f.Predicate == "cross_account_assumes" &&
			f.Subject == "arn:aws:iam::111122223333:role/AppRole" &&
			f.Object == "arn:aws:iam::444455556666:role/Admin" {
			return
		}
	}
	t.Errorf("cross_account_assumes triple missing; facts=%v", facts)
}

// TestSerializeJSONL_OneFactPerLine confirms the JSONL format:
// every line decodes to a Fact and the count matches the slice.
func TestSerializeJSONL_OneFactPerLine(t *testing.T) {
	t.Parallel()
	facts := extractFacts(fixtureDoc())
	var buf bytes.Buffer
	if err := serializeJSONL(facts, &buf); err != nil {
		t.Fatalf("serializeJSONL: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != len(facts) {
		t.Fatalf("line count = %d, fact count = %d", len(lines), len(facts))
	}
	for i, line := range lines {
		var f Fact
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Errorf("line %d not valid JSON: %v (line=%q)", i, err, line)
		}
		if f.Subject == "" || f.Predicate == "" || f.Object == "" {
			t.Errorf("line %d missing required field: %+v", i, f)
		}
	}
}

// TestSerializeJSONL_Deterministic asserts the same SIR yields
// byte-identical JSONL across runs. Triple consumers diff
// outputs across snapshots; non-determinism breaks that.
func TestSerializeJSONL_Deterministic(t *testing.T) {
	t.Parallel()
	a := extractFacts(fixtureDoc())
	b := extractFacts(fixtureDoc())
	var bufA, bufB bytes.Buffer
	if err := serializeJSONL(a, &bufA); err != nil {
		t.Fatalf("a: %v", err)
	}
	if err := serializeJSONL(b, &bufB); err != nil {
		t.Fatalf("b: %v", err)
	}
	if bufA.String() != bufB.String() {
		t.Errorf("JSONL output differs across runs:\nA=%q\nB=%q", bufA.String(), bufB.String())
	}
}

// TestSerializeSMT2_FactsOnlyNoQueries asserts the spec's hard
// rule: the file emits declarations + assertions but never
// (check-sat), (get-model), or query-shape constructs.
// Reasoning programs append those; the facts file stays
// solver-agnostic.
func TestSerializeSMT2_FactsOnlyNoQueries(t *testing.T) {
	t.Parallel()
	facts := extractFacts(fixtureDoc())
	var buf bytes.Buffer
	if err := serializeSMT2(facts, &buf); err != nil {
		t.Fatalf("serializeSMT2: %v", err)
	}
	body := buf.String()
	for _, banned := range []string{"(check-sat)", "(get-model)", "(get-unsat-core)", "(get-proof)"} {
		if strings.Contains(body, banned) {
			t.Errorf("SMT-LIB output contains %q — facts file must carry no queries", banned)
		}
	}
}

// TestSerializeSMT2_DeclaresEachPredicate confirms every
// predicate appearing in facts is also declared upstream as a
// (declare-fun ... Bool). SMT solvers reject undeclared symbols.
func TestSerializeSMT2_DeclaresEachPredicate(t *testing.T) {
	t.Parallel()
	facts := extractFacts(fixtureDoc())
	var buf bytes.Buffer
	if err := serializeSMT2(facts, &buf); err != nil {
		t.Fatalf("serializeSMT2: %v", err)
	}
	body := buf.String()
	for _, p := range uniquePredicates(facts) {
		decl := "(declare-fun " + p + " (String String) Bool)"
		if !strings.Contains(body, decl) {
			t.Errorf("missing declaration for predicate %q", p)
		}
	}
}

// TestSerializeSMT2_QuotesEmbeddedDoubles asserts the SMT-LIB
// v2.6 string-escape rule: embedded " characters double up.
// ARNs don't carry quotes today but the rule applies to any
// future asset whose ID is allowed to contain them.
func TestSerializeSMT2_QuotesEmbeddedDoubles(t *testing.T) {
	t.Parallel()
	got := smt2Quote(`weird"name`)
	want := `"weird""name"`
	if got != want {
		t.Errorf("smt2Quote escape: got %q, want %q", got, want)
	}
}

// TestSerializeSMT2_DeclaresBaselinePredicates asserts that every
// baseline predicate is declared in the output even when no fact
// of that type appears in this fixture. This is what makes
// queries portable across fixtures: the after-fixture (where the
// overpermission control did not fire) still has
// has_exposure_window declared so a query referencing it parses
// correctly.
func TestSerializeSMT2_DeclaresBaselinePredicates(t *testing.T) {
	t.Parallel()
	// Use an empty fact set deliberately: zero facts produced by
	// the projection should still yield a complete declaration
	// header.
	var buf bytes.Buffer
	if err := serializeSMT2(nil, &buf); err != nil {
		t.Fatalf("serializeSMT2: %v", err)
	}
	body := buf.String()
	for _, p := range baselineSMT2Predicates {
		decl := "(declare-fun " + p + " (String String) Bool)"
		if !strings.Contains(body, decl) {
			t.Errorf("baseline predicate %q not declared on empty fact set", p)
		}
	}
}

// TestSerializeSMT2_ClosedWorldAxiomsPresent confirms each
// declared predicate has a forall-axiom restricting it to the
// asserted facts. Without these axioms, queries against the
// open-world default would be trivially SAT.
func TestSerializeSMT2_ClosedWorldAxiomsPresent(t *testing.T) {
	t.Parallel()
	facts := extractFacts(fixtureDoc())
	var buf bytes.Buffer
	if err := serializeSMT2(facts, &buf); err != nil {
		t.Fatalf("serializeSMT2: %v", err)
	}
	body := buf.String()
	for _, p := range baselineSMT2Predicates {
		// Every predicate should appear in at least one forall
		// axiom — either as the negative-everywhere form (no
		// facts) or the disjunctive (=> (P x y) (or ...)) form.
		marker := "(forall ((x String) (y String))"
		if !strings.Contains(body, marker) {
			t.Fatalf("no forall axioms found in output (broken serializer)")
		}
		if !strings.Contains(body, p) {
			t.Errorf("predicate %q absent from output entirely", p)
		}
	}
}

// TestClosedWorldAxiom_EmptyTuples confirms the predicate-false-
// everywhere form when the projection produced no facts of the
// given type — the after-fixture case for the overpermission
// control's exposure_window predicate.
func TestClosedWorldAxiom_EmptyTuples(t *testing.T) {
	t.Parallel()
	got := closedWorldAxiom("has_exposure_window", nil)
	want := "(assert (forall ((x String) (y String)) (not (has_exposure_window x y))))"
	if got != want {
		t.Errorf("empty axiom mismatch:\ngot:  %q\nwant: %q", got, want)
	}
}

// TestClosedWorldAxiom_SingleTuple confirms the single-disjunct
// form: a predicate with exactly one fact gets a (=> (P x y)
// (and (= x A) (= y B))) axiom — no surrounding (or ...) wrapper.
func TestClosedWorldAxiom_SingleTuple(t *testing.T) {
	t.Parallel()
	tuples := []Fact{{Subject: "ARN", Predicate: "has_severity", Object: "high"}}
	got := closedWorldAxiom("has_severity", tuples)
	want := `(assert (forall ((x String) (y String)) (=> (has_severity x y) (and (= x "ARN") (= y "high")))))`
	if got != want {
		t.Errorf("single-tuple axiom mismatch:\ngot:  %q\nwant: %q", got, want)
	}
}

// cognitoFixture returns a synthetic SIR document that exercises
// the new chain-edge extractors: a Cognito identity pool
// allowing unauthenticated identities, mapped to an IAM role
// with broad S3 access. The shape mirrors the iter-16
// cognito-self-register fixture's writeup-config.
func cognitoFixture() *sir.Document {
	return &sir.Document{
		Assets: []sir.AssetFact{
			{
				ID:   "arn:aws:cognito-identity:us-east-1:111122223333:identitypool/us-east-1:abc",
				Type: "aws_cognito_identity_pool",
				Properties: map[string]any{
					"identity": map[string]any{
						"identity_pool": map[string]any{
							"allow_unauthenticated_identities": true,
							"unauthenticated_role_arn":         "arn:aws:iam::111122223333:role/UnauthRole",
							"authenticated_role_arn":           "arn:aws:iam::111122223333:role/AuthRole",
						},
					},
				},
			},
			{
				ID:   "arn:aws:iam::111122223333:role/UnauthRole",
				Type: "aws_iam_role",
				Properties: map[string]any{
					"identity": map[string]any{
						"policies": map[string]any{
							"attached_policies": []any{
								map[string]any{
									"statements": []any{
										map[string]any{
											"Effect":   "Allow",
											"Action":   []any{"s3:GetObject", "s3:ListBucket"},
											"Resource": []any{"arn:aws:s3:::app-data", "arn:aws:s3:::app-data/*"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// TestCognitoMappingFacts_EmitsChainEdges asserts the new
// cognito-pool extractor emits the three chain-relevant facts
// (allows_unauthenticated, maps_unauth_to, maps_auth_to) when
// the source pool has them populated. Without these facts, no
// chain query from "anonymous Cognito session → IAM role" is
// expressible.
func TestCognitoMappingFacts_EmitsChainEdges(t *testing.T) {
	t.Parallel()
	facts := extractFacts(cognitoFixture())
	want := map[string]string{
		"allows_unauthenticated": "true",
		"maps_unauth_to":         "arn:aws:iam::111122223333:role/UnauthRole",
		"maps_auth_to":           "arn:aws:iam::111122223333:role/AuthRole",
	}
	for pred, obj := range want {
		found := false
		for _, f := range facts {
			if f.Predicate == pred && f.Object == obj {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing %s fact with object %q", pred, obj)
		}
	}
}

// TestCognitoMappingFacts_OmitsNegativeCase confirms the
// remediated-config shape: when allow_unauthenticated_identities
// is false, no positive `allows_unauthenticated` fact is
// emitted. The closed-world axiom then restricts the predicate
// to false everywhere — which is what makes the chain query
// UNSAT on the safe fixture.
func TestCognitoMappingFacts_OmitsNegativeCase(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "pool",
			Type: "aws_cognito_identity_pool",
			Properties: map[string]any{
				"identity": map[string]any{
					"identity_pool": map[string]any{
						"allow_unauthenticated_identities": false,
					},
				},
			},
		}},
	}
	for _, f := range extractFacts(doc) {
		if f.Predicate == "allows_unauthenticated" {
			t.Errorf("unexpected positive allows_unauthenticated fact when source is false: %+v", f)
		}
	}
}

// TestIAMPolicyFacts_EmitsActionsAndResources walks an IAM role
// with one Allow statement that lists multiple actions and
// resources; every (action, resource) cross-product appears as
// separate has_action / has_resource facts. The over-
// approximation is intentional: chain queries get reachability
// without action↔resource binding.
func TestIAMPolicyFacts_EmitsActionsAndResources(t *testing.T) {
	t.Parallel()
	facts := extractFacts(cognitoFixture())
	wantActions := map[string]bool{"s3:GetObject": false, "s3:ListBucket": false}
	wantResources := map[string]bool{
		"arn:aws:s3:::app-data":   false,
		"arn:aws:s3:::app-data/*": false,
	}
	for _, f := range facts {
		if f.Subject != "arn:aws:iam::111122223333:role/UnauthRole" {
			continue
		}
		switch f.Predicate {
		case "has_action":
			if _, ok := wantActions[f.Object]; ok {
				wantActions[f.Object] = true
			}
		case "has_resource":
			if _, ok := wantResources[f.Object]; ok {
				wantResources[f.Object] = true
			}
		}
	}
	for a, found := range wantActions {
		if !found {
			t.Errorf("missing has_action %q on UnauthRole", a)
		}
	}
	for r, found := range wantResources {
		if !found {
			t.Errorf("missing has_resource %q on UnauthRole", r)
		}
	}
}

// TestTrustPolicyFacts_EmitsServicePrincipals confirms each
// entry in properties.identity.trusted_services projects to a
// `trusts_service` fact. The compound query
// "overpermission finding AND assumable by compute service"
// pivots on this predicate; without it the chain is silent
// even on roles whose trust policy clearly admits Lambda /
// EC2 / etc.
func TestTrustPolicyFacts_EmitsServicePrincipals(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "arn:aws:iam::111122223333:role/LambdaRole",
			Type: "aws_iam_role",
			Properties: map[string]any{
				"identity": map[string]any{
					"trusted_services": []any{
						"lambda.amazonaws.com",
						"ecs-tasks.amazonaws.com",
					},
				},
			},
		}},
	}
	facts := extractFacts(doc)
	want := map[string]bool{
		"lambda.amazonaws.com":    false,
		"ecs-tasks.amazonaws.com": false,
	}
	for _, f := range facts {
		if f.Predicate != "trusts_service" {
			continue
		}
		if _, ok := want[f.Object]; ok {
			want[f.Object] = true
		}
	}
	for svc, found := range want {
		if !found {
			t.Errorf("missing trusts_service fact for %q", svc)
		}
	}
}

// TestTrustPolicyFacts_SkipsNonRoleAssets asserts the
// extractor only fires on aws_iam_role. A bucket or Lambda
// function with a stray "trusted_services" key shouldn't
// produce trust policy facts — those are role-only.
func TestTrustPolicyFacts_SkipsNonRoleAssets(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "arn:aws:s3:::confused-asset",
			Type: "aws_s3_bucket",
			Properties: map[string]any{
				"identity": map[string]any{
					"trusted_services": []any{"lambda.amazonaws.com"},
				},
			},
		}},
	}
	for _, f := range extractFacts(doc) {
		if f.Predicate == "trusts_service" {
			t.Errorf("trusts_service fact leaked from non-role asset: %+v", f)
		}
	}
}

// TestIAMPolicyFacts_SkipsDeny confirms the extractor ignores
// non-Allow effects. A Deny statement should produce no facts;
// otherwise chain queries asking "does role R allow action A"
// get false positives from Deny grants.
func TestIAMPolicyFacts_SkipsDeny(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "role",
			Type: "aws_iam_role",
			Properties: map[string]any{
				"identity": map[string]any{
					"policies": map[string]any{
						"attached_policies": []any{
							map[string]any{
								"statements": []any{
									map[string]any{
										"Effect": "Deny", "Action": "s3:*", "Resource": "*",
									},
								},
							},
						},
					},
				},
			},
		}},
	}
	for _, f := range extractFacts(doc) {
		if f.Predicate == "has_action" || f.Predicate == "has_resource" {
			t.Errorf("Deny statement leaked into has_action/has_resource: %+v", f)
		}
	}
}
