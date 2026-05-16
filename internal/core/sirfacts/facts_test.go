package sirfacts

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
	facts := ExtractFacts(fixtureDoc())

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
	facts := ExtractFacts(fixtureDoc())
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
	facts := ExtractFacts(fixtureDoc())
	var buf bytes.Buffer
	if err := SerializeJSONL(facts, &buf); err != nil {
		t.Fatalf("SerializeJSONL: %v", err)
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
	a := ExtractFacts(fixtureDoc())
	b := ExtractFacts(fixtureDoc())
	var bufA, bufB bytes.Buffer
	if err := SerializeJSONL(a, &bufA); err != nil {
		t.Fatalf("a: %v", err)
	}
	if err := SerializeJSONL(b, &bufB); err != nil {
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
	facts := ExtractFacts(fixtureDoc())
	var buf bytes.Buffer
	if err := SerializeSMT2(facts, &buf); err != nil {
		t.Fatalf("SerializeSMT2: %v", err)
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
	facts := ExtractFacts(fixtureDoc())
	var buf bytes.Buffer
	if err := SerializeSMT2(facts, &buf); err != nil {
		t.Fatalf("SerializeSMT2: %v", err)
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
	if err := SerializeSMT2(nil, &buf); err != nil {
		t.Fatalf("SerializeSMT2: %v", err)
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
	facts := ExtractFacts(fixtureDoc())
	var buf bytes.Buffer
	if err := SerializeSMT2(facts, &buf); err != nil {
		t.Fatalf("SerializeSMT2: %v", err)
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
	facts := ExtractFacts(cognitoFixture())
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
	for _, f := range ExtractFacts(doc) {
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
	facts := ExtractFacts(cognitoFixture())
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
	facts := ExtractFacts(doc)
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

// TestTagFacts_EmitsKeyEqualsValue confirms the binary
// has_tag encoding: each (key, value) pair in any depth-2
// tags block becomes one fact with object "key=value". The
// concatenation lets a binary serializer carry tag data
// without ternary support; queries write
// (has_tag bucket "environment=production").
func TestTagFacts_EmitsKeyEqualsValue(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{
			{
				ID:   "arn:aws:s3:::prod-bucket",
				Type: "aws_s3_bucket",
				Properties: map[string]any{
					"bucket": map[string]any{
						"tags": map[string]any{
							"environment":         "production",
							"data_classification": "confidential",
						},
					},
				},
			},
		},
	}
	want := map[string]bool{
		"environment=production":           false,
		"data_classification=confidential": false,
	}
	for _, f := range ExtractFacts(doc) {
		if f.Predicate != "has_tag" {
			continue
		}
		if _, ok := want[f.Object]; ok {
			want[f.Object] = true
		}
	}
	for k, found := range want {
		if !found {
			t.Errorf("missing has_tag fact %q", k)
		}
	}
}

// TestTagFacts_WalksMultipleBlockNames confirms the extractor
// catches tags regardless of which top-level property block
// holds them. The bybit fixture uses properties.bucket.tags;
// older S3 controls use properties.storage.tags; IAM uses
// properties.identity.tags. One scan, all conventions.
func TestTagFacts_WalksMultipleBlockNames(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "weird-asset",
			Type: "aws_s3_bucket",
			Properties: map[string]any{
				"bucket":   map[string]any{"tags": map[string]any{"in_bucket": "yes"}},
				"storage":  map[string]any{"tags": map[string]any{"in_storage": "yes"}},
				"identity": map[string]any{"tags": map[string]any{"in_identity": "yes"}},
			},
		}},
	}
	want := map[string]bool{
		"in_bucket=yes":   false,
		"in_storage=yes":  false,
		"in_identity=yes": false,
	}
	for _, f := range ExtractFacts(doc) {
		if f.Predicate != "has_tag" {
			continue
		}
		if _, ok := want[f.Object]; ok {
			want[f.Object] = true
		}
	}
	for k, found := range want {
		if !found {
			t.Errorf("missing has_tag fact %q from multi-block walk", k)
		}
	}
}

// TestTagFacts_DeterministicOrder asserts the same SIR
// document yields byte-identical has_tag facts across runs.
// Go map iteration is randomised; the extractor sorts keys
// before emission so external goldens stay stable.
func TestTagFacts_DeterministicOrder(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "asset",
			Type: "aws_s3_bucket",
			Properties: map[string]any{
				"bucket": map[string]any{
					"tags": map[string]any{
						"zzz": "1", "aaa": "2", "mmm": "3", "kkk": "4",
					},
				},
			},
		}},
	}
	var seq1, seq2 []string
	for _, f := range ExtractFacts(doc) {
		if f.Predicate == "has_tag" {
			seq1 = append(seq1, f.Object)
		}
	}
	for _, f := range ExtractFacts(doc) {
		if f.Predicate == "has_tag" {
			seq2 = append(seq2, f.Object)
		}
	}
	if len(seq1) != len(seq2) {
		t.Fatalf("len mismatch: %d vs %d", len(seq1), len(seq2))
	}
	for i := range seq1 {
		if seq1[i] != seq2[i] {
			t.Errorf("non-deterministic tag order at %d: %q vs %q", i, seq1[i], seq2[i])
		}
	}
}

// TestCognitoUserPoolFacts_EmitsUnsafeOnly confirms the
// extractor's polarity: it emits self_registration_unrestricted
// ONLY when the source `self_registration_restricted` is false
// (the unsafe state), and stays silent when restricted=true or
// the field is absent. The closed-world axiom then correctly
// reports the predicate false on every pool that doesn't
// explicitly admit self-registration.
func TestCognitoUserPoolFacts_EmitsUnsafeOnly(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{
			{
				ID:   "pool-unsafe",
				Type: "aws_cognito_user_pool",
				Properties: map[string]any{
					"identity": map[string]any{
						"governance": map[string]any{
							"self_registration_restricted": false,
						},
					},
				},
			},
			{
				ID:   "pool-safe",
				Type: "aws_cognito_user_pool",
				Properties: map[string]any{
					"identity": map[string]any{
						"governance": map[string]any{
							"self_registration_restricted": true,
						},
					},
				},
			},
			{
				ID:   "pool-no-governance",
				Type: "aws_cognito_user_pool",
				Properties: map[string]any{
					"identity": map[string]any{},
				},
			},
		},
	}
	facts := ExtractFacts(doc)
	var subjects []string
	for _, f := range facts {
		if f.Predicate == "self_registration_unrestricted" {
			subjects = append(subjects, f.Subject)
		}
	}
	if len(subjects) != 1 || subjects[0] != "pool-unsafe" {
		t.Errorf("self_registration_unrestricted facts = %v, want exactly [pool-unsafe]", subjects)
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
	for _, f := range ExtractFacts(doc) {
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
	for _, f := range ExtractFacts(doc) {
		if f.Predicate == "has_action" || f.Predicate == "has_resource" {
			t.Errorf("Deny statement leaked into has_action/has_resource: %+v", f)
		}
	}
}

// TestAssumeEdgeFacts_EmitsWhenBothSidesAgree pins the both-sides
// requirement: a `can_assume(from, to)` fact emerges only when
// the assumer's policy grants sts:AssumeRole on the target AND
// the target's trust_policy_json admits the assumer. Either side
// alone is insufficient — that's the IAM resolver's contract,
// preserved here so SMT-side reasoning matches kernel-side
// reasoning.
func TestAssumeEdgeFacts_EmitsWhenBothSidesAgree(t *testing.T) {
	t.Parallel()
	const userARN = "arn:aws:iam::111122223333:user/dev"
	const roleARN = "arn:aws:iam::111122223333:role/onboarding"
	doc := &sir.Document{
		Assets: []sir.AssetFact{
			{
				ID:   userARN,
				Type: "aws_iam_user",
				Properties: map[string]any{
					"identity": map[string]any{
						"policies": map[string]any{
							"attached_policies": []any{
								map[string]any{
									"statements": []any{
										map[string]any{
											"Effect":   "Allow",
											"Action":   "sts:AssumeRole",
											"Resource": roleARN,
										},
									},
								},
							},
						},
					},
				},
			},
			{
				ID:   roleARN,
				Type: "aws_iam_role",
				Properties: map[string]any{
					"identity": map[string]any{
						"trust_policy_json": `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"` + userARN + `"}}]}`,
					},
				},
			},
		},
	}
	var found bool
	for _, f := range ExtractFacts(doc) {
		if f.Predicate == "can_assume" && f.Subject == userARN && f.Object == roleARN {
			found = true
		}
	}
	if !found {
		t.Errorf("expected can_assume(%s, %s); not emitted", userARN, roleARN)
	}
}

// TestAssumeEdgeFacts_AsymmetricNoEmit pins the negative path:
// when the target's trust policy does NOT admit the assumer, no
// can_assume fact emerges, even if the assumer's policy grants
// sts:AssumeRole on the target. Mirrors the IAM resolver's
// requirement for reciprocal trust.
func TestAssumeEdgeFacts_AsymmetricNoEmit(t *testing.T) {
	t.Parallel()
	const userARN = "arn:aws:iam::111122223333:user/dev"
	const roleARN = "arn:aws:iam::111122223333:role/onboarding"
	const otherARN = "arn:aws:iam::111122223333:user/someone-else"
	doc := &sir.Document{
		Assets: []sir.AssetFact{
			{
				ID:   userARN,
				Type: "aws_iam_user",
				Properties: map[string]any{
					"identity": map[string]any{
						"policies": map[string]any{
							"attached_policies": []any{
								map[string]any{
									"statements": []any{
										map[string]any{
											"Effect":   "Allow",
											"Action":   "sts:AssumeRole",
											"Resource": roleARN,
										},
									},
								},
							},
						},
					},
				},
			},
			{
				ID:   roleARN,
				Type: "aws_iam_role",
				Properties: map[string]any{
					"identity": map[string]any{
						// Trust admits a different principal — assumer is unauthorized.
						"trust_policy_json": `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"` + otherARN + `"}}]}`,
					},
				},
			},
		},
	}
	for _, f := range ExtractFacts(doc) {
		if f.Predicate == "can_assume" && f.Subject == userARN && f.Object == roleARN {
			t.Errorf("can_assume should NOT be emitted without reciprocal trust; got %+v", f)
		}
	}
}

// TestAssumeEdgeFacts_MultiHopChain pins the load-bearing case
// for multi-hop reasoning: a 3-hop A→B→C→D chain produces three
// independent can_assume edges. Transitive reachability is the
// SMT solver's job, not the extractor's; the extractor emits
// flat per-hop edges.
func TestAssumeEdgeFacts_MultiHopChain(t *testing.T) {
	t.Parallel()
	const a = "arn:aws:iam::111122223333:user/a"
	const b = "arn:aws:iam::111122223333:role/b"
	const c = "arn:aws:iam::111122223333:role/c"
	const d = "arn:aws:iam::111122223333:role/d"
	mkUser := func(id, target string) sir.AssetFact {
		return sir.AssetFact{
			ID:   id,
			Type: "aws_iam_user",
			Properties: map[string]any{
				"identity": map[string]any{
					"policies": map[string]any{
						"attached_policies": []any{
							map[string]any{
								"statements": []any{
									map[string]any{
										"Effect":   "Allow",
										"Action":   "sts:AssumeRole",
										"Resource": target,
									},
								},
							},
						},
					},
				},
			},
		}
	}
	mkRole := func(id, target, trustedAssumer string) sir.AssetFact {
		props := map[string]any{
			"identity": map[string]any{
				"trust_policy_json": `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"` + trustedAssumer + `"}}]}`,
				"policies": map[string]any{
					"attached_policies": []any{
						map[string]any{
							"statements": []any{
								map[string]any{
									"Effect":   "Allow",
									"Action":   "sts:AssumeRole",
									"Resource": target,
								},
							},
						},
					},
				},
			},
		}
		return sir.AssetFact{ID: id, Type: "aws_iam_role", Properties: props}
	}
	mkLeaf := func(id, trustedAssumer string) sir.AssetFact {
		return sir.AssetFact{
			ID:   id,
			Type: "aws_iam_role",
			Properties: map[string]any{
				"identity": map[string]any{
					"trust_policy_json": `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"` + trustedAssumer + `"}}]}`,
				},
			},
		}
	}
	doc := &sir.Document{Assets: []sir.AssetFact{
		mkUser(a, b),
		mkRole(b, c, a),
		mkRole(c, d, b),
		mkLeaf(d, c),
	}}
	want := map[[2]string]bool{
		{a, b}: false,
		{b, c}: false,
		{c, d}: false,
	}
	for _, f := range ExtractFacts(doc) {
		if f.Predicate != "can_assume" {
			continue
		}
		if _, ok := want[[2]string{f.Subject, f.Object}]; ok {
			want[[2]string{f.Subject, f.Object}] = true
		}
	}
	for edge, ok := range want {
		if !ok {
			t.Errorf("missing can_assume edge: %s -> %s", edge[0], edge[1])
		}
	}
}

// TestDenyPolicyFacts_EmitsDenyActions confirms Deny statements
// in attached_policies project to has_deny_action / has_deny_resource
// facts so external solvers can compute Allow ∩ ¬Deny.
func TestDenyPolicyFacts_EmitsDenyActions(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "arn:aws:iam::111122223333:user/data-scientist",
			Type: "aws_iam_user",
			Properties: map[string]any{
				"identity": map[string]any{
					"policies": map[string]any{
						"attached_policies": []any{
							map[string]any{
								"statements": []any{
									map[string]any{
										"Effect":   "Deny",
										"Action":   []any{"autoscaling:CreateAutoScalingGroup", "ecs:RunTask"},
										"Resource": "*",
									},
									map[string]any{
										"Effect":   "Allow",
										"Action":   "s3:GetObject",
										"Resource": "arn:aws:s3:::data-bucket/*",
									},
								},
							},
						},
					},
				},
			},
		}},
	}
	facts := ExtractFacts(doc)
	wantDenyActions := map[string]bool{
		"autoscaling:CreateAutoScalingGroup": false,
		"ecs:RunTask":                        false,
	}
	wantDenyResource := false
	wantAllowAction := false
	for _, f := range facts {
		if f.Predicate == "has_deny_action" {
			if _, ok := wantDenyActions[f.Object]; ok {
				wantDenyActions[f.Object] = true
			}
		}
		if f.Predicate == "has_deny_resource" && f.Object == "*" {
			wantDenyResource = true
		}
		if f.Predicate == "has_action" && f.Object == "s3:GetObject" {
			wantAllowAction = true
		}
	}
	for action, hit := range wantDenyActions {
		if !hit {
			t.Errorf("missing has_deny_action(%s)", action)
		}
	}
	if !wantDenyResource {
		t.Errorf("missing has_deny_resource(\"*\")")
	}
	if !wantAllowAction {
		t.Errorf("Allow statement still emits has_action; deny extraction did not displace it")
	}
}

// TestConditionFacts_EmitsOperatorKeyPairs confirms each Condition
// operator/key combination projects to one has_condition fact with
// "<operator>:<key>" as the binary object encoding.
func TestConditionFacts_EmitsOperatorKeyPairs(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "arn:aws:iam::111122223333:user/scoped",
			Type: "aws_iam_user",
			Properties: map[string]any{
				"identity": map[string]any{
					"policies": map[string]any{
						"attached_policies": []any{
							map[string]any{
								"statements": []any{
									map[string]any{
										"Effect":   "Allow",
										"Action":   "iam:PassRole",
										"Resource": "*",
										"Condition": map[string]any{
											"StringEquals": map[string]any{
												"iam:PassedToService": []any{"ec2.amazonaws.com"},
											},
											"StringLike": map[string]any{
												"aws:RequestTag/team": "data-*",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}},
	}
	facts := ExtractFacts(doc)
	want := map[string]bool{
		"StringEquals:iam:PassedToService": false,
		"StringLike:aws:RequestTag/team":   false,
	}
	for _, f := range facts {
		if f.Predicate != "has_condition" {
			continue
		}
		if _, ok := want[f.Object]; ok {
			want[f.Object] = true
		}
	}
	for obj, hit := range want {
		if !hit {
			t.Errorf("missing has_condition(%s)", obj)
		}
	}
}

// TestDataEventLoggingFacts_EmitsPerBucket confirms a CloudTrail
// trail's event_selectors[].data_resources[].values[] project to
// one has_data_event_logging(bucket, "true") fact per bucket ARN,
// trimming the trailing slash so the bucket subject matches
// has_type(bucket, "aws_s3_bucket") downstream.
func TestDataEventLoggingFacts_EmitsPerBucket(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "arn:aws:cloudtrail:us-east-1:111122223333:trail/audit-trail",
			Type: "aws_cloudtrail_trail",
			Properties: map[string]any{
				"trail": map[string]any{
					"event_selectors": []any{
						map[string]any{
							"data_resources": []any{
								map[string]any{
									"type": "AWS::S3::Object",
									"values": []any{
										"arn:aws:s3:::confidential-data/",
										"arn:aws:s3:::pii-records/",
									},
								},
							},
						},
					},
				},
			},
		}},
	}
	facts := ExtractFacts(doc)
	want := map[string]bool{
		"arn:aws:s3:::confidential-data": false,
		"arn:aws:s3:::pii-records":       false,
	}
	for _, f := range facts {
		if f.Predicate != "has_data_event_logging" {
			continue
		}
		if f.Object != "true" {
			t.Errorf("has_data_event_logging emitted with object=%q (expected \"true\")", f.Object)
		}
		if _, ok := want[f.Subject]; ok {
			want[f.Subject] = true
		}
	}
	for bucket, hit := range want {
		if !hit {
			t.Errorf("missing has_data_event_logging(%s)", bucket)
		}
	}
}

// TestPropertyFacts_EmitsAllowlistedLeaves walks a synthetic asset
// shaped like the s3-public-read fixture's storage block and
// confirms the propertyAllowlist projects each leaf as has_<leaf>
// with the verbatim string value. Asset-type filter is honoured;
// non-matching asset types skip the rule.
func TestPropertyFacts_EmitsAllowlistedLeaves(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{
			{
				ID:   "arn:aws:s3:::public-bucket",
				Type: "aws_s3_bucket",
				Properties: map[string]any{
					"storage": map[string]any{
						"access": map[string]any{
							"public_read":       true,
							"public_list":       false,
							"read_via_resource": true,
						},
						"controls": map[string]any{
							"public_access_fully_blocked": false,
						},
						"content": map[string]any{
							"exposed_repo_artifacts": true,
						},
					},
				},
			},
			{
				// Non-S3 asset; should not pick up the S3-typed rules.
				ID:   "arn:aws:cognito-idp:::userpool/p1",
				Type: "aws_cognito_user_pool",
				Properties: map[string]any{
					"identity": map[string]any{
						"auth": map[string]any{
							"mfa_enforced": false,
						},
						"advanced_security": map[string]any{
							"enabled": false,
						},
					},
				},
			},
		},
	}
	facts := ExtractFacts(doc)
	want := map[string]string{
		"has_public_read|arn:aws:s3:::public-bucket":                      "true",
		"has_public_list|arn:aws:s3:::public-bucket":                      "false",
		"has_read_via_resource|arn:aws:s3:::public-bucket":                "true",
		"has_public_access_blocked|arn:aws:s3:::public-bucket":            "false",
		"has_exposed_repo_artifacts|arn:aws:s3:::public-bucket":           "true",
		"has_mfa_enforced|arn:aws:cognito-idp:::userpool/p1":              "false",
		"has_advanced_security_enabled|arn:aws:cognito-idp:::userpool/p1": "false",
	}
	got := map[string]string{}
	for _, f := range facts {
		if !strings.HasPrefix(f.Predicate, "has_") {
			continue
		}
		key := f.Predicate + "|" + f.Subject
		if _, ok := want[key]; ok {
			got[key] = f.Object
		}
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("missing or wrong: %s = %q (got %q)", k, v, got[k])
		}
	}
	// Asset-type filter sanity: the cognito asset should NOT have S3 facts.
	for _, f := range facts {
		if f.Subject == "arn:aws:cognito-idp:::userpool/p1" &&
			(f.Predicate == "has_public_read" || f.Predicate == "has_public_list") {
			t.Errorf("S3-typed rule fired on cognito asset: %s", f.Predicate)
		}
	}
}

// TestPropertyFacts_SkipsNestedNonScalar confirms that when an
// allowlist path lands on a map or slice (not a scalar), no fact
// is emitted. Prevents accidental "true" / "false" emissions for
// {"key": "value"} structures.
func TestPropertyFacts_SkipsNestedNonScalar(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "arn:aws:s3:::nested-test",
			Type: "aws_s3_bucket",
			Properties: map[string]any{
				"storage": map[string]any{
					"access": map[string]any{
						// Wrong shape — public_read should be a scalar but is a map here.
						"public_read": map[string]any{"nested": true},
					},
				},
			},
		}},
	}
	facts := ExtractFacts(doc)
	for _, f := range facts {
		if f.Predicate == "has_public_read" {
			t.Errorf("emitted has_public_read on a non-scalar value: %v", f.Object)
		}
	}
}

// TestProvenance_AnnotatesAllFacts confirms every fact emitted by
// ExtractFacts carries a non-nil Provenance with a populated
// projector name and an observation-relative property_path.
// Asset-bound facts also carry captured_at when the asset has a
// lifecycle.last_seen timestamp.
func TestProvenance_AnnotatesAllFacts(t *testing.T) {
	t.Parallel()
	doc := fixtureDoc()
	facts := ExtractFacts(doc)
	if len(facts) == 0 {
		t.Fatalf("no facts produced from fixtureDoc")
	}
	for i, f := range facts {
		if f.Provenance == nil {
			t.Errorf("facts[%d] (%s/%s/%s) has nil Provenance", i, f.Subject, f.Predicate, f.Object)
			continue
		}
		if f.Provenance.Projector == "" {
			t.Errorf("facts[%d] empty projector", i)
		}
		if f.Provenance.PropertyPath == "" {
			t.Errorf("facts[%d] empty property_path", i)
		}
		// PropertyPath should be observation-relative — no leading "assets[N]." prefix.
		if strings.HasPrefix(f.Provenance.PropertyPath, "assets[") {
			t.Errorf("facts[%d] property_path still has assets[N] prefix: %s", i, f.Provenance.PropertyPath)
		}
	}
}

// TestStripIndexPrefix covers the path-rewriting helper.
func TestStripIndexPrefix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"assets[0].properties.identity.kind", "properties.identity.kind"},
		{"controls[3].severity", "severity"},
		{"identities[1].role_chains[0].hops[2]", "role_chains[0].hops[2]"},
		{"temporal.windows[0].asset_id", "asset_id"},
		// No prefix → unchanged
		{"properties.foo.bar", "properties.foo.bar"},
		{"", ""},
	}
	for _, c := range cases {
		got := stripIndexPrefix(c.in)
		if got != c.want {
			t.Errorf("stripIndexPrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestFactID_Deterministic confirms the same (subject, predicate,
// object) triple always produces the same 12-hex-character ID,
// across calls and across runs.
func TestFactID_Deterministic(t *testing.T) {
	t.Parallel()
	id1 := factID("arn:aws:iam::111122223333:role/X", "has_action", "s3:*")
	id2 := factID("arn:aws:iam::111122223333:role/X", "has_action", "s3:*")
	if id1 != id2 {
		t.Errorf("non-deterministic fact_id: %s vs %s", id1, id2)
	}
	if len(id1) != 12 {
		t.Errorf("fact_id length = %d, want 12", len(id1))
	}
	// Different content → different ID
	id3 := factID("arn:aws:iam::111122223333:role/X", "has_action", "s3:GetObject")
	if id1 == id3 {
		t.Errorf("fact_id collision on different objects: %s == %s", id1, id3)
	}
}

// TestFactID_AppearsOnEveryFact confirms ExtractFacts stamps a
// fact_id on every fact, never empty, always 12 chars.
func TestFactID_AppearsOnEveryFact(t *testing.T) {
	t.Parallel()
	doc := fixtureDoc()
	facts := ExtractFacts(doc)
	for i, f := range facts {
		if f.FactID == "" {
			t.Errorf("facts[%d] (%s/%s) has empty fact_id", i, f.Subject, f.Predicate)
		}
		if len(f.FactID) != 12 {
			t.Errorf("facts[%d] fact_id length=%d, want 12: %q", i, len(f.FactID), f.FactID)
		}
	}
}

// TestFactID_StableAcrossRuns confirms two ExtractFacts calls on
// the same fixture produce identical fact_id sequences.
func TestFactID_StableAcrossRuns(t *testing.T) {
	t.Parallel()
	doc := fixtureDoc()
	first := ExtractFacts(doc)
	second := ExtractFacts(doc)
	if len(first) != len(second) {
		t.Fatalf("fact count drift: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].FactID != second[i].FactID {
			t.Errorf("facts[%d] fact_id drift: %s vs %s", i, first[i].FactID, second[i].FactID)
		}
	}
}

// TestConditionFacts_EmitsValuesAlongsideKeys confirms each
// Condition operator/key/value triple projects to BOTH a
// has_condition (key presence) fact AND a has_condition_value
// (key=value) fact. Array-valued conditions emit one fact per
// value.
func TestConditionFacts_EmitsValuesAlongsideKeys(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "arn:aws:iam::111122223333:role/scoped",
			Type: "aws_iam_role",
			Properties: map[string]any{
				"identity": map[string]any{
					"policies": map[string]any{
						"attached_policies": []any{
							map[string]any{
								"statements": []any{
									map[string]any{
										"Effect":   "Allow",
										"Action":   "iam:PassRole",
										"Resource": "*",
										"Condition": map[string]any{
											"StringEquals": map[string]any{
												"iam:PassedToService": []any{"ec2.amazonaws.com", "lambda.amazonaws.com"},
											},
											"StringLike": map[string]any{
												"aws:RequestTag/team": "data-*",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}},
	}
	facts := ExtractFacts(doc)
	wantKeys := map[string]bool{
		"StringEquals:iam:PassedToService": false,
		"StringLike:aws:RequestTag/team":   false,
	}
	wantValues := map[string]bool{
		"StringEquals:iam:PassedToService=ec2.amazonaws.com":    false,
		"StringEquals:iam:PassedToService=lambda.amazonaws.com": false,
		"StringLike:aws:RequestTag/team=data-*":                 false,
	}
	for _, f := range facts {
		if f.Predicate == "has_condition" {
			if _, ok := wantKeys[f.Object]; ok {
				wantKeys[f.Object] = true
			}
		}
		if f.Predicate == "has_condition_value" {
			if _, ok := wantValues[f.Object]; ok {
				wantValues[f.Object] = true
			}
		}
	}
	for k, hit := range wantKeys {
		if !hit {
			t.Errorf("missing has_condition(%s)", k)
		}
	}
	for v, hit := range wantValues {
		if !hit {
			t.Errorf("missing has_condition_value(%s)", v)
		}
	}
}

// TestStringifiedPolicyFacts_ParsesAPIGWResourcePolicy walks the
// stringified resource_policy_json field on an API Gateway asset
// and confirms the parser lifts the StringNotEquals condition
// keys/values into has_condition / has_condition_value facts.
// Without this projector, the structured-map walker can't see
// inside the JSON string, and apigw-style fixtures stay
// SIR-identical between vulnerable and remediated.
func TestStringifiedPolicyFacts_ParsesAPIGWResourcePolicy(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "arn:aws:apigateway:us-east-1::/restapis/api1",
			Type: "aws_apigateway_rest_api",
			Properties: map[string]any{
				"api": map[string]any{
					"network": map[string]any{
						"resource_policy_json": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke","Resource":"*","Condition":{"StringNotEquals":{"aws:sourceVpce":"vpce-abc"}}}]}`,
					},
				},
			},
		}},
	}
	facts := ExtractFacts(doc)
	wantCond := "StringNotEquals:aws:sourceVpce"
	wantVal := "StringNotEquals:aws:sourceVpce=vpce-abc"
	var sawCond, sawVal bool
	for _, f := range facts {
		if f.Predicate == "has_condition" && f.Object == wantCond && f.Source == "stringified_policy" {
			sawCond = true
		}
		if f.Predicate == "has_condition_value" && f.Object == wantVal && f.Source == "stringified_policy" {
			sawVal = true
		}
	}
	if !sawCond {
		t.Errorf("missing has_condition(%s) from parsed resource_policy_json", wantCond)
	}
	if !sawVal {
		t.Errorf("missing has_condition_value(%s) from parsed resource_policy_json", wantVal)
	}
}

// TestStringifiedPolicyFacts_SilentOnInvalidJSON confirms a
// malformed policy_json string produces zero facts and no error.
// Some fixtures may carry non-JSON strings under the same field
// name on a different asset; the parser must not log or error.
func TestStringifiedPolicyFacts_SilentOnInvalidJSON(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "arn:aws:apigateway:us-east-1::/restapis/api2",
			Type: "aws_apigateway_rest_api",
			Properties: map[string]any{
				"api": map[string]any{
					"network": map[string]any{
						"resource_policy_json": "not valid JSON {",
					},
				},
			},
		}},
	}
	facts := ExtractFacts(doc)
	for _, f := range facts {
		if f.Source == "stringified_policy" {
			t.Errorf("invalid JSON produced fact: %+v", f)
		}
	}
}

// TestStringifiedPolicyFacts_SilentOnMissingField confirms a
// fixture without the configured field produces zero
// stringified_policy facts.
func TestStringifiedPolicyFacts_SilentOnMissingField(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "arn:aws:apigateway:us-east-1::/restapis/api3",
			Type: "aws_apigateway_rest_api",
			// No api.network.resource_policy_json present.
			Properties: map[string]any{
				"api": map[string]any{
					"network": map[string]any{
						"vpc_endpoint_ids": []any{"vpce-xyz"},
					},
				},
			},
		}},
	}
	facts := ExtractFacts(doc)
	for _, f := range facts {
		if f.Source == "stringified_policy" {
			t.Errorf("missing field produced fact: %+v", f)
		}
	}
}

// TestStringifiedPolicyFacts_AssetTypeGate confirms the parser
// only fires on the configured asset types — an S3 bucket
// happening to carry an api.network.resource_policy_json field
// would not be parsed (the allowlist's assetTypes filter holds).
func TestStringifiedPolicyFacts_AssetTypeGate(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "arn:aws:s3:::my-bucket",
			Type: "aws_s3_bucket", // not aws_apigateway_rest_api
			Properties: map[string]any{
				"api": map[string]any{
					"network": map[string]any{
						"resource_policy_json": `{"Statement":[{"Condition":{"StringEquals":{"aws:tag":"v"}}}]}`,
					},
				},
			},
		}},
	}
	facts := ExtractFacts(doc)
	for _, f := range facts {
		if f.Source == "stringified_policy" {
			t.Errorf("type gate breached: %+v", f)
		}
	}
}

// TestStringifiedPolicyFacts_DeterministicOrder confirms the
// projector sorts operators and keys so identical input
// produces byte-identical output across runs (Go map iteration
// is randomised).
func TestStringifiedPolicyFacts_DeterministicOrder(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "arn:aws:apigateway:us-east-1::/restapis/api4",
			Type: "aws_apigateway_rest_api",
			Properties: map[string]any{
				"api": map[string]any{
					"network": map[string]any{
						"resource_policy_json": `{"Statement":[{"Condition":{"StringNotEquals":{"aws:sourceVpc":"vpc-1","aws:sourceVpce":"vpce-1"},"StringEquals":{"aws:tag":"v"}}}]}`,
					},
				},
			},
		}},
	}
	var first []string
	for run := range 5 {
		facts := ExtractFacts(doc)
		var order []string
		for _, f := range facts {
			if f.Source == "stringified_policy" && f.Predicate == "has_condition" {
				order = append(order, f.Object)
			}
		}
		if run == 0 {
			first = order
			continue
		}
		if len(order) != len(first) {
			t.Fatalf("run %d: length differs (%d vs %d)", run, len(order), len(first))
		}
		for i := range order {
			if order[i] != first[i] {
				t.Errorf("run %d: order differs at %d: %q vs %q", run, i, order[i], first[i])
			}
		}
	}
}

// TestStringifiedPolicyFacts_EmitsResourcePolicyPrincipal walks
// a parsed S3 bucket policy with a Statement.Principal map of
// {"AWS": "arn:..."} and confirms PR 5's resource_policy_principal
// projection produces the expected fact. The same projector also
// handles the array form below.
func TestStringifiedPolicyFacts_EmitsResourcePolicyPrincipal(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "arn:aws:s3:::dest-bucket",
			Type: "aws_s3_bucket",
			Properties: map[string]any{
				"storage": map[string]any{
					"policy_json": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":["s3:Get*","s3:List*"],"Resource":"*"}]}`,
				},
			},
		}},
	}
	facts := ExtractFacts(doc)
	want := map[string]bool{
		`resource_policy_principal=arn:aws:iam::111122223333:root`: false,
		`resource_policy_action=s3:Get*`:                           false,
		`resource_policy_action=s3:List*`:                          false,
	}
	for _, f := range facts {
		if f.Source == "stringified_policy" {
			key := f.Predicate + "=" + f.Object
			if _, ok := want[key]; ok {
				want[key] = true
			}
		}
	}
	for k, hit := range want {
		if !hit {
			t.Errorf("missing %s from parsed bucket policy", k)
		}
	}
}

// TestExtractResourcePolicyPrincipals_StringForm checks the
// "Principal":"*" wildcard form (a public-read shape).
func TestExtractResourcePolicyPrincipals_StringForm(t *testing.T) {
	t.Parallel()
	got := extractResourcePolicyPrincipals("*")
	if len(got) != 1 || got[0] != "*" {
		t.Errorf("string form: got %v, want [*]", got)
	}
}

// TestExtractResourcePolicyPrincipals_ArrayForm checks the
// {"AWS": ["arn:1", "arn:2"]} form where multiple principals
// share the same prefix key. The projector flattens the values
// into a deterministic sorted list so SMT facts are stable
// across runs.
func TestExtractResourcePolicyPrincipals_ArrayForm(t *testing.T) {
	t.Parallel()
	in := map[string]any{
		"AWS": []any{"arn:aws:iam::222:root", "arn:aws:iam::111:root"},
	}
	got := extractResourcePolicyPrincipals(in)
	want := []string{"arn:aws:iam::111:root", "arn:aws:iam::222:root"}
	if len(got) != len(want) {
		t.Fatalf("array form: length differs (%d vs %d)", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("array form: got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestExtractResourcePolicyPrincipals_MixedKeys confirms that
// {"AWS": "arn:...", "Service": "ec2.amazonaws.com"} flattens
// both prefix-keyed values into a single deterministically
// sorted list. The flattening is intentional — the SMT
// serialiser is binary and re-emitting per prefix-key would
// require ternary predicates.
func TestExtractResourcePolicyPrincipals_MixedKeys(t *testing.T) {
	t.Parallel()
	in := map[string]any{
		"Service": "ec2.amazonaws.com",
		"AWS":     "arn:aws:iam::123:root",
	}
	got := extractResourcePolicyPrincipals(in)
	wantSet := map[string]bool{
		"arn:aws:iam::123:root": false,
		"ec2.amazonaws.com":     false,
	}
	for _, v := range got {
		wantSet[v] = true
	}
	for k, hit := range wantSet {
		if !hit {
			t.Errorf("missing principal value %q", k)
		}
	}
	// Determinism: sorted output.
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Errorf("output not sorted: %v", got)
		}
	}
}

// TestStringifiedPolicyFacts_EmitsActionAndPrincipalWithoutCondition
// confirms PR 5's extraction fires on Statements that have NO
// Condition block. PR 4's projector skipped these statements
// at the early-continue; PR 5 must still emit Principal/Action
// facts for them.
func TestStringifiedPolicyFacts_EmitsActionAndPrincipalWithoutCondition(t *testing.T) {
	t.Parallel()
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "arn:aws:s3:::dest",
			Type: "aws_s3_bucket",
			Properties: map[string]any{
				"storage": map[string]any{
					"policy_json": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111:root"},"Action":"s3:GetObject","Resource":"*"}]}`,
				},
			},
		}},
	}
	facts := ExtractFacts(doc)
	var sawPrincipal, sawAction bool
	for _, f := range facts {
		if f.Source != "stringified_policy" {
			continue
		}
		if f.Predicate == "resource_policy_principal" && f.Object == "arn:aws:iam::111:root" {
			sawPrincipal = true
		}
		if f.Predicate == "resource_policy_action" && f.Object == "s3:GetObject" {
			sawAction = true
		}
	}
	if !sawPrincipal {
		t.Error("missing resource_policy_principal on no-condition Statement")
	}
	if !sawAction {
		t.Error("missing resource_policy_action on no-condition Statement")
	}
}

// TestFreshness_PopulatedFromProvenance confirms AnnotateFreshness
// reads Provenance.CapturedAt (RFC3339 string), parses it back to
// a time.Time, and computes age_seconds against the supplied now.
// Facts without a CapturedAt receive no Freshness — preserving
// the omitempty contract on the field.
func TestFreshness_PopulatedFromProvenance(t *testing.T) {
	t.Parallel()
	facts := []Fact{
		{
			Subject:   "asset/with-time",
			Predicate: "has_type",
			Object:    "x",
			Provenance: &Provenance{
				CapturedAt: "2026-01-08T00:00:00Z",
				Projector:  "assetFacts",
			},
		},
		{
			Subject:    "asset/no-time",
			Predicate:  "has_severity",
			Object:     "high",
			Provenance: &Provenance{Projector: "controlFacts"},
		},
	}
	now, _ := time.Parse(time.RFC3339, "2026-05-06T00:00:00Z")
	AnnotateFreshness(facts, now)

	if facts[0].Freshness == nil {
		t.Fatalf("first fact should have freshness")
	}
	want := int64(10195200) // 118 days * 86400
	if got := facts[0].Freshness.AgeSeconds; got != want {
		t.Errorf("AgeSeconds = %d, want %d", got, want)
	}
	if facts[1].Freshness != nil {
		t.Errorf("second fact has no CapturedAt; Freshness should be nil, got %+v", facts[1].Freshness)
	}
}

// TestFreshness_ClampsNegativeAgeToZero confirms a CapturedAt
// after `now` (clock skew between collector and export host)
// reports age 0 rather than a negative duration.
func TestFreshness_ClampsNegativeAgeToZero(t *testing.T) {
	t.Parallel()
	facts := []Fact{{
		Subject: "asset/future",
		Provenance: &Provenance{
			CapturedAt: "2026-12-01T00:00:00Z",
		},
	}}
	now, _ := time.Parse(time.RFC3339, "2026-05-06T00:00:00Z")
	AnnotateFreshness(facts, now)

	if facts[0].Freshness == nil {
		t.Fatal("freshness should still be populated even when clamped")
	}
	if got := facts[0].Freshness.AgeSeconds; got != 0 {
		t.Errorf("negative age should clamp to 0, got %d", got)
	}
	// CapturedAt must still reflect the parsed value, not be zeroed.
	if facts[0].Freshness.CapturedAt.Year() != 2026 {
		t.Errorf("CapturedAt should preserve original time, got %v", facts[0].Freshness.CapturedAt)
	}
}

// TestFreshness_SilentOnInvalidCapturedAt — a malformed timestamp
// in Provenance.CapturedAt produces no Freshness rather than an
// error. The provenance field is informational; a parse failure
// shouldn't fail the export.
func TestFreshness_SilentOnInvalidCapturedAt(t *testing.T) {
	t.Parallel()
	facts := []Fact{{
		Provenance: &Provenance{CapturedAt: "not-a-timestamp"},
	}}
	now := time.Now()
	AnnotateFreshness(facts, now)
	if facts[0].Freshness != nil {
		t.Errorf("invalid CapturedAt produced freshness: %+v", facts[0].Freshness)
	}
}

// TestFreshness_DeterministicAcrossRuns — same (facts, now)
// input produces byte-identical Freshness values. The function
// has no internal map iteration or wall-clock read after `now`
// is captured, so this is a safety net against future drift.
func TestFreshness_DeterministicAcrossRuns(t *testing.T) {
	t.Parallel()
	now, _ := time.Parse(time.RFC3339, "2026-05-06T00:00:00Z")
	mk := func() []Fact {
		return []Fact{
			{Provenance: &Provenance{CapturedAt: "2026-01-08T00:00:00Z"}},
			{Provenance: &Provenance{CapturedAt: "2026-04-30T12:30:00Z"}},
			{Provenance: &Provenance{CapturedAt: "2026-05-05T23:59:59Z"}},
		}
	}
	first := mk()
	AnnotateFreshness(first, now)
	for run := range 5 {
		next := mk()
		AnnotateFreshness(next, now)
		for i := range first {
			if first[i].Freshness.AgeSeconds != next[i].Freshness.AgeSeconds {
				t.Errorf("run %d: facts[%d].AgeSeconds = %d, first run = %d",
					run, i, next[i].Freshness.AgeSeconds, first[i].Freshness.AgeSeconds)
			}
			if !first[i].Freshness.CapturedAt.Equal(next[i].Freshness.CapturedAt) {
				t.Errorf("run %d: facts[%d].CapturedAt drifts", run, i)
			}
		}
	}
}

// TestFreshness_SkipsFactsWithoutProvenance — facts with nil
// Provenance produce no Freshness. Rare in practice (every
// projector goes through annotateProvenance), but the API contract
// holds for ad-hoc callers building Fact slices manually.
func TestFreshness_SkipsFactsWithoutProvenance(t *testing.T) {
	t.Parallel()
	facts := []Fact{
		{Subject: "x", Predicate: "y", Object: "z"},
	}
	AnnotateFreshness(facts, time.Now())
	if facts[0].Freshness != nil {
		t.Errorf("nil provenance produced freshness: %+v", facts[0].Freshness)
	}
}
