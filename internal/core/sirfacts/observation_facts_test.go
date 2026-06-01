package sirfacts

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/sir"
)

// iam002Assets mirrors the Datadog iam-002-to-admin lab snapshot:
// a starting-user carrying the CreateAccessKey escalation primitive
// and a target-user that is admin-equivalent. These are the exact
// scalar leaves a reasoning engine needs to derive the escalation
// from first principles.
func iam002Assets() []sir.AssetFact {
	last := time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC)
	return []sir.AssetFact{
		{
			ID:        "arn:aws:iam::442426852386:user/starting-user",
			Type:      "aws_iam_user",
			Vendor:    "aws",
			Lifecycle: &sir.AssetLifecycleFact{LastSeen: last},
			Properties: map[string]any{
				"identity": map[string]any{
					"kind": "user",
					"name": "starting-user",
					"policies": map[string]any{
						"has_admin_access":          false,
						"service_wildcards_granted": false,
					},
					"escalation": map[string]any{
						"create_access_key": map[string]any{
							"present":         true,
							"target_user_arn": "arn:aws:iam::442426852386:user/target-user",
							"permission_delta": []any{ // slice — must be skipped
								"iam:*", "ssm:GetParameter",
							},
						},
					},
				},
			},
		},
		{
			ID:     "arn:aws:iam::442426852386:user/target-user",
			Type:   "aws_iam_user",
			Vendor: "aws",
			Properties: map[string]any{
				"identity": map[string]any{
					"kind":                "user",
					"is_admin_equivalent": true,
					"policies": map[string]any{
						"has_admin_access": true,
					},
					"note": nil, // null — must be skipped
				},
			},
		},
	}
}

func factSet(facts []Fact) map[string]string {
	out := make(map[string]string, len(facts))
	for _, f := range facts {
		out[f.Subject+"|"+f.Predicate] = f.Object
	}
	return out
}

func TestObservationFacts_EmitsScalarLeavesAsDottedPaths(t *testing.T) {
	facts := ObservationFacts(iam002Assets())
	set := factSet(facts)

	want := []struct {
		subject, predicate, object string
	}{
		{"arn:aws:iam::442426852386:user/starting-user", "identity.kind", "user"},
		{"arn:aws:iam::442426852386:user/starting-user", "identity.policies.has_admin_access", "false"},
		{"arn:aws:iam::442426852386:user/starting-user", "identity.escalation.create_access_key.present", "true"},
		{"arn:aws:iam::442426852386:user/starting-user", "identity.escalation.create_access_key.target_user_arn", "arn:aws:iam::442426852386:user/target-user"},
		{"arn:aws:iam::442426852386:user/target-user", "identity.policies.has_admin_access", "true"},
		{"arn:aws:iam::442426852386:user/target-user", "identity.is_admin_equivalent", "true"},
	}
	for _, w := range want {
		got, ok := set[w.subject+"|"+w.predicate]
		if !ok {
			t.Errorf("missing observation triple: %s %s", w.subject, w.predicate)
			continue
		}
		if got != w.object {
			t.Errorf("%s %s = %q, want %q", w.subject, w.predicate, got, w.object)
		}
	}

	for _, f := range facts {
		if f.Source != "observation" {
			t.Errorf("fact %s/%s has source %q, want observation", f.Subject, f.Predicate, f.Source)
		}
	}
}

func TestObservationFacts_SkipsSlicesAndNulls(t *testing.T) {
	for _, f := range ObservationFacts(iam002Assets()) {
		if strings.Contains(f.Predicate, "permission_delta") {
			t.Errorf("slice leaf projected: %s", f.Predicate)
		}
		if strings.HasSuffix(f.Predicate, ".note") {
			t.Errorf("null leaf projected: %s", f.Predicate)
		}
	}
}

func TestObservationFacts_SetsFactIDAndProvenance(t *testing.T) {
	for _, f := range ObservationFacts(iam002Assets()) {
		if f.FactID == "" {
			t.Errorf("fact %s/%s missing FactID", f.Subject, f.Predicate)
		}
		if f.Provenance == nil {
			t.Fatalf("fact %s/%s missing Provenance", f.Subject, f.Predicate)
		}
		if f.Provenance.Projector != "observationFacts" {
			t.Errorf("projector = %q, want observationFacts", f.Provenance.Projector)
		}
		if want := "properties." + f.Predicate; f.Provenance.PropertyPath != want {
			t.Errorf("property_path = %q, want %q", f.Provenance.PropertyPath, want)
		}
	}
}

func TestObservationFacts_Deterministic(t *testing.T) {
	var first []Fact
	for i := range 25 {
		got := ObservationFacts(iam002Assets())
		if i == 0 {
			first = got
			continue
		}
		if len(got) != len(first) {
			t.Fatalf("run %d: length %d != %d", i, len(got), len(first))
		}
		for j := range got {
			if got[j].Predicate != first[j].Predicate || got[j].Subject != first[j].Subject {
				t.Fatalf("run %d index %d: %s/%s != %s/%s", i, j,
					got[j].Subject, got[j].Predicate, first[j].Subject, first[j].Predicate)
			}
		}
	}
}

// TestSMT2Symbol verifies the symbol-safety helper leaves valid
// SMT-LIB simple symbols bare (no golden churn for has_* / dotted
// paths) and pipe-quotes names carrying characters outside the
// simple-symbol charset (IAM condition keys like "iam:PassedToService").
func TestSMT2Symbol(t *testing.T) {
	cases := map[string]string{
		"has_severity":                   "has_severity",
		"can_assume":                     "can_assume",
		"auto_prop_identity_kind":        "auto_prop_identity_kind",
		"identity.escalation.present":    "identity.escalation.present",
		"identity.condition.iam:Service": "|identity.condition.iam:Service|",
		"1leading":                       "|1leading|", // simple symbols cannot start with a digit
	}
	for in, want := range cases {
		if got := smt2Symbol(in); got != want {
			t.Errorf("smt2Symbol(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSerializeSMT2_QuotesUnsafeObservationPredicate confirms a
// colon-bearing observation predicate flows through declaration,
// assertion, and closed-world axiom as a single pipe-quoted symbol,
// and that parentheses stay balanced.
func TestSerializeSMT2_QuotesUnsafeObservationPredicate(t *testing.T) {
	facts := []Fact{
		{Subject: "asset-1", Predicate: "identity.condition.iam:PassedToService", Object: "ec2.amazonaws.com", Source: "observation"},
	}
	var buf bytes.Buffer
	if err := SerializeSMT2(facts, &buf, SMT2Options{ClosedWorld: true}); err != nil {
		t.Fatalf("SerializeSMT2: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "(declare-fun |identity.condition.iam:PassedToService| (String String) Bool)") {
		t.Errorf("missing pipe-quoted declaration:\n%s", out)
	}
	if !strings.Contains(out, "(assert (|identity.condition.iam:PassedToService| \"asset-1\" \"ec2.amazonaws.com\"))") {
		t.Errorf("missing pipe-quoted assertion:\n%s", out)
	}
	if o, c := strings.Count(out, "("), strings.Count(out, ")"); o != c {
		t.Errorf("unbalanced parentheses: %d open, %d close", o, c)
	}
}
