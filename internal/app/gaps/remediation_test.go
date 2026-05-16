package gaps

import "testing"

// TestClassifyRemediation_TaggableProperty confirms a path with a
// ".tags." segment classifies as a tag with FixableByAgent=true.
// Tags are the canonical "the agent can close this gap by writing
// metadata to the cloud provider" case — any other classification
// would break the OODA loop's retry rule.
func TestClassifyRemediation_TaggableProperty(t *testing.T) {
	r := classifyRemediation(
		"properties.storage.tags.data-classification",
		"aws_s3_bucket",
		true,
	)
	if r.Type != "tag" {
		t.Errorf("Type: got %q, want tag", r.Type)
	}
	if !r.FixableByAgent {
		t.Errorf("tag gaps must be FixableByAgent=true")
	}
	if r.Command == "" || r.Guidance == "" {
		t.Errorf("tag gaps must carry Command and Guidance; got %+v", r)
	}
}

// TestClassifyRemediation_APIProperty covers the secondary-API
// case: paths the collector can compute only by calling another
// cloud endpoint (Access Advisor, etc.). Agents authoring
// Steampipe transforms cannot synthesize the result — the
// underlying row simply doesn't have the column.
func TestClassifyRemediation_APIProperty(t *testing.T) {
	cases := []string{
		"properties.identity.permission_drift.threshold_exceeded",
		"properties.identity.access_advisor.available",
		"properties.identity.unused_service.count",
	}
	for _, p := range cases {
		r := classifyRemediation(p, "aws_iam_role", false)
		if r.Type != "api" {
			t.Errorf("%s: Type got %q, want api", p, r.Type)
		}
		if r.FixableByAgent {
			t.Errorf("%s: api gaps must NOT be FixableByAgent", p)
		}
	}
}

// TestClassifyRemediation_CollectorAnalysis covers paths that
// need a cross-inventory walk (ghost references, delegation,
// intent matching). These are NOT fixable by an agent — the
// collector code must grow.
func TestClassifyRemediation_CollectorAnalysis(t *testing.T) {
	cases := []string{
		"properties.identity.trust_policy.has_ghost_principal",
		"properties.identity.cognito.has_ghost_user_pool",
		"properties.identity.intent_match.has_intent_mismatch",
		"properties.identity.delegation.has_external_principals",
	}
	for _, p := range cases {
		r := classifyRemediation(p, "aws_iam_role", false)
		if r.Type != "collector" {
			t.Errorf("%s: Type got %q, want collector", p, r.Type)
		}
		if r.FixableByAgent {
			t.Errorf("%s: collector gaps must NOT be FixableByAgent", p)
		}
	}
}

// TestClassifyRemediation_DerivedFallback is the default arm: a
// path that doesn't match any special pattern falls through to
// the "derived" class — assumed to be a transform-time projection
// over data the source row carries. FixableByAgent: true because
// an agent authoring the Steampipe → Stave mapping can add the
// field map entry without touching the collector code.
func TestClassifyRemediation_DerivedFallback(t *testing.T) {
	r := classifyRemediation(
		"properties.storage.encryption.algorithm",
		"aws_s3_bucket",
		false,
	)
	if r.Type != "derived" {
		t.Errorf("Type: got %q, want derived", r.Type)
	}
	if !r.FixableByAgent {
		t.Errorf("derived gaps must be FixableByAgent=true")
	}
	if r.Guidance == "" {
		t.Error("derived gaps must carry Guidance")
	}
}

// TestMatchesSegment_RespectsBoundaries guards the segment-level
// match rule. A path's substring containing "has_ghost_principal"
// inside a larger token must NOT match — only when the token
// itself starts with "has_ghost_" does it count. This is what
// keeps "permission_drift_count" (a hypothetical future scalar)
// from being misclassified as an api gap just because its name
// contains "permission_drift" as a substring.
func TestMatchesSegment_RespectsBoundaries(t *testing.T) {
	if !matchesSegment("identity.trust_policy.has_ghost_principal", "has_ghost_") {
		t.Error("expected segment match on has_ghost_principal")
	}
	if matchesSegment("identity.not_a_has_ghost_thing", "has_ghost_") {
		t.Error("substring inside a larger segment must NOT match")
	}
}

// TestMatchesAnySegment_ExactSegment verifies the
// "permission_drift" / "permission_drift_count" disambiguation.
// matchesAnySegment compares the whole segment, not a prefix.
func TestMatchesAnySegment_ExactSegment(t *testing.T) {
	if !matchesAnySegment("identity.permission_drift.threshold", "permission_drift") {
		t.Error("expected match on segment permission_drift")
	}
	if matchesAnySegment("identity.permission_drift_count", "permission_drift") {
		t.Error("permission_drift_count must NOT match segment permission_drift")
	}
}
