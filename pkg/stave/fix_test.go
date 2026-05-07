package stave

import "testing"

// TestConvertSuggestedFix_NilOnEmpty asserts the converter returns
// nil for empty / nil internal maps. Consumers branch on nil to
// detect "no solver-derived fix"; an empty struct would be
// mistaken for "fix produced, no fields populated".
func TestConvertSuggestedFix_NilOnEmpty(t *testing.T) {
	t.Parallel()
	if got := convertSuggestedFix(nil); got != nil {
		t.Errorf("nil map -> %+v, want nil", got)
	}
	if got := convertSuggestedFix(map[string]any{}); got != nil {
		t.Errorf("empty map -> %+v, want nil", got)
	}
}

// TestConvertSuggestedFix_StringFields confirms the typed-string
// keys map to the typed struct fields. Unknown keys are silently
// dropped — the contract is "stable surface, evolving wire."
func TestConvertSuggestedFix_StringFields(t *testing.T) {
	t.Parallel()
	in := map[string]any{
		"fix_type":          "policy_replacement",
		"description":       "Scope action to s3:GetObject",
		"confidence":        "high",
		"confidence_reason": "predicate negation directly resolves",
		"unknown_key":       "ignored",
	}
	got := convertSuggestedFix(in)
	if got == nil {
		t.Fatal("expected non-nil SuggestedFix")
	}
	if got.FixType != "policy_replacement" {
		t.Errorf("FixType = %q", got.FixType)
	}
	if got.Description != "Scope action to s3:GetObject" {
		t.Errorf("Description = %q", got.Description)
	}
	if got.Confidence != "high" {
		t.Errorf("Confidence = %q", got.Confidence)
	}
	if got.ConfidenceReason != "predicate negation directly resolves" {
		t.Errorf("ConfidenceReason = %q", got.ConfidenceReason)
	}
}

// TestConvertSuggestedFix_PassesAnyValues asserts that current /
// replacement carry through verbatim, regardless of underlying
// type — JSON objects, strings, lists, etc. The internal map
// shape is intentionally untyped so the engine can produce
// service-specific fix payloads (an IAM policy doc vs. a single
// boolean) without per-service plumbing.
func TestConvertSuggestedFix_PassesAnyValues(t *testing.T) {
	t.Parallel()
	current := map[string]any{
		"Effect":   "Allow",
		"Action":   "s3:*",
		"Resource": "*",
	}
	replacement := map[string]any{
		"Effect":   "Allow",
		"Action":   "s3:GetObject",
		"Resource": "arn:aws:s3:::app-data/input/*",
	}
	got := convertSuggestedFix(map[string]any{
		"fix_type":    "policy_replacement",
		"current":     current,
		"replacement": replacement,
	})
	if got == nil {
		t.Fatal("expected non-nil SuggestedFix")
	}
	gotCurrent, ok := got.Current.(map[string]any)
	if !ok || gotCurrent["Action"] != "s3:*" {
		t.Errorf("Current = %#v", got.Current)
	}
	gotReplacement, ok := got.Replacement.(map[string]any)
	if !ok || gotReplacement["Action"] != "s3:GetObject" {
		t.Errorf("Replacement = %#v", got.Replacement)
	}
}
