//go:build cgo && z3

package main

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestSymbolic_Divergent_OpNe(t *testing.T) {
	// OpNe diverges between CEL and reference when a type mismatch
	// occurs on a present field with unequal Sprint values:
	//   CEL: type error → false
	//   Reference: Sprint inequality → true
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.network.protocol"), Op: predicate.OpNe, Value: policy.Str("tls")},
		},
	}
	fields := extractFields(pred)
	result := symbolicCheckImpl(pred, fields)

	if result.Status != "DIVERGE" {
		t.Fatalf("expected DIVERGE for OpNe predicate, got %s: %s", result.Status, result.Detail)
	}
	t.Logf("counterexample: %s", result.Detail)
}

func TestSymbolic_Divergent_OpEq(t *testing.T) {
	// OpEq diverges when types mismatch but Sprint values happen to
	// match (e.g., int 5 vs string "5"):
	//   CEL: type error → false
	//   Reference: Sprint("5") == Sprint("5") → true
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq, Value: policy.Str("bucket")},
		},
	}
	fields := extractFields(pred)
	result := symbolicCheckImpl(pred, fields)

	if result.Status != "DIVERGE" {
		t.Fatalf("expected DIVERGE for OpEq predicate, got %s: %s", result.Status, result.Detail)
	}
	t.Logf("counterexample: %s", result.Detail)
}

func TestSymbolic_Equivalent_OpMissing(t *testing.T) {
	// OpMissing has identical semantics in CEL and reference:
	// both check !hasField || isEmpty(field)
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.storage.tags.intent"), Op: predicate.OpMissing, Value: policy.Bool(true)},
		},
	}
	fields := extractFields(pred)
	result := symbolicCheckImpl(pred, fields)

	if result.Status != "EQUIV" {
		t.Fatalf("expected EQUIV for OpMissing predicate, got %s: %s", result.Status, result.Detail)
	}
}

func TestSymbolic_Equivalent_OpPresent(t *testing.T) {
	// OpPresent has identical semantics in both evaluators.
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.storage.name"), Op: predicate.OpPresent, Value: policy.Bool(true)},
		},
	}
	fields := extractFields(pred)
	result := symbolicCheckImpl(pred, fields)

	if result.Status != "EQUIV" {
		t.Fatalf("expected EQUIV for OpPresent predicate, got %s: %s", result.Status, result.Detail)
	}
}

func TestSymbolic_Mixed_OnlyComparisonOpsDiverge(t *testing.T) {
	// A predicate mixing OpMissing (equivalent) with OpNe (divergent)
	// should show DIVERGE — the type-mismatch counterexample exists.
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.storage.tags.intent"), Op: predicate.OpMissing, Value: policy.Bool(true)},
			{Field: predicate.NewFieldPath("properties.storage.encryption"), Op: predicate.OpNe, Value: policy.Str("AES256")},
		},
	}
	fields := extractFields(pred)
	result := symbolicCheckImpl(pred, fields)

	if result.Status != "DIVERGE" {
		t.Fatalf("expected DIVERGE for mixed predicate with OpNe, got %s: %s", result.Status, result.Detail)
	}
}

func TestSymbolic_PureMissing_Equivalent(t *testing.T) {
	// A predicate using ONLY OpMissing/OpPresent should be EQUIV.
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.storage.tags.intent"), Op: predicate.OpMissing, Value: policy.Bool(true)},
		},
		Any: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.storage.name"), Op: predicate.OpPresent, Value: policy.Bool(true)},
			{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpMissing, Value: policy.Bool(true)},
		},
	}
	fields := extractFields(pred)
	result := symbolicCheckImpl(pred, fields)

	if result.Status != "EQUIV" {
		t.Fatalf("expected EQUIV for pure missing/present predicate, got %s: %s", result.Status, result.Detail)
	}
}
