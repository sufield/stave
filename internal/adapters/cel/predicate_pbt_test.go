package cel

import (
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

func genFieldPath(t *rapid.T, label string) predicate.FieldPath {
	seg := rapid.SliceOfN(
		rapid.StringMatching(`[a-z][a-z0-9_]{0,9}`),
		1, 3,
	).Draw(t, label+"_segs")
	return predicate.NewFieldPath("properties." + strings.Join(seg, "."))
}

func genSimpleOp(t *rapid.T, label string) predicate.Operator {
	return rapid.SampledFrom([]predicate.Operator{
		predicate.OpEq, predicate.OpNe,
		predicate.OpGt, predicate.OpLt,
		predicate.OpMissing, predicate.OpPresent,
	}).Draw(t, label)
}

func genScalarValue(t *rapid.T, label string) any {
	kind := rapid.IntRange(0, 4).Draw(t, label+"_kind")
	switch kind {
	case 0:
		return rapid.Bool().Draw(t, label+"_bool")
	case 1:
		return rapid.IntRange(-100, 100).Draw(t, label+"_int")
	case 2:
		return rapid.Float64Range(-1e6, 1e6).Draw(t, label+"_float")
	case 3:
		return rapid.StringMatching(`[a-z]{0,10}`).Draw(t, label+"_str")
	default:
		return nil
	}
}

func genProperties(t *rapid.T) map[string]any {
	n := rapid.IntRange(0, 5).Draw(t, "nprops")
	props := make(map[string]any, n)
	for i := range n {
		key := rapid.StringMatching(`[a-z][a-z0-9_]{0,9}`).Draw(t, "key")
		val := genScalarValue(t, "val")
		_ = i
		props[key] = val
	}
	return props
}

// ---------------------------------------------------------------------------
// Harness 1 — Missing Fields Never Panic
// ---------------------------------------------------------------------------

func TestPBT_MissingFields_NeverPanics(t *testing.T) {
	t.Parallel()
	eval := MustPredicateEval()

	rapid.Check(t, func(t *rapid.T) {
		fp := genFieldPath(t, "field")
		op := genSimpleOp(t, "op")
		val := genScalarValue(t, "val")

		ctl := policy.ControlDefinition{
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: fp, Op: op, Value: policy.NewOperand(val)},
				},
			},
		}

		props := genProperties(t)
		a := asset.Asset{
			ID:         "pbt-asset",
			Properties: props,
		}

		unsafe, err := eval(&ctl, a, nil)

		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, "nil pointer") ||
				strings.Contains(msg, "index out of range") {
				t.Fatalf("crash-class error: %v", err)
			}
		}
		_ = unsafe
	})
}

// ---------------------------------------------------------------------------
// Harness 2 — Type Coercion Consistency
// ---------------------------------------------------------------------------

func TestPBT_BooleanCoercion_NoPanic(t *testing.T) {
	t.Parallel()
	eval := MustPredicateEval()

	variants := []any{
		true, false,
		"true", "false", "TRUE", "FALSE",
		0, 1,
		nil, "", "yes", "no",
		float64(0), float64(1),
	}

	rapid.Check(t, func(t *rapid.T) {
		fp := genFieldPath(t, "field")
		boolVal := rapid.SampledFrom([]bool{true, false}).Draw(t, "expected")

		ctl := policy.ControlDefinition{
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: fp, Op: predicate.OpEq, Value: policy.Bool(boolVal)},
				},
			},
		}

		variant := rapid.SampledFrom(variants).Draw(t, "variant")

		parts := fp.Parts()
		if len(parts) < 2 {
			return
		}
		propKey := parts[1]
		a := asset.Asset{
			ID:         "pbt-coerce",
			Properties: map[string]any{propKey: variant},
		}

		unsafe, err := eval(&ctl, a, nil)
		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, "nil pointer") ||
				strings.Contains(msg, "index out of range") {
				t.Fatalf("crash-class error with variant %v (%T): %v", variant, variant, err)
			}
		}
		_ = unsafe
	})
}

func TestPBT_BooleanCoercion_Consistency(t *testing.T) {
	t.Parallel()
	eval := MustPredicateEval()

	rapid.Check(t, func(t *rapid.T) {
		seg := rapid.StringMatching(`[a-z][a-z0-9_]{0,9}`).Draw(t, "seg")
		fp := predicate.NewFieldPath("properties." + seg)
		boolVal := rapid.SampledFrom([]bool{true, false}).Draw(t, "expected")

		ctl := policy.ControlDefinition{
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: fp, Op: predicate.OpEq, Value: policy.Bool(boolVal)},
				},
			},
		}

		mkAsset := func(v any) asset.Asset {
			return asset.Asset{
				ID:         "pbt-consist",
				Properties: map[string]any{seg: v},
			}
		}

		resBool, errBool := eval(&ctl, mkAsset(boolVal), nil)
		resStr, errStr := eval(&ctl, mkAsset(strings.ToLower(
			func() string {
				if boolVal {
					return "true"
				}
				return "false"
			}(),
		)), nil)

		// Log discrepancies for HAZOP review. CEL is type-strict (bool ≠ string),
		// so divergence is expected. A crash is the only failure here.
		if errBool == nil && errStr == nil && resBool != resStr {
			t.Logf("coercion divergence: bool(%v) → unsafe=%v, string(%q) → unsafe=%v, field=%s",
				boolVal, resBool, func() string {
					if boolVal {
						return "true"
					}
					return "false"
				}(), resStr, fp)
		}
	})
}

// ---------------------------------------------------------------------------
// Harness 3 — Fail Mode Observational (absent field behavior)
// ---------------------------------------------------------------------------

func TestPBT_FailMode_AbsentField_NoPanic(t *testing.T) {
	t.Parallel()
	eval := MustPredicateEval()

	rapid.Check(t, func(t *rapid.T) {
		fp := genFieldPath(t, "field")
		op := genSimpleOp(t, "op")
		val := genScalarValue(t, "val")

		ctl := policy.ControlDefinition{
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: fp, Op: op, Value: policy.NewOperand(val)},
				},
			},
		}

		// Empty properties — field always absent.
		a := asset.Asset{
			ID:         "pbt-absent",
			Properties: map[string]any{},
		}

		unsafe, err := eval(&ctl, a, nil)
		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, "nil pointer") ||
				strings.Contains(msg, "index out of range") {
				t.Fatalf("crash-class error: %v", err)
			}
		}

		t.Logf("field=%s op=%s absent → unsafe=%v err=%v", fp, op, unsafe, err)
	})
}
