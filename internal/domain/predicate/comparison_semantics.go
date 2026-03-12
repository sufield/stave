package predicate

import (
	"reflect"
	"strconv"
	"strings"
)

// comparison_semantics.go defines typed comparison behavior used by predicate
// operators over dynamic (any) values.

// EqualValues compares two values for semantic equality, supporting mixed types
// common in serialized cloud data (e.g., "true" == true, 1 == 1.0).
func EqualValues(a, b any) bool {
	if a == nil || b == nil {
		return a == b
	}

	// 1. Fast path: Direct equality for common comparable primitives.
	if eq, ok := tryDirectEqual(a, b); ok && eq {
		return true
	}

	// 2. Handle mixed numeric equality (e.g., int 1 vs float64 1.0).
	if af, aOk := ToFloat64(a); aOk {
		if bf, bOk := ToFloat64(b); bOk {
			return af == bf
		}
	}

	// 3. Handle boolean normalization (e.g., "true" vs true).
	if ab, aOk := ToBool(a); aOk {
		if bb, bOk := ToBool(b); bOk {
			return ab == bb
		}
	}

	// 4. Handle case-insensitive string comparison (e.g., "Public" vs "public").
	if as, aOk := toString(a); aOk {
		if bs, bOk := toString(b); bOk {
			return strings.EqualFold(strings.TrimSpace(as), strings.TrimSpace(bs))
		}
	}

	return false
}

// Numeric Comparisons

func GreaterThan(a, b any) bool        { return numericCompare(a, b, 1) }
func GreaterThanOrEqual(a, b any) bool { return numericCompare(a, b, 2) }
func LessThan(a, b any) bool           { return numericCompare(a, b, 3) }
func LessThanOrEqual(a, b any) bool    { return numericCompare(a, b, 4) }

func numericCompare(a, b any, op int) bool {
	af, aOk := ToFloat64(a)
	bf, bOk := ToFloat64(b)
	if !aOk || !bOk {
		return false // Fail closed on non-numeric types
	}
	switch op {
	case 1:
		return af > bf
	case 2:
		return af >= bf
	case 3:
		return af < bf
	case 4:
		return af <= bf
	}
	return false
}

// ToFloat64 converts numeric types and numeric strings to float64.
func ToFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	case int16:
		return float64(n), true
	case int8:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint64:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint8:
		return float64(n), true
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(n), 64); err == nil {
			return f, true
		}
	}
	return 0, false
}

// ToBool converts booleans and boolean-like strings to bool.
func ToBool(v any) (bool, bool) {
	switch b := v.(type) {
	case bool:
		return b, true
	case string:
		if val, err := strconv.ParseBool(strings.TrimSpace(b)); err == nil {
			return val, true
		}
	}
	return false, false
}

func toString(v any) (string, bool) {
	if s, ok := v.(string); ok {
		return s, true
	}
	// Named string types (e.g., kernel.AssetType) need a Kind check.
	// This is lightweight (no alloc) — unlike the reflect calls removed
	// from ToFloat64 which invoked .Int()/.Uint()/.Float().
	if rv := reflect.ValueOf(v); rv.Kind() == reflect.String {
		return rv.String(), true
	}
	return "", false
}

// tryDirectEqual safely attempts an a == b comparison for common comparable types.
// Slices, maps, and functions would panic with ==; this whitelist prevents that.
func tryDirectEqual(a, b any) (bool, bool) {
	switch a.(type) {
	case string, int, int64, float64, bool, uint64, int32:
		return a == b, true
	}
	return false, false
}
