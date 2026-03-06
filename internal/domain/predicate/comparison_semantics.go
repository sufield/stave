package predicate

import (
	"reflect"
	"strconv"
	"strings"
)

// comparison_semantics.go defines typed comparison behavior used by predicate
// operators over dynamic (any) values.

// EqualValues compares two values for equality.
func EqualValues(a, b any) bool {
	// Fast path for same-type comparable values.
	if eq, ok := equalComparable(a, b); ok && eq {
		return true
	}

	// Handle mixed numeric equality (for example: int vs float64).
	af, aOk := ToFloat64(a)
	bf, bOk := ToFloat64(b)
	if aOk && bOk {
		return af == bf
	}

	// Handle bool normalization (true/false, t/f, 1/0).
	ab, aBOk := ToBool(a)
	bb, bBOk := ToBool(b)
	if aBOk && bBOk {
		return ab == bb
	}

	// Handle case-insensitive string comparison for cloud export variation.
	as, aSOk := toString(a)
	bs, bSOk := toString(b)
	if aSOk && bSOk {
		return strings.EqualFold(strings.TrimSpace(as), strings.TrimSpace(bs))
	}

	return false
}

// GreaterThan compares two numeric values (a > b).
// Returns false if either value cannot be converted to a number (fail closed).
func GreaterThan(a, b any) bool {
	return compare(a, b, func(af, bf float64) bool { return af > bf })
}

// LessThan compares two numeric values (a < b).
func LessThan(a, b any) bool {
	return compare(a, b, func(af, bf float64) bool { return af < bf })
}

// GreaterThanOrEqual compares two numeric values (a >= b).
func GreaterThanOrEqual(a, b any) bool {
	return compare(a, b, func(af, bf float64) bool { return af >= bf })
}

// LessThanOrEqual compares two numeric values (a <= b).
func LessThanOrEqual(a, b any) bool {
	return compare(a, b, func(af, bf float64) bool { return af <= bf })
}

func compare(a, b any, compareFn func(af, bf float64) bool) bool {
	af, aOk := ToFloat64(a)
	bf, bOk := ToFloat64(b)
	if !aOk || !bOk {
		return false
	}
	return compareFn(af, bf)
}

// ToFloat64 converts numeric types to float64.
// Returns (value, true) on success, (0, false) if the value is not numeric.
func ToFloat64(v any) (float64, bool) {
	if str, ok := v.(string); ok {
		if f, err := strconv.ParseFloat(strings.TrimSpace(str), 64); err == nil {
			return f, true
		}
		return 0, false
	}
	return numericFloat64(v)
}

func numericFloat64(v any) (float64, bool) {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(rv.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(rv.Uint()), true
	case reflect.Float32, reflect.Float64:
		return rv.Float(), true
	}
	return 0, false
}

// ToBool converts booleans and boolean strings to bool.
func ToBool(v any) (bool, bool) {
	if b, ok := v.(bool); ok {
		return b, true
	}
	if s, ok := toString(v); ok {
		if val, err := strconv.ParseBool(strings.TrimSpace(s)); err == nil {
			return val, true
		}
	}
	return false, false
}

func equalComparable(a, b any) (_ bool, ok bool) {
	ok = true
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return a == b, ok
}

func toString(v any) (string, bool) {
	if s, ok := v.(string); ok {
		return s, true
	}
	rv := reflect.ValueOf(v)
	if rv.IsValid() && rv.Kind() == reflect.String {
		return rv.String(), true
	}
	return "", false
}
