package controldef

import (
	"strings"
)

// EnumCodec encodes enum values to canonical strings and decodes them
// back, with optional case-insensitive parsing. Replaces the
// switch-based String/Parse pairs that proliferated across closed-vocab
// types in this package.
//
// Construct one per enum type via NewEnumCodec and reuse it from the
// type's String() / ParseX functions.
type EnumCodec[T comparable] struct {
	forward map[T]string
	reverse map[string]T
	// caseFold normalizes lookup keys via strings.ToLower when true.
	// Outbound encoding always uses the canonical name from forward.
	caseFold bool
}

// NewEnumCodec returns a codec from the given canonical-name pairs.
// caseFold controls case-insensitive parsing on Decode.
func NewEnumCodec[T comparable](caseFold bool, pairs map[T]string) EnumCodec[T] {
	rev := make(map[string]T, len(pairs))
	for v, s := range pairs {
		key := s
		if caseFold {
			key = strings.ToLower(s)
		}
		rev[key] = v
	}
	return EnumCodec[T]{forward: pairs, reverse: rev, caseFold: caseFold}
}

// Encode returns the canonical string for v, or "" if v is not a member
// of the codec's set. Callers that distinguish between "unknown" and
// "empty" should consult Has first.
func (c EnumCodec[T]) Encode(v T) string {
	return c.forward[v]
}
