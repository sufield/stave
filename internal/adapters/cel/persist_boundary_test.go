package cel

import (
	"testing"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// The Bug-5 count guard rejects `count > remaining/minEntryBytes`. The absurd
// 2^62 test only exercises the extreme; this pins the exact boundary and the
// 40-byte minimum entry size. One 40-byte min-entry (empty expr + empty proto):
//   - count == 1: 1 > 40/40 (=1) is false -> accepted, decodes the entry.
//   - count == 2: 2 > 1 is true          -> rejected before make().
func TestDecodeCache_CountAtCapacityBoundary(t *testing.T) {
	oneEntry := appendEntry(nil, nil, nil) // 32 SHA + 4 + 0 + 4 + 0 = 40 bytes

	atCapacity := append(buildHeaderWithCount(1), oneEntry...)
	entries, err := decodeCache(atCapacity)
	if err != nil {
		t.Fatalf("count == capacity (1 entry, 40 bytes) must decode, got: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 decoded entry, got %d", len(entries))
	}

	overCapacity := append(buildHeaderWithCount(2), oneEntry...)
	if _, err := decodeCache(overCapacity); err == nil {
		t.Fatal("count == capacity+1 must be rejected by the buffer-capacity guard")
	}
}

// fitsUint32(0) must be true, so an entry with an empty expression survives
// encodeCache's pre-filter (it is not dropped) and round-trips. With the
// n >= 0 bound mutated to n > 0, fitsUint32(0) would be false and the entry
// would be silently filtered out, decoding to zero entries.
func TestEncodeCache_EmptyExpressionEntryRoundTrips(t *testing.T) {
	entries := []cachedEntry{{
		ExpressionSHA: hashExpression(""),
		Expression:    "",
		CheckedExpr:   &exprpb.CheckedExpr{},
	}}

	decoded, err := decodeCache(encodeCache(entries))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("empty-expression entry must round-trip; got %d entries (fitsUint32(0) dropped it?)", len(decoded))
	}
	if decoded[0].Expression != "" {
		t.Errorf("Expression = %q, want empty", decoded[0].Expression)
	}
}
