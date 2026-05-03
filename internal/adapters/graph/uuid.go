package graph

import (
	"crypto/sha1" //nolint:gosec // UUID v5 requires SHA-1 per RFC 4122
	"encoding/binary"
	"fmt"
)

// uuidV5 generates a deterministic UUID-shaped identifier from content
// parts. The output uses the v5 layout (variant + version bits set) but
// is NOT RFC 4122-compliant: parts are length-prefixed before hashing
// rather than serialized as a single canonical name. The length prefix
// makes part boundaries unambiguous so two distinct (parts...) tuples
// always produce distinct hashes — using a delimiter character (such
// as ":") would collide whenever a part legitimately contained that
// delimiter, which happens routinely with ARNs, resource paths, and
// IAM principal IDs.
//
// Migration impact: identifiers produced by this function have changed
// since the original colon-delimited implementation. Stored UUIDs from
// earlier runs will not match newly generated ones — graph imports
// that referenced previously emitted UUIDs must be regenerated, and
// any cached lookups keyed on the old hash should be invalidated.
func uuidV5(parts ...string) string {
	ns := []byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	h := sha1.New() //nolint:gosec // UUID v5 requires SHA-1
	h.Write(ns)
	var lenBuf [8]byte
	for _, p := range parts {
		// Length-prefix each part with a fixed-width big-endian uint64
		// so concatenation is unambiguous regardless of what bytes the
		// part itself contains.
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(p)))
		h.Write(lenBuf[:])
		h.Write([]byte(p))
	}
	sum := h.Sum(nil)

	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}
