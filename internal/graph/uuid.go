package graph

import (
	"crypto/sha1" //nolint:gosec // UUID v5 requires SHA-1 per RFC 4122
	"fmt"
)

// uuidV5 generates a deterministic UUID v5 from content parts.
func uuidV5(parts ...string) string {
	ns := []byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	h := sha1.New() //nolint:gosec // UUID v5 requires SHA-1
	h.Write(ns)
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{':'})
	}
	sum := h.Sum(nil)

	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}
