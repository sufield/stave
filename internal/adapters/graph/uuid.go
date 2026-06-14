package graph

import (
	"crypto/sha1" //nolint:gosec // UUID v5 requires SHA-1 per RFC 4122
	"encoding/binary"
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
//
// Modernized to perform hex-encoding directly onto a stack-allocated
// buffer instead of invoking the heavy reflection-based fmt.Sprintf.
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

	var buf [36]byte
	const hextable = "0123456789abcdef"

	buf[0] = hextable[sum[0]>>4]
	buf[1] = hextable[sum[0]&0x0f]
	buf[2] = hextable[sum[1]>>4]
	buf[3] = hextable[sum[1]&0x0f]
	buf[4] = hextable[sum[2]>>4]
	buf[5] = hextable[sum[2]&0x0f]
	buf[6] = hextable[sum[3]>>4]
	buf[7] = hextable[sum[3]&0x0f]
	buf[8] = '-'
	buf[9] = hextable[sum[4]>>4]
	buf[10] = hextable[sum[4]&0x0f]
	buf[11] = hextable[sum[5]>>4]
	buf[12] = hextable[sum[5]&0x0f]
	buf[13] = '-'
	buf[14] = hextable[sum[6]>>4]
	buf[15] = hextable[sum[6]&0x0f]
	buf[16] = hextable[sum[7]>>4]
	buf[17] = hextable[sum[7]&0x0f]
	buf[18] = '-'
	buf[19] = hextable[sum[8]>>4]
	buf[20] = hextable[sum[8]&0x0f]
	buf[21] = hextable[sum[9]>>4]
	buf[22] = hextable[sum[9]&0x0f]
	buf[23] = '-'
	buf[24] = hextable[sum[10]>>4]
	buf[25] = hextable[sum[10]&0x0f]
	buf[26] = hextable[sum[11]>>4]
	buf[27] = hextable[sum[11]&0x0f]
	buf[28] = hextable[sum[12]>>4]
	buf[29] = hextable[sum[12]&0x0f]
	buf[30] = hextable[sum[13]>>4]
	buf[31] = hextable[sum[13]&0x0f]
	buf[32] = hextable[sum[14]>>4]
	buf[33] = hextable[sum[14]&0x0f]
	buf[34] = hextable[sum[15]>>4]
	buf[35] = hextable[sum[15]&0x0f]

	return string(buf[:])
}
