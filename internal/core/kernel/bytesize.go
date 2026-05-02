package kernel

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Sentinel errors for ParseByteSize so callers can errors.Is against
// specific failure modes (range vs overflow vs malformed input).
var (
	ErrByteSizeNonPositive = errors.New("kernel: byte size must be positive")
	ErrByteSizeOverflow    = errors.New("kernel: byte size overflows int64")
	ErrByteSizeMalformed   = errors.New("kernel: invalid byte size; expected number with optional MB/GB suffix")
)

// ParseByteSize parses a human-readable byte size string into bytes.
// Supports: "256MB", "1GB", "512mb", "1024", plain integers (bytes).
func ParseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty byte size")
	}

	upper := strings.ToUpper(s)

	type suffix struct {
		label      string
		multiplier int64
	}
	suffixes := []suffix{
		{"GB", 1 << 30},
		{"MB", 1 << 20},
		{"KB", 1 << 10},
	}

	for _, sf := range suffixes {
		if !strings.HasSuffix(upper, sf.label) {
			continue
		}
		numStr := strings.TrimSpace(s[:len(s)-len(sf.label)])
		n, err := strconv.ParseInt(numStr, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%w: %q: %w", ErrByteSizeMalformed, s, err)
		}
		if n <= 0 {
			return 0, fmt.Errorf("%w: %q", ErrByteSizeNonPositive, s)
		}
		// Overflow guard: a value like "9000000000GB" would silently
		// wrap to a small positive int64 after multiplication and
		// then survive the > 0 check above, breaking downstream
		// limit assumptions in the most subtle way possible.
		if n > math.MaxInt64/sf.multiplier {
			return 0, fmt.Errorf("%w: %q (max %d %s)", ErrByteSizeOverflow,
				s, math.MaxInt64/sf.multiplier, sf.label)
		}
		return n * sf.multiplier, nil
	}

	// Plain integer = bytes
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %q", ErrByteSizeMalformed, s)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%w: %q", ErrByteSizeNonPositive, s)
	}
	return n, nil
}
