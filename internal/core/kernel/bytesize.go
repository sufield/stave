package kernel

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseByteSize parses a human-readable byte size string into bytes.
// Supports: "256MB", "1GB", "512mb", "1024", plain integers (bytes).
func ParseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty byte size")
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
			return 0, fmt.Errorf("invalid byte size %q: %w", s, err)
		}
		if n <= 0 {
			return 0, fmt.Errorf("byte size must be positive: %q", s)
		}
		return n * sf.multiplier, nil
	}

	// Plain integer = bytes
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid byte size %q: expected number with optional MB/GB suffix", s)
	}
	if n <= 0 {
		return 0, fmt.Errorf("byte size must be positive: %q", s)
	}
	return n, nil
}
