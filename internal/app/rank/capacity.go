package rank

import (
	"errors"
	"strconv"
	"strings"
)

// ParseCapacity converts a capacity string ("40h", "5d", or a bare number
// interpreted as hours) into engineer-hours. Returns an error if the input
// does not match one of the recognized forms.
//
// Days assume 8 hours per engineer-day (industry standard sprint accounting).
// Bare numbers are treated as hours so legacy callers with no suffix
// continue to work.
func ParseCapacity(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty capacity")
	}

	if before, ok := strings.CutSuffix(s, "d"); ok {
		val, err := strconv.ParseFloat(before, 64)
		if err != nil {
			return 0, err
		}
		return val * 8, nil
	}

	if before, ok := strings.CutSuffix(s, "h"); ok {
		val, err := strconv.ParseFloat(before, 64)
		if err != nil {
			return 0, err
		}
		return val, nil
	}

	val, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, errors.New("use format: 40h or 5d")
	}
	return val, nil
}
