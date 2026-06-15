package strutil

import (
	"strings"
	"unicode"
)

// ToLowerTrim returns the lower-cased, whitespace-trimmed form of s, but
// avoids the lower-casing allocation when the trimmed value contains no
// upper-case character. It is exactly equivalent to trimming then lower-casing
// for every input (TrimSpace is Unicode-aware and the fast-path uses
// unicode.IsUpper), so it is safe on arbitrary text — not only ASCII.
func ToLowerTrim(s string) string {
	s = strings.TrimSpace(s)
	if strings.IndexFunc(s, unicode.IsUpper) < 0 {
		return s
	}
	return strings.ToLower(s)
}
