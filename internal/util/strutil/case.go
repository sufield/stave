package strutil

import "strings"

// ToLowerTrim returns the lower-cased, whitespace-trimmed form of s.
func ToLowerTrim(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
