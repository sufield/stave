package strutil

import "strings"

// ContainsFold reports whether substrLower (which must already be
// lower-cased) appears anywhere in s, ignoring case.
func ContainsFold(s, substrLower string) bool {
	return strings.Contains(strings.ToLower(s), substrLower)
}
