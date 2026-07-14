package strutil

import "strings"

// ContainsFold reports whether substrLower (which must already be
// lower-cased) appears anywhere in s, ignoring ASCII case.
// Non-ASCII input falls back to strings.Contains after full
// lower-casing.
func ContainsFold(s, substrLower string) bool {
	if substrLower == "" {
		return true
	}
	if len(s) < len(substrLower) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= 128 {
			return strings.Contains(strings.ToLower(s), substrLower)
		}
	}
	for i := 0; i <= len(s)-len(substrLower); i++ {
		match := true
		for j := 0; j < len(substrLower); j++ {
			c1 := s[i+j]
			c2 := substrLower[j]
			if c1 != c2 {
				if c1 >= 'A' && c1 <= 'Z' {
					c1 += 'a' - 'A'
				}
				if c1 != c2 {
					match = false
					break
				}
			}
		}
		if match {
			return true
		}
	}
	return false
}
