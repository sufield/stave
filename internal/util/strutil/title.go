// Package strutil provides string helpers that avoid deprecated stdlib functions.
package strutil

import "strings"

// TitleCase capitalizes the first letter of s and lowercases the rest.
// Replacement for deprecated strings.Title for ASCII-only severity
// strings like "critical" → "Critical".
func TitleCase(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}
