package scrub

import (
	"regexp"
)

var defaultReplacement = []byte("[SANITIZED]")

var (
	// akiaMatch matches AWS Access Key IDs.
	akiaMatch = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)

	// urlCredMatch matches credentials in URLs (e.g., http://user:pass@host).
	urlCredMatch = regexp.MustCompile(`(?i)(https?://[^/\s:@]+:)[^@/\s]+@`)
)

// Credentials redacts known credential formats from the provided byte slice.
// This is a defense-in-depth measure that targets patterns regardless of
// variable names or context.
func Credentials(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	data = akiaMatch.ReplaceAll(data, defaultReplacement)
	data = urlCredMatch.ReplaceAll(data, []byte("${1}[SANITIZED]@"))
	return data
}
