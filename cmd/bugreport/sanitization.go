package bugreport

import "regexp"

// Format-based credential detectors. These match credential formats
// (not field names), providing defense-in-depth for unstructured text.
var (
	akiaRe    = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	urlCredRe = regexp.MustCompile(`(?i)(https?://[^/\s:@]+:)[^@/\s]+@`)
)

// redactCredentialFormats scrubs known credential formats from raw text.
// This catches AWS access key IDs and URL-embedded passwords regardless
// of field names. It does NOT use keyword-based matching.
func redactCredentialFormats(data []byte) []byte {
	data = akiaRe.ReplaceAll(data, []byte("[SANITIZED]"))
	data = urlCredRe.ReplaceAll(data, []byte("${1}[SANITIZED]@"))
	return data
}
