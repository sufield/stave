package ui

import "regexp"

// pathRe matches absolute POSIX-style paths embedded inside free-form strings
// (for example wrapped error messages), capturing the basename as group 1.
//
// This is intentionally message-level sanitization. filepath.Base/Clean operate
// on a single known path value; they do not sanitize paths that appear inside an
// arbitrary error string.
var pathRe = regexp.MustCompile(`/(?:[^\s:]+/)+([^\s:/]+)`)

// SanitizePaths replaces absolute paths in an error message with only their
// basenames, preserving debugging context while avoiding directory disclosure.
func SanitizePaths(msg string) string {
	return pathRe.ReplaceAllString(msg, "$1")
}
