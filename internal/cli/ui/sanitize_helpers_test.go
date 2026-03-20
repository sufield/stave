package ui

import "regexp"

// pathReTest matches absolute POSIX-style paths embedded inside free-form strings,
// capturing the basename as group 1.
var pathReTest = regexp.MustCompile(`/(?:[^\s:]+/)+([^\s:/]+)`)

// SanitizePaths replaces absolute paths in an error message with only their
// basenames, preserving debugging context while avoiding directory disclosure.
func SanitizePaths(msg string) string {
	return pathReTest.ReplaceAllString(msg, "$1")
}
