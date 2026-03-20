package logging

import (
	"path/filepath"
	"unicode/utf8"
)

// SanitizePath reduces a file path to its base name when fullPaths is false.
func SanitizePath(path string, fullPaths bool) string {
	if fullPaths || path == "" {
		return path
	}
	return filepath.Base(path)
}

// truncateString shortens s to at most maxLen runes, appending "..." if
// truncation occurs (the "..." counts toward maxLen). Returns "" for maxLen <= 0.
func truncateString(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}

	runeCount := utf8.RuneCountInString(s)
	if runeCount <= maxLen {
		return s
	}

	const ellipsis = "..."
	ellipsisLen := utf8.RuneCountInString(ellipsis)

	if maxLen <= ellipsisLen {
		// Not enough room for ellipsis; just take first maxLen runes.
		runes := []rune(s)
		return string(runes[:maxLen])
	}

	keep := maxLen - ellipsisLen
	runes := []rune(s)
	return string(runes[:keep]) + ellipsis
}
