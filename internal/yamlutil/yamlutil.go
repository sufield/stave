// Package yamlutil provides safe YAML value quoting and formatting.
package yamlutil

import "strings"

// Quote returns a safely double-quoted YAML scalar value.
// Escapes backslashes, double quotes, and control characters.
func Quote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return `"` + s + `"`
}

// Block returns a YAML literal block scalar at the given indent level.
// Safe for multi-line strings — preserves line breaks as block content.
func Block(s string, indent int) string {
	prefix := strings.Repeat(" ", indent)
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	var b strings.Builder
	b.WriteString("|\n")
	for _, line := range lines {
		b.WriteString(prefix)
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
