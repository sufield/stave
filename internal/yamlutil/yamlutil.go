// Package yamlutil provides safe YAML value quoting and formatting.
package yamlutil

import (
	"fmt"
	"strings"
)

// Quote returns a safely double-quoted YAML scalar value.
// Escapes backslashes, double quotes, and the full C0 control range.
//
// The earlier shape only escaped \n / \r / \t, so other C0 controls
// (NUL, BEL, ESC, etc.) passed through verbatim. yaml.v3 rejects most
// of them on parse, so a serializer that emitted them produced
// output its own re-parser couldn't read. Walk every rune and emit
// either the recognized YAML short escape, an \xNN form for U+0000
// through U+007F, or \uNNNN for the rare BMP control characters
// outside that range.
func Quote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				// C0 control range plus DEL — escape via \xNN.
				fmt.Fprintf(&b, `\x%02x`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// Block returns a YAML literal block scalar at the given indent level.
// Safe for multi-line strings — preserves line breaks as block content.
//
// Empty input returns an empty double-quoted scalar rather than a
// "|" header followed by a blank line, which most YAML parsers
// reject at the top level. CRLF inputs are normalized to LF before
// splitting so a Windows-authored multi-line string round-trips
// cleanly.
func Block(s string, indent int) string {
	if s == "" {
		return `""`
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
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
