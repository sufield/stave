package compliance

import "strings"

// truncate shortens s to limit runes, adding an ellipsis when cut.
func truncate(s string, limit int) string {
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	if limit <= 1 {
		return string(r[:limit])
	}
	return string(r[:limit-1]) + "…"
}

// join renders a control-ID list compactly for a single table cell.
func join(ids []string) string {
	if len(ids) == 0 {
		return "—"
	}
	return strings.Join(ids, ", ")
}

// mdEsc neutralizes the markdown table delimiter and collapses newlines so a
// cell stays on one row.
func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "|", "\\|")
}
