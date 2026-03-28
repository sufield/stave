package risk

import "strings"

// NormalizeActions lowercases and trims all action strings.
func NormalizeActions(actions []string) []string {
	out := make([]string, len(actions))
	for i, a := range actions {
		out[i] = strings.ToLower(strings.TrimSpace(a))
	}
	return out
}
