package initcmd

import (
	"regexp"
	"strings"
)

// slugRegexp matches one or more non-alphanumeric characters for slug generation.
var slugRegexp = regexp.MustCompile(`[^a-z0-9]+`)

func sanitizeSlug(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "snapshot"
	}
	var sb strings.Builder
	sb.Grow(len(trimmed))
	lastWasDash := true
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			sb.WriteByte(c)
			lastWasDash = false
		} else {
			if !lastWasDash {
				sb.WriteByte('-')
				lastWasDash = true
			}
		}
	}
	res := sb.String()
	if len(res) > 0 && res[len(res)-1] == '-' {
		res = res[:len(res)-1]
	}
	if res == "" {
		return "snapshot"
	}
	return res
}
