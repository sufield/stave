package initcmd

import (
	"regexp"
	"strings"
)

// slugRegexp matches one or more non-alphanumeric characters for slug generation.
var slugRegexp = regexp.MustCompile(`[^a-z0-9]+`)

func sanitizeSlug(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = slugRegexp.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "snapshot"
	}
	return s
}
