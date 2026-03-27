package initcmd

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/version"
)

// Constant aliases — shorthand for scaffold templates and tests.
const (
	defaultMaxUnsafeDuration = appconfig.DefaultMaxUnsafeDuration
	defaultSnapshotRetention = appconfig.DefaultSnapshotRetention
	defaultRetentionTier     = appconfig.DefaultRetentionTier
	defaultTierKeepMin       = appconfig.DefaultTierKeepMin
	defaultCIFailurePolicy   = string(appconfig.GatePolicyAny)
	projectConfigFile        = appconfig.ProjectConfigFile

	profileAWSS3 = "aws-s3"

	cadenceDaily  = "daily"
	cadenceHourly = "hourly"
)

// slugRegexp matches one or more non-alphanumeric characters for slug generation.
var slugRegexp = regexp.MustCompile(`[^a-z0-9]+`)

// Version returns the CLI version string.
func Version() string { return version.String }

// ---------------------------------------------------------------------------
// Utility helpers shared across init sub-files.
// ---------------------------------------------------------------------------

func normalizeTemplate(s string) string {
	s = strings.TrimLeft(s, "\n")
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s
}

func controlIDFromName(name string) string {
	f := func(c rune) bool {
		return !unicode.IsLetter(c) && !unicode.IsNumber(c)
	}
	parts := strings.FieldsFunc(strings.ToUpper(strings.TrimSpace(name)), f)

	if len(parts) == 0 {
		return "CTL.GENERATED.SAMPLE.001"
	}
	domain := parts[0]
	category := "SAMPLE"
	if len(parts) > 1 {
		category = strings.Join(parts[1:], "_")
	}
	return fmt.Sprintf("CTL.%s.%s.001", domain, category)
}

func sanitizeSlug(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = slugRegexp.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "snapshot"
	}
	return s
}
