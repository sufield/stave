package upcoming

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	appupcoming "github.com/sufield/stave/internal/app/prune/upcoming"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/pkg/timeutil"
)

// resolvedConfig holds CLI-resolved parameters before asset loading.
type resolvedConfig struct {
	MaxUnsafe    time.Duration
	MaxUnsafeRaw string
	DueSoon      time.Duration
	DueSoonRaw   string
	Now          time.Time
	Format       ui.OutputFormat
	Filter       risk.FilterCriteria
	Sanitizer    kernel.Sanitizer
	Quiet        bool
	Stdout       io.Writer
}

func gatherUpcomingConfig(
	obsDir, ctlDir string,
	maxUnsafeRaw, dueSoonRaw, nowRaw, formatRaw, dueWithinRaw string,
	controlIDs []kernel.ControlID,
	assetTypes []kernel.AssetType,
	statuses []string,
	san kernel.Sanitizer,
	quiet bool,
	stdout io.Writer,
	resolveFormat func(string) (ui.OutputFormat, error),
) (resolvedConfig, error) {
	maxUnsafeDur, err := parsePositiveDuration(maxUnsafeRaw, "--max-unsafe")
	if err != nil {
		return resolvedConfig{}, err
	}
	dueSoonDur, err := parsePositiveDuration(dueSoonRaw, "--due-soon")
	if err != nil {
		return resolvedConfig{}, err
	}

	var dueWithinDur time.Duration
	if strings.TrimSpace(dueWithinRaw) != "" {
		parsed, parseErr := parsePositiveDuration(dueWithinRaw, "--due-within")
		if parseErr != nil {
			return resolvedConfig{}, parseErr
		}
		dueWithinDur = parsed
	}

	now, err := compose.ResolveNow(nowRaw)
	if err != nil {
		return resolvedConfig{}, err
	}
	format, err := resolveFormat(formatRaw)
	if err != nil {
		return resolvedConfig{}, err
	}

	filter, err := appupcoming.NewUpcomingFilter(appupcoming.FilterCriteria{
		ControlIDs: controlIDs,
		AssetTypes: assetTypes,
		Statuses:   statuses,
		DueWithin:  dueWithinDur,
	})
	if err != nil {
		return resolvedConfig{}, err
	}

	return resolvedConfig{
		MaxUnsafe:    maxUnsafeDur,
		MaxUnsafeRaw: maxUnsafeRaw,
		DueSoon:      dueSoonDur,
		DueSoonRaw:   dueSoonRaw,
		Now:          now,
		Format:       format,
		Filter:       filter,
		Sanitizer:    san,
		Quiet:        quiet,
		Stdout:       stdout,
	}, nil
}

func parsePositiveDuration(raw, flag string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	dur, err := timeutil.ParseDurationFlag(raw, flag)
	if err != nil {
		return 0, err
	}
	if dur < 0 {
		return 0, fmt.Errorf("invalid %s %q: must be >= 0", flag, raw)
	}
	return dur, nil
}
