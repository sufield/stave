package upcoming

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appupcoming "github.com/sufield/stave/internal/app/prune/upcoming"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// resolvedConfig holds CLI-resolved parameters before asset loading.
type resolvedConfig struct {
	MaxUnsafeDuration    time.Duration
	MaxUnsafeDurationRaw string
	DueSoon              time.Duration
	DueSoonRaw           string
	Now                  time.Time
	Format               ui.OutputFormat
	Filter               risk.ThresholdFilter
	Sanitizer            kernel.Sanitizer
	Quiet                bool
	Stdout               io.Writer
}

// upcomingConfigInput groups the raw CLI flag values for upcoming config resolution.
type upcomingConfigInput struct {
	MaxUnsafeRaw  string
	DueSoonRaw    string
	NowRaw        string
	FormatRaw     string
	DueWithinRaw  string
	ControlIDs    []kernel.ControlID
	AssetTypes    []kernel.AssetType
	Statuses      []string
	Sanitizer     kernel.Sanitizer
	Quiet         bool
	Stdout        io.Writer
	ResolveFormat func(string) (ui.OutputFormat, error)
}

func gatherUpcomingConfig(in upcomingConfigInput) (resolvedConfig, error) {
	maxUnsafeDur, err := parsePositiveDuration(in.MaxUnsafeRaw, "--max-unsafe")
	if err != nil {
		return resolvedConfig{}, err
	}
	dueSoonDur, err := parsePositiveDuration(in.DueSoonRaw, "--due-soon")
	if err != nil {
		return resolvedConfig{}, err
	}

	var dueWithinDur time.Duration
	if strings.TrimSpace(in.DueWithinRaw) != "" {
		parsed, parseErr := parsePositiveDuration(in.DueWithinRaw, "--due-within")
		if parseErr != nil {
			return resolvedConfig{}, parseErr
		}
		dueWithinDur = parsed
	}

	now, err := compose.ResolveNow(in.NowRaw)
	if err != nil {
		return resolvedConfig{}, err
	}
	format, err := in.ResolveFormat(in.FormatRaw)
	if err != nil {
		return resolvedConfig{}, err
	}

	filter, err := appupcoming.NewUpcomingFilter(appupcoming.FilterCriteria{
		ControlIDs: in.ControlIDs,
		AssetTypes: in.AssetTypes,
		Statuses:   in.Statuses,
		DueWithin:  dueWithinDur,
	})
	if err != nil {
		return resolvedConfig{}, err
	}

	return resolvedConfig{
		MaxUnsafeDuration:    maxUnsafeDur,
		MaxUnsafeDurationRaw: in.MaxUnsafeRaw,
		DueSoon:              dueSoonDur,
		DueSoonRaw:           in.DueSoonRaw,
		Now:                  now,
		Format:               format,
		Filter:               filter,
		Sanitizer:            in.Sanitizer,
		Quiet:                in.Quiet,
		Stdout:               in.Stdout,
	}, nil
}

func parsePositiveDuration(raw, flag string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	dur, err := cmdutil.ParseDurationFlag(raw, flag)
	if err != nil {
		return 0, err
	}
	if dur < 0 {
		return 0, fmt.Errorf("invalid %s %q: must be >= 0", flag, raw)
	}
	return dur, nil
}
