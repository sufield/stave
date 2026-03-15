package upcoming

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/sanitize"
)

// UpcomingConfig defines the resolved parameters for upcoming action analysis.
type UpcomingConfig struct {
	ControlsDir     string
	ObservationsDir string
	MaxUnsafe       time.Duration
	MaxUnsafeRaw    string
	DueSoon         time.Duration
	DueSoonRaw      string
	Now             time.Time
	Format          ui.OutputFormat
	Filter          risk.FilterCriteria
	Sanitizer       *sanitize.Sanitizer
	Quiet           bool
	Stdout          io.Writer
}

// UpcomingRunner orchestrates the risk analysis and timeline projection.
type UpcomingRunner struct{}

// Run executes the upcoming analysis workflow.
func (r *UpcomingRunner) Run(ctx context.Context, cfg UpcomingConfig) error {
	loaded, err := compose.ActiveProvider().LoadAssets(ctx, cfg.ObservationsDir, cfg.ControlsDir)
	if err != nil {
		return err
	}

	riskItems := risk.ComputeItems(risk.Request{
		Controls:        loaded.Controls,
		Snapshots:       loaded.Snapshots,
		GlobalMaxUnsafe: cfg.MaxUnsafe,
		Now:             cfg.Now,
		PredicateParser: ctlyaml.ParsePredicate,
	})
	riskItems = riskItems.Filter(cfg.Filter)

	// Map domain items to display DTOs
	items := mapRiskItems(riskItems)
	if cfg.Sanitizer != nil {
		items = sanitizeItems(cfg.Sanitizer, items)
	}
	summary := summarizeUpcoming(items, cfg.DueSoon)

	// Assemble final output
	output := buildOutput(cfg, summary, items)

	// Render in requested format
	if cfg.Quiet {
		return nil
	}
	return renderOutput(cfg, output)
}

// --- Bridge Helpers ---

func gatherUpcomingConfig(
	obsDir, ctlDir string,
	maxUnsafeRaw, dueSoonRaw, nowRaw, formatRaw, dueWithinRaw string,
	controlIDs []kernel.ControlID,
	assetTypes []kernel.AssetType,
	statuses []string,
	san *sanitize.Sanitizer,
	quiet bool,
	stdout io.Writer,
	resolveFormat func(string) (ui.OutputFormat, error),
) (UpcomingConfig, error) {
	maxUnsafeDur, err := parsePositiveDuration(maxUnsafeRaw, "--max-unsafe")
	if err != nil {
		return UpcomingConfig{}, err
	}
	dueSoonDur, err := parsePositiveDuration(dueSoonRaw, "--due-soon")
	if err != nil {
		return UpcomingConfig{}, err
	}

	var dueWithinDur time.Duration
	if strings.TrimSpace(dueWithinRaw) != "" {
		parsed, parseErr := parsePositiveDuration(dueWithinRaw, "--due-within")
		if parseErr != nil {
			return UpcomingConfig{}, parseErr
		}
		dueWithinDur = parsed
	}

	now, err := compose.ResolveNow(nowRaw)
	if err != nil {
		return UpcomingConfig{}, err
	}
	format, err := resolveFormat(formatRaw)
	if err != nil {
		return UpcomingConfig{}, err
	}

	filter, err := newUpcomingFilter(FilterCriteria{
		ControlIDs: controlIDs,
		AssetTypes: assetTypes,
		Statuses:   statuses,
		DueWithin:  dueWithinDur,
	})
	if err != nil {
		return UpcomingConfig{}, err
	}

	return UpcomingConfig{
		ControlsDir:     ctlDir,
		ObservationsDir: obsDir,
		MaxUnsafe:       maxUnsafeDur,
		MaxUnsafeRaw:    maxUnsafeRaw,
		DueSoon:         dueSoonDur,
		DueSoonRaw:      dueSoonRaw,
		Now:             now,
		Format:          format,
		Filter:          filter,
		Sanitizer:       san,
		Quiet:           quiet,
		Stdout:          stdout,
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
