package config

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	appconfig "github.com/sufield/stave/internal/app/config"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	cliconfig "github.com/sufield/stave/internal/cli/config"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/pkg/alpha/domain/retention"
)

// --- Domain Types ---

// Runner orchestrates the reading, writing, and inspection of Stave configuration.
type Runner struct {
	RT     *ui.Runtime
	Stdout io.Writer
	Stderr io.Writer
}

// GetRequest defines the parameters for retrieving a single config value.
type GetRequest struct {
	Key    string
	Format ui.OutputFormat
}

// SetRequest defines the parameters for updating a project config value.
type SetRequest struct {
	Key   string
	Value string
}

// DeleteRequest defines the parameters for removing a project config value.
type DeleteRequest struct {
	Key string
}

// MutationOpts carries CLI-environment context needed for config mutations.
type MutationOpts struct {
	Format       ui.OutputFormat
	Force        bool
	IsTTY        bool
	AllowSymlink bool
	Quiet        bool
}

// ValueResult is the DTO used for JSON output and text rendering.
type ValueResult struct {
	Key    string `json:"key"`
	Value  string `json:"value,omitempty"`
	Source string `json:"source,omitempty"`
	Path   string `json:"path,omitempty"`
}

// --- Logic Implementation ---

// Get retrieves the effective value for a specific key and renders it.
func (r *Runner) Get(_ context.Context, req GetRequest) error {
	key := strings.TrimSpace(req.Key)
	cfg, cfgPath, err := projconfig.FindProjectConfigWithPath("")
	if err != nil {
		return err
	}
	eval := appconfig.NewEvaluator(cfg, cfgPath, nil, "")

	parsed, err := appconfig.ParseConfigKey(key)
	if err != nil {
		return err
	}

	var res ValueResult

	if parsed.TierName != "" {
		// Tier key resolution
		if parsed.SubField != "" {
			// Specific sub-field: read directly from config
			val, source, tierErr := tierSubFieldResolution(cfg, cfgPath, parsed)
			if tierErr != nil {
				return tierErr
			}
			res = ValueResult{Key: key, Value: val, Source: source}
		} else {
			// Tier retention duration: resolve via evaluator
			v := eval.ResolveSnapshotRetention(parsed.TierName)
			res = ValueResult{Key: key, Value: v.Value, Source: v.Source}
		}
	} else if parsed.TopLevel == "snapshot_retention" {
		// snapshot_retention needs the fallback tier
		v := eval.ResolveSnapshotRetention(eval.RetentionTier())
		res = ValueResult{Key: key, Value: v.Value, Source: v.Source}
	} else if parsed.TopLevel == "capture_cadence" {
		if cfg == nil || cfg.CaptureCadence == "" {
			return fmt.Errorf("key %q: not set in %s", key, appconfig.ProjectConfigFile)
		}
		res = ValueResult{Key: key, Value: cfg.CaptureCadence, Source: cfgPath + ":capture_cadence"}
	} else if parsed.TopLevel == "snapshot_filename_template" {
		if cfg == nil || cfg.SnapshotFilenameTemplate == "" {
			return fmt.Errorf("key %q: not set in %s", key, appconfig.ProjectConfigFile)
		}
		res = ValueResult{Key: key, Value: cfg.SnapshotFilenameTemplate, Source: cfgPath + ":snapshot_filename_template"}
	} else {
		// Standard top-level key: try reflection-based resolver first,
		// fall back to direct config field read for simple fields without
		// a Resolve* method (e.g., debug_mode).
		v, ok := appconfig.ResolveKey(eval, key)
		if ok {
			res = ValueResult{Key: key, Value: v.Value, Source: v.Source}
		} else if cfg != nil {
			val, found := appconfig.GetConfigValue(cfg, key)
			if !found {
				return fmt.Errorf("key %q: not set in %s", key, appconfig.ProjectConfigFile)
			}
			res = ValueResult{Key: key, Value: val, Source: cfgPath + ":" + key}
		} else {
			return fmt.Errorf("key %q: not set", key)
		}
	}

	if req.Format.IsJSON() {
		return jsonutil.WriteIndented(r.Stdout, res)
	}
	_, err = fmt.Fprintf(r.Stdout, "%s\n", res.Value)
	return err
}

// tierSubFieldResolution reads a specific tier sub-field directly from config.
func tierSubFieldResolution(cfg *appconfig.ProjectConfig, cfgPath string, parsed appconfig.ParsedKey) (string, string, error) {
	if cfg == nil || len(cfg.RetentionTiers) == 0 {
		return "", "", fmt.Errorf("key %q: not set in %s", parsed.Raw, appconfig.ProjectConfigFile)
	}
	tc, exists := cfg.RetentionTiers[parsed.TierName]
	if !exists {
		return "", "", fmt.Errorf("tier %q is not configured", parsed.TierName)
	}

	var val string
	switch parsed.SubField {
	case "older_than":
		val = tc.OlderThan
	case "keep_min":
		val = strconv.Itoa(retention.TierConfig{KeepMin: tc.KeepMin}.EffectiveKeepMin())
	default:
		return "", "", fmt.Errorf("unsupported tier field %q", parsed.SubField)
	}

	source := fmt.Sprintf("%s:%s%s.%s", cfgPath, appconfig.TierKeyPrefix, parsed.TierName, parsed.SubField)
	return val, source, nil
}

// Set updates the stave.yaml file in the nearest project root.
func (r *Runner) Set(_ context.Context, req SetRequest, opts MutationOpts) error {
	key := strings.TrimSpace(req.Key)
	value := strings.TrimSpace(req.Value)
	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}

	editor := r.newEditor(opts)
	result, err := editor.Set(key, value)
	if err != nil {
		return err
	}
	if !result.Applied {
		return nil
	}

	res := ValueResult{Key: result.Key, Value: result.Value, Path: result.Path}
	return r.presentMutation(opts, res,
		fmt.Sprintf("Set %s=%s in %s", res.Key, res.Value, res.Path), true)
}

// Delete removes a project config key, reverting it to the built-in default.
func (r *Runner) Delete(_ context.Context, req DeleteRequest, opts MutationOpts) error {
	key := strings.TrimSpace(req.Key)

	editor := r.newEditor(opts)
	result, err := editor.Delete(key)
	if err != nil {
		return err
	}
	if !result.Applied {
		return nil
	}

	res := ValueResult{Key: result.Key, Path: result.Path}
	return r.presentMutation(opts, res,
		fmt.Sprintf("Deleted %s from %s (reverted to default)", res.Key, res.Path), false)
}

// Show renders the full suite of effective values and their sources.
func (r *Runner) Show(_ context.Context, format ui.OutputFormat) error {
	out := buildShowOutput()
	presenter := &ShowPresenter{Stdout: r.Stdout}
	return presenter.Render(out, format.IsJSON())
}

// --- Internal Helpers ---

func (r *Runner) newEditor(opts MutationOpts) *cliconfig.Editor[appconfig.ProjectConfig] {
	cfgResolver, _ := projconfig.NewResolver()
	store := projectConfigStore{resolver: cfgResolver, allowSymlink: opts.AllowSymlink}
	return &cliconfig.Editor[appconfig.ProjectConfig]{
		SetStore:    store,
		DeleteStore: store,
		Stderr:      r.Stderr,
		Force:       opts.Force,
		IsTTY:       func() bool { return opts.IsTTY },
		Confirm:     ui.NewPrompter(os.Stdin, os.Stderr).Confirm,
	}
}

func (r *Runner) presentMutation(opts MutationOpts, res ValueResult, text string, showHint bool) error {
	if opts.Format.IsJSON() {
		return jsonutil.WriteIndented(r.Stdout, res)
	}

	if _, err := fmt.Fprintln(r.Stdout, text); err != nil {
		return err
	}
	if showHint && !opts.Quiet {
		ui.WriteHint(r.Stderr, "stave config show")
	}
	return nil
}
