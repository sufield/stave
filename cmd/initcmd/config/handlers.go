package config

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
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

	res, err := resolveConfigValue(cfg, cfgPath, eval, parsed)
	if err != nil {
		return err
	}

	return r.presentValue(res, req.Format)
}

func (r *Runner) presentValue(res ValueResult, format ui.OutputFormat) error {
	if format.IsJSON() {
		return jsonutil.WriteIndented(r.Stdout, res)
	}
	_, err := fmt.Fprintf(r.Stdout, "%s\n", res.Value)
	return err
}

// resolveConfigValue dispatches key resolution to the appropriate strategy.
func resolveConfigValue(cfg *appconfig.ProjectConfig, cfgPath string, eval *appconfig.Evaluator, parsed appconfig.ParsedKey) (ValueResult, error) {
	key := parsed.Raw

	// Tier keys: snapshot_retention_tiers.<tier>[.<field>]
	if parsed.TierName != "" {
		return resolveTierKey(cfg, cfgPath, eval, parsed)
	}

	// Known keys with special resolution logic.
	if resolver, ok := specialResolvers[parsed.TopLevel]; ok {
		return resolver(cfg, cfgPath, eval, parsed)
	}

	// Generic top-level key: evaluator method or direct config field.
	if v, ok := appconfig.ResolveKey(eval, key); ok {
		return ValueResult{Key: key, Value: v.Value, Source: v.Source}, nil
	}
	if cfg != nil {
		if val, found := appconfig.GetConfigValue(cfg, key); found {
			return ValueResult{Key: key, Value: val, Source: cfgPath + ":" + key}, nil
		}
	}
	return ValueResult{}, fmt.Errorf("key %q: not set", key)
}

// specialResolvers maps top-level keys that need custom resolution logic.
var specialResolvers = map[string]func(*appconfig.ProjectConfig, string, *appconfig.Evaluator, appconfig.ParsedKey) (ValueResult, error){
	"snapshot_retention": func(_ *appconfig.ProjectConfig, _ string, eval *appconfig.Evaluator, p appconfig.ParsedKey) (ValueResult, error) {
		v := eval.ResolveSnapshotRetention(eval.RetentionTier())
		return ValueResult{Key: p.Raw, Value: v.Value, Source: v.Source}, nil
	},
	"capture_cadence": func(cfg *appconfig.ProjectConfig, cfgPath string, _ *appconfig.Evaluator, p appconfig.ParsedKey) (ValueResult, error) {
		if cfg == nil || cfg.CaptureCadence == "" {
			return ValueResult{}, fmt.Errorf("key %q: not set in %s", p.Raw, appconfig.ProjectConfigFile)
		}
		return ValueResult{Key: p.Raw, Value: cfg.CaptureCadence, Source: cfgPath + ":capture_cadence"}, nil
	},
	"snapshot_filename_template": func(cfg *appconfig.ProjectConfig, cfgPath string, _ *appconfig.Evaluator, p appconfig.ParsedKey) (ValueResult, error) {
		if cfg == nil || cfg.SnapshotFilenameTemplate == "" {
			return ValueResult{}, fmt.Errorf("key %q: not set in %s", p.Raw, appconfig.ProjectConfigFile)
		}
		return ValueResult{Key: p.Raw, Value: cfg.SnapshotFilenameTemplate, Source: cfgPath + ":snapshot_filename_template"}, nil
	},
}

func resolveTierKey(cfg *appconfig.ProjectConfig, cfgPath string, eval *appconfig.Evaluator, parsed appconfig.ParsedKey) (ValueResult, error) {
	if parsed.SubField != "" {
		val, source, err := tierSubFieldResolution(cfg, cfgPath, parsed)
		if err != nil {
			return ValueResult{}, err
		}
		return ValueResult{Key: parsed.Raw, Value: val, Source: source}, nil
	}
	v := eval.ResolveSnapshotRetention(parsed.TierName)
	return ValueResult{Key: parsed.Raw, Value: v.Value, Source: v.Source}, nil
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

	editor, err := r.newEditor(opts)
	if err != nil {
		return err
	}
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

	editor, err := r.newEditor(opts)
	if err != nil {
		return err
	}
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
func (r *Runner) Show(_ context.Context, cmd *cobra.Command, format ui.OutputFormat) error {
	eval := cmdctx.EvaluatorFromCmd(cmd)
	if eval == nil {
		return fmt.Errorf("project config evaluator not available; ensure bootstrap runs before this command")
	}
	out := buildShowOutput(eval)
	presenter := &ShowPresenter{Stdout: r.Stdout}
	return presenter.Render(out, format.IsJSON())
}

// --- Internal Helpers ---

func (r *Runner) newEditor(opts MutationOpts) (*cliconfig.Editor[appconfig.ProjectConfig], error) {
	cfgResolver, err := projconfig.NewResolver()
	if err != nil {
		return nil, fmt.Errorf("resolve project context: %w", err)
	}
	store := projectConfigStore{resolver: cfgResolver, allowSymlink: opts.AllowSymlink}
	return &cliconfig.Editor[appconfig.ProjectConfig]{
		SetStore:    store,
		DeleteStore: store,
		Stderr:      r.Stderr,
		Force:       opts.Force,
		IsTTY:       func() bool { return opts.IsTTY },
		Confirm:     ui.NewPrompter(os.Stdin, r.Stderr).Confirm,
	}, nil
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
