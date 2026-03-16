package config

import (
	"context"
	"fmt"
	"io"
	"strings"

	appconfig "github.com/sufield/stave/internal/app/config"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	cliconfig "github.com/sufield/stave/internal/cli/config"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/configservice"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// --- Domain Types ---

// Runner orchestrates the reading, writing, and inspection of Stave configuration.
type Runner struct {
	Svc    *configservice.Service
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
	cfg, cfgPath, _ := projconfig.FindProjectConfigWithPath("")
	eval := appconfig.NewEvaluator(cfg, cfgPath, nil, "")

	kv, err := resolveServiceConfigKeyValue(r.Svc, key, cfg, cfgPath, eval.RetentionTier())
	if err != nil {
		return err
	}
	res := ValueResult{Key: kv.Key, Value: kv.Value, Source: kv.Source}

	if req.Format.IsJSON() {
		return jsonutil.WriteIndented(r.Stdout, res)
	}
	_, err = fmt.Fprintf(r.Stdout, "%s\n", res.Value)
	return err
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
	store := projectConfigStore{resolver: cfgResolver, svc: r.Svc, allowSymlink: opts.AllowSymlink}
	return &cliconfig.Editor[appconfig.ProjectConfig]{
		SetStore:    store,
		DeleteStore: store,
		Stderr:      r.Stderr,
		Force:       opts.Force,
		IsTTY:       func() bool { return opts.IsTTY },
		Confirm:     ui.Confirm,
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
