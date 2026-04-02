package config

import (
	"context"
	"fmt"
	"io"
	"strings"

	appconfig "github.com/sufield/stave/internal/app/config"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	cliconfig "github.com/sufield/stave/internal/cli/config"
	"github.com/sufield/stave/internal/cli/ui"
)

// --- Domain Types ---

// Runner orchestrates the reading, writing, and inspection of Stave configuration.
type Runner struct {
	RT     *ui.Runtime
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// GetRequest defines the parameters for retrieving a single config value.
type GetRequest struct {
	Key    string
	Format appcontracts.OutputFormat
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
	Format       appcontracts.OutputFormat
	Force        bool
	Yes          bool
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

// Set updates the stave.yaml file in the nearest project root.
func (r *Runner) Set(ctx context.Context, req SetRequest, opts MutationOpts) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
func (r *Runner) Delete(ctx context.Context, req DeleteRequest, opts MutationOpts) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
func (r *Runner) Show(_ context.Context, eval *appconfig.Evaluator, format appcontracts.OutputFormat) error {
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

	var confirmFn func(string) bool
	if opts.Yes {
		confirmFn = ui.NewAutoConfirmPrompter(r.Stderr).Confirm
	} else {
		confirmFn = ui.NewPrompter(r.Stdin, r.Stderr).Confirm
	}

	return &cliconfig.Editor[appconfig.ProjectConfig]{
		SetStore:    store,
		DeleteStore: store,
		Stderr:      r.Stderr,
		Force:       opts.Force,
		IsTTY:       func() bool { return opts.IsTTY },
		Confirm:     confirmFn,
	}, nil
}
