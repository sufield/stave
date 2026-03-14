package config

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil"
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
	Key    string
	Value  string
	Format ui.OutputFormat
	GF     cmdutil.GlobalFlags
}

// DeleteRequest defines the parameters for removing a project config value.
type DeleteRequest struct {
	Key    string
	Format ui.OutputFormat
	GF     cmdutil.GlobalFlags
}

// --- Logic Implementation ---

// Get retrieves the effective value for a specific key and renders it.
func (r *Runner) Get(_ context.Context, req GetRequest) error {
	key := strings.TrimSpace(req.Key)
	cfg, cfgPath, _ := projconfig.FindProjectConfigWithPath("")
	eval := projconfig.NewEvaluator(cfg, cfgPath, nil, "")

	kv, err := resolveServiceConfigKeyValue(r.Svc, key, cfg, cfgPath, eval.RetentionTier())
	if err != nil {
		return err
	}
	out := configKeyValueOutput{Key: kv.Key, Value: kv.Value, Source: kv.Source}

	if req.Format.IsJSON() {
		return jsonutil.WriteIndented(r.Stdout, out)
	}
	_, err = fmt.Fprintf(r.Stdout, "%s\n", out.Value)
	return err
}

// Set updates the stave.yaml file in the nearest project root.
func (r *Runner) Set(_ context.Context, req SetRequest) error {
	key := strings.TrimSpace(req.Key)
	value := strings.TrimSpace(req.Value)
	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}

	editor := r.newProjectConfigEditor(req.GF)
	result, err := editor.Set(key, value)
	if err != nil {
		return err
	}
	if !result.Applied {
		return nil
	}

	return r.writeMutationResult(req.Format, configKeyValueOutput{
		Key:   result.Key,
		Value: result.Value,
		Path:  result.Path,
	}, fmt.Sprintf("Set %s=%s in %s", result.Key, result.Value, result.Path), true, req.GF.Quiet)
}

// Delete removes a project config key, reverting it to the built-in default.
func (r *Runner) Delete(_ context.Context, req DeleteRequest) error {
	key := strings.TrimSpace(req.Key)

	editor := r.newProjectConfigEditor(req.GF)
	result, err := editor.Delete(key)
	if err != nil {
		return err
	}
	if !result.Applied {
		return nil
	}

	return r.writeMutationResult(req.Format, configKeyValueOutput{
		Key:  result.Key,
		Path: result.Path,
	}, fmt.Sprintf("Deleted %s from %s (reverted to default)", result.Key, result.Path), false, req.GF.Quiet)
}

// Show renders the full suite of effective values and their sources.
func (r *Runner) Show(_ context.Context, format ui.OutputFormat) error {
	out := buildConfigShowOutput()
	if format.IsJSON() {
		return writeConfigShowJSON(r.Stdout, out)
	}
	return writeConfigShowText(r.Stdout, out)
}

// --- Internal Helpers ---

func (r *Runner) newProjectConfigEditor(gf cmdutil.GlobalFlags) *cliconfig.Editor[projconfig.ProjectConfig] {
	store := projectConfigStore{allowSymlink: gf.AllowSymlinkOut, svc: r.Svc}
	return &cliconfig.Editor[projconfig.ProjectConfig]{
		SetStore:    store,
		DeleteStore: store,
		Stderr:      r.Stderr,
		Force:       gf.Force,
		IsTTY:       r.isTTY,
		Confirm:     ui.Confirm,
	}
}

func (r *Runner) isTTY() bool {
	if r.RT != nil && r.RT.IsTTY != nil {
		return *r.RT.IsTTY
	}
	return ui.IsStderrTTY()
}

func (r *Runner) writeMutationResult(
	format ui.OutputFormat,
	result configKeyValueOutput,
	textLine string,
	showHint bool,
	quiet bool,
) error {
	if format.IsJSON() {
		return jsonutil.WriteIndented(r.Stdout, result)
	}

	if _, err := fmt.Fprintln(r.Stdout, textLine); err != nil {
		return err
	}
	if showHint && !quiet {
		ui.WriteHint(r.Stderr, "stave config show")
	}
	return nil
}
