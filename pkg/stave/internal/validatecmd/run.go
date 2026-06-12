// Package validatecmd is the engine behind `stave validate` (and the
// validate facade in pkg/stave). It owns the load -> compute -> render
// pipeline so the command stays a thin shell. cli/ui-bound formatting
// (severity labels, template execution) is injected as callbacks because
// pkg/stave cannot import internal/cli/ui.
package validatecmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	builtinpredicate "github.com/sufield/stave/internal/adapters/predicate"
	"github.com/sufield/stave/internal/app/staleness"
	appvalidation "github.com/sufield/stave/internal/app/validation"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/core/kernel"
)

// LabelFunc formats a severity label for text output. Backed command-side by
// ui.SeverityLabel; passed across the facade so this engine avoids cli/ui.
type LabelFunc = func(level, message string, w io.Writer) string

// TemplateFunc renders a report through a template file. Backed command-side
// by ui.ExecuteTemplate.
type TemplateFunc = func(w io.Writer, templatePath string, data any) error

// Request is the parsed input for project validation. Every field is a
// primitive so the command constructs it without touching internal packages.
type Request struct {
	ControlsDir     string
	ObservationsDir string
	MaxUnsafe       string
	Now             string
	Sanitize        bool
	Strict          bool
	FixHints        bool
	Format          string
	Template        string
	AssertRecent    string
}

// Result is the rendered outcome of project validation.
type Result struct {
	// Output is the fully rendered report (text/json/template).
	Output []byte
	// ExitErr is the validation verdict: contracts.ErrValidationFailed,
	// contracts.ErrValidationWarnings, or nil. The command returns it so the
	// global exit-code map produces the right code.
	ExitErr error
	// StaleMessage, when non-empty, means --assert-recent tripped (or its
	// duration failed to parse); the command wraps it in ui.UserError (exit 2).
	StaleMessage string
}

// renderFormatStr resolves the effective renderer key: a non-empty template
// path overrides the format string, matching the command's pre-facade logic.
func renderFormatStr(format, template string) string {
	if template != "" {
		return template
	}
	return format
}

// Run executes project validation: parse params, run the core validation
// against the embedded builtin-catalog fallback, fold in pack-config issues,
// render to bytes, and apply the optional staleness assertion.
func Run(ctx context.Context, req Request, label LabelFunc, tmpl TemplateFunc, packIssues []diag.Finding) (Result, error) {
	var buf bytes.Buffer
	rep := &Reporter{
		Writer:   &buf,
		Format:   renderFormatStr(req.Format, req.Template),
		Strict:   req.Strict,
		FixHints: req.FixHints,
		Label:    label,
		Template: tmpl,
	}
	hc := hintContext{ControlsDir: req.ControlsDir, ObservationsDir: req.ObservationsDir}

	params := parseParams(req)
	if len(params.issues) > 0 {
		// Flag parsing itself produced diagnostic issues — render only those.
		result := &appvalidation.Report{Diagnostics: &diag.Assessment{Findings: params.issues}}
		if err := rep.Write(result, hc); err != nil {
			return Result{}, err
		}
		return Result{Output: buf.Bytes(), ExitErr: rep.ExitStatus(result)}, nil
	}

	result, err := executeValidateRun(ctx, req, params)
	if err != nil {
		return Result{}, err
	}

	// Add dynamic issues (e.g. unknown control packs in project config).
	result.Diagnostics.RecordAll(packIssues)

	if err := rep.Write(result, hc); err != nil {
		return Result{}, err
	}

	res := Result{Output: buf.Bytes()}

	// Staleness check: --assert-recent. Output is already rendered above; a
	// stale result becomes a command-side UserError after the report prints.
	if req.AssertRecent != "" {
		stale, msg, serr := checkStaleness(ctx, req, params)
		if serr != nil {
			return Result{}, serr
		}
		if stale {
			res.StaleMessage = msg
			return res, nil
		}
	}

	res.ExitErr = rep.ExitStatus(result)
	return res, nil
}

// validateParams holds the parsed domain values from the raw request strings.
type validateParams struct {
	maxUnsafe *time.Duration
	nowTime   time.Time
	issues    []diag.Finding
}

// parseParams converts the raw max-unsafe/now strings into structured values,
// recording a diagnostic finding (instead of failing) when a value is invalid.
// Mirrors compose.ResolveDurationDiag / ResolveNowDiag, which stay command-side
// for other callers.
func parseParams(req Request) validateParams {
	var p validateParams

	dur, err := kernel.ParseDuration(req.MaxUnsafe)
	if err != nil {
		issue := diag.NewFinding(diag.RuleInvalidMaxUnsafe).
			Error().
			Remediation("Use format like 168h, 7d, or 1d12h").
			FixCommand("stave validate --max-unsafe 168h").
			Attribute("value", req.MaxUnsafe).
			SensitiveAttribute("error", err.Error()).
			Build()
		p.issues = append(p.issues, issue)
	} else {
		p.maxUnsafe = &dur
	}

	if req.Now != "" {
		t, perr := time.Parse(time.RFC3339, req.Now)
		if perr != nil {
			issue := diag.NewFinding(diag.RuleInvalidNowTime).
				Error().
				Remediation("Use RFC3339 format").
				FixCommand("stave validate --now 2026-01-15T00:00:00Z").
				Attribute("value", req.Now).
				SensitiveAttribute("error", perr.Error()).
				Build()
			p.issues = append(p.issues, issue)
		} else {
			p.nowTime = t
		}
	}

	return p
}

// executeValidateRun builds the validation dependencies from the request paths
// and runs the core validation. Equivalent to the command's pre-facade
// executeValidateRun, but self-constructs the repositories (matching
// stave.Validate) instead of receiving cmd/cmdutil/compose factories.
func executeValidateRun(ctx context.Context, req Request, params validateParams) (*appvalidation.Report, error) {
	obsLoader := observations.NewObservationLoader()
	ctlLoader := ctlyaml.NewControlLoader()
	celEval, _, err := stavecel.NewPredicateEvalWithCompiler()
	if err != nil {
		return nil, fmt.Errorf("failed to init CEL evaluator: %w", err)
	}

	runner := appvalidation.NewRun(obsLoader, ctlLoader)
	runner.BuiltinCatalog = builtinCatalog
	cfg := appvalidation.Config{
		ControlsDir:     req.ControlsDir,
		ObservationsDir: req.ObservationsDir,
		NowTime:         params.nowTime,
		SanitizePaths:   req.Sanitize,
		PredicateParser: ctlyaml.ParsePredicate,
		PredicateEval:   celEval,
	}
	if params.maxUnsafe != nil {
		cfg.MaxUnsafeDuration = *params.maxUnsafe
	}

	result, err := runner.Execute(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("execute validation: %w", err)
	}
	return result, nil
}

// checkStaleness loads snapshots and applies the --assert-recent threshold.
// Returns (stale, message, error); a malformed duration is surfaced as a
// stale message so the command maps it to exit 2 (matching the prior
// ui.UserError on a bad --assert-recent value).
func checkStaleness(ctx context.Context, req Request, params validateParams) (bool, string, error) {
	threshold, parseErr := time.ParseDuration(req.AssertRecent)
	if parseErr != nil {
		return true, fmt.Sprintf("parse --assert-recent: %v", parseErr), nil
	}
	now := time.Now().UTC()
	if params.nowTime != (time.Time{}) {
		now = params.nowTime
	}
	repo := observations.NewObservationLoader()
	loaded, err := repo.LoadSnapshots(ctx, req.ObservationsDir)
	if err != nil {
		return false, "", fmt.Errorf("load snapshots for staleness check: %w", err)
	}
	sr := staleness.Check(loaded.Snapshots, threshold, now)
	if sr.Stale {
		return true, sr.Message, nil
	}
	return false, "", nil
}

// builtinCatalog loads the embedded builtin control catalog with the standard
// alias resolver — the "--controls absent" fallback. Equivalent to
// cmd/cmdutil/compose.BuiltinControlCatalog and pkg/stave.builtinControls.
func builtinCatalog() ([]policy.ControlDefinition, error) {
	store := ctlbuiltin.NewControlStore(
		ctlbuiltin.EmbeddedFS(), "embedded",
		ctlbuiltin.WithAliasResolver(builtinpredicate.ResolverFunc()),
	)
	controls, err := store.All()
	if err != nil {
		return nil, fmt.Errorf("load builtin controls: %w", err)
	}
	return controls, nil
}
