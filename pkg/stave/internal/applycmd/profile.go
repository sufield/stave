package applycmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	outjson "github.com/sufield/stave/internal/adapters/output/json"
	outsarif "github.com/sufield/stave/internal/adapters/output/sarif"
	outtext "github.com/sufield/stave/internal/adapters/output/text"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/capabilities"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/sanitize"
	"github.com/sufield/stave/internal/version"
)

// ErrInvalidProfileInput marks input errors in the profile pipeline (bad
// --input path) so the pkg/stave facade can map them to ErrInvalidInput
// (exit 2). The original command returned ui.UserError directly; the engine
// cannot import cli/ui, so it signals via this sentinel.
var ErrInvalidProfileInput = errors.New("invalid profile input")

// ProfileRequest is the parsed input for `apply --profile`. All fields are
// primitives or stdlib types so the command constructs it without holding
// internal types; the facade self-constructs the sanitizer/clock/repos.
type ProfileRequest struct {
	InputFile       string
	Profiles        []string // validated profile names
	BucketAllowlist []string
	IncludeAll      bool
	MaxUnsafe       string // duration string (e.g. "168h", "7d"); "" → 0
	Format          string // "text" | "json" | "sarif"
	Now             string // RFC3339 or "" for wall clock
	SanitizeIDs     bool
	PathMode        string
}

// parseProfileMaxUnsafe parses the --max-unsafe duration string with the same
// grammar standard apply uses (kernel.ParseDuration accepts the 'd' day unit
// that stdlib time.ParseDuration rejects). An empty value means 0 (immediate
// firing). Bad input is tagged ErrInvalidProfileInput so the facade maps it to
// exit 2.
func parseProfileMaxUnsafe(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := kernel.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%w: parse --max-unsafe %q: %v", ErrInvalidProfileInput, s, err) //nolint:errorlint // sentinel-tag wrap; %v keeps the cause readable
	}
	return d, nil
}

// ProfileResult is the rendered outcome of a profile evaluation. Output is
// the report (always written to stdout); Warnings + DiagnoseHint are
// stderr-bound (the command writes them, quiet-gated); HasViolations drives
// the exit code.
type ProfileResult struct {
	Output        []byte
	Warnings      []string
	DiagnoseHint  string
	HasViolations bool
}

// EvaluateProfile runs the `apply --profile` pipeline: load bundle, filter by
// scope, load multi-profile controls, evaluate, enrich, render. The facade
// self-constructs the CEL evaluator, control loader, finding marshaler,
// sanitizer, and clock from the request.
func EvaluateProfile(ctx context.Context, req ProfileRequest) (ProfileResult, error) {
	if err := validateInput(req.InputFile); err != nil {
		return ProfileResult{}, err
	}

	clock, err := buildClock(req.Now)
	if err != nil {
		return ProfileResult{}, err
	}
	maxUnsafe, err := parseProfileMaxUnsafe(req.MaxUnsafe)
	if err != nil {
		return ProfileResult{}, err
	}
	sanitizer := sanitize.Policy{SanitizeIDs: req.SanitizeIDs, PathMode: sanitize.PathMode(req.PathMode)}.NewSanitizer()

	profiles := parseProfileNames(req.Profiles)

	snapshots, err := observations.LoadBundle(req.InputFile)
	if err != nil {
		return ProfileResult{}, fmt.Errorf("load observation bundle: %w", err)
	}

	var res ProfileResult
	primary := primaryProfile(profiles)

	filtered, warnings := filterSnapshots(primary, req, snapshots)
	res.Warnings = append(res.Warnings, warnings...)

	if len(filtered) == 0 {
		// Mis-scoped allowlist matched nothing: still emit one (empty,
		// COMPLIANT) document so a --format json consumer parses a real
		// report rather than empty stdout.
		out, finalize, emptyErr := evaluateEmptyScope(ctx, req, maxUnsafe, clock, sanitizer, snapshots)
		if emptyErr != nil {
			return ProfileResult{}, emptyErr
		}
		res.Output = out
		res.Warnings = append(res.Warnings, finalize.Warnings...)
		res.DiagnoseHint = finalize.DiagnoseHint
		res.HasViolations = finalize.HasViolations
		return res, nil
	}

	ctlDir, controls, err := loadControlsMulti(ctx, profiles)
	if err != nil {
		return ProfileResult{}, fmt.Errorf("load controls: %w", err)
	}

	celEval, _, err := stavecel.NewPredicateEvalWithCompiler()
	if err != nil {
		return ProfileResult{}, fmt.Errorf("init CEL evaluator: %w", err)
	}

	chains, chainsErr := ctlyaml.LoadChains("chains", capabilities.Builtin())
	if chainsErr != nil {
		return ProfileResult{}, fmt.Errorf("loading chains: %w", chainsErr)
	}

	result, err := appeval.EvaluateLoaded(ctx, appeval.EvaluationRequest{
		Controls:          controls,
		Snapshots:         filtered,
		MaxUnsafeDuration: maxUnsafe,
		Clock:             clock,
		Hasher:            crypto.NewHasher(),
		StaveVersion:      version.String,
		PredicateParser:   ctlyaml.ParsePredicate,
		CELEvaluator:      celEval,
	})
	if err != nil {
		return ProfileResult{}, fmt.Errorf("evaluate: %w", err)
	}

	appeval.EnrichReport(&result, controls, chains, filtered)

	out, err := writeResults(ctx, req, sanitizer, &result, controls)
	if err != nil {
		return ProfileResult{}, fmt.Errorf("write findings: %w", err)
	}
	res.Output = out

	finalize := finalizeProfileEvaluation(&result, filtered, ctlDir, req.InputFile)
	res.Warnings = append(res.Warnings, finalize.Warnings...)
	res.DiagnoseHint = finalize.DiagnoseHint
	res.HasViolations = finalize.HasViolations
	return res, nil
}

// evaluateEmptyScope writes one document for a run whose scope filter matched
// no asset, stamping EvaluatedState from the original (pre-filter) snapshots.
func evaluateEmptyScope(ctx context.Context, req ProfileRequest, maxUnsafe time.Duration, clock ports.Clock, sanitizer kernel.Sanitizer, originalSnapshots []asset.Snapshot) ([]byte, finalizeOutcome, error) {
	result, err := appeval.EvaluateLoaded(ctx, appeval.EvaluationRequest{
		Controls:          nil,
		Snapshots:         nil,
		MaxUnsafeDuration: maxUnsafe,
		Clock:             clock,
		Hasher:            crypto.NewHasher(),
		StaveVersion:      version.String,
		PredicateParser:   ctlyaml.ParsePredicate,
	})
	if err != nil {
		return nil, finalizeOutcome{}, fmt.Errorf("evaluate empty scope: %w", err)
	}
	if result.Run.EvaluatedState == "" {
		result.Run.EvaluatedState = string(latestSnapshotSource(originalSnapshots))
	}

	out, err := writeResults(ctx, req, sanitizer, &result, nil)
	if err != nil {
		return nil, finalizeOutcome{}, fmt.Errorf("write findings: %w", err)
	}
	return out, finalizeProfileEvaluation(&result, nil, "", req.InputFile), nil
}

func validateInput(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("--input not found: %q: %w", path, ErrInvalidProfileInput)
		}
		if os.IsPermission(err) {
			return fmt.Errorf("--input not readable: %q (check file permissions): %w", path, ErrInvalidProfileInput)
		}
		return fmt.Errorf("cannot access --input %q: %w: %w", path, err, ErrInvalidProfileInput)
	}
	if fi.IsDir() {
		return fmt.Errorf("--input must be a file, got directory: %q: %w", path, ErrInvalidProfileInput)
	}
	return nil
}

func buildClock(now string) (ports.Clock, error) {
	if now == "" {
		return ports.RealClock{}, nil
	}
	t, err := time.Parse(time.RFC3339, now)
	if err != nil {
		return nil, fmt.Errorf("parse --now %q: %w: %w", now, err, ErrInvalidProfileInput)
	}
	return ports.FixedClock(t), nil
}

// buildFindingWriter replicates cmd/cmdutil/compose.DefaultFindingWriter
// (which stays command-side for other callers).
func buildFindingWriter(format string, verbose bool) (appcontracts.FindingMarshaler, error) {
	switch appcontracts.OutputFormat(format) {
	case appcontracts.FormatText:
		return &outtext.FindingWriter{Verbose: verbose}, nil
	case appcontracts.FormatJSON:
		return outjson.NewFindingWriter(true), nil
	case appcontracts.FormatSARIF:
		return outsarif.NewFindingWriter(), nil
	default:
		return nil, fmt.Errorf("invalid --format %q (use text, json, or sarif): %w", format, ErrInvalidProfileInput)
	}
}

func writeResults(ctx context.Context, req ProfileRequest, sanitizer kernel.Sanitizer, result *evaluation.ComplianceReport, controls []policy.ControlDefinition) ([]byte, error) {
	marshaler, err := buildFindingWriter(req.Format, false)
	if err != nil {
		return nil, err
	}

	enricher := remediation.NewPlanner()
	enrichFn := func(rep *evaluation.ComplianceReport) (appcontracts.EnrichedResult, error) {
		return appeval.Enrich(enricher, sanitizer, rep)
	}

	pipeline := &appeval.OutputPipeline{
		Marshaler:       marshaler,
		Enricher:        enrichFn,
		CoveragePosture: buildCoveragePosture(controls, nil),
	}
	var buf bytes.Buffer
	if err := pipeline.Run(ctx, &buf, result); err != nil {
		return nil, fmt.Errorf("run output pipeline: %w", err)
	}
	data := buf.Bytes()
	if len(data) == 0 {
		return nil, errors.New("output pipeline produced empty output")
	}
	if req.Format == "json" && !json.Valid(data) {
		return nil, fmt.Errorf("output pipeline produced invalid JSON (%d bytes)", len(data))
	}
	return data, nil
}

// finalizeOutcome carries the post-evaluation stderr warnings, diagnose hint,
// and violation signal back to the command (which owns stderr + exit routing).
type finalizeOutcome struct {
	Warnings      []string
	DiagnoseHint  string
	HasViolations bool
}

func finalizeProfileEvaluation(results *evaluation.ComplianceReport, snapshots []asset.Snapshot, ctlDir, inputFile string) finalizeOutcome {
	var out finalizeOutcome
	if unprovable := asset.CountUnprovablySafe(snapshots); unprovable > 0 {
		out.Warnings = append(out.Warnings, fmt.Sprintf("\nWarning: %d bucket(s) have missing inputs - safety cannot be proven", unprovable))
	}

	if len(results.Findings) > 0 {
		out.DiagnoseHint = fmt.Sprintf("stave diagnose --controls %s --observations %s", ctlDir, inputFile)
		out.HasViolations = true
		return out
	}

	out.Warnings = append(out.Warnings, "Evaluation complete. No violations found.")
	return out
}
