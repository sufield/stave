package stave

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	evaljson "github.com/sufield/stave/internal/adapters/evaluation"
	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/adapters/output"
	"github.com/sufield/stave/internal/adapters/predicate"
	appfix "github.com/sufield/stave/internal/app/fix"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/usecase"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/sanitize"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// FixFinding reads an evaluation artifact and returns the deterministic
// remediation guidance JSON for a single finding (selected by
// <control_id>@<asset_id>). It never modifies user files. Load/selection
// failures stay plain (exit 4); the command validates the input file +
// selector up front (exit 2). It is the library entry point behind
// `stave ci fix`.
func FixFinding(ctx context.Context, inputPath, findingRef string) ([]byte, error) {
	celEval, err := stavecel.NewPredicateEval()
	if err != nil {
		return nil, fmt.Errorf("initialize CEL evaluator for fix command: %w", err)
	}
	loader, err := appfix.NewFindingLoader(celEval, fsutil.ReadFileLimited, evaljson.ParseFindings)
	if err != nil {
		return nil, fmt.Errorf("init finding loader: %w", err)
	}
	resp, err := usecase.Fix(ctx, usecase.FixRequest{
		InputPath:  inputPath,
		FindingRef: findingRef,
	}, usecase.FixDeps{Loader: loader})
	if err != nil {
		return nil, fmt.Errorf("run fix: %w", err)
	}
	var buf bytes.Buffer
	if err := jsonutil.WriteIndented(&buf, resp.Data); err != nil {
		return nil, fmt.Errorf("write output: %w", err)
	}
	return buf.Bytes(), nil
}

// FixLoopConfig parameterizes [RunFixLoop]. MaxUnsafe / Now are raw strings
// (resolved internally); Force / AllowSymlinks / SanitizeIDs / PathMode mirror
// the global flags.
type FixLoopConfig struct {
	BeforeDir     string
	AfterDir      string
	ControlsDir   string
	OutDir        string
	MaxUnsafe     string
	Now           string
	Force         bool
	AllowSymlinks bool
	SanitizeIDs   bool
	PathMode      string
}

// RunFixLoop executes the remediation verification lifecycle in one run:
// evaluate the before + after observation states, compare findings, and emit
// the remediation report to stdout plus the evaluation.before / .after /
// verification / remediation-report artifacts to OutDir. It returns whether
// remaining-or-introduced violations exist (the caller maps that to exit 3).
// Setup / evaluation failures stay plain (exit 4). It is the library entry
// point behind `stave ci fix-loop` (the command owns directory creation +
// flag resolution defaults).
func RunFixLoop(ctx context.Context, cfg FixLoopConfig, stdout, stderr io.Writer) (hasViolations bool, err error) {
	maxUnsafe, err := kernel.ParseDuration(cfg.MaxUnsafe)
	if err != nil {
		return false, fmt.Errorf("resolve max-unsafe duration: %w", err)
	}
	clock, err := resolveVerifyClock(cfg.Now)
	if err != nil {
		return false, fmt.Errorf("resolve clock: %w", err)
	}

	celEval, err := stavecel.NewPredicateEval()
	if err != nil {
		return false, fmt.Errorf("init CEL evaluator: %w", err)
	}

	sanitizer := sanitize.Policy{SanitizeIDs: cfg.SanitizeIDs, PathMode: sanitize.PathMode(cfg.PathMode)}.NewSanitizer()

	svc := appfix.NewService(clock, remediation.NewPlanner())
	svc.ParseFindings = evaljson.ParseFindings
	svc.CELEvaluator = celEval
	svc.ReadFile = fsutil.ReadFileLimited
	svc.Sanitizer = sanitizer

	ctlRepo := ctlyaml.NewControlLoader(ctlyaml.WithAliasResolver(predicate.ResolverFunc()))
	obsRepo := observations.NewObservationLoader()

	// DirPerms 0o700 matches the pre-facade newLoopRunner wiring.
	writer, err := appfix.NewArtifactWriter(
		cfg.OutDir,
		appfix.WriteOptions{
			Overwrite:     cfg.Force,
			AllowSymlinks: cfg.AllowSymlinks,
			DirPerms:      os.FileMode(0o700),
		},
		stdout,
		fsutil.SafeFileSystem{
			Overwrite:    cfg.Force,
			AllowSymlink: cfg.AllowSymlinks,
		},
	)
	if err != nil {
		return false, fmt.Errorf("init artifact writer: %w", err)
	}

	eb := &appfix.EnvelopeBuilder{
		Sanitizer:     sanitizer,
		BuildEnvelope: output.BuildAssessmentFromEnriched,
	}

	loopErr := svc.Loop(ctx, appfix.LoopRequest{
		BeforeDir:         cfg.BeforeDir,
		AfterDir:          cfg.AfterDir,
		ControlsDir:       cfg.ControlsDir,
		OutDir:            cfg.OutDir,
		MaxUnsafeDuration: maxUnsafe,
		Stdout:            stdout,
		Stderr:            stderr,
	}, appfix.LoopDeps{
		ObservationRepo: obsRepo,
		ControlRepo:     ctlRepo,
	}, writer, eb)

	if errors.Is(loopErr, appfix.ErrViolationsRemaining) {
		return true, nil
	}
	if loopErr != nil {
		return false, fmt.Errorf("run fix loop: %w", loopErr)
	}
	return false, nil
}
