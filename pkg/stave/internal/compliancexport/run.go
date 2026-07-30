// Package compliancexport runs a snapshot against one or more compliance
// framework profiles and renders the resulting evidence package in the
// requested format (json / table / markdown / oscal, single or composite).
// It is the engine behind pkg/stave.ExportCompliance and the
// `stave export compliance` command; the command keeps only flag wiring,
// the output-file write, and the exit-code signal.
package compliancexport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	evidenceadapter "github.com/sufield/stave/internal/adapters/evidence"
	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/adapters/predicate"
	appeval "github.com/sufield/stave/internal/app/eval"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evidence"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/version"
	"github.com/sufield/stave/pkg/stave/internal/cmderr"
)

// Outcome is the compliance result the caller maps to an exit code.
type Outcome int

// Outcome values, worst-first precedence applied in computeOutcome.
const (
	// OutcomeSatisfied — all required requirements met (exit 0).
	OutcomeSatisfied Outcome = iota
	// OutcomeIncomplete — at least one requirement incomplete (exit 3).
	OutcomeIncomplete
	// OutcomeFailed — at least one required requirement not met (exit 1).
	OutcomeFailed
)

// Config parameterizes [Run]. It mirrors the `stave export compliance`
// flags 1:1.
type Config struct {
	SnapshotPath   string
	ProfileIDs     []string // built-in profile IDs (from --profile, comma-split)
	ProfileFiles   []string // custom profile YAML paths (from --profile-file)
	Format         string   // json | table | markdown | oscal
	MinSeverity    string
	IncludePass    bool
	Verbose        bool
	Composite      bool
	SystemUUID     string
	Assessor       string
	AssessmentUUID string
}

// Result carries the rendered evidence document and the compliance outcome.
type Result struct {
	Output  []byte
	Outcome Outcome
}

// Run loads the requested profiles + snapshot, evaluates the catalog with
// evidence generation, and renders the per-requirement evidence package.
func Run(ctx context.Context, cfg *Config) (Result, error) {
	switch cfg.Format {
	case "json", "table", "markdown", "oscal":
	default:
		return Result{}, &cmderr.InputError{Err: fmt.Errorf("unsupported format: %q", cfg.Format)}
	}

	profiles, err := loadProfiles(cfg)
	if err != nil {
		return Result{}, err
	}

	compositeMode := cfg.Composite || len(profiles) > 1

	snapshots, err := observations.LoadBundle(cfg.SnapshotPath)
	if err != nil {
		return Result{}, &cmderr.InputError{Err: fmt.Errorf("load snapshot: %w", err)}
	}
	if len(snapshots) == 0 {
		return Result{}, &cmderr.InputError{Err: errors.New("snapshot file contains no observations")}
	}

	repo := ctlyaml.NewControlLoader(ctlyaml.WithAliasResolver(predicate.ResolverFunc()))
	allControls, err := repo.LoadControls(ctx, resolveControlsDir())
	if err != nil {
		return Result{}, fmt.Errorf("load controls: %w", err)
	}

	// Collect controls matching any requested framework.
	fwSet := make(map[policy.ComplianceFramework]struct{})
	for _, p := range profiles {
		fwSet[policy.ComplianceFramework(p.FrameworkKey)] = struct{}{}
	}
	var controls []policy.ControlDefinition
	for i := range allControls {
		for fw := range fwSet {
			if allControls[i].HasCompliance(fw) {
				controls = append(controls, allControls[i])
				break
			}
		}
	}

	celEval, err := stavecel.NewPredicateEval()
	if err != nil {
		return Result{}, fmt.Errorf("init CEL evaluator: %w", err)
	}

	result, err := appeval.Evaluate(ctx, appeval.EvaluateInput{
		Controls:         controls,
		Snapshots:        snapshots,
		Clock:            ports.RealClock{},
		Hasher:           crypto.NewHasher(),
		StaveVersion:     version.String,
		PredicateParser:  ctlyaml.ParsePredicate,
		CELEvaluator:     celEval,
		GenerateEvidence: true,
	})
	if err != nil {
		return Result{}, fmt.Errorf("evaluate: %w", err)
	}

	pkg := result.EvidencePackage
	if pkg == nil {
		return Result{}, errors.New("assessment did not produce evidence package")
	}

	var assessments []*evidence.ProfileAssessment
	for _, profile := range profiles {
		assessments = append(assessments, evidence.EvaluateProfile(pkg, profile))
	}

	snapshotTime := snapshots[len(snapshots)-1].CapturedAt

	var buf bytes.Buffer
	switch {
	case cfg.Format == "oscal":
		// OSCAL needs the raw profiles / assessments / snapshotTime that the
		// trimmed EvidenceExport projection drops; route directly for both
		// single and composite.
		if err := renderOSCAL(&buf, cfg, profiles, assessments, pkg, snapshotTime); err != nil {
			return Result{}, err
		}
	case compositeMode:
		if err := runComposite(&buf, cfg, profiles, assessments, pkg, snapshotTime); err != nil {
			return Result{}, err
		}
	default:
		renderer, rErr := NewRenderer(cfg.Format, cfg.Verbose)
		if rErr != nil {
			return Result{}, &cmderr.InputError{Err: rErr}
		}
		export := buildExport(profiles[0], assessments[0], pkg, version.String, snapshotTime, cfg.IncludePass, cfg.MinSeverity, result.Findings)
		if err := renderer.Render(&buf, export); err != nil {
			return Result{}, fmt.Errorf("render compliance export: %w", err)
		}
	}

	return Result{Output: buf.Bytes(), Outcome: computeOutcome(assessments)}, nil
}

// loadProfiles resolves the built-in and custom profiles named in cfg.
// Returns ErrInput when a profile ID/file is invalid or none are given.
func loadProfiles(cfg *Config) ([]*evidence.FrameworkProfile, error) {
	var profiles []*evidence.FrameworkProfile
	for _, pid := range cfg.ProfileIDs {
		pid = strings.TrimSpace(pid)
		if pid == "" {
			continue
		}
		profile, err := evidenceadapter.LoadProfile(pid)
		if err != nil {
			return nil, &cmderr.InputError{Err: fmt.Errorf("invalid --profile %q: %w", pid, err)}
		}
		profiles = append(profiles, profile)
	}
	for _, path := range cfg.ProfileFiles {
		profile, err := evidenceadapter.LoadProfileFromFile(path)
		if err != nil {
			return nil, &cmderr.InputError{Err: fmt.Errorf("load profile file %q: %w", path, err)}
		}
		profiles = append(profiles, profile)
	}
	if len(profiles) == 0 {
		return nil, &cmderr.InputError{Err: errors.New("at least one of --profile or --profile-file is required")}
	}
	return profiles, nil
}

// computeOutcome returns the worst outcome across all assessments: a single
// not-met requirement fails the run (exit 1) ahead of any incomplete (exit 3).
func computeOutcome(assessments []*evidence.ProfileAssessment) Outcome {
	for _, a := range assessments {
		if a.NotMetCount > 0 {
			return OutcomeFailed
		}
	}
	for _, a := range assessments {
		if a.IncompleteCount > 0 {
			return OutcomeIncomplete
		}
	}
	return OutcomeSatisfied
}

// resolveControlsDir returns the controls directory, using the same fallback
// logic as `stave apply`: try <binary-dir>/controls first, then fall back to
// ./controls relative to cwd.
func resolveControlsDir() string {
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Join(filepath.Dir(exe), "controls")
		if fi, statErr := os.Stat(dir); statErr == nil && fi.IsDir() {
			return dir
		}
	}
	return "controls"
}
