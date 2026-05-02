package compliance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	evidenceadapter "github.com/sufield/stave/internal/adapters/evidence"
	"github.com/sufield/stave/internal/adapters/observations"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evidence"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/version"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/platform/crypto"
)

func runCompliance(
	ctx context.Context,
	opts *options,
	w io.Writer,
	newCtlRepo compose.CtlRepoFactory,
	newCELEvaluator compose.CELEvaluatorFactory,
) error {
	// Load built-in profiles (comma-separated).
	var profiles []*evidence.FrameworkProfile
	if opts.Profile != "" {
		profileIDs := strings.Split(opts.Profile, ",")
		for i := range profileIDs {
			profileIDs[i] = strings.TrimSpace(profileIDs[i])
		}
		for _, pid := range profileIDs {
			if pid == "" {
				continue
			}
			profile, loadErr := evidenceadapter.LoadProfile(pid)
			if loadErr != nil {
				return &ui.UserError{Err: fmt.Errorf("invalid --profile %q: %w", pid, loadErr)}
			}
			profiles = append(profiles, profile)
		}
	}

	// Load custom profile files.
	for _, path := range opts.ProfileFiles {
		profile, loadErr := evidenceadapter.LoadProfileFromFile(path)
		if loadErr != nil {
			return &ui.UserError{Err: fmt.Errorf("load profile file %q: %w", path, loadErr)}
		}
		profiles = append(profiles, profile)
	}

	if len(profiles) == 0 {
		return &ui.UserError{Err: errors.New("at least one of --profile or --profile-file is required")}
	}

	compositeMode := opts.Composite || len(profiles) > 1

	// Load snapshot.
	snapshots, err := observations.LoadBundle(opts.Snapshot)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("load snapshot: %w", err)}
	}
	if len(snapshots) == 0 {
		return &ui.UserError{Err: errors.New("snapshot file contains no observations")}
	}

	// Load all controls.
	repo, err := newCtlRepo()
	if err != nil {
		return fmt.Errorf("create control loader: %w", err)
	}
	ctlDir := resolveControlsDir()
	allControls, err := repo.LoadControls(ctx, ctlDir)
	if err != nil {
		return fmt.Errorf("load controls: %w", err)
	}

	// Collect controls matching any requested framework.
	fwSet := make(map[policy.ComplianceFramework]bool)
	for _, p := range profiles {
		fwSet[policy.ComplianceFramework(p.FrameworkKey)] = true
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

	// Initialize CEL evaluator.
	celEval, err := newCELEvaluator()
	if err != nil {
		return fmt.Errorf("init CEL evaluator: %w", err)
	}

	// Run assessment with evidence generation.
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
		return fmt.Errorf("evaluate: %w", err)
	}

	pkg := result.EvidencePackage
	if pkg == nil {
		return errors.New("assessment did not produce evidence package")
	}

	// Evaluate each profile.
	var assessments []*evidence.ProfileAssessment
	for _, profile := range profiles {
		assessments = append(assessments, evidence.EvaluateProfile(pkg, profile))
	}

	// Determine output writer.
	out := w
	if opts.Out != "" {
		f, fileErr := os.Create(opts.Out)
		if fileErr != nil {
			return fmt.Errorf("create output file: %w", fileErr)
		}
		defer f.Close()
		out = f
	}

	snapshotTime := snapshots[len(snapshots)-1].CapturedAt

	if compositeMode {
		return runComposite(out, opts, profiles, assessments, pkg, snapshotTime)
	}

	// OSCAL format — works for single and composite.
	if opts.Format == "oscal" {
		return renderOSCAL(out, opts, profiles, assessments, pkg, snapshotTime)
	}

	// Single-framework path (unchanged behavior).
	export := buildExport(profiles[0], assessments[0], pkg, version.String, snapshotTime, opts.IncludePass, opts.MinSeverity, result.Findings)
	switch opts.Format {
	case "json":
		if renderErr := renderJSON(out, export); renderErr != nil {
			return renderErr
		}
	case "table":
		if renderErr := renderTable(out, export, opts.Verbose); renderErr != nil {
			return renderErr
		}
	case "markdown":
		if renderErr := renderMarkdown(out, export); renderErr != nil {
			return renderErr
		}
	default:
		return &ui.UserError{Err: fmt.Errorf("unsupported format: %q", opts.Format)}
	}

	return exitError(assessments[0])
}

// exitError returns a sentinel error matching the assessment outcome.
func exitError(assessment *evidence.ProfileAssessment) error {
	if assessment.NotMetCount > 0 {
		return ui.ErrSecurityAuditFindings
	}
	if assessment.IncompleteCount > 0 {
		return ui.ErrViolationsFound
	}
	return nil
}

// exitErrorComposite checks all assessments and returns the worst outcome.
func exitErrorComposite(assessments []*evidence.ProfileAssessment) error {
	for _, a := range assessments {
		if a.NotMetCount > 0 {
			return ui.ErrSecurityAuditFindings
		}
	}
	for _, a := range assessments {
		if a.IncompleteCount > 0 {
			return ui.ErrViolationsFound
		}
	}
	return nil
}

// resolveControlsDir returns the controls directory, using the same
// fallback logic as stave apply: try <binary-dir>/controls first,
// then fall back to ./controls relative to cwd.
func resolveControlsDir() string {
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Join(filepath.Dir(exe), "controls")
		if fi, statErr := os.Stat(dir); statErr == nil && fi.IsDir() {
			return dir
		}
	}
	return "controls"
}
