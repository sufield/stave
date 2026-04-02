package apply

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/version"
)

// Profile represents a validated evaluation profile.
type Profile string

const (
	// ProfileAWSS3 selects the AWS S3 evaluation profile.
	ProfileAWSS3 Profile = "aws-s3"
	// ProfileHIPAA selects the HIPAA Security Rule evaluation profile.
	ProfileHIPAA Profile = "hipaa"
)

// ParseProfile validates and returns a Profile value.
func ParseProfile(s string) (Profile, error) {
	switch Profile(s) {
	case ProfileAWSS3, ProfileHIPAA:
		return Profile(s), nil
	default:
		return "", fmt.Errorf("unsupported --profile %q (supported: aws-s3, hipaa)", s)
	}
}

// Config holds the parameters for a profile-based apply operation.
type Config struct {
	InputFile       string
	Profile         Profile
	BucketAllowlist []string
	IncludeAll      bool
	OutputFormat    appcontracts.OutputFormat
	Quiet           bool
	Stdout          io.Writer
	Stderr          io.Writer
	Sanitizer       kernel.Sanitizer
}

// ControlLoaderFunc loads controls from a directory.
type ControlLoaderFunc func(ctx context.Context, dir string) ([]policy.ControlDefinition, error)

// Runner handles the execution of the profile apply logic.
type Runner struct {
	Clock            ports.Clock
	Hasher           ports.Digester
	UI               *ui.Runtime
	NewCELEvaluator  compose.CELEvaluatorFactory
	LoadControls     ControlLoaderFunc
	newFindingWriter compose.FindingWriterFactory
}

// RunnerOption configures optional Runner dependencies.
type RunnerOption func(*Runner)

// WithClock overrides the default wall clock.
func WithClock(c ports.Clock) RunnerOption {
	return func(r *Runner) { r.Clock = c }
}

// WithUI sets the UI runtime for progress and hints.
func WithUI(rt *ui.Runtime) RunnerOption {
	return func(r *Runner) { r.UI = rt }
}

// NewRunner initializes a runner with required factories and optional overrides.
func NewRunner(newCELEvaluator compose.CELEvaluatorFactory, loadControls ControlLoaderFunc, newFindingWriter compose.FindingWriterFactory, opts ...RunnerOption) *Runner {
	r := &Runner{
		Hasher:           crypto.NewHasher(),
		NewCELEvaluator:  newCELEvaluator,
		LoadControls:     loadControls,
		newFindingWriter: newFindingWriter,
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Run executes the profile evaluation workflow.
func (r *Runner) Run(ctx context.Context, cfg Config) error {
	if err := validateInput(cfg.InputFile); err != nil {
		return err
	}

	snapshots, err := observations.LoadBundle(cfg.InputFile)
	if err != nil {
		return fmt.Errorf("load observation bundle: %w", err)
	}

	filtered := filterSnapshots(cfg.Stderr, cfg.Quiet, cfg, snapshots)
	if len(filtered) == 0 {
		return nil
	}

	ctlDir, controls, err := r.loadControls(ctx, cfg.Profile)
	if err != nil {
		return fmt.Errorf("load controls: %w", err)
	}

	celEval, err := r.NewCELEvaluator()
	if err != nil {
		return fmt.Errorf("init CEL evaluator: %w", err)
	}

	done := r.UI.BeginProgress("apply profile observations")
	defer done()

	result, err := appeval.EvaluateLoaded(appeval.EvaluationRequest{
		Controls:          controls,
		Snapshots:         filtered,
		MaxUnsafeDuration: 0,
		Clock:             r.Clock,
		Hasher:            r.Hasher,
		StaveVersion:      version.String,
		PredicateParser:   ctlyaml.ParsePredicate,
		CELEvaluator:      celEval,
	})
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}

	if err := r.writeResults(ctx, cfg, result); err != nil {
		return fmt.Errorf("write findings: %w", err)
	}

	return finalizeProfileEvaluation(cfg.Stderr, cfg.Quiet, result, filtered, ctlDir, cfg.InputFile)
}

func validateInput(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &ui.UserError{Err: fmt.Errorf("--input not found: %q", path)}
		}
		if os.IsPermission(err) {
			return &ui.UserError{Err: fmt.Errorf("--input not readable: %q (check file permissions)", path)}
		}
		return &ui.UserError{Err: fmt.Errorf("cannot access --input %q: %w", path, err)}
	}
	if fi.IsDir() {
		return &ui.UserError{Err: fmt.Errorf("--input must be a file, got directory: %q", path)}
	}
	return nil
}

func (r *Runner) loadControls(ctx context.Context, prof Profile) (string, []policy.ControlDefinition, error) {
	domain := profileControlDomain(prof)
	ctlDir := filepath.Join(getControlsBaseDir(), domain)

	controls, err := r.LoadControls(ctx, ctlDir)
	if err != nil {
		return "", nil, err
	}
	if len(controls) == 0 {
		return "", nil, fmt.Errorf("%w: no %s controls found in %s", appeval.ErrNoControls, domain, ctlDir)
	}

	return ctlDir, controls, nil
}

// profileControlDomain maps a profile to its control subdirectory.
func profileControlDomain(prof Profile) string {
	switch prof {
	case ProfileHIPAA:
		// HIPAA reuses S3 controls — same directory, filtered by compliance ref.
		return "s3"
	default:
		return "s3"
	}
}

func getControlsBaseDir() string {
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Join(filepath.Dir(exe), "controls")
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			return dir
		}
	}
	return "controls"
}
