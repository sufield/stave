package apply

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	obsjson "github.com/sufield/stave/internal/adapters/input/observations/json"
	appeval "github.com/sufield/stave/internal/app/eval"
	appworkflow "github.com/sufield/stave/internal/app/workflow"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/logging"
	"github.com/sufield/stave/internal/version"
)

// Profile represents a validated evaluation profile.
type Profile string

const (
	// ProfileAWSS3 selects the AWS S3 evaluation profile.
	ProfileAWSS3 Profile = "aws-s3"
)

// ParseProfile validates and returns a Profile value.
func ParseProfile(s string) (Profile, error) {
	switch Profile(s) {
	case ProfileAWSS3:
		return ProfileAWSS3, nil
	default:
		return "", fmt.Errorf("unsupported --profile %q (supported: %s)", s, ProfileAWSS3)
	}
}

// Config holds the parameters for a profile-based apply operation.
type Config struct {
	InputFile       string
	BucketAllowlist []string
	IncludeAll      bool
	OutputFormat    string
	NowTime         string
	Quiet           bool
	Stdout          io.Writer
	Stderr          io.Writer
	IsJSONMode      bool
	Sanitizer       kernel.Sanitizer
}

// Runner handles the execution of the profile apply logic.
type Runner struct {
	Clock  ports.Clock
	Hasher ports.Digester
	UI     *ui.Runtime
}

// NewRunner initializes a runner with default dependencies.
func NewRunner(clock ports.Clock, quiet bool) *Runner {
	progress := ui.DefaultRuntime()
	progress.Quiet = quiet
	return &Runner{
		Clock:  clock,
		Hasher: crypto.NewHasher(),
		UI:     progress,
	}
}

// Run executes the profile evaluation workflow.
func (r *Runner) Run(ctx context.Context, cfg Config) error {
	if err := r.validateInput(cfg.InputFile); err != nil {
		return err
	}

	snapshots, err := obsjson.LoadBundle(cfg.InputFile)
	if err != nil {
		return err
	}

	filtered := r.filterSnapshots(cfg, snapshots)
	if len(filtered) == 0 {
		return nil
	}

	ctlDir, controls, err := r.loadControls(ctx)
	if err != nil {
		return err
	}

	r.setupRunLogging(cfg.InputFile, ctlDir)

	done := r.UI.BeginProgress("apply profile observations")
	result, err := appworkflow.EvaluateLoaded(appworkflow.EvaluationRequest{
		Controls:        controls,
		Snapshots:       filtered,
		MaxUnsafe:       0,
		Clock:           r.Clock,
		Hasher:          r.Hasher,
		ToolVersion:     version.Version,
		PredicateParser: ctlyaml.ParsePredicate,
	})
	done()
	if err != nil {
		return err
	}

	if err := r.writeResults(ctx, cfg, result); err != nil {
		return fmt.Errorf("write findings: %w", err)
	}

	return r.finalize(cfg, result, filtered, ctlDir)
}

func (r *Runner) validateInput(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("--input not found: %s", path)
		}
		if os.IsPermission(err) {
			return fmt.Errorf("--input not readable: %s (check file permissions)", path)
		}
		return fmt.Errorf("cannot access --input %q: %w", path, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("--input must be a file, got directory: %s", path)
	}
	return nil
}

func (r *Runner) loadControls(ctx context.Context) (string, []policy.ControlDefinition, error) {
	ctlDir := filepath.Join(getControlsBaseDir(), "s3")

	controls, err := compose.LoadControls(ctx, ctlDir)
	if err != nil {
		return "", nil, err
	}
	if len(controls) == 0 {
		return "", nil, fmt.Errorf("%w: no S3 controls found in %s", appeval.ErrNoControls, ctlDir)
	}

	return ctlDir, controls, nil
}

func (r *Runner) setupRunLogging(inputFile, ctlDir string) {
	inputsHash, _ := fsutil.HashFile(inputFile)
	controlsHash, _ := fsutil.HashDirByExt(ctlDir, ".yaml", ".yml")
	logging.SetDefaultLogger(cmdutil.SetupLoggingWithRunID(
		logging.DefaultLogger(),
		inputsHash.String(),
		controlsHash.String(),
	))
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
