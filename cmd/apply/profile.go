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
	"github.com/sufield/stave/internal/adapters/output"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	appworkflow "github.com/sufield/stave/internal/app/workflow"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
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

	ctlDir, controls, err := r.loadControls(ctx, cfg.InputFile)
	if err != nil {
		return err
	}

	done := r.UI.BeginProgress("apply profile observations")
	result, err := appworkflow.EvaluateLoaded(appworkflow.EvaluationRequest{
		Controls:        controls,
		Snapshots:       filtered,
		MaxUnsafe:       0,
		Clock:           r.Clock,
		Hasher:          r.Hasher,
		ToolVersion:     version.Version,
		PredicateParser: ctlyaml.YAMLPredicateParser,
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

func (r *Runner) resolveScopeFilter(cfg Config) asset.AssetPredicate {
	if cfg.IncludeAll {
		return asset.UniversalFilter
	}
	if len(cfg.BucketAllowlist) > 0 {
		return asset.NewScopeFilterFromAllowlist(cfg.BucketAllowlist)
	}
	return asset.DefaultHealthcareScopeFilter()
}

func (r *Runner) filterSnapshots(cfg Config, snapshots []asset.Snapshot) []asset.Snapshot {
	if len(snapshots) == 0 {
		if !cfg.Quiet {
			fmt.Fprintln(cfg.Stderr, "No snapshots in observations file")
		}
		return nil
	}

	scopeFilter := r.resolveScopeFilter(cfg)
	filtered := asset.FilterSnapshots(scopeFilter, snapshots)
	if len(filtered) == 0 {
		if !cfg.Quiet {
			fmt.Fprintln(cfg.Stderr, "No S3 buckets matching health scope found in observations")
		}
		return nil
	}

	return filtered
}

func (r *Runner) loadControls(ctx context.Context, inputFile string) (string, []policy.ControlDefinition, error) {
	ctlDir := filepath.Join(getControlsBaseDir(), "s3")

	controls, err := compose.LoadControls(ctx, ctlDir)
	if err != nil {
		return "", nil, err
	}
	if len(controls) == 0 {
		return "", nil, fmt.Errorf("%w: no S3 controls found in %s", appeval.ErrNoControls, ctlDir)
	}

	inputsHash, _ := fsutil.HashFile(inputFile)
	controlsHash, _ := fsutil.HashDirByExt(ctlDir, ".yaml", ".yml")
	cmdutil.AttachRunID(inputsHash.String(), controlsHash.String())

	return ctlDir, controls, nil
}

func (r *Runner) writeResults(ctx context.Context, cfg Config, result evaluation.Result) error {
	marshaler, err := compose.NewFindingWriter(cfg.OutputFormat, cfg.IsJSONMode)
	if err != nil {
		return err
	}

	enricher := remediation.NewMapper(crypto.NewHasher())
	enrichFn := func(res evaluation.Result) appcontracts.EnrichedResult {
		return output.Enrich(enricher, cfg.Sanitizer, res)
	}

	return appeval.NewPipeline(ctx, &appeval.PipelineData{
		Result: result,
		Output: cfg.Stdout,
	}).
		Then(appeval.EnrichStep(enrichFn)).
		Then(appeval.MarshalStep(marshaler)).
		Then(appeval.WriteStep()).
		Error()
}

func (r *Runner) finalize(cfg Config, results evaluation.Result, snapshots []asset.Snapshot, ctlDir string) error {
	unprovable := asset.CountUnprovablySafe(snapshots)
	if unprovable > 0 && !cfg.Quiet {
		fmt.Fprintf(cfg.Stderr, "\nWarning: %d bucket(s) have missing inputs - safety cannot be proven\n", unprovable)
	}

	if len(results.Findings) > 0 {
		if !cfg.Quiet {
			ui.WriteHint(cfg.Stderr, fmt.Sprintf("stave diagnose --controls %s --observations %s", ctlDir, cfg.InputFile))
		}
		return ui.ErrViolationsFound
	}

	if !cfg.Quiet {
		fmt.Fprintln(cfg.Stderr, "Evaluation complete. No violations found.")
	}
	return nil
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
