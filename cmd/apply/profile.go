package apply

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
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
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/version"
)

// ApplyProfile represents a validated evaluation profile.
type ApplyProfile string

const (
	// ApplyProfileAWSS3 selects the AWS S3 evaluation profile.
	ApplyProfileAWSS3 ApplyProfile = "aws-s3"
)

// ParseApplyProfile validates and returns an ApplyProfile value.
func ParseApplyProfile(s string) (ApplyProfile, error) {
	switch ApplyProfile(s) {
	case ApplyProfileAWSS3:
		return ApplyProfileAWSS3, nil
	default:
		return "", fmt.Errorf("unsupported --profile %q (supported: aws-s3)", s)
	}
}

// applyProfileOptions holds profile-compatible options for evaluation.
type applyProfileOptions struct {
	inputFile       string
	bucketAllowlist []string
	includeAll      bool
	outputFormat    string
	nowTime         string
	quiet           bool
}

func runApplyProfileWithOptions(cmd *cobra.Command, opts applyProfileOptions) error {
	if err := validateApplyProfileInput(opts.inputFile); err != nil {
		return err
	}
	clock, err := resolveApplyProfileClock(opts.nowTime)
	if err != nil {
		return err
	}
	scopeFilter := resolveApplyProfileScopeFilter(opts)
	snapshots, err := obsjson.LoadBundle(opts.inputFile)
	if err != nil {
		return err
	}
	filteredSnapshots, err := filterProfileSnapshots(cmd.ErrOrStderr(), snapshots, scopeFilter, opts.quiet)
	if err != nil {
		return err
	}
	if len(filteredSnapshots) == 0 {
		return nil
	}

	ctlDir, controls, err := loadProfileControls(cmd.Context(), opts.inputFile)
	if err != nil {
		return err
	}

	progress := ui.DefaultRuntime()
	progress.Quiet = opts.quiet
	done := progress.BeginProgress("apply profile observations")
	defer done()

	result := appworkflow.EvaluateLoaded(appworkflow.EvaluationRequest{
		Controls:        controls,
		Snapshots:       filteredSnapshots,
		MaxUnsafe:       0,
		Clock:           clock,
		ToolVersion:     version.Version,
		PredicateParser: ctlyaml.YAMLPredicateParser,
	})

	cannotProveSafeCount := asset.CountUnprovablySafe(filteredSnapshots)

	format, formatErr := compose.ResolveFormatValue(cmd, opts.outputFormat)
	if formatErr != nil {
		return formatErr
	}

	marshaler, writerErr := compose.NewFindingWriter(format.String(), cmdutil.IsJSONMode(cmd))
	if writerErr != nil {
		return writerErr
	}

	enricher := remediation.NewMapper()
	san := cmdutil.GetSanitizer(cmd)
	enrichFn := func(r evaluation.Result) appcontracts.EnrichedResult {
		return output.Enrich(enricher, san, r)
	}

	pipeOut := compose.ResolveStdout(cmd, opts.quiet, format)
	pipeErr := appeval.NewPipeline(cmd.Context(), &appeval.PipelineData{
		Result: result,
		Output: pipeOut,
	}).
		Then(appeval.EnrichStep(enrichFn)).
		Then(appeval.MarshalStep(marshaler)).
		Then(appeval.WriteStep()).
		Error()
	if pipeErr != nil {
		return fmt.Errorf("write findings: %w", pipeErr)
	}

	return finalizeApplyProfileRun(cmd.ErrOrStderr(), len(result.Findings), cannotProveSafeCount, opts.quiet, ctlDir, opts.inputFile)
}

func validateApplyProfileInput(inputFile string) error {
	fi, err := os.Stat(inputFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("--input not found: %s", inputFile)
		}
		if os.IsPermission(err) {
			return fmt.Errorf("--input not readable: %s (check file permissions)", inputFile)
		}
		return fmt.Errorf("cannot access --input %q: %w", inputFile, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("--input must be a file, got directory: %s", inputFile)
	}
	return nil
}

func resolveApplyProfileClock(nowTime string) (ports.Clock, error) {
	return compose.ResolveClock(nowTime)
}

func resolveApplyProfileScopeFilter(opts applyProfileOptions) asset.AssetPredicate {
	if opts.includeAll {
		return asset.UniversalFilter
	}
	if len(opts.bucketAllowlist) > 0 {
		return asset.NewScopeFilterFromAllowlist(opts.bucketAllowlist)
	}
	return asset.DefaultHealthcareScopeFilter()
}

func filterProfileSnapshots(stderr io.Writer, snapshots []asset.Snapshot, scopeFilter asset.AssetPredicate, quiet bool) ([]asset.Snapshot, error) {
	if len(snapshots) == 0 {
		if !quiet {
			fmt.Fprintln(stderr, "No snapshots in observations file")
		}
		return nil, nil
	}
	filteredSnapshots := asset.FilterSnapshots(scopeFilter, snapshots)
	if len(filteredSnapshots) == 0 {
		if !quiet {
			fmt.Fprintln(stderr, "No S3 buckets matching health scope found in observations")
		}
		return nil, nil
	}
	return filteredSnapshots, nil
}

func loadProfileControls(ctx context.Context, inputFile string) (string, []policy.ControlDefinition, error) {
	ctlDir := filepath.Join(getControlsBaseDir(), "s3")

	controls, err := compose.LoadControls(ctx, ctlDir)
	if err != nil {
		return "", nil, err
	}
	if len(controls) == 0 {
		return "", nil, fmt.Errorf("no S3 controls found in %s", ctlDir)
	}

	attachProfileRunID(inputFile, ctlDir)
	return ctlDir, controls, nil
}

// attachProfileRunID computes and attaches a deterministic run ID from input
// hashes. Best-effort: hash failures produce empty strings, which is harmless.
func attachProfileRunID(inputFile, ctlDir string) {
	inputsHash, _ := fsutil.HashFile(inputFile)
	controlsHash, _ := fsutil.HashDirByExt(ctlDir, ".yaml", ".yml")
	cmdutil.AttachRunID(inputsHash.String(), controlsHash.String())
}

func finalizeApplyProfileRun(
	stderr io.Writer,
	findingsCount int,
	cannotProveSafeCount int,
	quiet bool,
	ctlDir string,
	inputFile string,
) error {
	if cannotProveSafeCount > 0 && !quiet {
		fmt.Fprintf(stderr, "\nWarning: %d bucket(s) have missing inputs - safety cannot be proven\n", cannotProveSafeCount)
	}
	if findingsCount > 0 {
		if !quiet {
			ui.WriteHint(stderr, fmt.Sprintf("stave diagnose --controls %s --observations %s", ctlDir, inputFile))
		}
		return ui.ErrViolationsFound
	}
	if !quiet {
		fmt.Fprintln(stderr, "Evaluation complete. No violations found.")
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
