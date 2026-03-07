package apply

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	appworkflow "github.com/sufield/stave/internal/app/workflow"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
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
	scopeFile       string
	bucketAllowlist []string
	includeAll      bool
	outputFormat    string
	nowTime         string
	quiet           bool
}

// ObservationBundle represents a profile input observations bundle.
type ObservationBundle struct {
	SchemaVersion kernel.Schema    `json:"schema_version"`
	Snapshots     []asset.Snapshot `json:"snapshots"`
}

func runApplyProfileWithOptions(cmd *cobra.Command, opts applyProfileOptions) error {
	// Reserved for future profile-specific scope-file support.
	_ = opts.scopeFile

	if err := validateApplyProfileInput(opts.inputFile); err != nil {
		return err
	}
	clock, err := resolveApplyProfileClock(opts.nowTime)
	if err != nil {
		return err
	}
	scopeFilter := resolveApplyProfileScopeFilter(opts)
	snapshots, err := loadProfileSnapshots(opts.inputFile)
	if err != nil {
		return err
	}
	filteredSnapshots, err := filterProfileSnapshots(snapshots, scopeFilter, opts.quiet)
	if err != nil {
		return err
	}
	if len(filteredSnapshots) == 0 {
		return nil
	}

	ctlDir, controls, err := loadProfileControls(opts.inputFile)
	if err != nil {
		return err
	}

	progress := ui.NewRuntime(nil, nil)
	progress.Quiet = opts.quiet
	done := progress.BeginProgress("evaluate profile observations")
	defer done()

	result := appworkflow.EvaluateLoaded(appworkflow.EvaluationRequest{
		Controls:        controls,
		Snapshots:       filteredSnapshots,
		MaxUnsafe:       0,
		Clock:           clock,
		ToolVersion:     version.Version,
		PredicateParser: ctlyaml.YAMLPredicateParser,
	})

	cannotProveSafeCount := countCannotProveSafe(filteredSnapshots)

	format, formatErr := ui.ParseOutputFormat(opts.outputFormat)
	if formatErr != nil {
		return formatErr
	}

	writer, writerErr := cmdutil.NewFindingWriter(format.String(), cmdutil.IsJSONMode(cmd), cmdutil.GetSanitizer(cmd))
	if writerErr != nil {
		return writerErr
	}

	output := profileOutput(opts.quiet)
	if err := writer.WriteFindings(output, result); err != nil {
		return fmt.Errorf("write findings: %w", err)
	}

	return finalizeApplyProfileRun(len(result.Findings), cannotProveSafeCount, opts.quiet, ctlDir, opts.inputFile)
}

func validateApplyProfileInput(inputFile string) error {
	if _, err := os.Stat(inputFile); err != nil {
		return fmt.Errorf("--input not accessible: %s: %w", inputFile, err)
	}
	return nil
}

func resolveApplyProfileClock(nowTime string) (ports.Clock, error) {
	return cmdutil.ResolveClock(nowTime)
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

func loadProfileSnapshots(inputFile string) ([]asset.Snapshot, error) {
	obsData, err := fsutil.ReadFileLimited(inputFile)
	if err != nil {
		return nil, fmt.Errorf("read observations file: %w", err)
	}
	var obsFile ObservationBundle
	if err := json.Unmarshal(obsData, &obsFile); err != nil {
		return nil, fmt.Errorf("parse observations JSON: %w", err)
	}
	return obsFile.Snapshots, nil
}

func filterProfileSnapshots(snapshots []asset.Snapshot, scopeFilter asset.AssetPredicate, quiet bool) ([]asset.Snapshot, error) {
	if len(snapshots) == 0 {
		if !quiet {
			fmt.Fprintln(os.Stderr, "No snapshots in observations file")
		}
		return nil, nil
	}
	filteredSnapshots := asset.FilterSnapshots(scopeFilter, snapshots)
	if len(filteredSnapshots) == 0 || len(filteredSnapshots[0].Assets) == 0 {
		if !quiet {
			fmt.Fprintln(os.Stderr, "No S3 buckets matching health scope found in observations")
		}
		return nil, nil
	}
	return filteredSnapshots, nil
}

func loadProfileControls(inputFile string) (string, []policy.ControlDefinition, error) {
	ctlDir := filepath.Join(getControlsBaseDir(), "s3")
	inputsHash, _ := fsutil.HashFile(inputFile)
	controlsHash, _ := fsutil.HashDirByExt(ctlDir, ".yaml", ".yml")
	attachRunID(inputsHash.String(), controlsHash.String())

	ctlLoader, err := newControlRepository()
	if err != nil {
		return "", nil, fmt.Errorf("create control loader: %w", err)
	}
	controls, err := ctlLoader.LoadControls(context.Background(), ctlDir)
	if err != nil {
		return "", nil, fmt.Errorf("load S3 controls from %s: %w", ctlDir, err)
	}
	if len(controls) == 0 {
		return "", nil, fmt.Errorf("no S3 controls found in %s", ctlDir)
	}
	return ctlDir, controls, nil
}

func countCannotProveSafe(snapshots []asset.Snapshot) int {
	cannotProveSafeCount := 0
	for _, snap := range snapshots {
		for _, res := range snap.Assets {
			if provable, ok := res.Properties["safety_provable"].(bool); ok && !provable {
				cannotProveSafeCount++
			}
		}
	}
	return cannotProveSafeCount
}

func finalizeApplyProfileRun(
	findingsCount int,
	cannotProveSafeCount int,
	quiet bool,
	ctlDir string,
	inputFile string,
) error {
	if cannotProveSafeCount > 0 && !quiet {
		fmt.Fprintf(os.Stderr, "\nWarning: %d bucket(s) have missing inputs - safety cannot be proven\n", cannotProveSafeCount)
	}
	if findingsCount > 0 {
		if !quiet {
			fmt.Fprintf(os.Stderr, "Hint:\n  stave diagnose --controls %s --observations %s\n", ctlDir, inputFile)
		}
		return ui.ErrViolationsFound
	}
	if !quiet {
		fmt.Fprintln(os.Stderr, "Evaluation complete. No violations found.")
	}
	return nil
}

func profileOutput(quiet bool) io.Writer {
	if quiet {
		return io.Discard
	}
	return os.Stdout
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
