// Package bundle implements the 'stave bundle' command for generating
// portable, cryptographically sealed evidence archives that can be
// transferred across air-gap boundaries to GRC platforms.
package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/adapters/evidence"
	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/adapters/output/asff"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/report"
)

type options struct {
	ControlsDir     string
	ObservationsDir string
	MaxUnsafe       string
	SignKeyPath     string
	OutputPath      string
	IncludeASFF     bool
	AllowUnknown    bool
}

// NewCmd constructs the top-level bundle command.
func NewCmd() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Generate a sealed evidence bundle for air-gap GRC integration",
		Long: `Bundle runs a full assessment and packages the results into a
portable, cryptographically sealed evidence archive (.stave-bundle).
The bundle contains the assessment, logic trace, pruned resource
snapshots, and a SHA-256 manifest — optionally signed with an Ed25519
private key.

This enables air-gapped environments to produce verifiable compliance
evidence that can be transferred to GRC platforms (Vanta, Drata,
ServiceNow) via data diode or manual transfer.

Inputs:
  --controls, -i     Path to control definitions directory
  --observations, -o Path to observation snapshots directory
  --sign-key         Path to Ed25519 private key PEM for signing
  --output           Output file path (default: evidence-<timestamp>.stave-bundle)
  --include-asff     Include ASFF-formatted findings for Security Hub integration

Outputs:
  .stave-bundle      Tar.gz archive with assessment, trace, snapshots, manifest

Exit Codes:
  0   Bundle created, no violations
  2   Input or configuration error
  3   Bundle created with violations
  4   Internal error`,
		Example: `  stave bundle --controls ./controls --observations ./observations
  stave bundle -i ./controls -o ./observations --sign-key audit-private.pem
  stave bundle -i ./controls -o ./observations --include-asff --output evidence.stave-bundle`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
	}

	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "Path to control definitions directory")
	cmd.Flags().StringVarP(&opts.ObservationsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	cmd.Flags().StringVar(&opts.MaxUnsafe, "max-unsafe", "168h", "Maximum allowed unsafe duration")
	cmd.Flags().StringVar(&opts.SignKeyPath, "sign-key", "", "Path to Ed25519 private key PEM for signing")
	cmd.Flags().StringVar(&opts.OutputPath, "output", "", "Output file path")
	cmd.Flags().BoolVar(&opts.IncludeASFF, "include-asff", false, "Include ASFF-formatted findings")
	cmd.Flags().BoolVar(&opts.AllowUnknown, "allow-unknown-input", false, "Allow unknown observation source types")

	cmd.AddCommand(newAuditCmd())

	return cmd
}

func run(ctx context.Context, _, stderr io.Writer, opts *options) error {
	if _, err := os.Stat(opts.ControlsDir); err != nil {
		return fmt.Errorf("controls directory: %w", err)
	}
	if _, err := os.Stat(opts.ObservationsDir); err != nil {
		return fmt.Errorf("observations directory: %w", err)
	}

	// Resolve output path.
	outputPath := opts.OutputPath
	if outputPath == "" {
		outputPath = fmt.Sprintf("evidence-%s.stave-bundle", time.Now().UTC().Format("20060102T150405Z"))
	}

	// Run assessment via self-invocation.
	binary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}

	fmt.Fprintf(stderr, "Running assessment...\n")
	assessmentJSON, err := runAssessment(ctx, binary, opts)
	if err != nil {
		return fmt.Errorf("assessment: %w", err)
	}

	// Parse assessment for bundle metadata.
	var assessment report.Assessment
	if jsonErr := json.Unmarshal(assessmentJSON, &assessment); jsonErr != nil {
		return fmt.Errorf("parse assessment: %w", jsonErr)
	}

	// Load signing key if provided.
	var privateKeyPEM []byte
	if opts.SignKeyPath != "" {
		keyData, readErr := os.ReadFile(opts.SignKeyPath) //nolint:gosec // user-specified key path
		if readErr != nil {
			return fmt.Errorf("read signing key: %w", readErr)
		}
		privateKeyPEM = keyData
	}

	// Load observation snapshots so the bundle can include the asset
	// state that produced each finding. The bundler prunes to assets
	// referenced by Findings (see evidence.marshalPrunedSnapshots).
	loader := observations.NewObservationLoader()
	loadResult, loadErr := loader.LoadSnapshots(ctx, opts.ObservationsDir)
	if loadErr != nil {
		return fmt.Errorf("load snapshots for bundle: %w", loadErr)
	}

	// Build the bundle.
	fmt.Fprintf(stderr, "Packaging evidence bundle...\n")
	input := evidence.BundleInput{
		Assessment:    &assessment,
		Snapshots:     loadResult.Snapshots,
		TraceJSON:     nil, // Logic trace would be captured if --trace was active
		PrivateKeyPEM: privateKeyPEM,
		StaveVersion:  "edge",
	}

	bundleData, err := evidence.Build(input)
	if err != nil {
		return fmt.Errorf("build bundle: %w", err)
	}

	// Write bundle.
	if writeErr := os.WriteFile(outputPath, bundleData, 0o644); writeErr != nil { //nolint:gosec // user-specified output
		return fmt.Errorf("write bundle: %w", writeErr)
	}

	// Write ASFF if requested.
	if opts.IncludeASFF {
		asffData, asffErr := asff.MarshalASFF(&assessment)
		if asffErr != nil {
			return fmt.Errorf("marshal ASFF: %w", asffErr)
		}
		asffPath := outputPath + ".asff.json"
		if writeErr := os.WriteFile(asffPath, asffData, 0o644); writeErr != nil { //nolint:gosec // user-specified output
			return fmt.Errorf("write ASFF: %w", writeErr)
		}
		fmt.Fprintf(stderr, "ASFF output: %s\n", asffPath)
	}

	signed := "unsigned"
	if len(privateKeyPEM) > 0 {
		signed = "signed"
	}
	fmt.Fprintf(stderr, "Bundle created (%s): %s\n", signed, outputPath)
	fmt.Fprintf(stderr, "  %d violations, %d chain findings\n",
		assessment.Summary.Violations, len(assessment.ChainFindings))

	if assessment.Summary.Violations > 0 {
		return ui.ErrViolationsFound
	}
	return nil
}

func runAssessment(ctx context.Context, binary string, opts *options) ([]byte, error) {
	args := []string{
		"apply",
		"--controls", opts.ControlsDir,
		"--observations", opts.ObservationsDir,
		"--max-unsafe", opts.MaxUnsafe,
		"--now", time.Now().UTC().Format(time.RFC3339),
		"--format", "json",
	}
	if opts.AllowUnknown {
		args = append(args, "--allow-unknown-input")
	}

	cmd := exec.CommandContext(ctx, binary, args...) //nolint:gosec // binary is os.Executable()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Exit codes from `stave apply`:
	//   0 = success, no violations
	//   3 = success, violations found (still a valid assessment)
	// Any other code (2 = input error, 4 = internal error, 130 = SIGINT)
	// means the assessment failed; partial stdout is not safe to bundle.
	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](runErr); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("exec assessment: %w", runErr)
		}
	}
	if exitCode != 0 && exitCode != 3 {
		return nil, fmt.Errorf("assessment failed (exit %d): %s", exitCode, stderr.String())
	}

	if stdout.Len() == 0 {
		return nil, fmt.Errorf("no assessment output: %s", stderr.String())
	}
	return stdout.Bytes(), nil
}
