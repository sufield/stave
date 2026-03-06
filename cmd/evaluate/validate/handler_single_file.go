package validate

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/validation"
	"github.com/sufield/stave/internal/pkg/suggest"

	appvalidation "github.com/sufield/stave/internal/app/validation"
)

// runValidateSingleFile validates a single file (--in mode).
func runValidateSingleFile(cmd *cobra.Command, out io.Writer) error {
	return runValidateSingleFileWithOptions(cmd, out, validateOpts)
}

func runValidateSingleFileWithOptions(cmd *cobra.Command, out io.Writer, opts *options) error {
	data, sourceName, err := ui.ReadInput(os.Stdin, opts.InFile)
	if err != nil {
		return fmt.Errorf("cannot read --in: %s: %w", sourceName, err)
	}

	kind := strings.TrimSpace(opts.Kind)
	if kind != "" {
		normalizedKind, normErr := normalizeValidateKind(kind)
		if normErr != nil {
			return normErr
		}
		kind = normalizedKind
	}

	var req appvalidation.ContentValidator
	if kind != "" {
		req = appvalidation.ExplicitRequest{
			Data:          data,
			Kind:          kind,
			SchemaVersion: opts.SchemaVersion,
			Strict:        opts.StrictMode,
		}
	} else {
		req = appvalidation.AutoRequest{Data: data}
	}

	result, err := appvalidation.NewContentService().Validate(req)
	if err != nil {
		if kind != "" {
			return fmt.Errorf("validate %s %s: %w", kind, sourceName, err)
		}
		return fmt.Errorf("validate %s: %w", sourceName, err)
	}

	return outputAndExitWithOptions(cmd, out, result, validateIsJSONOutput(), opts)
}

func normalizeValidateKind(raw string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	switch normalized {
	case "control", "controls":
		return "control", nil
	case "observation", "obs", "snapshot", "snapshots":
		return "observation", nil
	case "finding", "findings":
		return "finding", nil
	}

	validKinds := []string{"control", "observation", "finding"}
	if suggestion := suggest.Closest(normalized, validKinds); suggestion != "" {
		return "", fmt.Errorf("invalid --kind %q (use control, observation, or finding)\nDid you mean %q?", raw, suggestion)
	}
	return "", fmt.Errorf("invalid --kind %q (use control, observation, or finding)", raw)
}

// NewReadinessValidateFn creates a validation function for readiness assessment.
// This is used by the plan/apply commands.
func NewReadinessValidateFn(cmd *cobra.Command, ctlDir, obsDir string) func(time.Duration, time.Time) (validation.ReadinessValidationResult, error) {
	return func(maxUnsafeDur time.Duration, now time.Time) (validation.ReadinessValidationResult, error) {
		obsLoader, err := cmdutil.NewObservationRepository()
		if err != nil {
			return validation.ReadinessValidationResult{}, err
		}
		ctlLoader, err := cmdutil.NewControlRepository()
		if err != nil {
			return validation.ReadinessValidationResult{}, err
		}
		validateRun := appvalidation.NewRun(obsLoader, ctlLoader)
		valResult, err := validateRun.Execute(context.Background(), appvalidation.Config{
			ControlsDir:     ctlDir,
			ObservationsDir: obsDir,
			MaxUnsafe:       maxUnsafeDur,
			NowTime:         now,
			SanitizePaths:   cmdutil.SanitizeEnabled(cmd),
		})
		if err != nil {
			return validation.ReadinessValidationResult{}, err
		}
		valResult.Diagnostics.AddAll(PackConfigIssues())
		return validation.ReadinessValidationResult{
			Diagnostics: valResult.Diagnostics,
			Summary: validation.ReadinessValidationSummary{
				ControlsLoaded:             valResult.Summary.ControlsLoaded,
				SnapshotsLoaded:            valResult.Summary.SnapshotsLoaded,
				AssetObservationsLoaded: valResult.Summary.AssetObservationsLoaded,
			},
		}, nil
	}
}
