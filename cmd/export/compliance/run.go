package compliance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

// runCompliance builds the export config from the flags, delegates the
// load → evaluate → render pipeline to the facade, writes the rendered
// document (to --out or stdout), and maps the compliance outcome to the
// standard exit-code sentinels.
func runCompliance(ctx context.Context, opts *options, w io.Writer) error {
	cfg := stave.ComplianceExportConfig{
		SnapshotPath:   opts.Snapshot,
		ProfileIDs:     splitProfiles(opts.Profile),
		ProfileFiles:   opts.ProfileFiles,
		Format:         opts.Format,
		MinSeverity:    opts.MinSeverity,
		IncludePass:    opts.IncludePass,
		Verbose:        opts.Verbose,
		Composite:      opts.Composite,
		SystemUUID:     opts.SystemUUID,
		Assessor:       opts.Assessor,
		AssessmentUUID: opts.AssessmentUUID,
	}

	out, outcome, err := stave.ExportCompliance(ctx, cfg)
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped ("evaluate"/"render..."); preserve exit 4.
	}

	if writeErr := cmdutil.WriteTo(w, opts.Out, func(dst io.Writer) error {
		_, e := dst.Write(out)
		return e
	}); writeErr != nil {
		return fmt.Errorf("write compliance export: %w", writeErr)
	}

	switch outcome {
	case stave.ComplianceFailed:
		return ui.ErrSecurityAuditFindings
	case stave.ComplianceIncomplete:
		return ui.ErrViolationsFound
	}
	return nil
}

// splitProfiles turns a comma-separated --profile value into IDs. Empty
// entries are tolerated and dropped by the facade.
func splitProfiles(raw string) []string {
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}
