package stave

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sufield/stave/pkg/stave/internal/cmderr"
	"github.com/sufield/stave/pkg/stave/internal/graphcmd"
)

// CoverageGraphConfig parameterizes [CoverageGraph]. It mirrors the
// `stave graph coverage` flags plus the global --sanitize / --path-mode
// settings.
type CoverageGraphConfig = graphcmd.CoverageConfig

// CoverageGraph loads the controls and the latest observation snapshot in the
// configured directories, builds the control→asset coverage graph, sanitizes
// identifiers, and renders it as DOT or JSON — returning the rendered bytes.
// An unknown format wraps [ErrInvalidInput] (exit 2); load/render failures
// stay plain (exit 4). It is the library entry point behind
// `stave graph coverage` (the command owns directory validation and the
// output write).
func CoverageGraph(ctx context.Context, cfg CoverageGraphConfig) ([]byte, error) {
	out, err := graphcmd.RunCoverage(ctx, cfg)
	if err != nil {
		return nil, mapGraphInputErr(err)
	}
	return out, nil
}

// ExportAssessmentGraph parses an out.v0.1 assessment (from `stave apply`) and
// renders a standards-based graph document (json/stix/jsonld/graphml),
// returning the rendered bytes. Bad assessment JSON wraps [ErrInvalidInput]
// (exit 2); an unknown format and render failures stay plain (exit 4). It is
// the library entry point behind `stave graph export` (the command owns the
// file read and the --out write).
func ExportAssessmentGraph(assessmentData []byte, format, sourcePath string, now time.Time) ([]byte, error) {
	out, err := graphcmd.ExportGraph(assessmentData, format, sourcePath, now)
	if err != nil {
		return nil, mapGraphInputErr(err)
	}
	return out, nil
}

// mapGraphInputErr re-wraps a cmderr.InputError with ErrInvalidInput (exit
// 2) and passes everything else through unchanged (plain, exit 4).
func mapGraphInputErr(err error) error {
	if ie, ok := errors.AsType[*cmderr.InputError](err); ok {
		return fmt.Errorf("%w: %w", ie.Err, ErrInvalidInput)
	}
	return err //nolint:wrapcheck // engine already wrapped; preserve exit 4.
}
