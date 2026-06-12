// Package forgecmd is the engine behind `stave forge` (custom control
// authoring): predicate preview, property-path discovery, control/chain
// linting, fixture scaffolding + testing, and post-generation validation. It
// is the engine behind the pkg/stave.Forge* functions; the command keeps only
// flag wiring, the interactive wizard prompt loop, the gencontrol subprocess,
// and the output write.
package forgecmd

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// Preview evaluates a control predicate (field/op/value, or a raw expression)
// against all matching assets in a snapshot and returns the per-asset
// FAIL/PASS report. It is the library entry point behind `stave forge preview`.
func Preview(snapshotPath, assetType, field, op, value, predicateExpr string) ([]byte, error) {
	if field == "" && predicateExpr == "" {
		return nil, errors.New("either --field or --predicate is required")
	}

	snap, err := loadLatestSnapshot(snapshotPath)
	if err != nil {
		return nil, err
	}

	ctl := policy.ControlDefinition{
		DSLVersion: "ctrl.v1",
		ID:         kernel.ControlID("CTL.FORGE.PREVIEW.000"),
		Name:       "Forge Preview",
		Type:       policy.TypeUnsafeState,
	}
	if field != "" {
		ctl.UnsafePredicate = policy.UnsafePredicate{
			All: []policy.PredicateRule{{
				Field: predicate.NewFieldPath(field),
				Op:    predicate.Operator(op),
				Value: policy.NewOperand(parseValue(value)),
			}},
		}
	}

	celEval, err := stavecel.NewPredicateEval()
	if err != nil {
		return nil, fmt.Errorf("init CEL evaluator: %w", err)
	}
	if err := ctl.Prepare(); err != nil {
		return nil, fmt.Errorf("prepare control: %w", err)
	}

	var buf bytes.Buffer
	var failCount, passCount, errCount int
	for i := range snap.Assets {
		a := &snap.Assets[i]
		if assetType != "" && string(a.Type) != assetType {
			continue
		}
		unsafe, evalErr := celEval(ctl, *a, nil)
		if evalErr != nil {
			fmt.Fprintf(&buf, "  ERROR  %s  %v\n", a.ID, evalErr)
			errCount++
			continue
		}
		if unsafe {
			fmt.Fprintf(&buf, "  FAIL   %s\n", a.ID)
			failCount++
		} else {
			fmt.Fprintf(&buf, "  PASS   %s\n", a.ID)
			passCount++
		}
	}
	fmt.Fprintf(&buf, "\n%d FAIL  |  %d PASS  |  %d ERROR\n", failCount, passCount, errCount)
	return buf.Bytes(), nil
}

// LivePreview renders the wizard's live-preview block (step 8): it evaluates a
// field/op/value predicate against the snapshot's assets of the given type and
// returns the FAIL/PASS lines. Distinct from [Preview]: it carries the
// wizard's exact output format and is best-effort (a CEL init failure renders
// inline rather than erroring).
func LivePreview(snapshotPath, assetType, field, op, value string) ([]byte, error) {
	snap, err := loadLatestSnapshot(snapshotPath)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	celEval, celErr := stavecel.NewPredicateEval()
	if celErr != nil {
		fmt.Fprintf(&buf, "  CEL evaluator error: %v\n", celErr)
		return buf.Bytes(), nil
	}
	ctl := policy.ControlDefinition{
		DSLVersion: "ctrl.v1",
		ID:         kernel.ControlID("CTL.FORGE.PREVIEW.000"),
		Name:       "Live Preview",
		Type:       policy.TypeUnsafeState,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{{
				Field: predicate.NewFieldPath(field),
				Op:    predicate.Operator(op),
				Value: policy.NewOperand(parseValue(value)),
			}},
		},
	}
	if err := ctl.Prepare(); err != nil {
		fmt.Fprintf(&buf, "  Predicate error: %v\n", err)
		return buf.Bytes(), nil
	}
	var failCount, passCount int
	for i := range snap.Assets {
		a := &snap.Assets[i]
		if assetType != "" && string(a.Type) != assetType {
			continue
		}
		unsafe, evalErr := celEval(ctl, *a, nil)
		if evalErr != nil {
			continue
		}
		if unsafe {
			fmt.Fprintf(&buf, "  FAIL  %s\n", a.ID)
			failCount++
		} else {
			fmt.Fprintf(&buf, "  PASS  %s\n", a.ID)
			passCount++
		}
	}
	fmt.Fprintf(&buf, "\n%d FAIL  |  %d PASS\n\n", failCount, passCount)
	return buf.Bytes(), nil
}

// parseValue converts a string flag value to its typed equivalent.
func parseValue(s string) any {
	switch strings.ToLower(s) {
	case "true":
		return true
	case "false":
		return false
	}
	return s
}

// loadLatestSnapshot loads the bundle and returns its most recent snapshot.
func loadLatestSnapshot(path string) (*asset.Snapshot, error) {
	snapshots, err := observations.LoadBundle(path)
	if err != nil {
		return nil, fmt.Errorf("load snapshot: %w", err)
	}
	if len(snapshots) == 0 {
		return nil, errors.New("snapshot file contains no observations")
	}
	return &snapshots[len(snapshots)-1], nil
}
