// Package loader bridges Stave's library exports into the Z3
// experiment. It calls pkg/stave's three Export functions and the
// public Apply path, then hands the results to the compiler.
//
// The bridge is intentionally thin: every function in pkg/stave is
// invoked with the canonical Config / ExportConfig /
// InvariantExportConfig form so the experiment cannot drift from
// the library's contract. When the library renames a field or
// changes a signature, this is the only file in the experiment
// that needs to follow.
package loader

import (
	"context"
	"fmt"

	"github.com/sufield/stave/pkg/stave"
)

// StaveExports is the bundle the compiler operates on. Assessment
// drives the GraphExport projection; Policies and Invariants are
// loaded directly from the snapshots / control catalog. Combining
// the three gives the compiler "what is" (Policies), "what reaches
// what" (Graph), and "what should not be" (Invariants).
type StaveExports struct {
	Assessment *stave.Assessment
	Policies   *stave.PolicyExport
	Graph      *stave.GraphExport
	Invariants *stave.InvariantExport
}

// LoadFromObservations runs the full pipeline against a snapshot
// directory:
//
//  1. stave.Apply — produces an *Assessment over the snapshots,
//     using the embedded built-in catalog by default.
//  2. stave.ExportPolicies — re-loads the same snapshots and emits
//     parsed resource / KMS-key / trust policies plus the asset
//     edges they imply.
//  3. stave.ExportGraph — projects the Assessment into a graph view
//     (assets, findings, chains, finding/chain edges).
//  4. stave.ExportInvariants — loads the control catalog and emits
//     the unsafe-predicate trees as solver-ready invariants.
//
// All four calls share the same observations / catalog so the
// compiler sees a consistent picture.
func LoadFromObservations(ctx context.Context, snapshotsDir string) (*StaveExports, error) {
	if snapshotsDir == "" {
		return nil, fmt.Errorf("loader: snapshotsDir is required")
	}

	cfg := stave.Config{
		SnapshotsDir:      snapshotsDir,
		AllowUnknownInput: true,
	}

	assessment, err := stave.Apply(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("stave.Apply: %w", err)
	}

	policies, err := stave.ExportPolicies(ctx, stave.ExportConfig{
		SnapshotsDir:      snapshotsDir,
		AllowUnknownInput: true,
	})
	if err != nil {
		return nil, fmt.Errorf("stave.ExportPolicies: %w", err)
	}

	graph := stave.ExportGraph(assessment)

	invariants, err := stave.ExportInvariants(ctx, stave.InvariantExportConfig{})
	if err != nil {
		return nil, fmt.Errorf("stave.ExportInvariants: %w", err)
	}

	return &StaveExports{
		Assessment: assessment,
		Policies:   policies,
		Graph:      graph,
		Invariants: invariants,
	}, nil
}
