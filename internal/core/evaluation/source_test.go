package evaluation

import (
	"context"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/controldef"
)

// nopFindingSource is the smallest possible FindingSource
// implementation: returns nil findings and nil error for every
// request. Its purpose is purely to assert that the interface
// shape compiles and that implementing it requires only the
// imports the contract documents (controldef, asset, evaluation,
// stdlib). A failure to compile this file would catch a future
// signature drift on FindingSource at the package boundary.
type nopFindingSource struct{}

func (nopFindingSource) ProduceFindings(_ context.Context, _ FindingRequest) ([]Finding, error) {
	return nil, nil
}

func TestFindingSourceInterfaceCompiles(t *testing.T) {
	var _ FindingSource = nopFindingSource{}

	req := FindingRequest{
		Controls:   []controldef.ControlDefinition{},
		Snapshots:  []asset.Snapshot{},
		Now:        time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC),
		SLADefault: 168 * time.Hour,
	}
	out, err := nopFindingSource{}.ProduceFindings(context.Background(), req)
	if err != nil {
		t.Fatalf("ProduceFindings: %v", err)
	}
	if out != nil {
		t.Fatalf("nop source must return nil findings, got %d", len(out))
	}
}
