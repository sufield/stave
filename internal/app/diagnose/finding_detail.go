package diagnose

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// FindingDetailInput holds everything needed to build a FindingDetail.
type FindingDetailInput struct {
	ControlID    kernel.ControlID
	AssetID      asset.ID
	Controls     policy.ControlDefinitions
	Snapshots    []asset.Snapshot
	Result       *evaluation.ComplianceReport
	TraceBuilder evaluation.FindingTraceBuilder
	IDGen        ports.IdentityGenerator
}

// BuildFindingDetail delegates to the Result aggregate, injecting the
// trace builder provided by the caller.
func BuildFindingDetail(input FindingDetailInput) (*evaluation.FindingDetail, error) {
	detail, err := remediation.BuildFindingDetail(input.Result, evaluation.FindingDetailRequest{
		ControlID:    input.ControlID,
		AssetID:      input.AssetID,
		Controls:     input.Controls,
		Snapshots:    input.Snapshots,
		TraceBuilder: input.TraceBuilder,
	}, input.IDGen)
	if err != nil {
		return nil, fmt.Errorf("build finding detail for %s/%s: %w", input.ControlID, input.AssetID, err)
	}
	return detail, nil
}
