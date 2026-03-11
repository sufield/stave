package service

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

// FindingDetailInput holds everything needed to build a FindingDetail.
type FindingDetailInput struct {
	ControlID    kernel.ControlID
	AssetID      asset.ID
	Controls     policy.ControlDefinitions
	Snapshots    []asset.Snapshot
	Result       *evaluation.Result
	TraceBuilder evaluation.FindingTraceBuilder
}

// BuildFindingDetail delegates to the Result aggregate, injecting the
// trace builder provided by the caller.
func BuildFindingDetail(input FindingDetailInput) (*evaluation.FindingDetail, error) {
	return remediation.BuildFindingDetail(input.Result, evaluation.FindingDetailRequest{
		ControlID:    input.ControlID,
		AssetID:      input.AssetID,
		Controls:     input.Controls,
		Snapshots:    input.Snapshots,
		TraceBuilder: input.TraceBuilder,
	})
}
