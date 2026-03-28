package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// ComplianceResolverPort resolves a compliance framework crosswalk.
type ComplianceResolverPort interface {
	ResolveCrosswalk(ctx context.Context, raw []byte, frameworks, checkIDs []string) (domain.InspectComplianceResponse, error)
}

// ComplianceInputReaderPort reads crosswalk input from a file path.
type ComplianceInputReaderPort interface {
	ReadInput(ctx context.Context, filePath string) ([]byte, error)
}

// InspectComplianceDeps groups the port interfaces for the inspect-compliance use case.
type InspectComplianceDeps struct {
	Resolver ComplianceResolverPort
	Reader   ComplianceInputReaderPort
}

// InspectCompliance resolves a compliance framework crosswalk.
func InspectCompliance(
	ctx context.Context,
	req domain.InspectComplianceRequest,
	deps InspectComplianceDeps,
) (domain.InspectComplianceResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.InspectComplianceResponse{}, fmt.Errorf("inspect-compliance: %w", err)
	}

	var input []byte
	if req.FilePath != "" {
		data, err := deps.Reader.ReadInput(ctx, req.FilePath)
		if err != nil {
			return domain.InspectComplianceResponse{}, fmt.Errorf("inspect-compliance: %w", err)
		}
		input = data
	} else if len(req.InputData) > 0 {
		input = req.InputData
	} else {
		return domain.InspectComplianceResponse{}, fmt.Errorf("inspect-compliance: no input provided (use --file or stdin)")
	}

	resp, err := deps.Resolver.ResolveCrosswalk(ctx, input, req.Frameworks, req.CheckIDs)
	if err != nil {
		return domain.InspectComplianceResponse{}, fmt.Errorf("inspect-compliance: %w", err)
	}

	return resp, nil
}
