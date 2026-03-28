package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// PolicyAnalyzerPort analyzes an S3 bucket policy document.
type PolicyAnalyzerPort interface {
	AnalyzePolicy(ctx context.Context, policyJSON []byte) (domain.InspectPolicyResponse, error)
}

// PolicyInputReaderPort reads policy input from a file path.
type PolicyInputReaderPort interface {
	ReadInput(ctx context.Context, filePath string) ([]byte, error)
}

// InspectPolicyDeps groups the port interfaces for the inspect-policy use case.
type InspectPolicyDeps struct {
	Analyzer PolicyAnalyzerPort
	Reader   PolicyInputReaderPort
}

// InspectPolicy analyzes an S3 bucket policy document for security posture.
func InspectPolicy(
	ctx context.Context,
	req domain.InspectPolicyRequest,
	deps InspectPolicyDeps,
) (domain.InspectPolicyResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.InspectPolicyResponse{}, fmt.Errorf("inspect-policy: %w", err)
	}

	var input []byte
	if req.FilePath != "" {
		data, err := deps.Reader.ReadInput(ctx, req.FilePath)
		if err != nil {
			return domain.InspectPolicyResponse{}, fmt.Errorf("inspect-policy: %w", err)
		}
		input = data
	} else if len(req.InputData) > 0 {
		input = req.InputData
	} else {
		return domain.InspectPolicyResponse{}, fmt.Errorf("inspect-policy: no input provided (use --file or stdin)")
	}

	resp, err := deps.Analyzer.AnalyzePolicy(ctx, input)
	if err != nil {
		return domain.InspectPolicyResponse{}, fmt.Errorf("inspect-policy: %w", err)
	}

	return resp, nil
}
