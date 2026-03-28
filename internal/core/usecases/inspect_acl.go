package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// ACLAnalyzerPort analyzes S3 ACL grants.
type ACLAnalyzerPort interface {
	AnalyzeACL(ctx context.Context, grantsJSON []byte) (domain.InspectACLResponse, error)
}

// ACLInputReaderPort reads ACL input from a file path.
type ACLInputReaderPort interface {
	ReadInput(ctx context.Context, filePath string) ([]byte, error)
}

// InspectACLDeps groups the port interfaces for the inspect-acl use case.
type InspectACLDeps struct {
	Analyzer ACLAnalyzerPort
	Reader   ACLInputReaderPort
}

// InspectACL analyzes S3 ACL grants for security posture.
func InspectACL(
	ctx context.Context,
	req domain.InspectACLRequest,
	deps InspectACLDeps,
) (domain.InspectACLResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.InspectACLResponse{}, fmt.Errorf("inspect-acl: %w", err)
	}

	var input []byte
	if req.FilePath != "" {
		data, err := deps.Reader.ReadInput(ctx, req.FilePath)
		if err != nil {
			return domain.InspectACLResponse{}, fmt.Errorf("inspect-acl: %w", err)
		}
		input = data
	} else if len(req.InputData) > 0 {
		input = req.InputData
	} else {
		return domain.InspectACLResponse{}, fmt.Errorf("inspect-acl: no input provided (use --file or stdin)")
	}

	resp, err := deps.Analyzer.AnalyzeACL(ctx, input)
	if err != nil {
		return domain.InspectACLResponse{}, fmt.Errorf("inspect-acl: %w", err)
	}

	return resp, nil
}
