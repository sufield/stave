package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// ExposureClassifierPort classifies resource exposure vectors.
type ExposureClassifierPort interface {
	ClassifyExposure(ctx context.Context, inputJSON []byte) (domain.InspectExposureResponse, error)
}

// ExposureInputReaderPort reads exposure input from a file path.
type ExposureInputReaderPort interface {
	ReadInput(ctx context.Context, filePath string) ([]byte, error)
}

// InspectExposureDeps groups the port interfaces for the inspect-exposure use case.
type InspectExposureDeps struct {
	Classifier ExposureClassifierPort
	Reader     ExposureInputReaderPort
}

// InspectExposure classifies resource exposure vectors and trust boundaries.
func InspectExposure(
	ctx context.Context,
	req domain.InspectExposureRequest,
	deps InspectExposureDeps,
) (domain.InspectExposureResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.InspectExposureResponse{}, fmt.Errorf("inspect-exposure: %w", err)
	}

	var input []byte
	if req.FilePath != "" {
		data, err := deps.Reader.ReadInput(ctx, req.FilePath)
		if err != nil {
			return domain.InspectExposureResponse{}, fmt.Errorf("inspect-exposure: %w", err)
		}
		input = data
	} else if len(req.InputData) > 0 {
		input = req.InputData
	} else {
		return domain.InspectExposureResponse{}, fmt.Errorf("inspect-exposure: no input provided (use --file or stdin)")
	}

	resp, err := deps.Classifier.ClassifyExposure(ctx, input)
	if err != nil {
		return domain.InspectExposureResponse{}, fmt.Errorf("inspect-exposure: %w", err)
	}

	return resp, nil
}
