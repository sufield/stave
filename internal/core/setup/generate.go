package setup

import (
	"context"
	"fmt"
)

// ControlGeneratorPort scaffolds a control YAML template.
type ControlGeneratorPort interface {
	GenerateControl(ctx context.Context, req GenerateControlRequest) (GenerateControlResponse, error)
}

// GenerateControlDeps groups the port interfaces for the generate-control use case.
type GenerateControlDeps struct {
	Generator ControlGeneratorPort
}

// GenerateControl scaffolds a ctrl.v1 YAML template.
func GenerateControl(ctx context.Context, req GenerateControlRequest, deps GenerateControlDeps) (GenerateControlResponse, error) {
	if err := ctx.Err(); err != nil {
		return GenerateControlResponse{}, fmt.Errorf("generate-control: %w", err)
	}

	if req.Name == "" {
		return GenerateControlResponse{}, fmt.Errorf("generate-control: name is required")
	}

	resp, err := deps.Generator.GenerateControl(ctx, req)
	if err != nil {
		return GenerateControlResponse{}, fmt.Errorf("generate-control: %w", err)
	}

	return resp, nil
}

// ObservationGeneratorPort scaffolds an observation JSON template.
type ObservationGeneratorPort interface {
	GenerateObservation(ctx context.Context, req GenerateObservationRequest) (GenerateObservationResponse, error)
}

// GenerateObservationDeps groups the port interfaces for the generate-observation use case.
type GenerateObservationDeps struct {
	Generator ObservationGeneratorPort
}

// GenerateObservation scaffolds an obs.v0.1 JSON template.
func GenerateObservation(ctx context.Context, req GenerateObservationRequest, deps GenerateObservationDeps) (GenerateObservationResponse, error) {
	if err := ctx.Err(); err != nil {
		return GenerateObservationResponse{}, fmt.Errorf("generate-observation: %w", err)
	}

	if req.Name == "" {
		return GenerateObservationResponse{}, fmt.Errorf("generate-observation: name is required")
	}

	resp, err := deps.Generator.GenerateObservation(ctx, req)
	if err != nil {
		return GenerateObservationResponse{}, fmt.Errorf("generate-observation: %w", err)
	}

	return resp, nil
}
