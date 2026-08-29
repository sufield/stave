package stave

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// IAMLoopConfig configures a single IAM policy analysis cycle.
type IAMLoopConfig struct {
	PolicyPath string
}

// IAMLoopResult holds the output of one IAM loop cycle.
type IAMLoopResult struct {
	Observation IAMObservation
	WallClock   time.Duration
}

// IAMObservation is the obs.v0.1 snapshot produced by iam-explain.
type IAMObservation struct {
	SchemaVersion string     `json:"schema_version"`
	CapturedAt    string     `json:"captured_at"`
	Source        string     `json:"source"`
	GeneratedBy   IAMGenBy   `json:"generated_by"`
	Assets        []IAMAsset `json:"assets"`
}

// IAMGenBy identifies the observation source.
type IAMGenBy struct {
	SourceType string `json:"source_type"`
}

// IAMAsset is a single asset in the obs.v0.1 output.
type IAMAsset struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Vendor     string         `json:"vendor"`
	Properties map[string]any `json:"properties"`
}

// IAMLoop runs one cycle of the IAM policy analysis loop: policy JSON in,
// micro-observation out. Shells out to the iam-explain binary (must be in PATH).
func IAMLoop(ctx context.Context, cfg IAMLoopConfig) (*IAMLoopResult, error) {
	start := time.Now()

	if cfg.PolicyPath == "" {
		return nil, errors.New("iam loop: policy path is required")
	}

	binary, err := exec.LookPath("iam-explain")
	if err != nil {
		return nil, errors.New("iam loop: iam-explain not found in PATH — build from projects/iam-explain/")
	}

	cmd := exec.CommandContext(ctx, binary, cfg.PolicyPath, "--output", "obs") //nolint:gosec // binary is from LookPath, PolicyPath is user-supplied input (same pattern as prove_universal.go)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("iam loop: iam-explain: %w: %s", err, stderr.String())
	}

	var obs IAMObservation
	if err := json.Unmarshal(stdout.Bytes(), &obs); err != nil {
		return nil, fmt.Errorf("iam loop: parse obs output: %w", err)
	}

	if obs.SchemaVersion != "obs.v0.1" {
		return nil, fmt.Errorf("iam loop: unexpected schema version %q (want obs.v0.1)", obs.SchemaVersion)
	}

	return &IAMLoopResult{
		Observation: obs,
		WallClock:   time.Since(start),
	}, nil
}
