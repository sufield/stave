package prompt

import (
	"context"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

// EvalLoadFunc loads an evaluation result from a file path.
// Injected by the cmd layer (typically backed by evaljson.NewLoader).
type EvalLoadFunc func(path string) (*evaluation.Result, error)

// PromptOutput contains the assembled prompt and metadata.
type PromptOutput struct {
	Rendered   string
	FindingIDs []kernel.ControlID
	AssetID    string
}

// BuildFunc assembles matched findings into a rendered prompt.
// Injected by the cmd layer (typically backed by adapters/output/prompt).
type BuildFunc func(
	assetID string,
	controlsByID map[kernel.ControlID]*policy.ControlDefinition,
	assetPropsJSON string,
	matched []evaluation.Finding,
) PromptOutput

// DiagnosticContext holds pre-loaded state the prompt generator needs
// to produce rich, context-aware prompts.
type DiagnosticContext struct {
	// ControlsByID maps control IDs to their full definitions, including
	// remediation guidance and YAML representation.
	ControlsByID map[kernel.ControlID]*policy.ControlDefinition

	// AssetPropsJSON is the JSON-serialized asset properties from the
	// latest observation snapshot. Empty if observations were not provided.
	AssetPropsJSON string

	// LoadEval loads an evaluation result from a file path.
	LoadEval EvalLoadFunc

	// BuildPrompt assembles findings into a rendered prompt.
	BuildPrompt BuildFunc
}

// Config defines parameters for generating an LLM prompt.
type Config struct {
	EvalFile string
	AssetID  string
	Format   ui.OutputFormat
	Quiet    bool
	Stdout   io.Writer
	Stderr   io.Writer
}

// Result represents the structured JSON output for a prompt.
type Result struct {
	Prompt     string   `json:"prompt"`
	FindingIDs []string `json:"finding_ids"`
	AssetID    string   `json:"asset_id"`
}

// Runner orchestrates collection of context and generation of prompts.
type Runner struct {
	Ctx DiagnosticContext
}

// NewRunner creates a runner with the provided diagnostic context.
func NewRunner(dctx DiagnosticContext) *Runner {
	return &Runner{Ctx: dctx}
}

// Run generates an LLM prompt based on evaluation findings.
func (r *Runner) Run(_ context.Context, cfg Config) error {
	if cfg.EvalFile == "" {
		return fmt.Errorf("--evaluation-file is required")
	}
	if cfg.AssetID == "" {
		return fmt.Errorf("--asset-id is required")
	}

	evalResult, err := r.Ctx.LoadEval(cfg.EvalFile)
	if err != nil {
		return fmt.Errorf("load evaluation file: %w", err)
	}

	assetID := asset.ID(cfg.AssetID)
	var matched []evaluation.Finding
	for _, f := range evalResult.Findings {
		if f.AssetID == assetID {
			matched = append(matched, f)
		}
	}
	if len(matched) == 0 {
		return fmt.Errorf("no findings for asset %q in %s", cfg.AssetID, cfg.EvalFile)
	}

	out := r.Ctx.BuildPrompt(cfg.AssetID, r.Ctx.ControlsByID, r.Ctx.AssetPropsJSON, matched)
	return r.write(cfg, out)
}
