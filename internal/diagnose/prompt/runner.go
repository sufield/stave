package prompt

import (
	"context"
	"fmt"
	"io"

	"github.com/samber/lo"

	evaljson "github.com/sufield/stave/internal/adapters/input/evaluation/json"
	promptout "github.com/sufield/stave/internal/adapters/output/prompt"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

// DiagnosticContext holds pre-loaded state the prompt generator needs
// to produce rich, context-aware prompts.
type DiagnosticContext struct {
	// ControlsByID maps control IDs to their full definitions, including
	// remediation guidance and YAML representation.
	ControlsByID map[kernel.ControlID]*policy.ControlDefinition

	// AssetPropsJSON is the JSON-serialized asset properties from the
	// latest observation snapshot. Empty if observations were not provided.
	AssetPropsJSON string
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
func (r *Runner) Run(ctx context.Context, cfg Config) error {
	if cfg.EvalFile == "" {
		return fmt.Errorf("--evaluation-file is required")
	}
	if cfg.AssetID == "" {
		return fmt.Errorf("--asset-id is required")
	}

	evalResult, err := evaljson.NewLoader().LoadFromFile(cfg.EvalFile)
	if err != nil {
		return fmt.Errorf("load evaluation file: %w", err)
	}

	assetID := asset.ID(cfg.AssetID)
	matched := lo.Filter(evalResult.Findings, func(v evaluation.Finding, _ int) bool { return v.AssetID == assetID })
	if len(matched) == 0 {
		return fmt.Errorf("no findings for asset %q in %s", cfg.AssetID, cfg.EvalFile)
	}

	builder := &promptout.PromptBuilder{
		AssetID:        cfg.AssetID,
		ControlsByID:   r.Ctx.ControlsByID,
		AssetPropsJSON: r.Ctx.AssetPropsJSON,
	}
	data := builder.Build(matched)
	rendered := promptout.RenderPrompt(data)

	return r.write(cfg, rendered, data)
}
