package generate

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sufield/stave/cmd/cmdutil"
	evaljson "github.com/sufield/stave/internal/adapters/input/evaluation/json"
	outenforce "github.com/sufield/stave/internal/adapters/output/enforcement"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// Mode represents a validated enforcement mode.
type Mode string

const (
	// ModePAB selects Public Access Block enforcement.
	ModePAB Mode = "pab"
	// ModeSCP selects Service Control Policy enforcement.
	ModeSCP Mode = "scp"
)

// ParseMode validates and returns a Mode value.
func ParseMode(s string) (Mode, error) {
	normalized := Mode(ui.NormalizeToken(s))
	switch normalized {
	case ModePAB, ModeSCP:
		return normalized, nil
	default:
		return "", ui.EnumError("--mode", s, []string{string(ModePAB), string(ModeSCP)})
	}
}

// String implements fmt.Stringer.
func (m Mode) String() string {
	return string(m)
}

// Config holds the validated parameters for the generation engine.
type Config struct {
	InputPath string
	OutDir    string
	Mode      Mode
	DryRun    bool
	Stdout    io.Writer
}

// Runner orchestrates reading evaluation data and writing enforcement templates.
type Runner struct {
	FileOptions cmdutil.FileOptions
}

// NewRunner initializes a generate runner.
func NewRunner() *Runner {
	return &Runner{}
}

type result struct {
	SchemaVersion kernel.Schema     `json:"schema_version"`
	Kind          kernel.OutputKind `json:"kind"`
	Mode          Mode              `json:"mode"`
	DryRun        bool              `json:"dry_run,omitempty"`
	OutputFile    string            `json:"output_file"`
	Targets       []string          `json:"targets"`
}

type plan struct {
	result   result
	rendered string
}

// Run executes the template generation workflow.
func (r *Runner) Run(_ context.Context, cfg Config) error {
	p, err := r.buildPlan(cfg)
	if err != nil {
		return err
	}
	if cfg.DryRun {
		return r.writeDryRun(cfg.Stdout, p.result)
	}
	if err := r.writeOutputFile(p.result.OutputFile, p.rendered); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return r.writeResult(cfg.Stdout, p.result)
}

func (r *Runner) buildPlan(cfg Config) (plan, error) {
	if err := validateInputPath(cfg.InputPath); err != nil {
		return plan{}, err
	}
	refs, err := loadFindingRefs(cfg.InputPath)
	if err != nil {
		return plan{}, err
	}
	targets := outenforce.ExtractBucketTargets(refs)
	outPath, rendered, err := buildOutput(cfg.Mode, cfg.OutDir, targets)
	if err != nil {
		return plan{}, err
	}
	return plan{
		result: result{
			SchemaVersion: kernel.SchemaEnforce,
			Kind:          kernel.KindEnforcement,
			Mode:          cfg.Mode,
			OutputFile:    outPath,
			Targets:       targetNames(targets),
		},
		rendered: rendered,
	}, nil
}

func validateInputPath(inputPath string) error {
	fi, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("--in not accessible: %s: %w", inputPath, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("--in must be a file: %s", inputPath)
	}
	return nil
}

func loadFindingRefs(inputPath string) ([]outenforce.FindingRef, error) {
	data, err := fsutil.ReadFileLimited(inputPath)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	findings, err := evaljson.ParseFindings(data)
	if err != nil {
		return nil, fmt.Errorf("parse input JSON: %w", err)
	}
	refs := make([]outenforce.FindingRef, len(findings))
	for i, f := range findings {
		refs[i] = outenforce.FindingRef{
			ControlID: f.ControlID,
			AssetID:   f.AssetID,
		}
	}
	return refs, nil
}

func targetNames(targets []outenforce.BucketTarget) []string {
	names := make([]string, len(targets))
	for i, target := range targets {
		names[i] = target.BucketName.Name()
	}
	return names
}

func (r *Runner) writeDryRun(w io.Writer, res result) error {
	res.DryRun = true
	return r.writeResult(w, res)
}

func (r *Runner) writeOutputFile(outPath, rendered string) error {
	file, err := cmdutil.OpenOutputFile(outPath, r.FileOptions)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteString(rendered); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}
	return nil
}

func (r *Runner) writeResult(w io.Writer, res result) error {
	return jsonutil.WriteIndented(w, res)
}

func buildOutput(mode Mode, outDir string, targets []outenforce.BucketTarget) (string, string, error) {
	base := filepath.Join(outDir, "enforcement", "aws")
	switch mode {
	case ModePAB:
		return filepath.Join(base, "pab.tf"), outenforce.RenderPABTerraform(targets), nil
	case ModeSCP:
		rendered, err := outenforce.RenderSCP(targets)
		if err != nil {
			return "", "", fmt.Errorf("render scp: %w", err)
		}
		return filepath.Join(base, "scp.json"), rendered, nil
	default:
		return "", "", fmt.Errorf("unsupported mode: %s", mode)
	}
}
