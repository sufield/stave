package generate

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	outenforce "github.com/sufield/stave/internal/adapters/output/enforcement"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type input struct {
	Findings []struct {
		ControlID kernel.ControlID `json:"control_id"`
		AssetID   asset.ID         `json:"asset_id"`
	} `json:"findings"`
}

type result struct {
	SchemaVersion kernel.Schema `json:"schema_version"`
	Kind          string        `json:"kind"`
	Mode          string        `json:"mode"`
	OutputFile    string        `json:"output_file"`
	Targets       []string      `json:"targets"`
}

type runRequest struct {
	inputPath string
	outDir    string
	mode      Mode
	dryRun    bool
}

type plan struct {
	result   result
	rendered string
}

func run(cmd *cobra.Command, opts *options) error {
	out := cmd.OutOrStdout()

	req, err := resolveRunRequest(opts)
	if err != nil {
		return fmt.Errorf("resolve request: %w", err)
	}
	p, err := buildPlan(req)
	if err != nil {
		return fmt.Errorf("build plan: %w", err)
	}
	if req.dryRun {
		return writeDryRun(out, p.result)
	}
	if err := writeOutputFile(cmd, p.result.OutputFile, p.rendered); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return writeResult(out, p.result)
}

func resolveRunRequest(opts *options) (runRequest, error) {
	inputPath := fsutil.CleanUserPath(opts.InputPath)
	outDir := fsutil.CleanUserPath(opts.OutDir)
	if err := validateInputPath(inputPath); err != nil {
		return runRequest{}, err
	}
	mode, err := ParseMode(strings.ToLower(strings.TrimSpace(opts.Mode)))
	if err != nil {
		return runRequest{}, err
	}
	return runRequest{
		inputPath: inputPath,
		outDir:    outDir,
		mode:      mode,
		dryRun:    opts.DryRun,
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

func buildPlan(req runRequest) (plan, error) {
	in, err := loadInput(req.inputPath)
	if err != nil {
		return plan{}, err
	}
	refs := make([]outenforce.FindingRef, len(in.Findings))
	for i, f := range in.Findings {
		refs[i] = outenforce.FindingRef{
			ControlID: f.ControlID,
			AssetID:   f.AssetID,
		}
	}
	targets := outenforce.ExtractBucketTargets(refs)
	outPath, rendered, err := buildOutput(req.mode, req.outDir, targets)
	if err != nil {
		return plan{}, err
	}
	return plan{
		result: result{
			SchemaVersion: kernel.SchemaEnforce,
			Kind:          "enforcement",
			Mode:          string(req.mode),
			OutputFile:    outPath,
			Targets:       targetNames(targets),
		},
		rendered: rendered,
	}, nil
}

func loadInput(inputPath string) (input, error) {
	data, err := fsutil.ReadFileLimited(inputPath)
	if err != nil {
		return input{}, fmt.Errorf("read input: %w", err)
	}
	var in input
	if err := json.Unmarshal(data, &in); err != nil {
		return input{}, fmt.Errorf("parse input JSON: %w", err)
	}
	return in, nil
}

func targetNames(targets []outenforce.BucketTarget) []string {
	names := make([]string, len(targets))
	for i, target := range targets {
		names[i] = target.BucketName
	}
	return names
}

func writeDryRun(w io.Writer, res result) error {
	if _, err := fmt.Fprintf(w, "[dry-run] would write: %s\n", res.OutputFile); err != nil {
		return err
	}
	return writeResult(w, res)
}

func writeOutputFile(cmd *cobra.Command, outPath, rendered string) error {
	file, err := cmdutil.CreateOutputFile(cmd, outPath)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteString(rendered); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}
	return nil
}

func writeResult(w io.Writer, res result) error {
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
