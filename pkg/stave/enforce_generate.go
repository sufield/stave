package stave

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	evaljson "github.com/sufield/stave/internal/adapters/evaluation"
	outenforce "github.com/sufield/stave/internal/adapters/output/enforcement"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fileout"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// GenerateEnforcementConfig parameterizes [GenerateEnforcement]. Mode is
// the validated enforcement mode string ("pab" or "scp"); Overwrite and
// AllowSymlinks come from the global --force / --allow-symlink-out flags.
type GenerateEnforcementConfig struct {
	InputPath     string
	OutDir        string
	Mode          string
	DryRun        bool
	Overwrite     bool
	AllowSymlinks bool
}

// enforceResult is the JSON summary of a generate-enforcement run.
type enforceResult struct {
	SchemaVersion kernel.Schema     `json:"schema_version"`
	Kind          kernel.OutputKind `json:"kind"`
	Mode          string            `json:"mode"`
	DryRun        bool              `json:"dry_run,omitempty"`
	OutputFile    string            `json:"output_file"`
	Targets       []string          `json:"targets"`
}

// GenerateEnforcement reads a schema-valid out.v0.1 evaluation, extracts
// the S3 bucket targets, and generates a deterministic enforcement
// template (Public Access Block Terraform for mode "pab", a Service
// Control Policy JSON for mode "scp") under OutDir/enforcement/aws. Unless
// DryRun is set it writes the template file (symlink-safe via fileout) and
// then returns the JSON run summary. All failures stay plain (exit 4). It
// is the library entry point behind `stave ci enforce`.
func GenerateEnforcement(ctx context.Context, cfg GenerateEnforcementConfig) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	if err := enforceValidateInputPath(cfg.InputPath); err != nil {
		return nil, err
	}
	refs, err := enforceLoadFindingRefs(ctx, cfg.InputPath)
	if err != nil {
		return nil, err
	}
	targets := outenforce.ExtractBucketTargets(refs)
	outPath, rendered, err := enforceBuildOutput(cfg.Mode, cfg.OutDir, targets)
	if err != nil {
		return nil, err
	}

	result := enforceResult{
		SchemaVersion: kernel.SchemaEnforce,
		Kind:          kernel.KindEnforcement,
		Mode:          cfg.Mode,
		OutputFile:    outPath,
		Targets:       enforceTargetNames(targets),
	}
	if cfg.DryRun {
		result.DryRun = true
	} else {
		if err := enforceWriteOutputFile(outPath, rendered, fileout.FileOptions{
			Overwrite:     cfg.Overwrite,
			AllowSymlinks: cfg.AllowSymlinks,
			DirPerms:      0o700,
		}); err != nil {
			return nil, fmt.Errorf("write output: %w", err)
		}
	}

	var buf bytes.Buffer
	if err := jsonutil.WriteIndented(&buf, result); err != nil {
		return nil, fmt.Errorf("write output: %w", err)
	}
	return buf.Bytes(), nil
}

func enforceValidateInputPath(inputPath string) error {
	fi, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("--in not accessible: %s: %w", inputPath, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("--in must be a file: %s", inputPath)
	}
	return nil
}

func enforceLoadFindingRefs(ctx context.Context, inputPath string) ([]outenforce.FindingRef, error) {
	// Load via the schema-validating envelope path. Enforcement generation
	// drives gating decisions — the input must be a schema-valid out.v0.1
	// Assessment, not just any JSON with `kind: "ASSESSMENT"`. This blocks
	// the trust-boundary attack where a forged
	// `{"kind":"ASSESSMENT","findings":[]}` could drive the gate into an
	// empty-rules "clean" state.
	loader := evaljson.NewLoader().WithStrictSchema()
	assessment, err := loader.LoadEnvelopeFromFile(ctx, inputPath)
	if err != nil {
		return nil, fmt.Errorf("load evaluation: %w", err)
	}
	refs := make([]outenforce.FindingRef, len(assessment.Findings))
	for i := range assessment.Findings {
		f := &assessment.Findings[i]
		refs[i] = outenforce.FindingRef{
			ControlID: f.ControlID,
			AssetID:   f.AssetID,
		}
	}
	return refs, nil
}

func enforceTargetNames(targets []outenforce.BucketTarget) []string {
	names := make([]string, len(targets))
	for i, target := range targets {
		names[i] = target.BucketName.Name()
	}
	return names
}

func enforceBuildOutput(mode, outDir string, targets []outenforce.BucketTarget) (filePath, content string, err error) {
	base := filepath.Join(outDir, "enforcement", "aws")
	switch mode {
	case "pab":
		return filepath.Join(base, "pab.tf"), outenforce.RenderPABTerraform(targets), nil
	case "scp":
		rendered, err := outenforce.RenderSCP(targets)
		if err != nil {
			return "", "", fmt.Errorf("render scp: %w", err)
		}
		return filepath.Join(base, "scp.json"), rendered, nil
	default:
		return "", "", fmt.Errorf("unsupported mode: %s", mode)
	}
}

func enforceWriteOutputFile(outPath, rendered string, opts fileout.FileOptions) (err error) {
	file, err := fileout.OpenOutputFile(outPath, opts)
	if err != nil {
		return fmt.Errorf("open output file %s: %w", outPath, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	if _, err = file.WriteString(rendered); err != nil {
		return fmt.Errorf("write content to %s: %w", outPath, err)
	}
	return nil
}
