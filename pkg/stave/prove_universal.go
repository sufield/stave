package stave

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/app/universals"
)

// ProveUniversalConfig configures a universal evaluation run.
type ProveUniversalConfig struct {
	SnapshotsDir  string
	FormulaDir    string
	GroundingPath string
}

// UniversalSummary is the facade result type for universal evaluation.
type UniversalSummary = universals.Summary

// UniversalResult is a single universal's evaluation result.
type UniversalResult = universals.Result

// ProveUniversal evaluates all universal statements against observations
// via Z3 subprocess. Does not require CGO — the Z3 binary must be on PATH.
func ProveUniversal(_ context.Context, cfg ProveUniversalConfig) (*UniversalSummary, error) {
	if cfg.SnapshotsDir == "" {
		return nil, errors.New("prove universal: --observations is required")
	}
	if cfg.FormulaDir == "" {
		return nil, errors.New("prove universal: --formulas is required (no embedded formulas available)")
	}

	if _, err := exec.LookPath("z3"); err != nil {
		return nil, errors.New("prove universal: z3 not found in PATH — install with: apt install z3")
	}

	assets, err := universals.LoadAssetsFromDir(cfg.SnapshotsDir)
	if err != nil {
		return nil, fmt.Errorf("prove universal: %w", err)
	}

	result, err := universals.EvaluateAll(universals.EvaluateConfig{
		FormulaDir:    cfg.FormulaDir,
		GroundingPath: cfg.GroundingPath,
		Assets:        assets,
		Solver:        runZ3,
	})
	if err != nil {
		return nil, fmt.Errorf("prove universal: %w", err)
	}
	return result, nil
}

func runZ3(formulaContent string) (result, output string) {
	tmp, err := os.CreateTemp("", "prove-*.smt2")
	if err != nil {
		return "error", err.Error()
	}
	defer os.Remove(tmp.Name())
	_, _ = fmt.Fprint(tmp, formulaContent)
	_ = tmp.Close()

	cmd := exec.Command("z3", tmp.Name()) //nolint:gosec,noctx // z3 binary with temp file
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run()

	out := strings.TrimSpace(stdout.String())
	lines := strings.Split(out, "\n")
	for _, line := range slices.Backward(lines) {
		line := strings.TrimSpace(line)
		switch line {
		case "sat", "unsat", "unknown":
			return line, out
		}
	}
	return "error", out + "\n" + stderr.String()
}
