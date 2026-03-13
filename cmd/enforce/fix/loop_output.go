package fix

import (
	"fmt"
	"path/filepath"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/adapters/output"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/safetyenvelope"
)

func (r *Runner) writeFixLoopArtifacts(
	execCtx fixLoopExecution,
	beforeEval safetyenvelope.Evaluation,
	afterEval safetyenvelope.Evaluation,
	verification safetyenvelope.Verification,
) (fixLoopArtifacts, error) {
	artifacts := fixLoopArtifacts{}
	if execCtx.outDir == "" {
		return artifacts, nil
	}
	if err := fsutil.SafeMkdirAll(execCtx.outDir, fsutil.WriteOptions{Perm: 0o700, AllowSymlink: r.FileOptions.AllowSymlinks}); err != nil {
		return fixLoopArtifacts{}, fmt.Errorf("--out directory not writable: %s: %w", execCtx.outDir, err)
	}
	beforePath := filepath.Join(execCtx.outDir, "evaluation.before.json")
	if err := r.writeOutputJSONFile(beforePath, beforeEval); err != nil {
		return fixLoopArtifacts{}, err
	}
	artifacts.BeforeEvaluation = beforePath

	afterPath := filepath.Join(execCtx.outDir, "evaluation.after.json")
	if err := r.writeOutputJSONFile(afterPath, afterEval); err != nil {
		return fixLoopArtifacts{}, err
	}
	artifacts.AfterEvaluation = afterPath

	verifyPath := filepath.Join(execCtx.outDir, "verification.json")
	if err := r.writeOutputJSONFile(verifyPath, verification); err != nil {
		return fixLoopArtifacts{}, err
	}
	artifacts.Verification = verifyPath
	return artifacts, nil
}

func (r *Runner) writeFixLoopReport(execCtx fixLoopExecution, report *fixLoopReport) error {
	if execCtx.outDir != "" {
		report.Artifacts.Report = filepath.Join(execCtx.outDir, "remediation-report.json")
		if err := r.writeOutputJSONFile(report.Artifacts.Report, report); err != nil {
			return err
		}
	}
	if err := jsonutil.WriteIndented(execCtx.stdout, report); err != nil {
		return fmt.Errorf("write remediation report: %w", err)
	}
	return nil
}

func (r *Runner) buildEvaluationEnvelope(result evaluation.Result) safetyenvelope.Evaluation {
	enricher := remediation.NewMapper(crypto.NewHasher())
	enriched := output.Enrich(enricher, r.Sanitizer, result)
	return output.BuildSafetyEnvelopeFromEnriched(enriched)
}

func (r *Runner) writeOutputJSONFile(path string, value any) error {
	f, err := cmdutil.OpenOutputFile(path, r.FileOptions)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := jsonutil.WriteIndented(f, value); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
