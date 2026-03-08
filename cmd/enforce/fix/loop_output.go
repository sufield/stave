package fix

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/enforce/shared"
	"github.com/sufield/stave/internal/adapters/output"
	appworkflow "github.com/sufield/stave/internal/app/workflow"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/safetyenvelope"
)

func writeFixLoopArtifacts(
	cmd *cobra.Command,
	execCtx fixLoopExecution,
	beforeEval safetyenvelope.Evaluation,
	afterEval safetyenvelope.Evaluation,
	verification safetyenvelope.Verification,
) (fixLoopArtifacts, error) {
	artifacts := fixLoopArtifacts{}
	if execCtx.outDir == "" {
		return artifacts, nil
	}
	if err := fsutil.SafeMkdirAll(execCtx.outDir, fsutil.WriteOptions{Perm: 0o700, AllowSymlink: cmdutil.AllowSymlinkOutEnabled(cmd)}); err != nil {
		return fixLoopArtifacts{}, fmt.Errorf("--out directory not writable: %s: %w", execCtx.outDir, err)
	}
	beforePath := filepath.Join(execCtx.outDir, "evaluation.before.json")
	if err := writeOutputJSONFile(cmd, beforePath, beforeEval); err != nil {
		return fixLoopArtifacts{}, err
	}
	artifacts.BeforeEvaluation = beforePath

	afterPath := filepath.Join(execCtx.outDir, "evaluation.after.json")
	if err := writeOutputJSONFile(cmd, afterPath, afterEval); err != nil {
		return fixLoopArtifacts{}, err
	}
	artifacts.AfterEvaluation = afterPath

	verifyPath := filepath.Join(execCtx.outDir, "verification.json")
	if err := writeVerificationJSONFile(cmd, verifyPath, verification); err != nil {
		return fixLoopArtifacts{}, err
	}
	artifacts.Verification = verifyPath
	return artifacts, nil
}

func writeFixLoopReport(cmd *cobra.Command, execCtx fixLoopExecution, report *fixLoopReport) error {
	if execCtx.outDir != "" {
		report.Artifacts.Report = filepath.Join(execCtx.outDir, "remediation-report.json")
		if err := writeOutputJSONFile(cmd, report.Artifacts.Report, report); err != nil {
			return err
		}
	}
	if err := shared.WriteJSON(cmd.OutOrStdout(), report); err != nil {
		return fmt.Errorf("write remediation report: %w", err)
	}
	return nil
}

func buildEvaluationEnvelope(cmd *cobra.Command, result evaluation.Result) safetyenvelope.Evaluation {
	enricher := remediation.NewMapper()
	sanitizer := cmdutil.GetSanitizer(cmd)
	enriched := output.Enrich(enricher, sanitizer, result)
	return appworkflow.BuildSafetyEnvelopeFromEnriched(enriched)
}

func writeOutputJSONFile(cmd *cobra.Command, path string, value any) error {
	f, err := cmdutil.CreateOutputFile(cmd, path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := shared.WriteJSON(f, value); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func writeVerificationJSONFile(cmd *cobra.Command, path string, result safetyenvelope.Verification) error {
	opts := fsutil.DefaultWriteOpts()
	opts.Overwrite = cmdutil.ForceEnabled(cmd)
	opts.AllowSymlink = cmdutil.AllowSymlinkOutEnabled(cmd)
	f, err := fsutil.SafeCreateFile(path, opts)
	if err != nil {
		return fmt.Errorf("cannot create %s: %w", path, err)
	}
	defer f.Close()
	if err := safetyenvelope.ValidateVerification(result); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
