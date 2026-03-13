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

func (r *Runner) persist(
	outDir string,
	before safetyenvelope.Evaluation,
	after safetyenvelope.Evaluation,
	verification safetyenvelope.Verification,
	report *loopReport,
) error {
	if err := fsutil.SafeMkdirAll(outDir, fsutil.WriteOptions{Perm: 0o700, AllowSymlink: r.FileOptions.AllowSymlinks}); err != nil {
		return fmt.Errorf("--out directory not writable: %s: %w", outDir, err)
	}

	artifacts := []struct {
		name  string
		value any
	}{
		{"evaluation.before.json", before},
		{"evaluation.after.json", after},
		{"verification.json", verification},
		{"remediation-report.json", report},
	}
	for _, a := range artifacts {
		if err := r.writeOutputJSONFile(filepath.Join(outDir, a.name), a.value); err != nil {
			return err
		}
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
