package stave

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	"github.com/sufield/stave/internal/adapters/evidence"
	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/adapters/output/asff"
	"github.com/sufield/stave/internal/app/auditbundle"
	appexempt "github.com/sufield/stave/internal/app/exempt"
	"github.com/sufield/stave/internal/core/report"
)

// EvidenceBundleResult carries the assembled evidence bundle bytes (and
// optional ASFF bytes) plus the finding counts the CLI reports.
type EvidenceBundleResult struct {
	BundleData    []byte
	ASFFData      []byte
	Violations    int
	ChainFindings int
}

// BuildEvidenceBundle assembles a sealed evidence bundle from a `stave
// apply` assessment (JSON) and the observation snapshots that produced it:
// it parses the assessment, loads + prunes the snapshots, builds the
// tar.gz bundle (optionally Ed25519-signed with privateKeyPEM), and — when
// includeASFF is set — also marshals the ASFF findings. All failures stay
// plain (exit 4). It is the library entry point behind `stave bundle`
// (the command owns the self-assessment subprocess + the file writes).
func BuildEvidenceBundle(ctx context.Context, assessmentJSON []byte, observationsDir string, privateKeyPEM []byte, includeASFF bool) (EvidenceBundleResult, error) {
	var assessment report.Assessment
	if err := json.Unmarshal(assessmentJSON, &assessment); err != nil {
		return EvidenceBundleResult{}, fmt.Errorf("parse assessment: %w", err)
	}

	loader := observations.NewObservationLoader()
	loadResult, err := loader.LoadSnapshots(ctx, observationsDir)
	if err != nil {
		return EvidenceBundleResult{}, fmt.Errorf("load snapshots for bundle: %w", err)
	}

	bundleData, err := evidence.Build(evidence.BundleInput{
		Assessment:    &assessment,
		Snapshots:     loadResult.Snapshots,
		TraceJSON:     nil,
		PrivateKeyPEM: privateKeyPEM,
		StaveVersion:  "edge",
	})
	if err != nil {
		return EvidenceBundleResult{}, fmt.Errorf("build bundle: %w", err)
	}

	res := EvidenceBundleResult{
		BundleData:    bundleData,
		Violations:    assessment.Summary.Violations,
		ChainFindings: len(assessment.ChainFindings),
	}
	if includeASFF {
		asffData, asffErr := asff.MarshalASFF(&assessment)
		if asffErr != nil {
			return EvidenceBundleResult{}, fmt.Errorf("marshal ASFF: %w", asffErr)
		}
		res.ASFFData = asffData
	}
	return res, nil
}

// AuditBundleInput parameterizes [AssembleAuditBundle].
type AuditBundleInput struct {
	Framework  string
	Period     string
	Start      time.Time
	End        time.Time
	HistoryDir string
	ExemptPath string
	OutDir     string
	DryRun     bool
}

// AuditBundleResult carries the assessment count (always) and, for a real
// run, the number of components written.
type AuditBundleResult struct {
	AssessmentCount int
	ComponentCount  int
}

// AssembleAuditBundle gathers the assessment artifacts in [Start,End] from
// HistoryDir and, unless DryRun, assembles a compliance-period evidence
// package (report JSON + markdown, optional exemptions, SHA-256 manifest)
// under OutDir. It returns the assessment count and (for a real run) the
// component count. All failures stay plain (exit 4). It is the library
// entry point behind `stave bundle audit`.
func AssembleAuditBundle(ctx context.Context, in AuditBundleInput) (AuditBundleResult, error) {
	assessments, err := loadPeriodAssessments(ctx, in.HistoryDir, in.Start, in.End)
	if err != nil {
		return AuditBundleResult{}, fmt.Errorf("load assessments: %w", err)
	}

	if in.DryRun {
		return AuditBundleResult{AssessmentCount: len(assessments)}, nil
	}

	if in.OutDir == "" {
		return AuditBundleResult{}, errors.New("--out is required (output directory)")
	}

	reportJSON, err := json.MarshalIndent(map[string]any{
		"framework":   in.Framework,
		"period":      in.Period,
		"assessments": len(assessments),
	}, "", "  ")
	if err != nil {
		return AuditBundleResult{}, fmt.Errorf("marshal audit report: %w", err)
	}

	reportMD := fmt.Appendf(nil, "# %s Audit Report — %s\n\nAssessments in period: %d\n",
		strings.ToUpper(in.Framework), in.Period, len(assessments))

	var exemptJSON []byte
	if in.ExemptPath != "" {
		af, loadErr := appexempt.Load(in.ExemptPath)
		if loadErr != nil {
			return AuditBundleResult{}, fmt.Errorf("load exemptions %q: %w", in.ExemptPath, loadErr)
		}
		exemptJSON, err = json.MarshalIndent(af, "", "  ")
		if err != nil {
			return AuditBundleResult{}, fmt.Errorf("marshal exemptions: %w", err)
		}
	}

	pkg, err := auditbundle.Assemble(auditbundle.AssembleInput{
		Framework:      in.Framework,
		Period:         in.Period,
		OutputDir:      in.OutDir,
		ReportJSON:     reportJSON,
		ReportMarkdown: reportMD,
		ExemptionsJSON: exemptJSON,
		GeneratedAt:    time.Now().UTC(),
	})
	if err != nil {
		return AuditBundleResult{}, fmt.Errorf("assemble audit bundle: %w", err)
	}

	return AuditBundleResult{AssessmentCount: len(assessments), ComponentCount: len(pkg.Components)}, nil
}

// loadPeriodAssessments loads every assessment artifact in dir whose run
// timestamp falls within [start, end]. Unreadable files are skipped.
func loadPeriodAssessments(ctx context.Context, dir string, start, end time.Time) ([]*report.Assessment, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read directory: %w", err)
	}

	loader := artifact.NewLoader()
	var assessments []*report.Assessment
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		a, loadErr := loader.Evaluation(ctx, path)
		if loadErr != nil {
			continue
		}
		if (a.Run.EvalTime.Equal(start) || a.Run.EvalTime.After(start)) &&
			(a.Run.EvalTime.Equal(end) || a.Run.EvalTime.Before(end)) {
			assessments = append(assessments, a)
		}
	}
	return assessments, nil
}
