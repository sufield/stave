package fix

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/safetyenvelope"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/remediation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

// EnvelopeBuilderFunc transforms an enriched result into a safety envelope.
// Injected from the adapters layer by cmd/ callers.
type EnvelopeBuilderFunc func(enriched contracts.EnrichedResult) safetyenvelope.Evaluation

// WriteOptions controls file output behavior.
type WriteOptions struct {
	Overwrite     bool
	AllowSymlinks bool
	DirPerms      fs.FileMode
}

// ArtifactWriter persists verification results to the filesystem.
type ArtifactWriter struct {
	OutDir  string
	Options WriteOptions
	Stdout  io.Writer

	// MkdirAllFn creates directories. Injected by the cmd layer to use
	// fsutil.SafeMkdirAll for symlink protection. Defaults to os.MkdirAll.
	MkdirAllFn func(path string, perm fs.FileMode) error

	// WriteFileFn writes data to a file. Injected by the cmd layer to use
	// fsutil.SafeWriteFile. Defaults to os.WriteFile.
	WriteFileFn func(path string, data []byte, perm fs.FileMode) error
}

// PersistVerification writes the full suite of verification artifacts to disk.
func (m *ArtifactWriter) PersistVerification(
	before safetyenvelope.Evaluation,
	after safetyenvelope.Evaluation,
	verification safetyenvelope.Verification,
) (LoopArtifacts, error) {
	artifacts := LoopArtifacts{}
	if m.OutDir == "" {
		return artifacts, nil
	}

	mkdirAll := m.MkdirAllFn
	if mkdirAll == nil {
		mkdirAll = os.MkdirAll
	}
	if err := mkdirAll(m.OutDir, m.Options.DirPerms); err != nil {
		return artifacts, fmt.Errorf("output directory access error: %w", err)
	}

	targets := []struct {
		name string
		data any
		ref  *string
	}{
		{"evaluation.before.json", before, &artifacts.BeforeEvaluation},
		{"evaluation.after.json", after, &artifacts.AfterEvaluation},
		{"verification.json", verification, &artifacts.Verification},
	}

	for _, t := range targets {
		path := filepath.Join(m.OutDir, t.name)
		if err := m.writeJSON(path, t.data); err != nil {
			return artifacts, err
		}
		*t.ref = path
	}

	return artifacts, nil
}

// PersistReport writes the summary report to disk and stdout.
func (m *ArtifactWriter) PersistReport(report *LoopReport) error {
	if m.OutDir != "" {
		report.Artifacts.Report = filepath.Join(m.OutDir, "remediation-report.json")
		if err := m.writeJSON(report.Artifacts.Report, report); err != nil {
			return err
		}
	}
	if !report.Pass {
		if err := jsonutil.WriteIndented(m.Stdout, report); err != nil {
			return err
		}
		return ErrViolationsRemaining
	}
	return jsonutil.WriteIndented(m.Stdout, report)
}

func (m *ArtifactWriter) writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json for %s: %w", path, err)
	}
	writeFile := m.WriteFileFn
	if writeFile == nil {
		writeFile = os.WriteFile
	}
	if err := writeFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// EnvelopeBuilder handles the transformation and enrichment of domain results.
type EnvelopeBuilder struct {
	Sanitizer     kernel.Sanitizer
	IDGen         ports.IdentityGenerator
	BuildEnvelope EnvelopeBuilderFunc
}

// BuildEvaluation creates a compliant safety envelope from a raw evaluation result.
func (b *EnvelopeBuilder) BuildEvaluation(result evaluation.Result) (safetyenvelope.Evaluation, error) {
	enricher := remediation.NewMapper(b.IDGen)
	enriched, err := appeval.Enrich(enricher, b.Sanitizer, result)
	if err != nil {
		return safetyenvelope.Evaluation{}, fmt.Errorf("enrich evaluation: %w", err)
	}
	return b.BuildEnvelope(enriched), nil
}

// --- Data Models ---

// LoopArtifacts tracks the paths of written verification artifacts.
type LoopArtifacts struct {
	BeforeEvaluation string `json:"before_evaluation,omitempty"`
	AfterEvaluation  string `json:"after_evaluation,omitempty"`
	Verification     string `json:"verification,omitempty"`
	Report           string `json:"report,omitempty"`
}

// LoopReport is the structured output of a fix-loop run.
type LoopReport struct {
	SchemaVersion     kernel.Schema                      `json:"schema_version"`
	Kind              kernel.OutputKind                  `json:"kind"`
	CheckedAt         time.Time                          `json:"checked_at"`
	Pass              bool                               `json:"pass"`
	Reason            string                             `json:"reason"`
	MaxUnsafeDuration string                             `json:"max_unsafe"`
	Before            ObservationSummary                 `json:"before"`
	After             ObservationSummary                 `json:"after"`
	Verification      safetyenvelope.VerificationSummary `json:"verification"`
	Artifacts         LoopArtifacts                      `json:"artifacts,omitzero"`
}

// ObservationSummary captures snapshot and violation counts for one side.
type ObservationSummary struct {
	Directory  string `json:"directory"`
	Snapshots  int    `json:"snapshots"`
	Violations int    `json:"violations"`
}

// ErrViolationsRemaining is returned when the fix-loop finds unresolved violations.
var ErrViolationsRemaining = fmt.Errorf("remaining or introduced violations exist")
