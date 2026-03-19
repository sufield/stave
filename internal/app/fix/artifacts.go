package fix

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/safetyenvelope"
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

// ArtifactManager handles the persistence of verification results to the filesystem.
type ArtifactManager struct {
	OutDir  string
	Options WriteOptions
	Stdout  io.Writer
}

// PersistVerification writes the full suite of verification artifacts to disk.
func (m *ArtifactManager) PersistVerification(
	before safetyenvelope.Evaluation,
	after safetyenvelope.Evaluation,
	verification safetyenvelope.Verification,
) (LoopArtifacts, error) {
	artifacts := LoopArtifacts{}
	if m.OutDir == "" {
		return artifacts, nil
	}

	if err := os.MkdirAll(m.OutDir, m.Options.DirPerms); err != nil {
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
func (m *ArtifactManager) PersistReport(report *LoopReport) error {
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

func (m *ArtifactManager) writeJSON(path string, value any) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !m.Options.Overwrite {
		flags |= os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, 0o600) //nolint:gosec // path is constructed from hardcoded filenames, not user input
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()
	if err := jsonutil.WriteIndented(f, value); err != nil {
		return fmt.Errorf("writing json to %s: %w", path, err)
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
func (b *EnvelopeBuilder) BuildEvaluation(result evaluation.Result) safetyenvelope.Evaluation {
	enricher := remediation.NewMapper(b.IDGen)
	enriched := appeval.Enrich(enricher, b.Sanitizer, result)
	return b.BuildEnvelope(enriched)
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
	SchemaVersion kernel.Schema                      `json:"schema_version"`
	Kind          kernel.OutputKind                  `json:"kind"`
	CheckedAt     time.Time                          `json:"checked_at"`
	Pass          bool                               `json:"pass"`
	Reason        string                             `json:"reason"`
	MaxUnsafe     string                             `json:"max_unsafe"`
	Before        ObservationSummary                 `json:"before"`
	After         ObservationSummary                 `json:"after"`
	Verification  safetyenvelope.VerificationSummary `json:"verification"`
	Artifacts     LoopArtifacts                      `json:"artifacts,omitzero"`
}

// ObservationSummary captures snapshot and violation counts for one side.
type ObservationSummary struct {
	Directory  string `json:"directory"`
	Snapshots  int    `json:"snapshots"`
	Violations int    `json:"violations"`
}

// ErrViolationsRemaining is returned when the fix-loop finds unresolved violations.
var ErrViolationsRemaining = fmt.Errorf("remaining or introduced violations exist")
