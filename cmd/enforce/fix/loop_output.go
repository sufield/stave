package fix

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/adapters/output"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// ArtifactManager handles the persistence of verification results to the filesystem.
type ArtifactManager struct {
	OutDir    string
	IOOptions cmdutil.FileOptions
	Stdout    io.Writer
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

	mkdirOpts := fsutil.WriteOptions{
		Perm:         m.IOOptions.DirPerms,
		AllowSymlink: m.IOOptions.AllowSymlinks,
	}
	if err := fsutil.SafeMkdirAll(m.OutDir, mkdirOpts); err != nil {
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
	return jsonutil.WriteIndented(m.Stdout, report)
}

func (m *ArtifactManager) writeJSON(path string, value any) error {
	f, err := cmdutil.OpenOutputFile(path, m.IOOptions)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := jsonutil.WriteIndented(f, value); err != nil {
		return fmt.Errorf("writing json to %s: %w", path, err)
	}
	return nil
}

// --- Envelope Logic ---

// EnvelopeBuilder handles the transformation and enrichment of domain results.
type EnvelopeBuilder struct {
	Sanitizer kernel.Sanitizer
	IDGen     ports.IdentityGenerator
}

// NewEnvelopeBuilder creates an EnvelopeBuilder with default crypto.
func NewEnvelopeBuilder(san kernel.Sanitizer) *EnvelopeBuilder {
	return &EnvelopeBuilder{
		Sanitizer: san,
		IDGen:     crypto.NewHasher(),
	}
}

// BuildEvaluation creates a compliant safety envelope from a raw evaluation result.
func (b *EnvelopeBuilder) BuildEvaluation(result evaluation.Result) safetyenvelope.Evaluation {
	enricher := remediation.NewMapper(b.IDGen)
	enriched := output.Enrich(enricher, b.Sanitizer, result)
	return output.BuildSafetyEnvelopeFromEnriched(enriched)
}

// --- Data Models ---

// LoopArtifacts tracks the paths of written verification artifacts.
type LoopArtifacts struct {
	BeforeEvaluation string `json:"before_evaluation,omitempty"`
	AfterEvaluation  string `json:"after_evaluation,omitempty"`
	Verification     string `json:"verification,omitempty"`
	Report           string `json:"report,omitempty"`
}
