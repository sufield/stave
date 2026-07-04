// Package auditbundle assembles a composite audit evidence package
// for a specific compliance framework and time period.
package auditbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sufield/stave/internal/platform/fsutil"
)

// Package describes the assembled audit evidence package.
type Package struct {
	Framework   string      `json:"framework"`
	Period      string      `json:"period"`
	GeneratedAt time.Time   `json:"generated_at"`
	Components  []Component `json:"components"`
}

// Component is one file in the evidence package.
type Component struct {
	Filename    string `json:"filename"`
	Description string `json:"description"`
	SHA256      string `json:"sha256,omitempty"`
}

// AssembleInput holds all candidate components for the audit bundle.
type AssembleInput struct {
	Framework      string
	Period         string
	OutputDir      string
	ReportJSON     []byte
	ReportMarkdown []byte
	Continuity     []byte
	TrendJSON      []byte
	ExemptionsJSON []byte
	GeneratedAt    time.Time
}

// Assemble validates OutputDir, writes all non-nil components, and produces
// a manifest JSON file with file descriptions and SHA-256 integrity hashes.
func Assemble(input AssembleInput) (*Package, error) {
	dir := input.OutputDir
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	pkg := &Package{
		Framework:   input.Framework,
		Period:      input.Period,
		GeneratedAt: input.GeneratedAt,
	}

	writeComponent := func(filename, desc string, data []byte) error {
		if data == nil {
			return nil
		}
		path := filepath.Join(dir, filename)
		// 0o644 (world-readable) is intentional: auditors / external tooling
		// read the bundle as a different user. SafeWriteFile keeps that perm
		// while refusing to follow a symlink at the target path.
		if err := fsutil.SafeWriteFile(path, data, fsutil.ConfigWriteOpts()); err != nil {
			return fmt.Errorf("write %s: %w", filename, err)
		}
		h := sha256.New()
		h.Write(data)
		sha := hex.EncodeToString(h.Sum(nil))
		pkg.Components = append(pkg.Components, Component{
			Filename:    filename,
			Description: desc,
			SHA256:      sha,
		})
		return nil
	}

	if err := writeComponent("01-executive-summary.md", "Executive summary", input.ReportMarkdown); err != nil {
		return nil, err
	}
	if err := writeComponent("02-posture-report.json", "Posture report", input.ReportJSON); err != nil {
		return nil, err
	}
	if err := writeComponent("04-continuity-attestation.json", "Evidence continuity attestation", input.Continuity); err != nil {
		return nil, err
	}
	if err := writeComponent("06-remediation-trend.json", "Remediation trend", input.TrendJSON); err != nil {
		return nil, err
	}
	if err := writeComponent("07-exemption-register.json", "Active exemptions", input.ExemptionsJSON); err != nil {
		return nil, err
	}

	// Write manifest.
	manifestData, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	if writeErr := fsutil.SafeWriteFile(filepath.Join(dir, "00-manifest.json"), manifestData, fsutil.ConfigWriteOpts()); writeErr != nil {
		return nil, fmt.Errorf("write manifest: %w", writeErr)
	}

	return pkg, nil
}
