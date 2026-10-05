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

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// Checksum represents a SHA-256 hex digest.
type Checksum string

// String returns the underlying SHA-256 hex digest string.
func (c Checksum) String() string {
	return string(c)
}

// IsValid reports whether the checksum string is a non-empty, 64-character SHA-256 hex digest.
func (c Checksum) IsValid() bool {
	if len(c) != 64 {
		return false
	}
	for i := 0; i < len(c); i++ {
		b := c[i]
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')) {
			return false
		}
	}
	return true
}

// Short returns the abbreviated 8-character prefix of the hex digest.
func (c Checksum) Short() string {
	if len(c) < 8 {
		return string(c)
	}
	return string(c[:8])
}

// Component is one file in the evidence package.
type Component struct {
	Filename    string   `json:"filename"`
	Description string   `json:"description"`
	SHA256      Checksum `json:"sha256,omitempty"`
}

// Components is a domain collection of Component items with querying methods.
type Components []Component

// Len returns the number of components in the collection.
func (cs Components) Len() int {
	return len(cs)
}

// ByFilename returns the component matching the given filename, or nil if not found.
func (cs Components) ByFilename(filename string) *Component {
	for i := range cs {
		if cs[i].Filename == filename {
			return &cs[i]
		}
	}
	return nil
}

// HasIntegrityHashes reports whether all components have valid SHA256 checksums.
func (cs Components) HasIntegrityHashes() bool {
	if len(cs) == 0 {
		return false
	}
	for i := range cs {
		if !cs[i].SHA256.IsValid() {
			return false
		}
	}
	return true
}

// Package describes the assembled audit evidence package.
type Package struct {
	Framework   policy.ComplianceFramework `json:"framework"`
	Period      string                     `json:"period"`
	GeneratedAt time.Time                  `json:"generated_at"`
	Components  Components                 `json:"components"`
}

// AssembleInput holds all candidate components for the audit bundle.
type AssembleInput struct {
	Framework      policy.ComplianceFramework
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
		if len(data) == 0 {
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
			SHA256:      Checksum(sha),
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
