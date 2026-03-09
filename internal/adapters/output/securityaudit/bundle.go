package securityaudit

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/kernel"
	domain "github.com/sufield/stave/internal/domain/securityaudit"
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// BundleWriteOpts configures filesystem behavior for bundle writing.
type BundleWriteOpts struct {
	Force        bool
	AllowSymlink bool
}

// WrittenFile tracks a file that was written to the bundle.
type WrittenFile struct {
	Name    string
	Content []byte
}

// ManifestFile is a single file entry in the run manifest.
type ManifestFile struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// RunManifest is the structured run manifest written alongside bundles.
type RunManifest struct {
	SchemaVersion     string         `json:"schema_version"`
	GeneratedAt       string         `json:"generated_at"`
	MainReport        string         `json:"main_report"`
	BundleDir         string         `json:"bundle_dir"`
	ToolVersion       string         `json:"tool_version"`
	FailOn            string         `json:"fail_on"`
	Gated             bool           `json:"gated"`
	GatedFindings     int            `json:"gated_findings"`
	Files             []ManifestFile `json:"files"`
	EvidenceFreshness string         `json:"evidence_freshness"`
	VulnSourceUsed    string         `json:"vuln_source_used"`
}

// WriteBundle writes the report, artifacts, and manifest into a bundle directory.
func WriteBundle(opts BundleWriteOpts, now time.Time, bundleDir, mainName string, mainData []byte, report domain.Report, artifacts domain.ArtifactManifest, resolveOutPath func(string) string) (string, error) {
	if err := fsutil.SafeMkdirAll(bundleDir, fsutil.WriteOptions{
		Perm:         0o700,
		AllowSymlink: opts.AllowSymlink,
	}); err != nil {
		return "", fmt.Errorf("create bundle directory: %w", err)
	}

	var written []WrittenFile

	mainBundlePath := filepath.Join(bundleDir, mainName)
	if err := writeOutputFile(opts, mainBundlePath, mainData); err != nil {
		return "", err
	}
	written = append(written, WrittenFile{Name: mainName, Content: mainData})

	mainOutPath := resolveOutPath(mainBundlePath)
	if mainOutPath != mainBundlePath {
		if err := writeOutputFile(opts, mainOutPath, mainData); err != nil {
			return "", err
		}
	}

	for _, artifact := range artifacts.Files {
		target := filepath.Join(bundleDir, artifact.Path)
		if err := writeOutputFile(opts, target, artifact.Content); err != nil {
			return "", err
		}
		written = append(written, WrittenFile{Name: artifact.Path, Content: artifact.Content})
	}

	runManifestPath := filepath.Join(bundleDir, "run_manifest.json")
	if err := writeRunManifest(opts, runManifestPath, now, bundleDir, mainName, written, report); err != nil {
		return "", err
	}

	return mainOutPath, nil
}

func writeOutputFile(opts BundleWriteOpts, path string, data []byte) error {
	parent := filepath.Dir(path)
	if strings.TrimSpace(parent) != "" && parent != "." {
		if err := fsutil.SafeMkdirAll(parent, fsutil.WriteOptions{
			Perm:         0o700,
			AllowSymlink: opts.AllowSymlink,
		}); err != nil {
			return fmt.Errorf("create output directory %q: %w", parent, err)
		}
	}
	wopts := fsutil.DefaultWriteOpts()
	wopts.Overwrite = opts.Force
	wopts.AllowSymlink = opts.AllowSymlink
	if err := fsutil.SafeWriteFile(path, data, wopts); err != nil {
		return fmt.Errorf("write output %q: %w", path, err)
	}
	return nil
}

func writeRunManifest(opts BundleWriteOpts, path string, now time.Time, bundleDir string, mainReport string, written []WrittenFile, report domain.Report) error {
	files := make([]ManifestFile, 0, len(written))
	for _, w := range written {
		files = append(files, ManifestFile{
			Path:      w.Name,
			SHA256:    string(platformcrypto.HashBytes(w.Content)),
			SizeBytes: int64(len(w.Content)),
		})
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	manifest := RunManifest{
		SchemaVersion:     string(kernel.SchemaSecurityAuditRunManifest),
		GeneratedAt:       now.Format(time.RFC3339),
		MainReport:        mainReport,
		BundleDir:         bundleDir,
		ToolVersion:       report.ToolVersion,
		FailOn:            string(report.Summary.FailOn),
		Gated:             report.Summary.Gated,
		GatedFindings:     report.Summary.GatedFindingCount,
		Files:             files,
		EvidenceFreshness: report.Summary.EvidenceFreshness,
		VulnSourceUsed:    report.Summary.VulnSourceUsed,
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal run manifest: %w", err)
	}
	wopts := fsutil.DefaultWriteOpts()
	wopts.Overwrite = opts.Force
	wopts.AllowSymlink = opts.AllowSymlink
	if err := fsutil.SafeWriteFile(path, append(data, '\n'), wopts); err != nil {
		return fmt.Errorf("write run manifest: %w", err)
	}
	return nil
}
