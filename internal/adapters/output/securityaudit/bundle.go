package securityaudit

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
	domain "github.com/sufield/stave/internal/core/securityaudit"
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
	SchemaVersion     kernel.Schema  `json:"schema_version"`
	GeneratedAt       string         `json:"generated_at"`
	MainReport        string         `json:"main_report"`
	BundleDir         string         `json:"bundle_dir"`
	StaveVersion      string         `json:"tool_version"`
	FailOn            string         `json:"fail_on"`
	Gated             bool           `json:"gated"`
	GatedFindings     int            `json:"gated_findings"`
	Files             []ManifestFile `json:"files"`
	EvidenceFreshness string         `json:"evidence_freshness"`
	VulnSourceUsed    string         `json:"vuln_source_used"`
}

// BundleRequest groups the parameters for WriteBundle.
type BundleRequest struct {
	Opts           BundleWriteOpts
	Now            time.Time
	BundleDir      string
	MainName       string
	MainData       []byte
	Report         domain.Report
	Artifacts      domain.ArtifactManifest
	ResolveOutPath func(string) string
}

// WriteBundle writes the report, artifacts, and manifest into a bundle directory.
func WriteBundle(req BundleRequest) (string, error) {
	if err := fsutil.SafeMkdirAll(req.BundleDir, fsutil.WriteOptions{
		Perm:         0o700,
		AllowSymlink: req.Opts.AllowSymlink,
	}); err != nil {
		return "", fmt.Errorf("create bundle directory: %w", err)
	}

	var written []WrittenFile

	mainBundlePath := filepath.Join(req.BundleDir, req.MainName)
	if err := writeOutputFile(req.Opts, mainBundlePath, req.MainData); err != nil {
		return "", err
	}
	written = append(written, WrittenFile{Name: req.MainName, Content: req.MainData})

	mainOutPath := req.ResolveOutPath(mainBundlePath)
	if mainOutPath != mainBundlePath {
		if err := writeOutputFile(req.Opts, mainOutPath, req.MainData); err != nil {
			return "", err
		}
	}

	for _, artifact := range req.Artifacts.Files {
		target := filepath.Join(req.BundleDir, artifact.Path)
		if err := writeOutputFile(req.Opts, target, artifact.Content); err != nil {
			return "", err
		}
		written = append(written, WrittenFile{Name: artifact.Path, Content: artifact.Content})
	}

	runManifestPath := filepath.Join(req.BundleDir, "run_manifest.json")
	if err := writeRunManifest(req.Opts, runManifestPath, req.Now, req.BundleDir, req.MainName, written, req.Report); err != nil {
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

	g := report.Summary.Gating
	m := report.Summary.Metadata
	manifest := RunManifest{
		SchemaVersion:     kernel.SchemaSecurityAuditRunManifest,
		GeneratedAt:       now.Format(time.RFC3339),
		MainReport:        mainReport,
		BundleDir:         bundleDir,
		StaveVersion:      report.StaveVersion,
		FailOn:            g.DisplayFailOn(),
		Gated:             g.Gated,
		GatedFindings:     g.GatedFindingCount,
		Files:             files,
		EvidenceFreshness: m.EvidenceFreshness,
		VulnSourceUsed:    m.VulnSourceUsed,
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
