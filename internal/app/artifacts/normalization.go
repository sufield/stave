package artifacts

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// NormalizationConfig defines the behavior for standardizing security manifests.
type NormalizationConfig struct {
	SourcePath string
	VerifyOnly bool

	// Reader abstracts file access for air-gapped or virtualized environments.
	Reader func(path string) ([]byte, error)

	// Writer handles the persistent storage of the canonicalized data.
	// Only invoked if VerifyOnly is false.
	Writer func(path string, data []byte) error
}

// NormalizationMetrics captures the scope and impact of the canonicalization run.
type NormalizationMetrics struct {
	TotalManifests    int
	ModifiedManifests int
}

// Canonicalizer manages the deterministic formatting of security controls and resource states.
type Canonicalizer struct{}

// Normalize ensures all security manifests at the source path follow a deterministic structure.
func (c *Canonicalizer) Normalize(ctx context.Context, cfg NormalizationConfig) (NormalizationMetrics, error) {
	manifests, err := DiscoverManifests(ctx, cfg.SourcePath)
	if err != nil {
		return NormalizationMetrics{}, err
	}

	readFn := cfg.Reader
	if readFn == nil {
		readFn = os.ReadFile
	}

	metrics := NormalizationMetrics{TotalManifests: len(manifests)}

	for _, path := range manifests {
		modified, err := c.processManifest(path, cfg, readFn)
		if err != nil {
			return metrics, err
		}
		if modified {
			metrics.ModifiedManifests++
		}
	}

	if cfg.VerifyOnly && metrics.ModifiedManifests > 0 {
		return metrics, fmt.Errorf("%d/%d security manifest(s) are not in canonical form",
			metrics.ModifiedManifests, metrics.TotalManifests)
	}

	return metrics, nil
}

func (c *Canonicalizer) processManifest(path string, cfg NormalizationConfig, readFn func(string) ([]byte, error)) (bool, error) {
	original, err := readFn(path)
	if err != nil {
		return false, fmt.Errorf("reading manifest %s: %w", path, err)
	}

	canonical, err := CanonicalizeByExtension(path, original)
	if err != nil {
		return false, fmt.Errorf("canonicalizing %s: %w", path, err)
	}
	if canonical == nil {
		return false, nil
	}

	if bytes.Equal(original, canonical) {
		return false, nil
	}

	if cfg.VerifyOnly {
		return true, nil
	}

	if cfg.Writer != nil {
		if err := cfg.Writer(path, canonical); err != nil {
			return true, fmt.Errorf("persisting canonical manifest %s: %w", path, err)
		}
	}

	return true, nil
}

// DiscoverManifests identifies security control (YAML) and resource state (JSON) files.
func DiscoverManifests(ctx context.Context, root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat manifest root %s: %w", root, err)
	}

	if !info.IsDir() {
		return []string{root}, nil
	}

	var manifests []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("discover manifests cancelled: %w", ctxErr)
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".json" || ext == ".yaml" || ext == ".yml" {
			manifests = append(manifests, path)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk manifest directory %s: %w", root, err)
	}

	slices.Sort(manifests)
	return manifests, nil
}
