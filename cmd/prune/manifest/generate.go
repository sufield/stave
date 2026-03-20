package manifest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	appeval "github.com/sufield/stave/internal/app/eval"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/integrity"
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// GenerateConfig defines the parameters for manifest generation.
type GenerateConfig struct {
	ObservationsDir string
	OutPath         string
	TextOutput      bool
	Stdout          io.Writer
}

// GenerateRunner orchestrates the indexing of observation files and manifest creation.
type GenerateRunner struct {
	validator *contractvalidator.Validator
}

// Run executes the manifest generation workflow.
func (r *GenerateRunner) Run(ctx context.Context, cfg GenerateConfig) error {
	dir := filepath.Clean(cfg.ObservationsDir)
	out := filepath.Clean(cfg.OutPath)

	if fi, err := os.Stat(dir); err != nil {
		return fmt.Errorf("access observations directory %q: %w", dir, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("--observations must be a directory: %s", dir)
	}

	files, skipped, err := r.collectHashes(ctx, dir)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("%w: no observation snapshots found in %q", appeval.ErrNoSnapshots, dir)
	}

	m := integrity.Manifest{
		Files:   files,
		Overall: integrity.ComputeOverall(files),
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	if err := fsutil.WriteFileAtomic(out, data, 0o600); err != nil {
		return fmt.Errorf("write manifest %q: %w", out, err)
	}

	if cfg.TextOutput {
		fmt.Fprintf(cfg.Stdout, "Wrote manifest with %d files: %s\n", len(files), out)
		if skipped > 0 {
			fmt.Fprintf(cfg.Stdout, "Skipped %d non-observation JSON file(s)\n", skipped)
		}
	}
	return nil
}

func (r *GenerateRunner) ensureValidator() *contractvalidator.Validator {
	if r.validator == nil {
		r.validator = contractvalidator.New()
	}
	return r.validator
}

func (r *GenerateRunner) collectHashes(ctx context.Context, dir string) (map[evaluation.FilePath]kernel.Digest, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, fmt.Errorf("reading observations directory: %w", err)
	}

	v := r.ensureValidator()
	files := make(map[evaluation.FilePath]kernel.Digest)
	skipped := 0

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		default:
		}

		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || isManifestArtifact(entry.Name()) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, readErr := fsutil.ReadFileLimited(path)
		if readErr != nil {
			return nil, 0, fmt.Errorf("reading %q: %w", path, readErr)
		}
		issues, validateErr := v.ValidateObservationJSON(data)
		if validateErr != nil {
			return nil, 0, fmt.Errorf("validating schema for %q: %w", path, validateErr)
		}
		if issues.HasErrors() || issues.HasWarnings() {
			skipped++
			continue
		}
		files[evaluation.FilePath(entry.Name())] = platformcrypto.HashBytes(data)
	}
	return files, skipped, nil
}

func isManifestArtifact(name string) bool {
	lower := strings.ToLower(name)
	return lower == "manifest.json" ||
		lower == "signed-manifest.json" ||
		strings.HasSuffix(lower, ".manifest.json") ||
		strings.HasSuffix(lower, ".signed-manifest.json")
}
