package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	appeval "github.com/sufield/stave/internal/app/eval"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/integrity"
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func runSnapshotManifestGenerate(cmd *cobra.Command, observationsDir, outFile string) error {
	dir := filepath.Clean(observationsDir)
	out := filepath.Clean(outFile)

	if fi, err := os.Stat(dir); err != nil {
		return fmt.Errorf("access observations directory %q: %w", dir, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("--observations must be a directory: %s", dir)
	}

	files, skipped, err := collectObservationHashes(dir)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("%w: no observation snapshots found in %q", appeval.ErrNoSnapshots, dir)
	}
	manifest := integrity.Manifest{
		Files:   files,
		Overall: integrity.ComputeOverall(files),
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	if err := writeFileAtomic(out, data, 0o600); err != nil {
		return fmt.Errorf("write manifest %q: %w", out, err)
	}

	if cmdutil.TextOutputEnabled(cmd) {
		fmt.Fprintf(cmd.OutOrStdout(), "Wrote manifest with %d files: %s\n", len(files), out)
		if skipped > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "Skipped %d non-observation JSON file(s)\n", skipped)
		}
	}
	return nil
}

func collectObservationHashes(dir string) (map[evaluation.FilePath]kernel.Digest, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, fmt.Errorf("read observations directory: %w", err)
	}

	validator := contractvalidator.New()
	files := make(map[evaluation.FilePath]kernel.Digest)
	skipped := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || isExcludedManifestArtifact(entry.Name()) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, readErr := fsutil.ReadFileLimited(path)
		if readErr != nil {
			return nil, 0, fmt.Errorf("read observation %q: %w", path, readErr)
		}
		issues, validateErr := validator.ValidateObservationJSON(data)
		if validateErr != nil {
			return nil, 0, fmt.Errorf("validate observation schema for %q: %w", path, validateErr)
		}
		if issues.HasErrors() || issues.HasWarnings() {
			skipped++
			continue
		}
		files[evaluation.FilePath(entry.Name())] = platformcrypto.HashBytes(data)
	}
	return files, skipped, nil
}

func isExcludedManifestArtifact(name string) bool {
	lower := strings.ToLower(name)
	return lower == "manifest.json" ||
		lower == "signed-manifest.json" ||
		strings.HasSuffix(lower, ".manifest.json") ||
		strings.HasSuffix(lower, ".signed-manifest.json")
}
