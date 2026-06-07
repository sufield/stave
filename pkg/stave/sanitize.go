package stave

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/sufield/stave/internal/adapters/observations"
	appsanitize "github.com/sufield/stave/internal/app/sanitize"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// SanitizeStats reports what a sanitize pass changed.
type SanitizeStats struct {
	AssetsTouched   int
	RulesApplied    int
	AccountIDHashes int
}

// SanitizeSnapshot loads an observation snapshot bundle, replaces ARNs,
// account IDs, and sensitive fields with deterministic tokens (default
// rules, or a custom rules YAML when rulesPath is non-empty), and
// returns the sanitized bundle as indented JSON plus what changed. The
// sanitized snapshot remains evaluable by Apply. It is the library entry
// point behind `stave sanitize`.
func SanitizeSnapshot(snapshotPath, rulesPath string) ([]byte, SanitizeStats, error) {
	snaps, err := observations.LoadBundle(snapshotPath)
	if err != nil {
		return nil, SanitizeStats{}, fmt.Errorf("load snapshot: %w", err)
	}

	cfg := appsanitize.DefaultConfig()
	if rulesPath != "" {
		data, readErr := fsutil.ReadFileLimited(rulesPath)
		if readErr != nil {
			return nil, SanitizeStats{}, fmt.Errorf("read rules: %w", readErr)
		}
		if unmarshalErr := yaml.Unmarshal(data, &cfg); unmarshalErr != nil {
			return nil, SanitizeStats{}, fmt.Errorf("parse rules: %w", unmarshalErr)
		}
	}

	res := appsanitize.Sanitize(snaps, cfg)
	bundle := observations.ObservationBundle{
		SchemaVersion: "obs.v0.1",
		Snapshots:     snaps,
	}
	out, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, SanitizeStats{}, fmt.Errorf("marshal sanitized output: %w", err)
	}
	return out, SanitizeStats{
		AssetsTouched:   res.AssetsTouched,
		RulesApplied:    res.RulesApplied,
		AccountIDHashes: res.AccountIDHashes,
	}, nil
}
