package stave

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/sufield/stave/internal/adapters/observations"
	appsanitize "github.com/sufield/stave/internal/app/sanitize"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/sanitize"
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

	// Phase 1: structural scrub — the strong engine scrubs both Assets
	// and Identities, applies profile-driven property removal, and
	// tokenizes ARNs/paths with prefix-aware sanitization.
	scrubber := sanitize.New(sanitize.WithIDSanitization(true))
	for i := range snaps {
		snaps[i] = scrubber.Snapshot(snaps[i])
	}

	// Phase 2: rule-based field scrub (default: hash asset_id + account
	// IDs in property values). Custom rules layer on top.
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
