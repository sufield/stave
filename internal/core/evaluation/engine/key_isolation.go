package engine

import (
	"maps"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
)

// SensitivityLevel represents a position in the data classification hierarchy.
// Higher values indicate more sensitive data.
type SensitivityLevel int

const (
	SensitivityUnclassified SensitivityLevel = iota
	SensitivityPublic
	SensitivityInternal
	SensitivityConfidential
	SensitivityPHI // phi, cde — highest sensitivity
)

// ParseSensitivity maps a data-classification tag value to its level.
// Unknown or empty values are treated as Unclassified.
func ParseSensitivity(classification string) SensitivityLevel {
	switch classification {
	case "phi", "cde":
		return SensitivityPHI
	case "confidential":
		return SensitivityConfidential
	case "internal":
		return SensitivityInternal
	case "public", "non-sensitive":
		return SensitivityPublic
	default:
		return SensitivityUnclassified
	}
}

// KeyUsageEntry tracks the sensitivity domains using a single KMS key.
type KeyUsageEntry struct {
	Domains  map[string]struct{} // distinct data-classification values
	MinLevel SensitivityLevel    // lowest sensitivity level using this key
	MaxLevel SensitivityLevel    // highest sensitivity level using this key
}

// IsExclusive reports whether the key is used by resources within a
// single sensitivity level (or no resources at all).
func (e KeyUsageEntry) IsExclusive() bool {
	return e.MinLevel == e.MaxLevel
}

// KeyUsageIndex maps each KMS key ARN to the set of sensitivity domains
// that use it across the snapshot.
type KeyUsageIndex map[string]*KeyUsageEntry

// buildKeyUsageIndexForSnapshot iterates all assets in a single snapshot and
// builds a mapping from KMS key ARN to the set of sensitivity domains.
func buildKeyUsageIndexForSnapshot(snap asset.Snapshot) KeyUsageIndex {
	idx := make(KeyUsageIndex)
	for _, a := range snap.Assets {
		keyID := extractKMSKeyID(a)
		if keyID == "" {
			continue
		}
		classification := extractClassification(a)
		level := ParseSensitivity(strings.ToLower(strings.TrimSpace(classification)))

		entry, exists := idx[keyID]
		if !exists {
			entry = &KeyUsageEntry{
				Domains:  make(map[string]struct{}),
				MinLevel: level,
				MaxLevel: level,
			}
			idx[keyID] = entry
		}
		entry.Domains[classification] = struct{}{}
		if level < entry.MinLevel {
			entry.MinLevel = level
		}
		if level > entry.MaxLevel {
			entry.MaxLevel = level
		}
	}
	return idx
}

// EnrichKeyIsolation injects derived key isolation properties into each
// asset's properties map. Each snapshot uses its OWN key sharing state
// to avoid retroactively applying future key sharing to historical data.
//
// The returned snapshots own their Assets slice and every Asset's
// Properties map: callers may mutate either without disturbing the
// input snapshots. This invariant must hold on every code path,
// including the fast paths where no enrichment fires.
func EnrichKeyIsolation(snapshots []asset.Snapshot) []asset.Snapshot {
	enriched := make([]asset.Snapshot, len(snapshots))
	for i, snap := range snapshots {
		idx := buildKeyUsageIndexForSnapshot(snap)
		enriched[i] = snap
		assets := make([]asset.Asset, len(snap.Assets))
		if len(idx) == 0 {
			for j, a := range snap.Assets {
				assets[j] = cloneAssetProperties(a)
			}
			enriched[i].Assets = assets
			continue
		}
		for j, a := range snap.Assets {
			assets[j] = enrichAssetIsolation(a, idx)
		}
		enriched[i].Assets = assets
	}
	return enriched
}

// cloneAssetProperties returns a copy of the asset whose Properties
// map is independent of the input. Used to preserve the
// EnrichKeyIsolation contract (returned assets are mutation-safe)
// even on paths that do not otherwise need to clone.
func cloneAssetProperties(a asset.Asset) asset.Asset {
	if a.Properties == nil {
		return a
	}
	props := make(map[string]any, len(a.Properties))
	maps.Copy(props, a.Properties)
	a.Properties = props
	return a
}

func enrichAssetIsolation(a asset.Asset, idx KeyUsageIndex) asset.Asset {
	keyID := extractKMSKeyID(a)
	if keyID == "" {
		return cloneAssetProperties(a)
	}
	entry, exists := idx[keyID]
	if !exists {
		return cloneAssetProperties(a)
	}

	// Clone properties to avoid mutating the original.
	props := make(map[string]any, len(a.Properties))
	maps.Copy(props, a.Properties)

	// Build or extend the cryptography.key_isolation sub-object.
	crypto := getOrCreateMap(props, "cryptography")
	isolation := make(map[string]any, 3)
	isolation["is_exclusive_to_domain"] = entry.IsExclusive()
	isolation["domain_count"] = len(entry.Domains)
	isolation["mixed_classification"] = entry.MaxLevel != entry.MinLevel
	crypto["key_isolation"] = isolation

	a.Properties = props
	return a
}

// extractKMSKeyID retrieves cryptography.kms_key_id from asset properties.
func extractKMSKeyID(a asset.Asset) string {
	crypto, ok := a.Properties["cryptography"].(map[string]any)
	if !ok {
		return ""
	}
	keyID, _ := crypto["kms_key_id"].(string)
	return keyID
}

// extractClassification retrieves the data-classification tag.
// Falls back to "unclassified" when missing.
func extractClassification(a asset.Asset) string {
	tags, ok := a.Properties["tags"].(map[string]any)
	if !ok {
		// Try nested storage.tags path.
		if storage, ok := a.Properties["storage"].(map[string]any); ok {
			tags, _ = storage["tags"].(map[string]any)
		}
	}
	if tags == nil {
		return "unclassified"
	}
	// Check multiple common tag key variants.
	for _, key := range []string{"data-classification", "data_classification", "DataClassification"} {
		if dc, ok := tags[key].(string); ok && dc != "" {
			return strings.ToLower(strings.TrimSpace(dc))
		}
	}
	return "unclassified"
}

// getOrCreateMap gets or creates a map[string]any at the given key.
func getOrCreateMap(m map[string]any, key string) map[string]any {
	if existing, ok := m[key].(map[string]any); ok {
		// Clone to avoid mutating nested maps from the original.
		cloned := make(map[string]any, len(existing)+1)
		maps.Copy(cloned, existing)
		m[key] = cloned
		return cloned
	}
	created := make(map[string]any, 2)
	m[key] = created
	return created
}
