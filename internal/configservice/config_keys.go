package configservice

import (
	"fmt"
	"strings"
)

// ParsedKey represents a validated configuration key, either a top-level
// key or a hierarchical retention-tier subkey.
type ParsedKey struct {
	TopLevel ConfigKey
	TierName string
	SubField string
	Raw      string
}

// String returns the original key string.
func (k ParsedKey) String() string { return k.Raw }

// ParseConfigKey validates a raw key string and returns a ParsedKey.
func (s *Service) ParseConfigKey(raw string) (ParsedKey, error) {
	// Handle hierarchical tier keys: snapshot_retention_tiers.<tier>[.<field>]
	if subKey, ok := strings.CutPrefix(raw, tierKeyPrefix); ok {
		tier, field, _ := strings.Cut(subKey, ".")
		tier = s.validator.NormalizeTier(tier)
		if tier == "" {
			return ParsedKey{}, fmt.Errorf("invalid tier key %q: tier name cannot be empty", raw)
		}
		return ParsedKey{TierName: tier, SubField: field, Raw: raw}, nil
	}

	// Handle top-level keys
	k := ConfigKey(raw)
	switch k {
	case KeyMaxUnsafe, KeySnapshotRetention, KeyDefaultTier, KeyCIFailurePolicy, KeyCaptureCadence, KeyFilenameTemplate:
		return ParsedKey{TopLevel: k, Raw: raw}, nil
	}
	return ParsedKey{}, fmt.Errorf("unsupported configuration key %q", raw)
}

// TopLevelKeys returns supported keys in a deterministic order.
func (s *Service) TopLevelKeys() []string {
	return []string{
		string(KeyCaptureCadence),
		string(KeyCIFailurePolicy),
		string(KeyDefaultTier),
		string(KeyMaxUnsafe),
		string(KeyFilenameTemplate),
		string(KeySnapshotRetention),
	}
}

// ParseCadence validates and returns a CaptureCadence from a raw string.
func ParseCadence(v string) (CaptureCadence, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "daily":
		return CadenceDaily, nil
	case "hourly":
		return CadenceHourly, nil
	default:
		return "", fmt.Errorf("invalid cadence: use 'daily' or 'hourly'")
	}
}
