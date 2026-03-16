package configservice

import (
	"fmt"
	"strconv"
	"strings"
)

func (s *Service) SetConfigKeyValue(cfg *Config, key ParsedKey, val string) error {
	if key.TierName != "" {
		return s.setTierValue(cfg, key, val)
	}

	switch key.TopLevel {
	case KeyMaxUnsafe, KeySnapshotRetention:
		if err := s.validator.ParseDuration(val); err != nil {
			return fmt.Errorf("invalid duration %q for %s", val, key.TopLevel)
		}
		if key.TopLevel == KeyMaxUnsafe {
			cfg.MaxUnsafe = val
		} else {
			cfg.SnapshotRetention = val
		}
	case KeyDefaultTier:
		tier := s.validator.NormalizeTier(val)
		if tier == "" {
			return fmt.Errorf("tier cannot be empty for %s", key.TopLevel)
		}
		cfg.RetentionTier = tier
	case KeyCIFailurePolicy:
		p, err := s.validator.NormalizePolicy(val)
		if err != nil {
			return err
		}
		cfg.CIFailurePolicy = p
	case KeyCaptureCadence:
		c, err := ParseCadence(val)
		if err != nil {
			return err
		}
		cfg.CaptureCadence = c
	case KeyFilenameTemplate:
		if strings.TrimSpace(val) == "" {
			return fmt.Errorf("template cannot be empty")
		}
		cfg.SnapshotFilenameTemplate = val
	}
	return nil
}

func (s *Service) setTierValue(cfg *Config, key ParsedKey, val string) error {
	if cfg.RetentionTiers == nil {
		cfg.RetentionTiers = make(RetentionTiers)
	}
	tc := cfg.RetentionTiers[key.TierName]

	field := key.SubField
	if field == "" {
		field = tierFieldOlderThan // Default field if none provided
	}

	switch field {
	case tierFieldOlderThan:
		if err := s.validator.ParseDuration(val); err != nil {
			return fmt.Errorf("invalid duration %q for tier %s", val, key.TierName)
		}
		tc.OlderThan = val
	case tierFieldKeepMin:
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 {
			return fmt.Errorf("keep_min must be a non-negative integer")
		}
		tc.KeepMin = n
	default:
		return fmt.Errorf("unsupported tier field %q", field)
	}

	cfg.RetentionTiers[key.TierName] = tc
	return nil
}

func (s *Service) DeleteConfigKeyValue(cfg *Config, key ParsedKey) error {
	if key.TopLevel != "" {
		switch key.TopLevel {
		case KeyMaxUnsafe:
			cfg.MaxUnsafe = ""
		case KeySnapshotRetention:
			cfg.SnapshotRetention = ""
		case KeyDefaultTier:
			cfg.RetentionTier = ""
		case KeyCIFailurePolicy:
			cfg.CIFailurePolicy = ""
		case KeyCaptureCadence:
			cfg.CaptureCadence = ""
		case KeyFilenameTemplate:
			cfg.SnapshotFilenameTemplate = ""
		}
		return nil
	}
	delete(cfg.RetentionTiers, key.TierName)
	return nil
}
