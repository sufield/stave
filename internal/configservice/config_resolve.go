package configservice

import (
	"fmt"
	"strconv"
)

func (s *Service) ResolveConfigKeyValue(key ParsedKey, cfg *Config, cfgPath, fallbackTier string) (KeyValueOutput, error) {
	if key.TopLevel != "" {
		return s.resolveTopLevel(key.TopLevel, cfg, cfgPath, fallbackTier)
	}
	return s.resolveTierKey(key, cfg, cfgPath)
}

func (s *Service) resolveTopLevel(key ConfigKey, cfg *Config, path, fallback string) (KeyValueOutput, error) {
	var vs ValueSource
	switch key {
	case KeyMaxUnsafe:
		vs = s.resolver.MaxUnsafe(cfg, path)
	case KeySnapshotRetention:
		vs = s.resolver.SnapshotRetention(cfg, path, fallback)
	case KeyDefaultTier:
		vs = s.resolver.RetentionTier(cfg, path)
	case KeyCIFailurePolicy:
		vs = s.resolver.CIFailurePolicy(cfg, path)
	case KeyCaptureCadence:
		if cfg == nil || cfg.CaptureCadence == "" {
			return KeyValueOutput{}, fmt.Errorf("key %q: not set in %s", key, s.projectConfigFile)
		}
		vs = ValueSource{Value: string(cfg.CaptureCadence), Source: path + ":capture_cadence"}
	case KeyFilenameTemplate:
		if cfg == nil || cfg.SnapshotFilenameTemplate == "" {
			return KeyValueOutput{}, fmt.Errorf("key %q: not set in %s", key, s.projectConfigFile)
		}
		vs = ValueSource{Value: cfg.SnapshotFilenameTemplate, Source: path + ":snapshot_filename_template"}
	default:
		return KeyValueOutput{}, fmt.Errorf("unsupported key %q", key)
	}
	return KeyValueOutput{Key: string(key), Value: vs.Value, Source: vs.Source}, nil
}

func (s *Service) resolveTierKey(key ParsedKey, cfg *Config, path string) (KeyValueOutput, error) {
	// Case 1: Resolving the tier duration itself (delegates to resolver)
	if key.SubField == "" {
		vs := s.resolver.SnapshotRetention(cfg, path, key.TierName)
		return KeyValueOutput{Key: key.Raw, Value: vs.Value, Source: vs.Source}, nil
	}

	// Case 2: Resolving a specific sub-field (older_than or keep_min)
	if cfg == nil || len(cfg.RetentionTiers) == 0 {
		return KeyValueOutput{}, fmt.Errorf("key %q: not set in %s", key.Raw, s.projectConfigFile)
	}
	tc, exists := cfg.RetentionTiers[key.TierName]
	if !exists {
		return KeyValueOutput{}, fmt.Errorf("tier %q is not configured", key.TierName)
	}

	var val string
	switch key.SubField {
	case tierFieldOlderThan:
		val = tc.OlderThan
	case tierFieldKeepMin:
		val = strconv.Itoa(s.keepMinResolver.EffectiveKeepMin(tc.KeepMin))
	default:
		return KeyValueOutput{}, fmt.Errorf("unsupported tier field %q", key.SubField)
	}

	return KeyValueOutput{
		Key:    key.Raw,
		Value:  val,
		Source: fmt.Sprintf("%s:%s%s.%s", path, tierKeyPrefix, key.TierName, key.SubField),
	}, nil
}
