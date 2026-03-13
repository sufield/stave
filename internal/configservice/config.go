package configservice

import (
	"fmt"
	"strconv"
	"strings"
)

// ConfigKey identifies a supported top-level configuration key.
type ConfigKey string

const (
	KeyMaxUnsafe         ConfigKey = "max_unsafe"
	KeySnapshotRetention ConfigKey = "snapshot_retention"
	KeyDefaultTier       ConfigKey = "default_retention_tier"
	KeyCIFailurePolicy   ConfigKey = "ci_failure_policy"
	KeyCaptureCadence    ConfigKey = "capture_cadence"
	KeyFilenameTemplate  ConfigKey = "snapshot_filename_template"
)

const (
	tierKeyPrefix      = "snapshot_retention_tiers."
	tierFieldOlderThan = "older_than"
	tierFieldKeepMin   = "keep_min"
)

// --- Types & Interfaces ---

// CaptureCadence represents how often snapshots are captured.
type CaptureCadence string

const (
	CadenceDaily  CaptureCadence = "daily"
	CadenceHourly CaptureCadence = "hourly"
)

type RetentionTierConfig struct {
	OlderThan string
	KeepMin   int
}

type RetentionTiers map[string]RetentionTierConfig

type Config struct {
	MaxUnsafe                string
	SnapshotRetention        string
	RetentionTier            string
	RetentionTiers           RetentionTiers
	CIFailurePolicy          CIFailurePolicy
	CaptureCadence           CaptureCadence
	SnapshotFilenameTemplate string
}

// CIFailurePolicy represents the gate failure mode.
// Valid values are owned by the gate command and injected via ConfigValidator.NormalizePolicy.
type CIFailurePolicy string

type ValueSource struct {
	Value  string
	Source string
}

type KeyValueOutput struct {
	Key    string
	Value  string
	Source string
}

// ConfigValidator validates and normalizes raw config values.
type ConfigValidator interface {
	ParseDuration(string) error
	NormalizeTier(string) string
	NormalizePolicy(string) (CIFailurePolicy, error)
}

// KeepMinResolver resolves the effective keep_min value for a retention tier.
type KeepMinResolver interface {
	EffectiveKeepMin(int) int
}

// ConfigResolver resolves config values from env/file/default sources.
type ConfigResolver interface {
	MaxUnsafe(cfg *Config, cfgPath string) ValueSource
	SnapshotRetention(cfg *Config, cfgPath, fallbackTier string) ValueSource
	RetentionTier(cfg *Config, cfgPath string) ValueSource
	CIFailurePolicy(cfg *Config, cfgPath string) ValueSource
}

// --- Service Implementation ---

type Service struct {
	projectConfigFile string
	validator         ConfigValidator
	resolver          ConfigResolver
	keepMinResolver   KeepMinResolver
}

func New(projectConfigFile string, v ConfigValidator, r ConfigResolver, k KeepMinResolver) *Service {
	return &Service{
		projectConfigFile: projectConfigFile,
		validator:         v,
		resolver:          r,
		keepMinResolver:   k,
	}
}

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

// --- Resolution Logic ---

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

// --- Mutation Logic ---

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

// --- Helpers ---

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
