package configservice

import (
	"fmt"
	"strings"
)

// ConfigKey identifies a supported configuration key.
type ConfigKey string

const (
	KeyMaxUnsafe         ConfigKey = "max_unsafe"
	KeySnapshotRetention ConfigKey = "snapshot_retention"
	KeyDefaultTier       ConfigKey = "default_retention_tier"
	KeyCIFailurePolicy   ConfigKey = "ci_failure_policy"
	KeyCaptureCadence    ConfigKey = "capture_cadence"
	KeyFilenameTemplate  ConfigKey = "snapshot_filename_template"
)

// CaptureCadence represents how often snapshots are captured.
type CaptureCadence string

const (
	CadenceDaily  CaptureCadence = "daily"
	CadenceHourly CaptureCadence = "hourly"
)

// ParseCadence validates and returns a CaptureCadence from a raw string.
func ParseCadence(v string) (CaptureCadence, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "daily":
		return CadenceDaily, nil
	case "hourly":
		return CadenceHourly, nil
	default:
		return "", fmt.Errorf("invalid value: use daily or hourly")
	}
}

// CIFailurePolicy represents the gate failure mode.
// Valid values are owned by the gate command and injected via ConfigValidator.NormalizePolicy.
type CIFailurePolicy string

const (
	tierKeyPrefix      = "snapshot_retention_tiers."
	tierFieldOlderThan = "older_than"
	tierFieldKeepMin   = "keep_min"
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

type Service struct {
	projectConfigFile string
	validator         ConfigValidator
	resolver          ConfigResolver
	keepMinResolver   KeepMinResolver
}

func New(projectConfigFile string, validator ConfigValidator, resolver ConfigResolver, keepMin KeepMinResolver) *Service {
	return &Service{
		projectConfigFile: projectConfigFile,
		validator:         validator,
		resolver:          resolver,
		keepMinResolver:   keepMin,
	}
}

// ParsedKey represents a validated configuration key, either a top-level
// key or a hierarchical retention-tier subkey.
type ParsedKey struct {
	topLevel ConfigKey
	tierSub  string
	raw      string
}

// String returns the original key string.
func (k ParsedKey) String() string { return k.raw }

// ParseConfigKey validates a raw key string and returns a ParsedKey.
func ParseConfigKey(raw string) (ParsedKey, error) {
	if after, ok := tierSubKey(raw); ok {
		if after == "" {
			return ParsedKey{}, fmt.Errorf("invalid tier key %q", raw)
		}
		return ParsedKey{tierSub: after, raw: raw}, nil
	}
	k := ConfigKey(raw)
	switch k {
	case KeyMaxUnsafe, KeySnapshotRetention, KeyDefaultTier, KeyCIFailurePolicy, KeyCaptureCadence, KeyFilenameTemplate:
		return ParsedKey{topLevel: k, raw: raw}, nil
	}
	return ParsedKey{}, fmt.Errorf("unsupported key %q", raw)
}

var topLevelKeys = []string{
	string(KeyCaptureCadence),
	string(KeyCIFailurePolicy),
	string(KeyDefaultTier),
	string(KeyMaxUnsafe),
	string(KeyFilenameTemplate),
	string(KeySnapshotRetention),
}

// TopLevelKeys returns the supported non-tier keys in deterministic order.
func (s *Service) TopLevelKeys() []string {
	return append([]string(nil), topLevelKeys...)
}

// ResolveLocalField resolves config-local fields that don't need an external resolver.
func (c *Config) ResolveLocalField(key ConfigKey, cfgPath, projectFile string) (KeyValueOutput, error) {
	switch key {
	case KeyCaptureCadence:
		if c == nil || strings.TrimSpace(string(c.CaptureCadence)) == "" {
			return KeyValueOutput{}, fmt.Errorf("key %q: not set in %s", string(key), projectFile)
		}
		return KeyValueOutput{Key: string(key), Value: string(c.CaptureCadence), Source: cfgPath + ":capture_cadence"}, nil
	case KeyFilenameTemplate:
		if c == nil || strings.TrimSpace(c.SnapshotFilenameTemplate) == "" {
			return KeyValueOutput{}, fmt.Errorf("key %q: not set in %s", string(key), projectFile)
		}
		return KeyValueOutput{Key: string(key), Value: c.SnapshotFilenameTemplate, Source: cfgPath + ":snapshot_filename_template"}, nil
	default:
		return KeyValueOutput{}, fmt.Errorf("unsupported local key %q", string(key))
	}
}

// resolveViaResolver handles keys that delegate to ConfigResolver.
func resolveViaResolver(key ConfigKey, cfg *Config, cfgPath, fallbackTier string, r ConfigResolver) (KeyValueOutput, bool) {
	var v ValueSource
	switch key {
	case KeyMaxUnsafe:
		v = r.MaxUnsafe(cfg, cfgPath)
	case KeySnapshotRetention:
		v = r.SnapshotRetention(cfg, cfgPath, fallbackTier)
	case KeyDefaultTier:
		v = r.RetentionTier(cfg, cfgPath)
	case KeyCIFailurePolicy:
		v = r.CIFailurePolicy(cfg, cfgPath)
	default:
		return KeyValueOutput{}, false
	}
	return KeyValueOutput{Key: string(key), Value: v.Value, Source: v.Source}, true
}

func (s *Service) ResolveConfigKeyValue(key ParsedKey, cfg *Config, cfgPath, fallbackTier string) (KeyValueOutput, error) {
	if key.topLevel != "" {
		if kv, ok := resolveViaResolver(key.topLevel, cfg, cfgPath, fallbackTier, s.resolver); ok {
			return kv, nil
		}
		return cfg.ResolveLocalField(key.topLevel, cfgPath, s.projectConfigFile)
	}
	return s.ResolveRetentionTierConfigKey(key.raw, key.tierSub, cfg, cfgPath)
}

// SetField validates and assigns value to the field identified by key.
func (c *Config) SetField(key ConfigKey, value string, v ConfigValidator) error {
	switch key {
	case KeyMaxUnsafe:
		if err := v.ParseDuration(value); err != nil {
			return fmt.Errorf("invalid value for %s: use duration like 168h, 7d, or 1d12h", key)
		}
		c.MaxUnsafe = value
	case KeySnapshotRetention:
		if err := v.ParseDuration(value); err != nil {
			return fmt.Errorf("invalid value for %s: use duration like 30d, 720h, or 1d12h", key)
		}
		c.SnapshotRetention = value
	case KeyDefaultTier:
		tier := v.NormalizeTier(value)
		if tier == "" {
			return fmt.Errorf("invalid value for %s: tier cannot be empty", key)
		}
		c.RetentionTier = tier
	case KeyCIFailurePolicy:
		policy, err := v.NormalizePolicy(value)
		if err != nil {
			return fmt.Errorf("invalid value for %s: %w", key, err)
		}
		c.CIFailurePolicy = policy
	case KeyCaptureCadence:
		cadence, err := ParseCadence(value)
		if err != nil {
			return fmt.Errorf("invalid value for %s: %w", key, err)
		}
		c.CaptureCadence = cadence
	case KeyFilenameTemplate:
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("invalid value for %s: template cannot be empty", key)
		}
		c.SnapshotFilenameTemplate = value
	default:
		return fmt.Errorf("unsupported key %q", key)
	}
	return nil
}

func (s *Service) SetConfigKeyValue(cfg *Config, key ParsedKey, value string) error {
	if key.tierSub != "" {
		return s.SetRetentionTierConfigKey(cfg, key.tierSub, value)
	}
	return cfg.SetField(key.topLevel, value, s.validator)
}

// DeleteField clears the field identified by key. Returns true if key was recognized.
func (c *Config) DeleteField(key ConfigKey) bool {
	switch key {
	case KeyMaxUnsafe:
		c.MaxUnsafe = ""
	case KeySnapshotRetention:
		c.SnapshotRetention = ""
	case KeyDefaultTier:
		c.RetentionTier = ""
	case KeyCIFailurePolicy:
		c.CIFailurePolicy = ""
	case KeyCaptureCadence:
		c.CaptureCadence = ""
	case KeyFilenameTemplate:
		c.SnapshotFilenameTemplate = ""
	default:
		return false
	}
	return true
}

func (s *Service) DeleteConfigKeyValue(cfg *Config, key ParsedKey) error {
	if key.topLevel != "" {
		cfg.DeleteField(key.topLevel)
		return nil
	}
	tier := s.validator.NormalizeTier(key.tierSub)
	if tier == "" {
		return fmt.Errorf("invalid tier key %q", key.raw)
	}
	delete(cfg.RetentionTiers, tier)
	return nil
}

func (s *Service) SetRetentionTierConfigKey(cfg *Config, subKey, value string) error {
	if cfg.RetentionTiers == nil {
		cfg.RetentionTiers = RetentionTiers{}
	}

	tierPart, field, hasField := splitTierSubKey(subKey)
	tier := s.validator.NormalizeTier(tierPart)
	if tier == "" {
		return fmt.Errorf("invalid tier key %q", subKey)
	}

	if hasField {
		tc := cfg.RetentionTiers[tier]
		if err := s.setTierField(&tc, field, value); err != nil {
			return err
		}
		cfg.RetentionTiers[tier] = tc
		return nil
	}

	if err := s.validator.ParseDuration(value); err != nil {
		return fmt.Errorf("invalid value for %s: use duration like 30d, 720h, or 1d12h", subKey)
	}
	tc := cfg.RetentionTiers[tier]
	tc.OlderThan = value
	cfg.RetentionTiers[tier] = tc
	return nil
}

func (s *Service) ResolveRetentionTierConfigKey(fullKey, subKey string, cfg *Config, cfgPath string) (KeyValueOutput, error) {
	tierPart, field, hasField := splitTierSubKey(subKey)
	tier := s.validator.NormalizeTier(tierPart)
	if tier == "" {
		return KeyValueOutput{}, fmt.Errorf("tier key cannot be empty")
	}

	if hasField {
		return s.resolveTierFieldKey(tierFieldResolutionRequest{
			FullKey: fullKey,
			CfgPath: cfgPath,
			Tier:    tier,
			Field:   field,
			Cfg:     cfg,
		})
	}

	v := s.resolver.SnapshotRetention(cfg, cfgPath, tier)
	return KeyValueOutput{Key: fullKey, Value: v.Value, Source: v.Source}, nil
}

func (s *Service) setTierField(tc *RetentionTierConfig, field, value string) error {
	switch field {
	case tierFieldOlderThan:
		if err := s.validator.ParseDuration(value); err != nil {
			return fmt.Errorf("invalid value for %s: use duration like 30d, 720h, or 1d12h", tierFieldOlderThan)
		}
		tc.OlderThan = value
		return nil
	case tierFieldKeepMin:
		n, err := parseNonNegativeInt(value)
		if err != nil {
			return fmt.Errorf("invalid value for %s: %w", tierFieldKeepMin, err)
		}
		tc.KeepMin = n
		return nil
	default:
		return fmt.Errorf("unsupported tier field %q (use %s or %s)", field, tierFieldOlderThan, tierFieldKeepMin)
	}
}

type tierFieldResolutionRequest struct {
	FullKey string
	CfgPath string
	Tier    string
	Field   string
	Cfg     *Config
}

func (s *Service) resolveTierFieldKey(req tierFieldResolutionRequest) (KeyValueOutput, error) {
	if req.Cfg == nil || len(req.Cfg.RetentionTiers) == 0 {
		return KeyValueOutput{}, fmt.Errorf("key %q is not set in %s", req.FullKey, s.projectConfigFile)
	}
	tc, exists := req.Cfg.RetentionTiers[req.Tier]
	if !exists {
		return KeyValueOutput{}, fmt.Errorf("tier %q is not configured", req.Tier)
	}

	switch req.Field {
	case tierFieldOlderThan:
		return KeyValueOutput{
			Key:    req.FullKey,
			Value:  tc.OlderThan,
			Source: tierFieldSource(req.CfgPath, req.Tier, tierFieldOlderThan),
		}, nil
	case tierFieldKeepMin:
		return KeyValueOutput{
			Key:    req.FullKey,
			Value:  fmt.Sprintf("%d", s.keepMinResolver.EffectiveKeepMin(tc.KeepMin)),
			Source: tierFieldSource(req.CfgPath, req.Tier, tierFieldKeepMin),
		}, nil
	default:
		return KeyValueOutput{}, fmt.Errorf("unsupported tier field %q (use %s or %s)", req.Field, tierFieldOlderThan, tierFieldKeepMin)
	}
}

func tierSubKey(key string) (string, bool) {
	return strings.CutPrefix(key, tierKeyPrefix)
}

func splitTierSubKey(subKey string) (tier string, field string, hasField bool) {
	tier, field, hasField = strings.Cut(subKey, ".")
	if !hasField {
		tier = subKey
	}
	return tier, field, hasField
}

func tierFieldSource(cfgPath, tier, field string) string {
	return cfgPath + ":" + tierKeyPrefix + tier + "." + field
}

func parseNonNegativeInt(s string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, fmt.Errorf("must be a non-negative integer")
	}
	if n < 0 {
		return 0, fmt.Errorf("must be a non-negative integer, got %d", n)
	}
	return n, nil
}
