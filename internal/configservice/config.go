package configservice

import (
	"github.com/sufield/stave/internal/domain/retention"
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

// CaptureCadence represents how often snapshots are captured.
type CaptureCadence string

const (
	CadenceDaily  CaptureCadence = "daily"
	CadenceHourly CaptureCadence = "hourly"
)

// RetentionTiers maps tier names to their retention configuration.
type RetentionTiers map[string]retention.TierConfig

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
