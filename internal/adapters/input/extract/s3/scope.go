package s3

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
)

const s3ARNPrefix = "arn:aws:s3:::"

// AssetID is a bucket identifier that can be bucket name or S3 ARN.
type AssetID string

// Normalize converts a resource id into canonical bucket-name form.
func (r AssetID) Normalize() string {
	s := strings.ToLower(strings.TrimSpace(string(r)))
	return strings.TrimPrefix(s, s3ARNPrefix)
}

// Equals compares two resource ids after normalization.
func (r AssetID) Equals(other string) bool {
	return r.Normalize() == AssetID(other).Normalize()
}

// ScopeOption configures ScopeConfig construction.
type ScopeOption func(*ScopeConfig)

// WithHealthTags configures health tag predicates.
func WithHealthTags(tags map[string]string) ScopeOption {
	return func(c *ScopeConfig) {
		c.HealthTags = tags
	}
}

// WithBucketAllowlist configures explicit bucket allowlist.
func WithBucketAllowlist(buckets []string) ScopeOption {
	return func(c *ScopeConfig) {
		c.BucketAllowlist = buckets
		c.indexAllowlist()
	}
}

// ScopeConfig defines the health domain scope for S3 bucket filtering.
type ScopeConfig struct {
	// HealthTagKeys are tag key-value pairs that identify health/PHI buckets
	// Default: DataDomain=health, containsPHI=true
	HealthTags map[string]string

	// BucketAllowlist is an explicit list of bucket names/ARNs to include
	BucketAllowlist []string

	// IncludeAll disables filtering (evaluate all buckets)
	IncludeAll bool

	allowlistIndex map[string]struct{} `yaml:"-" json:"-"`
}

// DefaultScopeConfig returns the default health scope configuration.
func DefaultScopeConfig() *ScopeConfig {
	cfg := &ScopeConfig{
		HealthTags: map[string]string{
			"DataDomain":  "health",
			"containsPHI": "true",
		},
	}
	cfg.indexAllowlist()
	return cfg
}

// NewScopeConfig constructs scope configuration with defaults and optional overrides.
func NewScopeConfig(opts ...ScopeOption) *ScopeConfig {
	cfg := DefaultScopeConfig()
	for _, opt := range opts {
		opt(cfg)
	}
	cfg.indexAllowlist()
	return cfg
}

// NewScopeConfigFromFile loads scope configuration from a YAML or JSON file.
func NewScopeConfigFromFile(path string) (*ScopeConfig, error) {
	cfg := DefaultScopeConfig()

	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, err
	}

	// yaml.v3 unmarshaler accepts JSON as well.
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse scope config: %w", err)
	}

	// Ensure defaults if empty
	if cfg.HealthTags == nil && len(cfg.BucketAllowlist) == 0 && !cfg.IncludeAll {
		cfg.HealthTags = DefaultScopeConfig().HealthTags
	}
	cfg.indexAllowlist()

	return cfg, nil
}

// NewScopeConfigFromAllowlist creates a scope config from a bucket allowlist.
func NewScopeConfigFromAllowlist(buckets []string) *ScopeConfig {
	return NewScopeConfig(WithHealthTags(nil), WithBucketAllowlist(buckets))
}

func (c *ScopeConfig) indexAllowlist() {
	if len(c.BucketAllowlist) == 0 {
		c.allowlistIndex = nil
		return
	}
	idx := make(map[string]struct{}, len(c.BucketAllowlist))
	for _, allowed := range c.BucketAllowlist {
		normalized := AssetID(allowed).Normalize()
		if normalized == "" {
			continue
		}
		idx[normalized] = struct{}{}
	}
	c.allowlistIndex = idx
}

func (c *ScopeConfig) hasAllowlistMatch(bucketNameOrARN string) bool {
	if len(c.allowlistIndex) == 0 && len(c.BucketAllowlist) > 0 {
		c.indexAllowlist()
	}
	if len(c.allowlistIndex) == 0 {
		return false
	}
	_, ok := c.allowlistIndex[AssetID(bucketNameOrARN).Normalize()]
	return ok
}

func (c *ScopeConfig) hasTagMatch(tags map[string]string) bool {
	if len(c.HealthTags) == 0 || len(tags) == 0 {
		return false
	}
	for key, expected := range c.HealthTags {
		if actual, ok := tags[key]; ok && strings.EqualFold(actual, expected) {
			return true
		}
	}
	return false
}

// Matches checks if a bucket matches the configured scope predicates.
func (c *ScopeConfig) Matches(tags map[string]string, bucketNameOrARN string) bool {
	if c == nil {
		return false
	}
	if c.IncludeAll {
		return true
	}

	if c.hasAllowlistMatch(bucketNameOrARN) {
		return true
	}

	// If allowlist is specified and tags are disabled, non-members are excluded.
	if len(c.BucketAllowlist) > 0 && len(c.HealthTags) == 0 {
		return false
	}

	return c.hasTagMatch(tags)
}

// IsHealthBucket checks if a bucket matches the health scope criteria.
func (c *ScopeConfig) IsHealthBucket(tags map[string]string, bucketNameOrARN string) bool {
	return c.Matches(tags, bucketNameOrARN)
}

// matchesBucket checks if a bucket name or ARN matches the pattern.
func matchesBucket(pattern, bucketNameOrARN string) bool {
	return AssetID(pattern).Equals(bucketNameOrARN)
}
