// Package sensitivity provides asset sensitivity classification
// for risk score weighting based on data classification.
package sensitivity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest defines asset sensitivity classifications.
type Manifest struct {
	SchemaVersion string              `yaml:"schema_version"`
	Defaults      SensitivityDefaults `yaml:"defaults"`
	Assets        []AssetEntry        `yaml:"assets"`
	TagRules      []TagRule           `yaml:"tag_rules"`
}

// SensitivityDefaults holds multipliers per classification.
type SensitivityDefaults struct {
	Unclassified float64 `yaml:"unclassified_multiplier"`
	PHI          float64 `yaml:"phi_multiplier"`
	PII          float64 `yaml:"pii_multiplier"`
	PCI          float64 `yaml:"pci_multiplier"`
	TradeSecret  float64 `yaml:"trade_secret_multiplier"`
}

// AssetEntry classifies a specific asset.
type AssetEntry struct {
	AssetID     string `yaml:"asset_id"`
	Sensitivity string `yaml:"sensitivity"`
	Regulation  string `yaml:"regulation"`
	Description string `yaml:"data_description"`
	DataOwner   string `yaml:"data_owner"`
}

// TagRule classifies assets by tag value.
type TagRule struct {
	TagKey      string `yaml:"tag_key"`
	TagValue    string `yaml:"tag_value"`
	Sensitivity string `yaml:"sensitivity"`
}

// Classification is the resolved sensitivity for an asset.
type Classification struct {
	Sensitivity string  `json:"sensitivity"`
	Multiplier  float64 `json:"sensitivity_multiplier"`
	Regulation  string  `json:"regulation,omitempty"`
	DataOwner   string  `json:"data_owner,omitempty"`
}

// LoadManifest reads an asset sensitivity manifest.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("read sensitivity manifest: %w", err)
	}
	var m Manifest
	if unmarshalErr := yaml.Unmarshal(data, &m); unmarshalErr != nil {
		return nil, fmt.Errorf("parse sensitivity manifest: %w", unmarshalErr)
	}
	if m.Defaults.Unclassified == 0 {
		m.Defaults.Unclassified = 1.0
	}
	if m.Defaults.PHI == 0 {
		m.Defaults.PHI = 3.0
	}
	if m.Defaults.PII == 0 {
		m.Defaults.PII = 2.5
	}
	if m.Defaults.PCI == 0 {
		m.Defaults.PCI = 2.5
	}
	if m.Defaults.TradeSecret == 0 {
		m.Defaults.TradeSecret = 2.0
	}
	return &m, nil
}

// Classify resolves the sensitivity for an asset.
// Explicit entries take priority over tag rules.
func (m *Manifest) Classify(assetID string, tags map[string]string) Classification {
	// Explicit entry match (supports glob).
	for i := range m.Assets {
		a := &m.Assets[i]
		if globMatch(a.AssetID, assetID) {
			return Classification{
				Sensitivity: a.Sensitivity,
				Multiplier:  m.multiplierFor(a.Sensitivity),
				Regulation:  a.Regulation,
				DataOwner:   a.DataOwner,
			}
		}
	}

	// Tag rule match.
	for i := range m.TagRules {
		r := &m.TagRules[i]
		if tags[r.TagKey] == r.TagValue {
			return Classification{
				Sensitivity: r.Sensitivity,
				Multiplier:  m.multiplierFor(r.Sensitivity),
			}
		}
	}

	return Classification{
		Sensitivity: "unclassified",
		Multiplier:  m.Defaults.Unclassified,
	}
}

func (m *Manifest) multiplierFor(sensitivity string) float64 {
	switch strings.ToLower(sensitivity) {
	case "phi":
		return m.Defaults.PHI
	case "pii":
		return m.Defaults.PII
	case "pci":
		return m.Defaults.PCI
	case "trade_secret":
		return m.Defaults.TradeSecret
	default:
		return m.Defaults.Unclassified
	}
}

func globMatch(pattern, value string) bool {
	if pattern == value {
		return true
	}
	if before, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(value, before)
	}
	matched, _ := filepath.Match(pattern, value)
	return matched
}
