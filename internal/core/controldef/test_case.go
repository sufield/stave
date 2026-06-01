package controldef

// ControlTest defines a test case embedded in a control YAML file.
type ControlTest struct {
	Name    string    `yaml:"name"    json:"name"`
	Verdict string    `yaml:"verdict" json:"verdict"`
	Asset   TestAsset `yaml:"asset"   json:"asset"`
}

// TestAsset is a minimal asset definition for test cases.
type TestAsset struct {
	AssetID    string         `yaml:"asset_id"    json:"asset_id"`
	AssetType  string         `yaml:"asset_type"  json:"asset_type"`
	Vendor     string         `yaml:"vendor"      json:"vendor"`
	Properties map[string]any `yaml:"properties"  json:"properties"`
}
