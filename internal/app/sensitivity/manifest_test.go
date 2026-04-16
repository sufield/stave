package sensitivity

import "testing"

func TestClassify_ExplicitPHI(t *testing.T) {
	m := &Manifest{
		Defaults: SensitivityDefaults{PHI: 3.0, Unclassified: 1.0},
		Assets: []AssetEntry{
			{AssetID: "arn:aws:s3:::patient-records-*", Sensitivity: "phi", Regulation: "hipaa", DataOwner: "Clinical"},
		},
	}

	c := m.Classify("arn:aws:s3:::patient-records-prod", nil)
	if c.Sensitivity != "phi" {
		t.Errorf("sensitivity = %q, want phi", c.Sensitivity)
	}
	if c.Multiplier != 3.0 {
		t.Errorf("multiplier = %f, want 3.0", c.Multiplier)
	}
	if c.Regulation != "hipaa" {
		t.Errorf("regulation = %q, want hipaa", c.Regulation)
	}
	if c.DataOwner != "Clinical" {
		t.Errorf("owner = %q, want Clinical", c.DataOwner)
	}
}

func TestClassify_TagRule(t *testing.T) {
	m := &Manifest{
		Defaults: SensitivityDefaults{PII: 2.5, Unclassified: 1.0},
		TagRules: []TagRule{
			{TagKey: "data-classification", TagValue: "pii", Sensitivity: "pii"},
		},
	}

	c := m.Classify("arn:aws:s3:::some-bucket", map[string]string{"data-classification": "pii"})
	if c.Sensitivity != "pii" {
		t.Errorf("sensitivity = %q, want pii", c.Sensitivity)
	}
	if c.Multiplier != 2.5 {
		t.Errorf("multiplier = %f, want 2.5", c.Multiplier)
	}
}

func TestClassify_ExplicitOverridesTag(t *testing.T) {
	m := &Manifest{
		Defaults: SensitivityDefaults{PHI: 3.0, PII: 2.5, Unclassified: 1.0},
		Assets: []AssetEntry{
			{AssetID: "arn:aws:s3:::special-*", Sensitivity: "phi"},
		},
		TagRules: []TagRule{
			{TagKey: "data-classification", TagValue: "pii", Sensitivity: "pii"},
		},
	}

	// Asset matches both explicit (phi) and tag rule (pii) — explicit wins.
	c := m.Classify("arn:aws:s3:::special-bucket", map[string]string{"data-classification": "pii"})
	if c.Sensitivity != "phi" {
		t.Errorf("sensitivity = %q, want phi (explicit beats tag)", c.Sensitivity)
	}
}

func TestClassify_Unclassified(t *testing.T) {
	m := &Manifest{
		Defaults: SensitivityDefaults{Unclassified: 1.0},
	}
	c := m.Classify("arn:aws:s3:::random-bucket", nil)
	if c.Sensitivity != "unclassified" {
		t.Errorf("sensitivity = %q, want unclassified", c.Sensitivity)
	}
	if c.Multiplier != 1.0 {
		t.Errorf("multiplier = %f, want 1.0", c.Multiplier)
	}
}
