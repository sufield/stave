package configservice

import (
	"reflect"
	"strings"
	"testing"
)

type testValidator struct{}

func (testValidator) ParseDuration(string) error { return nil }

func (testValidator) NormalizeTier(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func (testValidator) NormalizePolicy(value string) (CIFailurePolicy, error) {
	return CIFailurePolicy(value), nil
}

type testKeepMinResolver struct{}

func (testKeepMinResolver) EffectiveKeepMin(v int) int { return v }

type testResolver struct{}

func (testResolver) MaxUnsafe(*Config, string) ValueSource { return ValueSource{} }

func (testResolver) SnapshotRetention(*Config, string, string) ValueSource { return ValueSource{} }

func (testResolver) RetentionTier(*Config, string) ValueSource { return ValueSource{} }

func (testResolver) CIFailurePolicy(*Config, string) ValueSource { return ValueSource{} }

func newTestService() *Service {
	return New("stave.yaml", testValidator{}, testResolver{}, testKeepMinResolver{})
}

func TestTopLevelKeys(t *testing.T) {
	svc := newTestService()
	got := svc.TopLevelKeys()
	want := []string{
		"capture_cadence",
		"ci_failure_policy",
		"default_retention_tier",
		"max_unsafe",
		"snapshot_filename_template",
		"snapshot_retention",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TopLevelKeys() = %v, want %v", got, want)
	}
}

func TestParseConfigKey(t *testing.T) {
	svc := newTestService()
	for _, key := range svc.TopLevelKeys() {
		k, err := svc.ParseConfigKey(key)
		if err != nil {
			t.Errorf("ParseConfigKey(%q) error = %v", key, err)
		}
		if k.String() != key {
			t.Errorf("String() = %q, want %q", k.String(), key)
		}
	}

	k, err := svc.ParseConfigKey("snapshot_retention_tiers.staging")
	if err != nil {
		t.Fatalf("ParseConfigKey(tier) error = %v", err)
	}
	if k.String() != "snapshot_retention_tiers.staging" {
		t.Errorf("String() = %q, want tier key", k.String())
	}

	_, err = svc.ParseConfigKey("unknown_key")
	if err == nil {
		t.Fatal("expected error for unsupported key")
	}
}

func mustParseKey(t *testing.T, svc *Service, raw string) ParsedKey {
	t.Helper()
	k, err := svc.ParseConfigKey(raw)
	if err != nil {
		t.Fatalf("ParseConfigKey(%q) error = %v", raw, err)
	}
	return k
}

func TestDeleteConfigKeyValue(t *testing.T) {
	svc := newTestService()
	cfg := &Config{
		MaxUnsafe:                "72h",
		SnapshotRetention:        "30d",
		RetentionTier:            "critical",
		CIFailurePolicy:          "fail_on_new_violation",
		CaptureCadence:           "daily",
		SnapshotFilenameTemplate: "{timestamp}.json",
		RetentionTiers: RetentionTiers{
			"critical": {OlderThan: "30d", KeepMin: 2},
		},
	}

	keys := []string{
		"max_unsafe",
		"snapshot_retention",
		"default_retention_tier",
		"ci_failure_policy",
		"capture_cadence",
		"snapshot_filename_template",
	}
	for _, key := range keys {
		if err := svc.DeleteConfigKeyValue(cfg, mustParseKey(t, svc, key)); err != nil {
			t.Fatalf("DeleteConfigKeyValue(%q) error = %v", key, err)
		}
	}

	if cfg.MaxUnsafe != "" ||
		cfg.SnapshotRetention != "" ||
		cfg.RetentionTier != "" ||
		cfg.CIFailurePolicy != "" ||
		cfg.CaptureCadence != "" ||
		cfg.SnapshotFilenameTemplate != "" {
		t.Fatalf("top-level delete did not clear config: %#v", cfg)
	}

	if err := svc.DeleteConfigKeyValue(cfg, mustParseKey(t, svc, "snapshot_retention_tiers.critical")); err != nil {
		t.Fatalf("DeleteConfigKeyValue(tier) error = %v", err)
	}
	if _, ok := cfg.RetentionTiers["critical"]; ok {
		t.Fatalf("tier was not deleted: %#v", cfg.RetentionTiers)
	}
}
