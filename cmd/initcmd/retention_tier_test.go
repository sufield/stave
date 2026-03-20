package initcmd

import (
	"testing"

	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/pkg/alpha/domain/retention"
	"gopkg.in/yaml.v3"
)

func TestRetentionTierConfig_UnmarshalStructForm(t *testing.T) {
	input := "older_than: 14d\nkeep_min: 5\n"
	var c retention.TierConfig
	if err := yaml.Unmarshal([]byte(input), &c); err != nil {
		t.Fatalf("unmarshal struct form: %v", err)
	}
	if c.OlderThan != "14d" {
		t.Fatalf("OlderThan=%q, want 14d", c.OlderThan)
	}
	if c.KeepMin != 5 {
		t.Fatalf("KeepMin=%d, want 5", c.KeepMin)
	}
}

func TestRetentionTierConfig_UnmarshalDefaultKeepMin(t *testing.T) {
	input := "older_than: 7d\n"
	var c retention.TierConfig
	if err := yaml.Unmarshal([]byte(input), &c); err != nil {
		t.Fatalf("unmarshal without keep_min: %v", err)
	}
	if c.OlderThan != "7d" {
		t.Fatalf("OlderThan=%q, want 7d", c.OlderThan)
	}
	if c.KeepMin != 0 {
		t.Fatalf("KeepMin=%d, want 0 (zero value; EffectiveKeepMin handles default)", c.KeepMin)
	}
}

func TestRetentionTierConfig_MarshalRoundTrip(t *testing.T) {
	c := retention.TierConfig{OlderThan: "14d", KeepMin: 5}
	out, err := yaml.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundTrip retention.TierConfig
	if err := yaml.Unmarshal(out, &roundTrip); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if roundTrip.OlderThan != "14d" || roundTrip.KeepMin != 5 {
		t.Fatalf("round-trip=%+v, want {14d 5}", roundTrip)
	}
}

func TestRetentionTiersMap_StructuredForm(t *testing.T) {
	input := `critical:
  older_than: 30d
  keep_min: 3
non_critical:
  older_than: 14d
`
	var m map[string]retention.TierConfig
	if err := yaml.Unmarshal([]byte(input), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	crit, ok := m["critical"]
	if !ok {
		t.Fatal("missing critical tier")
	}
	if crit.OlderThan != "30d" || crit.KeepMin != 3 {
		t.Fatalf("critical=%+v", crit)
	}
	nc, ok := m["non_critical"]
	if !ok {
		t.Fatal("missing non_critical tier")
	}
	if nc.OlderThan != "14d" {
		t.Fatalf("non_critical.OlderThan=%q, want 14d", nc.OlderThan)
	}
}

func TestRetentionTierConfig_ParseDuration(t *testing.T) {
	c := retention.TierConfig{OlderThan: "14d"}
	d, err := c.ParseDuration()
	if err != nil {
		t.Fatalf("ParseDuration: %v", err)
	}
	if d != 14*24*60*60*1e9 {
		t.Fatalf("duration=%v, want 14 days", d)
	}
}

func TestRetentionTierConfig_ParseDurationEmpty(t *testing.T) {
	c := retention.TierConfig{}
	_, err := c.ParseDuration()
	if err == nil {
		t.Fatal("expected error for empty older_than")
	}
}

func TestRetentionTierConfig_EffectiveKeepMin(t *testing.T) {
	tests := []struct {
		name    string
		keepMin int
		want    int
	}{
		{"zero defaults", 0, defaultTierKeepMin},
		{"negative defaults", -1, defaultTierKeepMin},
		{"explicit value", 5, 5},
		{"explicit default", defaultTierKeepMin, defaultTierKeepMin},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := retention.TierConfig{KeepMin: tt.keepMin}
			if got := c.EffectiveKeepMin(); got != tt.want {
				t.Fatalf("EffectiveKeepMin()=%d, want %d", got, tt.want)
			}
		})
	}
}

func TestProjectConfig_StructuredTiers(t *testing.T) {
	input := `max_unsafe: 168h
snapshot_retention_tiers:
  critical:
    older_than: 30d
    keep_min: 3
  non_critical:
    older_than: 14d
`
	var cfg appconfig.ProjectConfig
	if err := yaml.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("unmarshal project config: %v", err)
	}
	if len(cfg.RetentionTiers) != 2 {
		t.Fatalf("got %d tiers, want 2", len(cfg.RetentionTiers))
	}
	crit := cfg.RetentionTiers["critical"]
	if crit.OlderThan != "30d" {
		t.Fatalf("critical.OlderThan=%q, want 30d", crit.OlderThan)
	}
	if crit.KeepMin != 3 {
		t.Fatalf("critical.KeepMin=%d, want 3", crit.KeepMin)
	}
}
