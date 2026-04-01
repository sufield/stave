package config

import (
	"testing"

	"github.com/sufield/stave/internal/core/retention"
)

func TestNormalizeTier(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Hot", "hot"},
		{"  COLD  ", "cold"},
		{"warm", "warm"},
		{"", ""},
		{" Archive ", "archive"},
	}
	for _, tt := range tests {
		if got := NormalizeTier(tt.input); got != tt.want {
			t.Errorf("NormalizeTier(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSortedTierNames(t *testing.T) {
	t.Run("multiple tiers sorted", func(t *testing.T) {
		tiers := map[string]retention.Tier{
			"cold": {OlderThan: "30d"},
			"hot":  {OlderThan: "7d"},
			"warm": {OlderThan: "14d"},
		}
		got := SortedTierNames(tiers)
		want := []string{"cold", "hot", "warm"}
		if len(got) != len(want) {
			t.Fatalf("len = %d, want %d", len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("index %d = %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("empty map", func(t *testing.T) {
		got := SortedTierNames(nil)
		if len(got) != 0 {
			t.Errorf("expected empty, got %v", got)
		}
	})
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"observations/**", "observations/2026-01-01.json", true},
		{"observations/**", "observations/sub/file.json", true},
		{"observations/**", "controls/file.yaml", false},
		{"*.json", "foo.json", true},
		{"*.json", "foo.yaml", false},
		{"controls/*.yaml", "controls/s3.yaml", true},
		{"controls/*.yaml", "controls/sub/s3.yaml", false},
	}
	for _, tt := range tests {
		got, err := MatchGlob(tt.pattern, tt.path)
		if err != nil {
			t.Errorf("MatchGlob(%q, %q) error: %v", tt.pattern, tt.path, err)
			continue
		}
		if got != tt.want {
			t.Errorf("MatchGlob(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

func TestResolveTierForPath(t *testing.T) {
	rules := []retention.Rule{
		{Pattern: "observations/**", Tier: "hot"},
		{Pattern: "controls/**", Tier: "cold"},
	}

	t.Run("matches first rule", func(t *testing.T) {
		got := ResolveTierForPath("observations/snap.json", rules, "default")
		if got != "hot" {
			t.Errorf("got %q, want hot", got)
		}
	})

	t.Run("matches second rule", func(t *testing.T) {
		got := ResolveTierForPath("controls/s3.yaml", rules, "default")
		if got != "cold" {
			t.Errorf("got %q, want cold", got)
		}
	})

	t.Run("no match returns default", func(t *testing.T) {
		got := ResolveTierForPath("other/file.txt", rules, "archive")
		if got != "archive" {
			t.Errorf("got %q, want archive", got)
		}
	})

	t.Run("empty rules returns default", func(t *testing.T) {
		got := ResolveTierForPath("any/path", nil, "fallback")
		if got != "fallback" {
			t.Errorf("got %q, want fallback", got)
		}
	})
}

func TestResolveDefinedRetentionTiers(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		got := ResolveDefinedRetentionTiers(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("empty tiers", func(t *testing.T) {
		got := ResolveDefinedRetentionTiers(&ProjectConfig{})
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("normalizes tier names", func(t *testing.T) {
		cfg := &ProjectConfig{
			RetentionTiers: map[string]retention.Tier{
				"HOT":    {OlderThan: "7d", KeepMin: 2},
				"  Cold": {OlderThan: "30d", KeepMin: 1},
			},
		}
		got := ResolveDefinedRetentionTiers(cfg)
		if len(got) != 2 {
			t.Fatalf("len = %d, want 2", len(got))
		}
		if _, ok := got["hot"]; !ok {
			t.Error("missing normalized key 'hot'")
		}
		if _, ok := got["cold"]; !ok {
			t.Error("missing normalized key 'cold'")
		}
		if got["hot"].KeepMin != 2 {
			t.Errorf("hot.KeepMin = %d, want 2", got["hot"].KeepMin)
		}
	})
}
