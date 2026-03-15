package initcmd

import (
	"testing"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/domain/retention"
)

func TestResolveTierForPath_FirstMatchWins(t *testing.T) {
	rules := []retention.MappingRule{
		{Pattern: "prod/**", Tier: "critical"},
		{Pattern: "prod/**", Tier: "non_critical"}, // should never match
	}
	got := projconfig.ResolveTierForPath("prod/2026-01-01.json", rules, "default")
	if got != "critical" {
		t.Fatalf("got %q, want critical", got)
	}
}

func TestResolveTierForPath_DefaultFallback(t *testing.T) {
	rules := []retention.MappingRule{
		{Pattern: "prod/**", Tier: "critical"},
	}
	got := projconfig.ResolveTierForPath("staging/2026-01-01.json", rules, "non_critical")
	if got != "non_critical" {
		t.Fatalf("got %q, want non_critical", got)
	}
}

func TestResolveTierForPath_NoRules(t *testing.T) {
	got := projconfig.ResolveTierForPath("any/file.json", nil, "fallback")
	if got != "fallback" {
		t.Fatalf("got %q, want fallback", got)
	}
}

func TestMatchGlob_PrefixStarStar(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"prod/**", "prod/file.json", true},
		{"prod/**", "prod/sub/file.json", true},
		{"prod/**", "prod/a/b/c.json", true},
		{"prod/**", "dev/file.json", false},
		{"prod/**", "production/file.json", false}, // no prefix match without /
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.path, func(t *testing.T) {
			got, err := projconfig.MatchGlob(tt.pattern, tt.path)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("projconfig.MatchGlob(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

func TestMatchGlob_ExactFile(t *testing.T) {
	got, err := projconfig.MatchGlob("special.json", "special.json")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !got {
		t.Fatal("expected match for exact file")
	}
}

func TestMatchGlob_SimpleWildcard(t *testing.T) {
	got, err := projconfig.MatchGlob("*.json", "snapshot.json")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !got {
		t.Fatal("expected match for *.json")
	}

	got2, err := projconfig.MatchGlob("*.json", "sub/snapshot.json")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if got2 {
		t.Fatal("*.json should not match paths with directory separators")
	}
}
