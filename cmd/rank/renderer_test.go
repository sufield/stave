package rank

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/app/rank/formatter"
)

func TestNewRoadmapRenderer_KnownFormats(t *testing.T) {
	opts := &options{}
	cases := []struct {
		format string
		want   any
	}{
		{"json", formatter.JSON{}},
		{"csv", formatter.CSV{}},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			r, err := NewRoadmapRenderer(tc.format, opts)
			if err != nil {
				t.Fatalf("NewRoadmapRenderer(%q): %v", tc.format, err)
			}
			if r != tc.want {
				t.Errorf("got %T, want %T", r, tc.want)
			}
		})
	}
	// table + empty both return *TextRoadmap (pointer, opts-dependent)
	for _, format := range []string{"table", ""} {
		t.Run("text-"+format, func(t *testing.T) {
			r, err := NewRoadmapRenderer(format, opts)
			if err != nil {
				t.Fatalf("NewRoadmapRenderer(%q): %v", format, err)
			}
			if _, ok := r.(*formatter.TextRoadmap); !ok {
				t.Errorf("got %T, want *formatter.TextRoadmap", r)
			}
		})
	}
}

func TestNewRoadmapRenderer_UnknownFormatErrors(t *testing.T) {
	if _, err := NewRoadmapRenderer("xml", &options{}); err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected unsupported-format error, got: %v", err)
	}
}

func TestNewTeamRoadmapsRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", formatter.JSONTeamRoadmaps{}},
		{"table", formatter.TextTeamRoadmaps{}},
		{"", formatter.TextTeamRoadmaps{}},
	}
	for _, tc := range cases {
		r, err := NewTeamRoadmapsRenderer(tc.format)
		if err != nil {
			t.Errorf("NewTeamRoadmapsRenderer(%q): %v", tc.format, err)
			continue
		}
		if r != tc.want {
			t.Errorf("got %T, want %T", r, tc.want)
		}
	}
}

func TestNewTeamRoadmapsRenderer_UnknownFormatErrors(t *testing.T) {
	if _, err := NewTeamRoadmapsRenderer("xml"); err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected unsupported-format error, got: %v", err)
	}
}

func TestNewSprintRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", formatter.JSONSprint{}},
		{"table", formatter.TextSprint{}},
		{"", formatter.TextSprint{}},
	}
	for _, tc := range cases {
		r, err := NewSprintRenderer(tc.format)
		if err != nil {
			t.Errorf("NewSprintRenderer(%q): %v", tc.format, err)
			continue
		}
		if r != tc.want {
			t.Errorf("got %T, want %T", r, tc.want)
		}
	}
}

func TestNewSprintRenderer_UnknownFormatErrors(t *testing.T) {
	if _, err := NewSprintRenderer("xml"); err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected unsupported-format error, got: %v", err)
	}
}

func TestNewIdentityRankingRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", formatter.JSONIdentityRanking{}},
		{"table", formatter.TextIdentityRanking{}},
		{"", formatter.TextIdentityRanking{}},
	}
	for _, tc := range cases {
		r, err := NewIdentityRankingRenderer(tc.format)
		if err != nil {
			t.Errorf("NewIdentityRankingRenderer(%q): %v", tc.format, err)
			continue
		}
		if r != tc.want {
			t.Errorf("got %T, want %T", r, tc.want)
		}
	}
}

func TestNewIdentityRankingRenderer_UnknownFormatErrors(t *testing.T) {
	if _, err := NewIdentityRankingRenderer("xml"); err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected unsupported-format error, got: %v", err)
	}
}
