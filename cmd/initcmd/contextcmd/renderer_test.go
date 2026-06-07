package contextcmd

import (
	"bytes"
	"strings"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

func TestNewListRenderer_KnownFormats(t *testing.T) {
	tests := []struct {
		name   string
		format appcontracts.OutputFormat
		want   ListRenderer
	}{
		{"json", appcontracts.FormatJSON, ListJSONRenderer{}},
		{"text", appcontracts.FormatText, ListTextRenderer{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewListRenderer(tt.format)
			if err != nil {
				t.Fatalf("NewListRenderer(%q) error = %v", tt.format, err)
			}
			if got != tt.want {
				t.Fatalf("NewListRenderer(%q) = %T, want %T", tt.format, got, tt.want)
			}
		})
	}
}

func TestNewListRenderer_UnknownFormat(t *testing.T) {
	got, err := NewListRenderer(appcontracts.OutputFormat("bogus"))
	if err == nil {
		t.Fatalf("NewListRenderer(bogus) error = nil, want error")
	}
	if got != nil {
		t.Fatalf("NewListRenderer(bogus) renderer = %T, want nil", got)
	}
}

func TestNewShowRenderer_KnownFormats(t *testing.T) {
	tests := []struct {
		name   string
		format appcontracts.OutputFormat
		want   ShowRenderer
	}{
		{"json", appcontracts.FormatJSON, ShowJSONRenderer{}},
		{"text", appcontracts.FormatText, ShowTextRenderer{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewShowRenderer(tt.format)
			if err != nil {
				t.Fatalf("NewShowRenderer(%q) error = %v", tt.format, err)
			}
			if got != tt.want {
				t.Fatalf("NewShowRenderer(%q) = %T, want %T", tt.format, got, tt.want)
			}
		})
	}
}

func TestNewShowRenderer_UnknownFormat(t *testing.T) {
	got, err := NewShowRenderer(appcontracts.OutputFormat("bogus"))
	if err == nil {
		t.Fatalf("NewShowRenderer(bogus) error = nil, want error")
	}
	if got != nil {
		t.Fatalf("NewShowRenderer(bogus) renderer = %T, want nil", got)
	}
}

func TestListRenderers_Smoke(t *testing.T) {
	items := []ListItem{
		{Name: "prod", ProjectRoot: "/tmp/prod", ControlsDir: "controls", ObserveDir: "observations", Active: true},
	}
	for _, format := range []appcontracts.OutputFormat{appcontracts.FormatJSON, appcontracts.FormatText} {
		renderer, err := NewListRenderer(format)
		if err != nil {
			t.Fatalf("NewListRenderer(%q): %v", format, err)
		}
		var buf bytes.Buffer
		if err := renderer.Render(&buf, items); err != nil {
			t.Fatalf("Render(%q): %v", format, err)
		}
		if buf.Len() == 0 {
			t.Fatalf("Render(%q) produced empty output", format)
		}
		if !strings.Contains(buf.String(), "prod") {
			t.Fatalf("Render(%q) missing context name: %q", format, buf.String())
		}
	}
}

func TestListTextRenderer_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := (ListTextRenderer{}).Render(&buf, nil); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if buf.String() != "No contexts configured.\n" {
		t.Fatalf("empty list output = %q", buf.String())
	}
}

func TestShowRenderers_Smoke(t *testing.T) {
	res := ShowResult{
		StoreFile:   "/tmp/contexts.yaml",
		SelectedBy:  "active",
		Name:        "prod",
		ProjectRoot: "/tmp/prod",
		ControlsDir: "controls",
		ObserveDir:  "observations",
	}
	for _, format := range []appcontracts.OutputFormat{appcontracts.FormatJSON, appcontracts.FormatText} {
		renderer, err := NewShowRenderer(format)
		if err != nil {
			t.Fatalf("NewShowRenderer(%q): %v", format, err)
		}
		var buf bytes.Buffer
		if err := renderer.Render(&buf, res); err != nil {
			t.Fatalf("Render(%q): %v", format, err)
		}
		if buf.Len() == 0 {
			t.Fatalf("Render(%q) produced empty output", format)
		}
		if !strings.Contains(buf.String(), "prod") {
			t.Fatalf("Render(%q) missing context name: %q", format, buf.String())
		}
	}
}
