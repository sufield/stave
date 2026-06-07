package config

import (
	"bytes"
	"reflect"
	"testing"

	appconfig "github.com/sufield/stave/internal/app/config"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

func TestNewValueRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format appcontracts.OutputFormat
		want   reflect.Type
	}{
		{appcontracts.FormatJSON, reflect.TypeFor[ValueJSONRenderer]()},
		{appcontracts.FormatText, reflect.TypeFor[ValueTextRenderer]()},
		// Non-JSON formats the shared parser admits fall through to text,
		// matching the pre-Renderer `if format.IsJSON()` dispatch.
		{appcontracts.FormatSARIF, reflect.TypeFor[ValueTextRenderer]()},
		{appcontracts.FormatMarkdown, reflect.TypeFor[ValueTextRenderer]()},
	}
	for _, tc := range cases {
		t.Run(string(tc.format), func(t *testing.T) {
			r, err := NewValueRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewValueRenderer(%q) error: %v", tc.format, err)
			}
			if got := reflect.TypeOf(r); got != tc.want {
				t.Fatalf("NewValueRenderer(%q) = %v, want %v", tc.format, got, tc.want)
			}
		})
	}
}

func TestNewValueRenderer_UnknownFormat(t *testing.T) {
	if _, err := NewValueRenderer(appcontracts.OutputFormat("bogus")); err == nil {
		t.Fatal("NewValueRenderer with bogus format: expected error, got nil")
	}
}

func TestNewMutationRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format appcontracts.OutputFormat
		want   reflect.Type
	}{
		{appcontracts.FormatJSON, reflect.TypeFor[MutationJSONRenderer]()},
		{appcontracts.FormatText, reflect.TypeFor[MutationTextRenderer]()},
		{appcontracts.FormatSARIF, reflect.TypeFor[MutationTextRenderer]()},
		{appcontracts.FormatMarkdown, reflect.TypeFor[MutationTextRenderer]()},
	}
	for _, tc := range cases {
		t.Run(string(tc.format), func(t *testing.T) {
			r, err := NewMutationRenderer(tc.format, &bytes.Buffer{}, "Set k=v", MutationOpts{}, true)
			if err != nil {
				t.Fatalf("NewMutationRenderer(%q) error: %v", tc.format, err)
			}
			if got := reflect.TypeOf(r); got != tc.want {
				t.Fatalf("NewMutationRenderer(%q) = %v, want %v", tc.format, got, tc.want)
			}
		})
	}
}

func TestNewMutationRenderer_UnknownFormat(t *testing.T) {
	if _, err := NewMutationRenderer(appcontracts.OutputFormat("bogus"), &bytes.Buffer{}, "", MutationOpts{}, false); err == nil {
		t.Fatal("NewMutationRenderer with bogus format: expected error, got nil")
	}
}

func TestNewShowRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format appcontracts.OutputFormat
		want   reflect.Type
	}{
		{appcontracts.FormatJSON, reflect.TypeFor[ShowJSONRenderer]()},
		{appcontracts.FormatText, reflect.TypeFor[ShowTextRenderer]()},
		{appcontracts.FormatSARIF, reflect.TypeFor[ShowTextRenderer]()},
		{appcontracts.FormatMarkdown, reflect.TypeFor[ShowTextRenderer]()},
	}
	for _, tc := range cases {
		t.Run(string(tc.format), func(t *testing.T) {
			r, err := NewShowRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewShowRenderer(%q) error: %v", tc.format, err)
			}
			if got := reflect.TypeOf(r); got != tc.want {
				t.Fatalf("NewShowRenderer(%q) = %v, want %v", tc.format, got, tc.want)
			}
		})
	}
}

func TestNewShowRenderer_UnknownFormat(t *testing.T) {
	if _, err := NewShowRenderer(appcontracts.OutputFormat("bogus")); err == nil {
		t.Fatal("NewShowRenderer with bogus format: expected error, got nil")
	}
}

func TestValueRenderers_Smoke(t *testing.T) {
	res := ValueResult{Key: "max_unsafe", Value: "168h", Source: "default"}
	for _, format := range []appcontracts.OutputFormat{appcontracts.FormatJSON, appcontracts.FormatText} {
		t.Run(string(format), func(t *testing.T) {
			r, err := NewValueRenderer(format)
			if err != nil {
				t.Fatalf("NewValueRenderer(%q) error: %v", format, err)
			}
			var buf bytes.Buffer
			if err := r.Render(&buf, res); err != nil {
				t.Fatalf("Render(%q) error: %v", format, err)
			}
			if buf.Len() == 0 {
				t.Fatalf("Render(%q) produced empty output", format)
			}
		})
	}
}

func TestMutationRenderers_Smoke(t *testing.T) {
	res := ValueResult{Key: "max_unsafe", Value: "168h", Path: "stave.yaml"}
	for _, format := range []appcontracts.OutputFormat{appcontracts.FormatJSON, appcontracts.FormatText} {
		t.Run(string(format), func(t *testing.T) {
			var stderr bytes.Buffer
			r, err := NewMutationRenderer(format, &stderr, "Set max_unsafe=168h in stave.yaml", MutationOpts{Format: format}, true)
			if err != nil {
				t.Fatalf("NewMutationRenderer(%q) error: %v", format, err)
			}
			var buf bytes.Buffer
			if err := r.Render(&buf, res); err != nil {
				t.Fatalf("Render(%q) error: %v", format, err)
			}
			if buf.Len() == 0 {
				t.Fatalf("Render(%q) produced empty output", format)
			}
		})
	}
}

func TestShowRenderers_Smoke(t *testing.T) {
	eval := appconfig.NewResolver(nil, "", nil, "")
	out := buildShowOutput(eval)
	for _, format := range []appcontracts.OutputFormat{appcontracts.FormatJSON, appcontracts.FormatText} {
		t.Run(string(format), func(t *testing.T) {
			r, err := NewShowRenderer(format)
			if err != nil {
				t.Fatalf("NewShowRenderer(%q) error: %v", format, err)
			}
			var buf bytes.Buffer
			if err := r.Render(&buf, out); err != nil {
				t.Fatalf("Render(%q) error: %v", format, err)
			}
			if buf.Len() == 0 {
				t.Fatalf("Render(%q) produced empty output", format)
			}
		})
	}
}
