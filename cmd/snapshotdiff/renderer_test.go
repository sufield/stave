package snapshotdiff

import (
	"bytes"
	"strings"
	"testing"

	appdiff "github.com/sufield/stave/internal/app/catalogdiff"
	"github.com/sufield/stave/internal/app/snapshotdiff"
)

// --- CatalogRenderer ---

func TestNewCatalogRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", CatalogJSONRenderer{}},
		{"table", CatalogTableRenderer{}},
		{"", CatalogTableRenderer{}},
	}
	for _, tc := range cases {
		r, err := NewCatalogRenderer(tc.format)
		if err != nil {
			t.Errorf("NewCatalogRenderer(%q): %v", tc.format, err)
			continue
		}
		if r != tc.want {
			t.Errorf("got %T, want %T", r, tc.want)
		}
	}
}

func TestNewCatalogRenderer_UnknownFormatErrors(t *testing.T) {
	if _, err := NewCatalogRenderer("xml"); err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected unsupported-format error, got: %v", err)
	}
}

func TestCatalogRenderers_NonEmptyOutput(t *testing.T) {
	delta := &appdiff.Delta{}
	for _, r := range []CatalogRenderer{CatalogJSONRenderer{}, CatalogTableRenderer{}} {
		var buf bytes.Buffer
		if err := r.Render(&buf, delta); err != nil {
			t.Errorf("%T.Render: %v", r, err)
		}
		if buf.Len() == 0 {
			t.Errorf("%T produced empty output", r)
		}
	}
}

// --- SnapshotRenderer ---

func TestNewSnapshotRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", SnapshotJSONRenderer{}},
		{"table", SnapshotTextRenderer{}},
		{"", SnapshotTextRenderer{}},
	}
	for _, tc := range cases {
		r, err := NewSnapshotRenderer(tc.format)
		if err != nil {
			t.Errorf("NewSnapshotRenderer(%q): %v", tc.format, err)
			continue
		}
		if r != tc.want {
			t.Errorf("got %T, want %T", r, tc.want)
		}
	}
}

func TestNewSnapshotRenderer_UnknownFormatErrors(t *testing.T) {
	if _, err := NewSnapshotRenderer("xml"); err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected unsupported-format error, got: %v", err)
	}
}

func TestSnapshotRenderers_NonEmptyOutput(t *testing.T) {
	result := &snapshotdiff.DiffResult{}
	for _, r := range []SnapshotRenderer{SnapshotJSONRenderer{}, SnapshotTextRenderer{}} {
		var buf bytes.Buffer
		if err := r.Render(&buf, result); err != nil {
			t.Errorf("%T.Render: %v", r, err)
		}
		if buf.Len() == 0 {
			t.Errorf("%T produced empty output", r)
		}
	}
}
