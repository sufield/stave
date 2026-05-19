package consolidate

import (
	"bytes"
	"strings"
	"testing"

	appconsolidate "github.com/sufield/stave/internal/app/consolidate"
	"github.com/sufield/stave/internal/app/orgtrend"
	"github.com/sufield/stave/internal/app/outlieranalysis"
)

// --- ConsolidatedRenderer ---

func TestNewConsolidatedRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		focus  string
	}{
		{"json", "111122223333"},
		{"table", "111122223333"},
		{"", ""},
	}
	for _, tc := range cases {
		name := tc.format
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			r, err := NewConsolidatedRenderer(tc.format, tc.focus)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			switch tc.format {
			case "json":
				if _, ok := r.(ConsolidatedJSONRenderer); !ok {
					t.Errorf("got %T, want ConsolidatedJSONRenderer", r)
				}
			default:
				got, ok := r.(ConsolidatedTextRenderer)
				if !ok {
					t.Errorf("got %T, want ConsolidatedTextRenderer", r)
					return
				}
				if got.FocusAccount != tc.focus {
					t.Errorf("FocusAccount: got %q, want %q", got.FocusAccount, tc.focus)
				}
			}
		})
	}
}

func TestNewConsolidatedRenderer_UnknownFormatErrors(t *testing.T) {
	if _, err := NewConsolidatedRenderer("xml", ""); err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected unsupported-format error, got: %v", err)
	}
}

func TestConsolidatedRenderers_NonEmptyOutput(t *testing.T) {
	rep := &appconsolidate.ConsolidatedReport{}
	for _, r := range []ConsolidatedRenderer{ConsolidatedJSONRenderer{}, ConsolidatedTextRenderer{}} {
		var buf bytes.Buffer
		if err := r.Render(&buf, rep); err != nil {
			t.Errorf("%T.Render: %v", r, err)
		}
		if buf.Len() == 0 {
			t.Errorf("%T produced empty output", r)
		}
	}
}

// --- DiffRenderer ---

func TestNewDiffRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", DiffJSONRenderer{}},
		{"table", DiffTableRenderer{}},
		{"", DiffTableRenderer{}},
	}
	for _, tc := range cases {
		r, err := NewDiffRenderer(tc.format)
		if err != nil {
			t.Errorf("NewDiffRenderer(%q): %v", tc.format, err)
			continue
		}
		if r != tc.want {
			t.Errorf("NewDiffRenderer(%q) = %T, want %T", tc.format, r, tc.want)
		}
	}
}

func TestNewDiffRenderer_UnknownFormatErrors(t *testing.T) {
	if _, err := NewDiffRenderer("xml"); err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected unsupported-format error, got: %v", err)
	}
}

func TestDiffRenderers_NonEmptyOutput(t *testing.T) {
	rep := outlieranalysis.OutlierReport{ControlID: "CTL.A.001"}
	for _, r := range []DiffRenderer{DiffJSONRenderer{}, DiffTableRenderer{}} {
		var buf bytes.Buffer
		if err := r.Render(&buf, rep); err != nil {
			t.Errorf("%T.Render: %v", r, err)
		}
		if buf.Len() == 0 {
			t.Errorf("%T produced empty output", r)
		}
	}
}

// --- HistoryRenderer ---

func TestNewHistoryRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", HistoryJSONRenderer{}},
		{"markdown", HistoryMarkdownRenderer{}},
		{"table", HistoryTableRenderer{}},
		{"", HistoryTableRenderer{}},
	}
	for _, tc := range cases {
		r, err := NewHistoryRenderer(tc.format)
		if err != nil {
			t.Errorf("NewHistoryRenderer(%q): %v", tc.format, err)
			continue
		}
		if r != tc.want {
			t.Errorf("NewHistoryRenderer(%q) = %T, want %T", tc.format, r, tc.want)
		}
	}
}

func TestNewHistoryRenderer_UnknownFormatErrors(t *testing.T) {
	if _, err := NewHistoryRenderer("xml"); err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected unsupported-format error, got: %v", err)
	}
}

func TestHistoryRenderers_NonEmptyOutput(t *testing.T) {
	rep := &orgtrend.OrgTrendReport{}
	for _, r := range []HistoryRenderer{HistoryJSONRenderer{}, HistoryMarkdownRenderer{}, HistoryTableRenderer{}} {
		var buf bytes.Buffer
		if err := r.Render(&buf, rep); err != nil {
			t.Errorf("%T.Render: %v", r, err)
		}
		if buf.Len() == 0 {
			t.Errorf("%T produced empty output", r)
		}
	}
}
