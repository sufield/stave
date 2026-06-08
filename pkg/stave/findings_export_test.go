package stave

import (
	"errors"
	"testing"
	"time"
)

// These exercise the findings-export facade functions that absorbed the
// cmd/export subcommand pipelines (ocsf/oscal/changes/tickets).

func TestExportTickets_Formats(t *testing.T) {
	data := []byte(`{"findings":[]}`)
	for _, format := range []string{"json", "csv", ""} {
		out, err := ExportTickets(data, "", "", format)
		if err != nil {
			t.Fatalf("ExportTickets(%q): unexpected error: %v", format, err)
		}
		if len(out) == 0 {
			t.Errorf("ExportTickets(%q): produced empty output", format)
		}
	}
}

func TestExportTickets_UnknownFormat(t *testing.T) {
	_, err := ExportTickets([]byte(`{"findings":[]}`), "", "", "xml")
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("unknown format should wrap ErrInvalidInput, got: %v", err)
	}
}

func TestExport_ParseErrorWrapsInvalidInput(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := map[string]func() error{
		"ocsf":    func() error { _, e := ExportOCSF([]byte("not json")); return e },
		"oscal":   func() error { _, e := ExportOSCAL([]byte("not json"), "", "", now); return e },
		"changes": func() error { _, e := ExportChanges([]byte("not json"), 0, now); return e },
		"tickets": func() error { _, e := ExportTickets([]byte("not json"), "", "", "json"); return e },
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			err := fn()
			if err == nil {
				t.Fatal("expected parse error")
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("parse error should wrap ErrInvalidInput, got: %v", err)
			}
		})
	}
}

func TestExportOSCAL_SSPNotImplemented(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := ExportOSCAL([]byte(`{"findings":[]}`), "ssp", "", now)
	if err == nil {
		t.Fatal("expected error for ssp")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("ssp stub should wrap ErrInvalidInput, got: %v", err)
	}
}

func TestExportOCSFAndChangesAndOSCAL_NonEmpty(t *testing.T) {
	data := []byte(`{"findings":[]}`)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if out, err := ExportOSCAL(data, "assessment-results", "", now); err != nil || len(out) == 0 {
		t.Errorf("ExportOSCAL: out=%d err=%v", len(out), err)
	}
	if out, err := ExportChanges(data, 0, now); err != nil || len(out) == 0 {
		t.Errorf("ExportChanges: out=%d err=%v", len(out), err)
	}
	// OCSF over zero findings yields zero NDJSON lines (empty output) — that
	// is valid; just assert no error.
	if _, err := ExportOCSF(data); err != nil {
		t.Errorf("ExportOCSF: %v", err)
	}
}
