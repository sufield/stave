package export

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/app/ticketexport"
)

func TestNewTicketsRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", ticketsJSONRenderer{}},
		{"csv", ticketsCSVRenderer{}},
		{"", ticketsJSONRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			r, err := NewTicketsRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewTicketsRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewTicketsRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestNewTicketsRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewTicketsRenderer("xml")
	if err == nil {
		t.Fatalf("NewTicketsRenderer(\"xml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("error should mention \"unknown format\", got: %q", err.Error())
	}
}

func TestTicketsRenderers_NonEmptyOutput(t *testing.T) {
	tickets := []ticketexport.Ticket{{TicketID: "T-1", Title: "example"}}
	cases := []struct {
		name     string
		renderer TicketsRenderer
	}{
		{"json", ticketsJSONRenderer{}},
		{"csv", ticketsCSVRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, tickets); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}
