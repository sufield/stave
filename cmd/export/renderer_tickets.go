package export

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/app/ticketexport"
)

// TicketsRenderer is the polymorphic format-dispatch interface for
// `stave export tickets`. Concrete implementations delegate to
// writeTicketsCSV / encoding/json so the rendered bytes are
// byte-identical to the pre-Renderer-pattern output.
//
// New formats add an implementation here and a factory case in
// NewTicketsRenderer.
type TicketsRenderer interface {
	Render(w io.Writer, tickets []ticketexport.Ticket) error
}

// ticketsJSONRenderer encodes tickets as indented JSON.
type ticketsJSONRenderer struct{}

// Render implements TicketsRenderer.
func (ticketsJSONRenderer) Render(w io.Writer, tickets []ticketexport.Ticket) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(tickets)
}

// ticketsCSVRenderer writes tickets as CSV.
type ticketsCSVRenderer struct{}

// Render implements TicketsRenderer.
func (ticketsCSVRenderer) Render(w io.Writer, tickets []ticketexport.Ticket) error {
	return writeTicketsCSV(w, tickets)
}

// NewTicketsRenderer maps a format string to its concrete
// TicketsRenderer. Returns an error for unknown formats; the previous
// switch defaulted to JSON only for the empty/json case, so this
// surfaces unknown formats explicitly through the factory.
func NewTicketsRenderer(format string) (TicketsRenderer, error) {
	switch format {
	case "csv":
		return ticketsCSVRenderer{}, nil
	case "json", "":
		return ticketsJSONRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: json, csv)", format)
}
