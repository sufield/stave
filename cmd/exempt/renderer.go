package exempt

import (
	"encoding/json"
	"fmt"
	"io"

	appexempt "github.com/sufield/stave/internal/app/exempt"
	"github.com/sufield/stave/internal/app/exemptionsuggest"
)

// `stave exempt` has two subcommands — history and suggest — that
// dispatch a different payload type per format. Each gets its own
// Renderer interface keyed by the payload it renders; the factories
// share the format-string contract but the concrete types and
// dispatch tables are per-mode. Same multi-payload shape as cmd/nep.
//
// The renderers cover only the json-vs-table dispatch. The "no
// history" / "no suggestions" early-return guards stay in the
// calling sites because they short-circuit before any format
// selection — they are not a format choice.

// --- HistoryRenderer ---

// HistoryRenderer renders the acknowledgment audit trail.
type HistoryRenderer interface {
	Render(w io.Writer, entries []appexempt.AcknowledgmentEntry) error
}

// HistoryJSONRenderer encodes the history entries as indented JSON.
type HistoryJSONRenderer struct{}

// Render implements HistoryRenderer.
func (HistoryJSONRenderer) Render(w io.Writer, entries []appexempt.AcknowledgmentEntry) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(entries); err != nil {
		return fmt.Errorf("encode history JSON: %w", err)
	}
	return nil
}

// HistoryTableRenderer writes the default human-readable table.
type HistoryTableRenderer struct{}

// Render implements HistoryRenderer.
func (HistoryTableRenderer) Render(w io.Writer, entries []appexempt.AcknowledgmentEntry) error {
	appexempt.WriteHistory(w, entries)
	return nil
}

// NewHistoryRenderer maps a format string to its concrete renderer.
func NewHistoryRenderer(format string) (HistoryRenderer, error) {
	switch format {
	case "json":
		return HistoryJSONRenderer{}, nil
	case "table", "":
		return HistoryTableRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: table, json)", format)
}

// --- SuggestRenderer ---

// SuggestRenderer renders the exemption-suggestion result.
type SuggestRenderer interface {
	Render(w io.Writer, result *exemptionsuggest.Result) error
}

// SuggestJSONRenderer encodes the suggestion result as indented JSON.
type SuggestJSONRenderer struct{}

// Render implements SuggestRenderer.
func (SuggestJSONRenderer) Render(w io.Writer, result *exemptionsuggest.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encode suggestions JSON: %w", err)
	}
	return nil
}

// SuggestTableRenderer writes the default human-readable table.
type SuggestTableRenderer struct{}

// Render implements SuggestRenderer.
func (SuggestTableRenderer) Render(w io.Writer, result *exemptionsuggest.Result) error {
	return writeSuggestTable(w, result)
}

// NewSuggestRenderer maps a format string to its concrete renderer.
func NewSuggestRenderer(format string) (SuggestRenderer, error) {
	switch format {
	case "json":
		return SuggestJSONRenderer{}, nil
	case "table", "":
		return SuggestTableRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: table, json)", format)
}
