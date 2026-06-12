package stave

import (
	"encoding/json"
	"fmt"
	"io"

	appexempt "github.com/sufield/stave/internal/app/exempt"
	"github.com/sufield/stave/internal/app/exemptionsuggest"
)

// exemptHistoryRenderer renders the acknowledgment audit trail per format.
type exemptHistoryRenderer interface {
	Render(w io.Writer, entries []appexempt.AcknowledgmentEntry) error
}

type exemptHistoryJSONRenderer struct{}

func (exemptHistoryJSONRenderer) Render(w io.Writer, entries []appexempt.AcknowledgmentEntry) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(entries); err != nil {
		return fmt.Errorf("encode history JSON: %w", err)
	}
	return nil
}

type exemptHistoryTableRenderer struct{}

func (exemptHistoryTableRenderer) Render(w io.Writer, entries []appexempt.AcknowledgmentEntry) error {
	appexempt.WriteHistory(w, entries)
	return nil
}

func exemptNewHistoryRenderer(format string) (exemptHistoryRenderer, error) {
	switch format {
	case "json":
		return exemptHistoryJSONRenderer{}, nil
	case "table", "":
		return exemptHistoryTableRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: table, json)", format)
}

// exemptSuggestRenderer renders the exemption-suggestion result per format.
type exemptSuggestRenderer interface {
	Render(w io.Writer, result *exemptionsuggest.Result) error
}

type exemptSuggestJSONRenderer struct{}

func (exemptSuggestJSONRenderer) Render(w io.Writer, result *exemptionsuggest.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encode suggestions JSON: %w", err)
	}
	return nil
}

type exemptSuggestTableRenderer struct{}

func (exemptSuggestTableRenderer) Render(w io.Writer, result *exemptionsuggest.Result) error {
	return exemptWriteSuggestTable(w, result)
}

func exemptNewSuggestRenderer(format string) (exemptSuggestRenderer, error) {
	switch format {
	case "json":
		return exemptSuggestJSONRenderer{}, nil
	case "table", "":
		return exemptSuggestTableRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: table, json)", format)
}
