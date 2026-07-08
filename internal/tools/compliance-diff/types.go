package main

import "github.com/sufield/stave/internal/adapters/compliance"

// DiffReport holds the full diff result for one framework.
type DiffReport struct {
	Framework string        `json:"framework"`
	Version   string        `json:"version,omitempty"`
	Source    string        `json:"source,omitempty"`
	Results   []MatchResult `json:"results"`
	Summary   Summary       `json:"summary"`
}

// MatchResult holds the match outcome for one check.
type MatchResult struct {
	Check      compliance.Check `json:"check"`
	Status     string           `json:"status"` // covered | partial | gap | out_of_scope
	ControlIDs []string         `json:"control_ids,omitempty"`
	Confidence string           `json:"confidence,omitempty"` // exact | keyword
	Notes      string           `json:"notes,omitempty"`
}

// Summary holds aggregate counts.
type Summary struct {
	Total      int `json:"total"`
	InScope    int `json:"in_scope"`
	OutOfScope int `json:"out_of_scope"`
	Covered    int `json:"covered"`
	Partial    int `json:"partial"`
	Gap        int `json:"gap"`
}

func (r *DiffReport) computeSummary() {
	for _, m := range r.Results {
		r.Summary.Total++
		switch m.Status {
		case "covered":
			r.Summary.InScope++
			r.Summary.Covered++
		case "partial":
			r.Summary.InScope++
			r.Summary.Partial++
		case "gap":
			r.Summary.InScope++
			r.Summary.Gap++
		case "out_of_scope":
			r.Summary.OutOfScope++
		}
	}
}
