package contracts

import "github.com/sufield/stave/internal/domain/predicate"

// ExplainResult holds the structured output of an explain analysis.
type ExplainResult struct {
	ControlID          string        `json:"control_id"`
	Name               string        `json:"name"`
	Description        string        `json:"description"`
	Type               string        `json:"type"`
	MatchedFields      []string      `json:"matched_fields"`
	Rules              []ExplainRule `json:"rules"`
	MinimalObservation any           `json:"minimal_observation"`
}

// ExplainRule describes a single predicate rule.
type ExplainRule struct {
	Path    string             `json:"path"`
	Op      predicate.Operator `json:"op"`
	Value   any                `json:"value,omitempty"`
	From    string             `json:"from,omitempty"`
	Comment string             `json:"comment,omitempty"`
}
