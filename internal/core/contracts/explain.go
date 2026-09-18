package contracts

import (
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// ExplainRules is a domain collection of ExplainRule items with query and filter methods.
type ExplainRules []ExplainRule

// Len returns the number of explain rules in the collection.
func (er ExplainRules) Len() int {
	return len(er)
}

// ByPath returns a new ExplainRules collection filtered by field path.
func (er ExplainRules) ByPath(path string) ExplainRules {
	if len(er) == 0 {
		return nil
	}
	var filtered ExplainRules
	for i := range er {
		if er[i].Path == path {
			filtered = append(filtered, er[i])
		}
	}
	return filtered
}

// ByOp returns a new ExplainRules collection filtered by predicate operator.
func (er ExplainRules) ByOp(op predicate.Operator) ExplainRules {
	if len(er) == 0 {
		return nil
	}
	var filtered ExplainRules
	for i := range er {
		if er[i].Op == op {
			filtered = append(filtered, er[i])
		}
	}
	return filtered
}

// ExplainResult holds the structured output of an explain analysis.
type ExplainResult struct {
	ControlID          kernel.ControlID `json:"control_id"`
	Name               string           `json:"name"`
	Description        string           `json:"description"`
	Type               string           `json:"type"`
	MatchedFields      []string         `json:"matched_fields"`
	Rules              ExplainRules     `json:"rules"`
	MinimalObservation any              `json:"minimal_observation"`
}

// ExplainRule describes a single predicate rule.
type ExplainRule struct {
	Path    string             `json:"path"`
	Op      predicate.Operator `json:"op"`
	Value   any                `json:"value,omitempty"`
	From    string             `json:"from,omitempty"`
	Comment string             `json:"comment,omitempty"`
}
