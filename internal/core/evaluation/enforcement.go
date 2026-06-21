package evaluation

// EnforcementLevel classifies the required response to a security evaluation.
type EnforcementLevel string

// Enforcement level constants.
const (
	LevelAllow    EnforcementLevel = "ALLOW"
	LevelAdvisory EnforcementLevel = "ADVISORY"
	LevelBlock    EnforcementLevel = "BLOCK"
)

// EnforcementOutcome describes the final decision made by the policy engine.
type EnforcementOutcome struct {
	Signal EnforcementLevel
}

// SummaryMessage returns the human-readable line a CLI handler
// should emit before applying its own hints / next-steps. Centralises
// the per-signal phrasing so a future message tweak is one edit.
// Returns "" for unrecognised signals.
func (o EnforcementOutcome) SummaryMessage() string {
	switch o.Signal {
	case LevelAllow:
		return "Evaluation complete. No violations found."
	case LevelAdvisory:
		return "Evaluation complete. No violations, but at-risk assets detected."
	case LevelBlock:
		return ""
	default:
		return ""
	}
}

// EnforcementPolicy defines the rules for how security states are translated
// into terminal actions (Allow/Block). StrictMode ensures that any resource
// not explicitly Compliant results in a Block signal.
type EnforcementPolicy struct {
	StrictMode bool
}

// Evaluate determines the appropriate EnforcementOutcome for a given SecurityState.
func (p EnforcementPolicy) Evaluate(state SecurityState) EnforcementOutcome {
	switch state {
	case StateCompliant:
		return EnforcementOutcome{Signal: LevelAllow}
	case StateAtRisk:
		if p.StrictMode {
			return EnforcementOutcome{Signal: LevelBlock}
		}
		return EnforcementOutcome{Signal: LevelAdvisory}
	default:
		return EnforcementOutcome{Signal: LevelBlock}
	}
}
