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
