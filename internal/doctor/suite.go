package doctor

import (
	"slices"
)

// DiagnosticSuite maintains an ordered collection of environment probes.
type DiagnosticSuite struct {
	probes []Probe
}

// NewSuite creates a new DiagnosticSuite from the provided probe functions.
func NewSuite(probes ...Probe) *DiagnosticSuite {
	return &DiagnosticSuite{
		probes: slices.Clone(probes),
	}
}

// Execute runs all probes in the suite against the current system environment.
// It returns a list of diagnostics and a boolean indicating if the environment
// is ready (true if no status is outcome.Fail).
func (s *DiagnosticSuite) Execute(env *SystemEnvironment) ([]Diagnostic, bool) {
	if s == nil || len(s.probes) == 0 {
		return nil, true
	}

	if env == nil {
		env = NewEnvironment()
	}
	env.FillDefaults()

	results := make([]Diagnostic, 0, len(s.probes))
	isReady := true

	for _, probe := range s.probes {
		res := probe(env)

		if res.Name == "" {
			continue
		}

		if res.IsFailure() {
			isReady = false
		}

		results = append(results, res)
	}

	return results, isReady
}
