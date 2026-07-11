package template

// Template is a JTBD bundle — everything needed to run a specific
// security assessment job.
type Template struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`

	RecommendWhen RecommendWhen `yaml:"recommend_when"`
	Parameters    []Parameter   `yaml:"parameters"`
	Scope         Scope         `yaml:"scope"`
	Controls      Selection     `yaml:"controls"`
	Chains        Selection     `yaml:"chains"`
	Runbook       Runbook       `yaml:"runbook"`
	Fixture       Fixture       `yaml:"fixture"`
}

type Metadata struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Job         string `yaml:"job"`
	Version     string `yaml:"version"`
}

type RecommendWhen struct {
	Predicate string `yaml:"predicate"`
	Priority  int    `yaml:"priority"`
}

type Parameter struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Type        string   `yaml:"type"`
	Required    bool     `yaml:"required"`
	Default     any      `yaml:"default"`
	Options     []string `yaml:"options"`
}

type Scope struct {
	Services []string `yaml:"services"`
}

type Selection struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

type Runbook struct {
	Steps []Step `yaml:"steps"`
}

type Step struct {
	Action      string            `yaml:"action"`
	Description string            `yaml:"description"`
	Args        map[string]string `yaml:"args"`
	When        string            `yaml:"when,omitempty"`
}

type Fixture struct {
	Snapshot         string   `yaml:"snapshot"`
	ExpectedFindings string   `yaml:"expected_findings"`
	MatchKeys        []string `yaml:"match_keys"`
}
