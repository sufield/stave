package diag

import "github.com/sufield/stave/internal/core/kernel"

// Severity defines the severity of a security finding.
type Severity string

// Finding severity levels.
const (
	SeverityError Severity = "error"
	SeverityWarn  Severity = "warning"
	SeverityInfo  Severity = "info"
)

// Finding is the canonical security finding shape across validation flows.
type Finding struct {
	RuleID   RuleID                `json:"rule_id"`
	Severity Severity              `json:"severity"`
	Message  string                `json:"message,omitempty"`
	Action   string                `json:"action"`
	Resource kernel.SanitizableMap `json:"resource"`
	Command  string                `json:"command,omitempty"`
}

// Builder provides fluent finding construction.
type Builder struct {
	finding Finding
}

// New starts a new finding builder with a required rule ID.
func New(rule RuleID) *Builder {
	return &Builder{
		finding: Finding{
			RuleID:   rule,
			Severity: SeverityError,
			Resource: kernel.NewSanitizableMap(nil),
		},
	}
}

// Error sets the finding severity to error.
func (b *Builder) Error() *Builder {
	b.finding.Severity = SeverityError
	return b
}

// Warning sets the finding severity to warning.
func (b *Builder) Warning() *Builder {
	b.finding.Severity = SeverityWarn
	return b
}

// Msg sets the human-readable finding message.
func (b *Builder) Msg(message string) *Builder {
	b.finding.Message = message
	return b
}

// Action sets the recommended remediation action.
func (b *Builder) Action(action string) *Builder {
	b.finding.Action = action
	return b
}

// Command sets the suggested CLI command to resolve the finding.
func (b *Builder) Command(command string) *Builder {
	b.finding.Command = command
	return b
}

// With adds a non-sensitive resource entry.
func (b *Builder) With(key, value string) *Builder {
	b.finding.Resource.Set(key, value)
	return b
}

// WithMap merges non-sensitive resource entries.
func (b *Builder) WithMap(values map[string]string) *Builder {
	for key, value := range values {
		b.finding.Resource.Set(key, value)
	}
	return b
}

// WithSensitive adds a sensitive resource entry.
func (b *Builder) WithSensitive(key, value string) *Builder {
	b.finding.Resource.SetSensitive(key, value)
	return b
}

// Build returns the finalized finding.
func (b *Builder) Build() Finding {
	finding := b.finding
	finding.Resource = b.finding.Resource.Clone()
	return finding
}
