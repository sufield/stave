package diag

import "github.com/sufield/stave/internal/core/kernel"

// Signal defines the severity of a diagnostic issue.
type Signal string

const (
	SignalError Signal = "error"
	SignalWarn  Signal = "warning"
	SignalInfo  Signal = "info"
)

// Issue is the canonical diagnostic finding shape across validation flows.
type Issue struct {
	Code     Code                  `json:"code"`
	Signal   Signal                `json:"signal"`
	Message  string                `json:"message,omitempty"`
	Action   string                `json:"action"`
	Evidence kernel.SanitizableMap `json:"evidence"`
	Command  string                `json:"command,omitempty"`
}

// Builder provides fluent issue construction.
type Builder struct {
	issue Issue
}

// New starts a new issue builder with a required code.
func New(code Code) *Builder {
	return &Builder{
		issue: Issue{
			Code:     code,
			Signal:   SignalError,
			Evidence: kernel.NewSanitizableMap(nil),
		},
	}
}

// Error sets the issue signal to error severity.
func (b *Builder) Error() *Builder {
	b.issue.Signal = SignalError
	return b
}

// Warning sets the issue signal to warning severity.
func (b *Builder) Warning() *Builder {
	b.issue.Signal = SignalWarn
	return b
}

// Msg sets the human-readable issue message.
func (b *Builder) Msg(message string) *Builder {
	b.issue.Message = message
	return b
}

// Action sets the recommended remediation action.
func (b *Builder) Action(action string) *Builder {
	b.issue.Action = action
	return b
}

// Command sets the suggested CLI command to resolve the issue.
func (b *Builder) Command(command string) *Builder {
	b.issue.Command = command
	return b
}

// With adds a non-sensitive evidence entry.
func (b *Builder) With(key, value string) *Builder {
	b.issue.Evidence.Set(key, value)
	return b
}

// WithMap merges non-sensitive evidence entries.
func (b *Builder) WithMap(values map[string]string) *Builder {
	for key, value := range values {
		b.issue.Evidence.Set(key, value)
	}
	return b
}

// WithSensitive adds a sensitive evidence entry.
func (b *Builder) WithSensitive(key, value string) *Builder {
	b.issue.Evidence.SetSensitive(key, value)
	return b
}

// Build returns the finalized issue.
func (b *Builder) Build() Issue {
	issue := b.issue
	issue.Evidence = b.issue.Evidence.Clone()
	return issue
}
