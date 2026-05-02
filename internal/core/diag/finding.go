package diag

import "github.com/sufield/stave/internal/core/kernel"

// DiagLevel defines the diagnostic risk level of a security finding.
// Renamed from "Severity" to disambiguate from controldef.Severity,
// which represents the criticality of a control (Low/Medium/High/
// Critical) rather than a diagnostic level (Info/Warning/Error).
type DiagLevel string

const (
	SeverityError DiagLevel = "ERROR"
	SeverityWarn  DiagLevel = "WARNING"
	SeverityInfo  DiagLevel = "INFO"
)

// Finding is the industry-standard representation of a security violation.
// It maps closely to formats like SARIF or AWS Security Finding Format (ASFF).
type Finding struct {
	RuleID      RuleID                `json:"rule_id"`
	Severity    DiagLevel             `json:"severity"`
	Message     string                `json:"message,omitempty"`
	Remediation string                `json:"remediation"`
	Resource    kernel.SanitizableMap `json:"resource"`
	FixCommand  string                `json:"fix_command,omitempty"`
}

// IsError reports whether this finding is recorded at the Error
// severity level. Replaces (f.Severity == SeverityError) probes in
// assessment.go's filter loop, app/lint, app/readiness, and the
// validate/handler renderer so callers branch on the predicate
// instead of repeating the constant comparison.
func (f Finding) IsError() bool {
	return f.Severity == SeverityError
}

// IsWarning reports whether this finding is recorded at the Warning
// severity level. Sibling of IsError; together they let
// Assessment.HasWarnings / Failed scans drop the inline constant
// compare.
func (f Finding) IsWarning() bool {
	return f.Severity == SeverityWarn
}

// HasSeverity reports whether the finding's severity equals sev.
// Generic accessor used by Assessment.filter so the package-private
// loop stops comparing fields directly.
func (f Finding) HasSeverity(sev DiagLevel) bool {
	return f.Severity == sev
}

// SeverityLabel returns the human-readable label a text renderer
// should display for this finding's severity. Centralises the
// (severity == SeverityError ? "ERROR" : "WARNING") branch so
// renderers stop reproducing the comparison and a future
// SeverityInfo / SeverityWarn split touches one place.
func (f Finding) SeverityLabel() string {
	switch f.Severity {
	case SeverityError:
		return "ERROR"
	case SeverityWarn:
		return "WARNING"
	case SeverityInfo:
		return "INFO"
	default:
		return string(f.Severity)
	}
}

// Builder provides a fluent API for constructing security findings.
type Builder struct {
	finding Finding
}

// NewFinding starts a new finding builder for a specific security rule.
func NewFinding(rule RuleID) *Builder {
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

// Message sets the human-readable explanation of the security violation.
func (b *Builder) Message(msg string) *Builder {
	b.finding.Message = msg
	return b
}

// Remediation provides a high-level description of how to resolve the finding.
func (b *Builder) Remediation(r string) *Builder {
	b.finding.Remediation = r
	return b
}

// FixCommand provides a specific CLI command the user can run to remediate the issue.
func (b *Builder) FixCommand(cmd string) *Builder {
	b.finding.FixCommand = cmd
	return b
}

// Attribute adds non-sensitive metadata to the resource.
func (b *Builder) Attribute(key, value string) *Builder {
	b.finding.Resource.Set(key, value)
	return b
}

// Attributes merges a map of non-sensitive resource metadata.
func (b *Builder) Attributes(values map[string]string) *Builder {
	for k, v := range values {
		b.finding.Resource.Set(k, v)
	}
	return b
}

// SensitiveAttribute adds metadata that should be redacted in logs but visible in reports.
func (b *Builder) SensitiveAttribute(key, value string) *Builder {
	b.finding.Resource.SetSensitive(key, value)
	return b
}

// Build returns the finalized Finding.
func (b *Builder) Build() Finding {
	f := b.finding
	f.Resource = b.finding.Resource.Clone()
	return f
}
