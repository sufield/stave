package diag

import (
	"fmt"
	"strings"
)

// RawIssue is a generic adapter for third-party validation diagnostics.
// It allows the mapper to ingest errors from external libraries.
type RawIssue interface {
	Field() string
	Description() string
	Code() string
}

// FindingMapper converts external validation diagnostics into canonical security findings.
type FindingMapper struct {
	defaultRule        RuleID
	defaultRemediation string
	pathPrefix         string
}

// Option configures a FindingMapper during construction.
type Option func(*FindingMapper)

// WithDefaultRemediation sets a fallback remediation instruction for unmapped rules.
func WithDefaultRemediation(r string) Option {
	return func(m *FindingMapper) {
		m.defaultRemediation = strings.TrimSpace(r)
	}
}

// WithPathPrefix adds a context prefix (e.g., a filename) to the resource path.
func WithPathPrefix(prefix string) Option {
	return func(m *FindingMapper) {
		m.pathPrefix = strings.TrimSpace(prefix)
	}
}

var schemaViolationRules = map[string]struct{}{
	"required":              {},
	"type":                  {},
	"enum":                  {},
	"additional_properties": {},
}

var schemaRemediationByRule = map[string]func(string) string{
	"required":              requiredFieldRemediation,
	"type":                  expectedTypeRemediation,
	"enum":                  enumRemediation,
	"additional_properties": additionalPropertiesRemediation,
}

// NewMapper creates a normalizer that maps external issues to canonical RuleIDs.
func NewMapper(defaultRule RuleID, opts ...Option) *FindingMapper {
	rule := RuleID(strings.TrimSpace(string(defaultRule)))
	if rule == "" {
		rule = RuleSchemaViolation
	}
	m := &FindingMapper{defaultRule: rule}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Map converts a slice of external issues into a security Assessment.
func (m *FindingMapper) Map(rawIssues []RawIssue) *Assessment {
	assessment := NewAssessment()
	findings := make([]Finding, 0, len(rawIssues))
	for _, raw := range rawIssues {
		findings = append(findings, m.MapOne(raw))
	}
	assessment.RecordAll(findings)
	return assessment
}

// MapOne converts a single external diagnostic into a canonical Finding.
func (m *FindingMapper) MapOne(raw RawIssue) Finding {
	field := strings.TrimSpace(raw.Field())
	fullPath := field
	if m.pathPrefix != "" {
		if fullPath == "" {
			fullPath = m.pathPrefix
		} else {
			fullPath = fmt.Sprintf("%s: %s", m.pathPrefix, fullPath)
		}
	}

	extCode := strings.ToLower(strings.TrimSpace(raw.Code()))
	builder := NewFinding(m.mapRule(extCode)).
		Error().
		Message(strings.TrimSpace(raw.Description())).
		Remediation(m.deriveRemediation(extCode, field))
	if fullPath != "" {
		builder.Attribute("path", fullPath)
	}
	return builder.Build()
}

func (m *FindingMapper) mapRule(extCode string) RuleID {
	if _, ok := schemaViolationRules[extCode]; ok {
		return RuleSchemaViolation
	}
	return m.defaultRule
}

func (m *FindingMapper) deriveRemediation(extCode, field string) string {
	if builder, ok := schemaRemediationByRule[extCode]; ok {
		return builder(field)
	}
	if m.defaultRemediation != "" {
		return m.defaultRemediation
	}
	return "Correct the schema violation in your policy file."
}

// remediationTemplate pairs a field-specific format string with a fallback message.
type remediationTemplate struct {
	withField string // fmt template with one %s for the field name
	fallback  string // used when the field name is empty
}

func (t remediationTemplate) render(field string) string {
	if field != "" {
		return fmt.Sprintf(t.withField, field)
	}
	return t.fallback
}

var (
	remedyRequiredField      = remediationTemplate{"Add the missing field: %s", "Add the missing required field."}
	remedyExpectedType       = remediationTemplate{"Set %s to a value of the expected type.", "Use a value of the expected type."}
	remedyEnum               = remediationTemplate{"Set %s to one of the allowed values.", "Use one of the allowed values."}
	remedyAdditionalProperty = remediationTemplate{"Remove unsupported field: %s", "Remove unsupported fields from the payload."}
)

func requiredFieldRemediation(f string) string        { return remedyRequiredField.render(f) }
func expectedTypeRemediation(f string) string         { return remedyExpectedType.render(f) }
func enumRemediation(f string) string                 { return remedyEnum.render(f) }
func additionalPropertiesRemediation(f string) string { return remedyAdditionalProperty.render(f) }
