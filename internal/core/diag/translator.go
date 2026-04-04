package diag

import (
	"fmt"
	"strings"
)

// ExternalError is a generic adapter for third-party validation diagnostics.
type ExternalError interface {
	Field() string
	Description() string
	Code() string
}

// Translator converts external validation diagnostics into canonical issues.
type Translator struct {
	defaultCode   Code
	defaultAction string
	pathPrefix    string
}

// Option configures a Translator during construction.
type Option func(*Translator)

// WithDefaultAction returns an Option that sets a fallback action for unmapped codes.
func WithDefaultAction(action string) Option {
	return func(t *Translator) {
		t.defaultAction = strings.TrimSpace(action)
	}
}

// WithPathPrefix returns an Option that adds a context prefix to translated paths.
func WithPathPrefix(prefix string) Option {
	return func(t *Translator) {
		t.pathPrefix = strings.TrimSpace(prefix)
	}
}

var schemaViolationCodes = map[string]struct{}{
	"required":              {},
	"type":                  {},
	"enum":                  {},
	"additional_properties": {},
}

var schemaActionByCode = map[string]func(string) string{
	"required":              requiredFieldAction,
	"type":                  expectedTypeAction,
	"enum":                  enumAction,
	"additional_properties": additionalPropertiesAction,
}

// NewTranslator creates a translator with a fallback canonical code and optional configuration.
func NewTranslator(defaultCode Code, opts ...Option) *Translator {
	code := Code(strings.TrimSpace(string(defaultCode)))
	if code == "" {
		code = CodeSchemaViolation
	}
	t := &Translator{defaultCode: code}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

// Translate converts external diagnostics into a Result.
func (t *Translator) Translate(externalErrors []ExternalError) *Result {
	result := NewResult()
	issues := make([]Issue, 0, len(externalErrors))
	for _, externalErr := range externalErrors {
		issues = append(issues, t.TranslateOne(externalErr))
	}
	result.AddAll(issues)
	return result
}

// TranslateOne converts one external diagnostic into a canonical issue.
func (t *Translator) TranslateOne(externalErr ExternalError) Issue {
	field := strings.TrimSpace(externalErr.Field())
	fullPath := field
	if t.pathPrefix != "" {
		if fullPath == "" {
			fullPath = t.pathPrefix
		} else {
			fullPath = fmt.Sprintf("%s: %s", t.pathPrefix, fullPath)
		}
	}

	extCode := strings.ToLower(strings.TrimSpace(externalErr.Code()))
	builder := New(t.mapCode(extCode)).
		Error().
		Msg(strings.TrimSpace(externalErr.Description())).
		Action(t.deriveAction(extCode, field))
	if fullPath != "" {
		builder.With("path", fullPath)
	}
	return builder.Build()
}

func (t *Translator) mapCode(extCode string) Code {
	if _, ok := schemaViolationCodes[extCode]; ok {
		return CodeSchemaViolation
	}
	return t.defaultCode
}

func (t *Translator) deriveAction(extCode, field string) string {
	if builder, ok := schemaActionByCode[extCode]; ok {
		return builder(field)
	}
	if t.defaultAction != "" {
		return t.defaultAction
	}
	return "Correct the schema violation in your YAML/JSON file."
}

// actionTemplate pairs a field-specific format string with a fallback message.
type actionTemplate struct {
	withField string // fmt template with one %s for the field name
	fallback  string // used when the field name is empty
}

func (t actionTemplate) render(field string) string {
	if field != "" {
		return fmt.Sprintf(t.withField, field)
	}
	return t.fallback
}

var (
	actionRequiredField      = actionTemplate{"Add the missing field: %s", "Add the missing required field."}
	actionExpectedType       = actionTemplate{"Set %s to a value of the expected type.", "Use a value of the expected type."}
	actionEnum               = actionTemplate{"Set %s to one of the allowed values.", "Use one of the allowed values."}
	actionAdditionalProperty = actionTemplate{"Remove unsupported field: %s", "Remove unsupported fields from the payload."}
)

func requiredFieldAction(field string) string        { return actionRequiredField.render(field) }
func expectedTypeAction(field string) string         { return actionExpectedType.render(field) }
func enumAction(field string) string                 { return actionEnum.render(field) }
func additionalPropertiesAction(field string) string { return actionAdditionalProperty.render(field) }
