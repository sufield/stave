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
	defaultCode   string
	defaultAction string
	pathPrefix    string
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

// NewTranslator creates a translator with a fallback canonical code.
func NewTranslator(defaultCode string) *Translator {
	code := strings.TrimSpace(defaultCode)
	if code == "" {
		code = CodeSchemaViolation
	}
	return &Translator{defaultCode: code}
}

// WithDefaultAction sets a fallback action for unmapped external error codes.
func (t *Translator) WithDefaultAction(action string) *Translator {
	t.defaultAction = strings.TrimSpace(action)
	return t
}

// WithPathPrefix adds a context prefix (for example file path) to translated paths.
func (t *Translator) WithPathPrefix(prefix string) *Translator {
	t.pathPrefix = strings.TrimSpace(prefix)
	return t
}

// Translate converts external diagnostics into a Result.
func (t *Translator) Translate(externalErrors []ExternalError) *Result {
	result := NewResult()
	for _, externalErr := range externalErrors {
		result.Add(t.TranslateOne(externalErr))
	}
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

func (t *Translator) mapCode(extCode string) string {
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

func requiredFieldAction(field string) string {
	return actionWithField(field, "Add the missing field: %s", "Add the missing required field.")
}

func expectedTypeAction(field string) string {
	return actionWithField(field, "Set %s to a value of the expected type.", "Use a value of the expected type.")
}

func enumAction(field string) string {
	return actionWithField(field, "Set %s to one of the allowed values.", "Use one of the allowed values.")
}

func additionalPropertiesAction(field string) string {
	return actionWithField(field, "Remove unsupported field: %s", "Remove unsupported fields from the payload.")
}

func actionWithField(field, withField, fallback string) string {
	if field != "" {
		return fmt.Sprintf(withField, field)
	}
	return fallback
}
