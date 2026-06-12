package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

// GovernanceSettings is the set of top-level audit parameters exposed to the CLI.
var GovernanceSettings = discoverGovernanceSettings()

// discoverGovernanceSettings walks WorkspacePolicy and returns the
// yaml-tag names of every field carrying `governance:"include"`. The
// opt-in tag replaces a Kind-based heuristic that exposed every
// scalar field automatically — that shape silently widened the
// settings surface as new internal scalars landed and silently
// dropped fields that switched from string to a typed wrapper. The
// explicit tag makes governance membership a deliberate decision at
// the field site.
func discoverGovernanceSettings() []string {
	t := reflect.TypeFor[WorkspacePolicy]()
	var settings []string
	for f := range t.Fields() {
		if f.Tag.Get("governance") != "include" {
			continue
		}
		tag, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if tag == "" || tag == "-" {
			continue
		}
		settings = append(settings, tag)
	}
	return settings
}

// SettingPath represents a validated reference to an audit configuration attribute.
type SettingPath struct {
	Attribute string
	Raw       string
}

// IdentifySetting parses and validates a raw string into a structured SettingPath.
func IdentifySetting(raw string) (SettingPath, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return SettingPath{}, errors.New("governance setting name cannot be empty")
	}

	if slices.Contains(GovernanceSettings, raw) {
		return SettingPath{Attribute: raw, Raw: raw}, nil
	}
	return SettingPath{}, fmt.Errorf("unsupported audit setting %q", raw)
}

// GetAttribute retrieves the current value of a governance setting.
func GetAttribute(cfg *WorkspacePolicy, name string) (string, bool) {
	if cfg == nil {
		return "", false
	}
	field, ok := fieldByYAMLTag(reflect.ValueOf(cfg).Elem(), name)
	if !ok {
		return "", false
	}
	return fmt.Sprint(field.Interface()), true
}

// UpdateAttribute validates and applies a change to a governance setting.
//
// On validation failure the field is restored to its pre-update value
// (snapshot taken before the type-specific assignment) so a rejected
// value does not leave the field zeroed — the earlier shape called
// reflect.Zero on the field which silently corrupted the policy.
func UpdateAttribute(cfg *WorkspacePolicy, name, value string) error {
	if cfg == nil {
		return errors.New("governance: nil WorkspacePolicy")
	}
	field, ok := fieldByYAMLTag(reflect.ValueOf(cfg).Elem(), name)
	if !ok {
		return fmt.Errorf("unknown governance setting: %s", name)
	}

	// Snapshot the original so we can restore on validation error.
	// reflect.Value carries an internal flag for addressability; the
	// snapshot value itself is a copy and is safe to keep across the
	// mutation that follows.
	original := reflect.New(field.Type()).Elem()
	original.Set(field)

	if field.Kind() == reflect.String {
		field.Set(reflect.ValueOf(value).Convert(field.Type()))
	} else {
		tmp := reflect.New(field.Type())
		if err := json.Unmarshal([]byte(value), tmp.Interface()); err != nil {
			return fmt.Errorf("invalid value %q for %s: %w", value, name, err)
		}
		field.Set(tmp.Elem())
	}

	fieldName := structFieldNameByYAMLTag(cfg, name)
	if fieldName != "" {
		if err := validateAuditSetting(cfg, fieldName); err != nil {
			field.Set(original)
			return fmt.Errorf("invalid value %q for %s: %w", value, name, err)
		}
	}
	return nil
}

func validateAuditSetting(cfg *WorkspacePolicy, fieldName string) error {
	switch fieldName {
	case "MaxUnsafe":
		return validateDuration(cfg.MaxUnsafe, "max_unsafe")
	case "CIFailurePolicy":
		return validateEnforcementGate(cfg.CIFailurePolicy)
	case "CaptureCadence":
		return validateFrequency(cfg.CaptureCadence)
	case "SnapshotFilenameTemplate":
		return validateNonEmpty(cfg.SnapshotFilenameTemplate, "snapshot_filename_template")
	}
	return nil
}

func validateDuration(v, name string) error {
	if v == "" {
		return nil
	}
	if _, err := kernel.ParseDuration(v); err != nil {
		return fmt.Errorf("invalid %s duration: %w", name, err)
	}
	return nil
}

func validateEnforcementGate(v string) error {
	if v == "" {
		return nil
	}
	if _, err := ParseEnforcementGate(v); err != nil {
		return fmt.Errorf("invalid ci_failure_policy: %w", err)
	}
	return nil
}

func validateFrequency(v string) error {
	if v == "" {
		return nil
	}
	if v != "daily" && v != "hourly" {
		return fmt.Errorf("capture_cadence must be 'daily' or 'hourly', got %q", v)
	}
	return nil
}

func validateNonEmpty(v, name string) error {
	if v == "" {
		return nil
	}
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("%s must not be blank", name)
	}
	return nil
}

// ResetAttribute restores a governance setting to its zero/default state.
func ResetAttribute(cfg *WorkspacePolicy, name string) error {
	field, ok := fieldByYAMLTag(reflect.ValueOf(cfg).Elem(), name)
	if !ok {
		return fmt.Errorf("unknown governance setting: %s", name)
	}
	field.Set(reflect.Zero(field.Type()))
	return nil
}

// attributeResolvers maps audit settings to their evaluation logic.
var attributeResolvers = map[string]func(*GovernanceResolver) PolicyValue[string]{
	"max_unsafe":        (*GovernanceResolver).ResolveMaxUnsafeDuration,
	"ci_failure_policy": (*GovernanceResolver).ResolveCIFailurePolicy,
	"cli_output":        (*GovernanceResolver).ResolveCLIOutput,
	"cli_path_mode":     (*GovernanceResolver).ResolveCLIPathMode,
}

// ResolveAuditSetting uses the GovernanceResolver to determine the effective value
// of a governance setting.
func ResolveAuditSetting(eval *GovernanceResolver, name string) (PolicyValue[string], bool) {
	resolver, ok := attributeResolvers[name]
	if !ok {
		return PolicyValue[string]{}, false
	}
	return resolver(eval), true
}

// BuildSettingCompletions generates shell completion strings for governance settings.
func BuildSettingCompletions() []string {
	completions := make([]string, 0, len(GovernanceSettings))
	completions = append(completions, GovernanceSettings...)
	return completions
}

// --- Reflection helpers ---

func fieldByYAMLTag(v reflect.Value, tag string) (reflect.Value, bool) {
	t := v.Type()
	for i := range t.NumField() {
		yamlTag, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
		if yamlTag == tag {
			return v.Field(i), true
		}
	}
	return reflect.Value{}, false
}

func structFieldNameByYAMLTag(_ *WorkspacePolicy, yamlKey string) string {
	t := reflect.TypeFor[WorkspacePolicy]()
	for field := range t.Fields() {
		tag, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		if tag == yamlKey {
			return field.Name
		}
	}
	return ""
}
