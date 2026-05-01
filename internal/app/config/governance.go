package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/retention"
)

// GovernanceSettings is the set of top-level audit parameters exposed to the CLI.
var GovernanceSettings = discoverGovernanceSettings()

func discoverGovernanceSettings() []string {
	t := reflect.TypeFor[WorkspacePolicy]()
	var settings []string
	for f := range t.Fields() {
		tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		switch f.Type.Kind() {
		case reflect.String, reflect.Bool, reflect.Int, reflect.Float64:
			settings = append(settings, tag)
		}
	}
	return settings
}

// RetentionPrefix is the key prefix for snapshot lifecycle tier configuration.
const RetentionPrefix = "snapshot_retention_tiers."

// SettingPath represents a validated reference to an audit configuration attribute.
type SettingPath struct {
	Attribute string
	TierName  string
	Property  string
	Raw       string
}

// IdentifySetting parses and validates a raw string into a structured SettingPath.
func IdentifySetting(raw string) (SettingPath, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return SettingPath{}, errors.New("governance setting name cannot be empty")
	}

	if after, ok := strings.CutPrefix(raw, RetentionPrefix); ok {
		parts := strings.SplitN(after, ".", 2)
		tier := NormalizeTier(parts[0])
		if tier == "" {
			return SettingPath{}, fmt.Errorf("lifecycle tier name required in %q", raw)
		}
		sp := SettingPath{TierName: tier, Raw: raw}
		if len(parts) > 1 {
			prop := parts[1]
			if prop != "older_than" && prop != "keep_min" {
				return SettingPath{}, fmt.Errorf("unsupported lifecycle property %q", prop)
			}
			sp.Property = prop
		}
		return sp, nil
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
	case "SnapshotRetention":
		return validateDuration(cfg.SnapshotRetention, "snapshot_retention")
	case "RetentionTier":
		return validateNonEmpty(cfg.RetentionTier, "default_retention_tier")
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

// ConfigureLifecycleTier sets specific retention rules for an snapshot tier.
func ConfigureLifecycleTier(cfg *WorkspacePolicy, tierName, property, value string) error {
	if cfg.RetentionTiers == nil {
		cfg.RetentionTiers = make(map[string]retention.Tier)
	}
	tc := cfg.RetentionTiers[tierName]
	if property == "" {
		property = "older_than"
	}
	switch property {
	case "older_than":
		if _, err := kernel.ParseDuration(value); err != nil {
			return fmt.Errorf("invalid duration %q for tier %s: %w", value, tierName, err)
		}
		tc.OlderThan = value
	case "keep_min":
		tmp := 0
		if err := json.Unmarshal([]byte(value), &tmp); err != nil || tmp < 0 {
			return errors.New("keep_min must be a non-negative integer")
		}
		tc.KeepMin = tmp
	default:
		return fmt.Errorf("unsupported lifecycle property %q", property)
	}
	cfg.RetentionTiers[tierName] = tc
	return nil
}

// RemoveLifecycleTier deletes a custom retention policy for a specific tier.
func RemoveLifecycleTier(cfg *WorkspacePolicy, tierName string) {
	delete(cfg.RetentionTiers, tierName)
}

// attributeResolvers maps audit settings to their evaluation logic.
var attributeResolvers = map[string]func(*GovernanceResolver) PolicyValue[string]{
	"max_unsafe":             (*GovernanceResolver).ResolveMaxUnsafeDuration,
	"default_retention_tier": (*GovernanceResolver).ResolveRetentionTier,
	"ci_failure_policy":      (*GovernanceResolver).ResolveCIFailurePolicy,
	"cli_output":             (*GovernanceResolver).ResolveCLIOutput,
	"cli_path_mode":          (*GovernanceResolver).ResolveCLIPathMode,
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
func BuildSettingCompletions(tiers []string) []string {
	completions := make([]string, 0, len(GovernanceSettings)+len(tiers)*3)
	completions = append(completions, GovernanceSettings...)
	for _, t := range tiers {
		completions = append(completions,
			RetentionPrefix+t,
			RetentionPrefix+t+".older_than",
			RetentionPrefix+t+".keep_min",
		)
	}
	return completions
}

// --- Reflection helpers ---

func fieldByYAMLTag(v reflect.Value, tag string) (reflect.Value, bool) {
	t := v.Type()
	for i := range t.NumField() {
		yamlTag := strings.Split(t.Field(i).Tag.Get("yaml"), ",")[0]
		if yamlTag == tag {
			return v.Field(i), true
		}
	}
	return reflect.Value{}, false
}

func structFieldNameByYAMLTag(_ *WorkspacePolicy, yamlKey string) string {
	t := reflect.TypeFor[WorkspacePolicy]()
	for field := range t.Fields() {
		tag := strings.Split(field.Tag.Get("yaml"), ",")[0]
		if tag == yamlKey {
			return field.Name
		}
	}
	return ""
}
