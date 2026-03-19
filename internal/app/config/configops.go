package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/go-playground/validator/v10"

	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/retention"
)

var validate = validator.New()

func init() {
	_ = validate.RegisterValidation("stave_duration", func(fl validator.FieldLevel) bool {
		_, err := kernel.ParseDuration(fl.Field().String())
		return err == nil
	})
	_ = validate.RegisterValidation("stave_policy", func(fl validator.FieldLevel) bool {
		_, err := ParseGatePolicy(fl.Field().String())
		return err == nil
	})
	_ = validate.RegisterValidation("stave_cadence", func(fl validator.FieldLevel) bool {
		v := fl.Field().String()
		return v == "daily" || v == "hourly"
	})
}

// ConfigKeys is the set of top-level config keys exposed to `stave config`.
// Derived automatically from ProjectConfig fields that have a yaml tag and
// are simple types (string, bool, int). Complex types (maps, slices, structs)
// are excluded — they require specialized handling (e.g., retention tiers).
var ConfigKeys = deriveConfigKeys()

func deriveConfigKeys() []string {
	t := reflect.TypeFor[ProjectConfig]()
	var keys []string
	for f := range t.Fields() {
		tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		// Only expose simple scalar types to stave config get/set
		switch f.Type.Kind() {
		case reflect.String, reflect.Bool, reflect.Int, reflect.Float64:
			keys = append(keys, tag)
		}
	}
	return keys
}

const TierKeyPrefix = "snapshot_retention_tiers."

// ParsedKey represents a validated config key reference.
type ParsedKey struct {
	TopLevel string // e.g., "max_unsafe" or "" for tier keys
	TierName string // e.g., "non_critical" (only for tier keys)
	SubField string // e.g., "older_than" or "keep_min" (only for tier sub-fields)
	Raw      string // original input
}

// ParseConfigKey validates and parses a raw config key string.
func ParseConfigKey(raw string) (ParsedKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ParsedKey{}, fmt.Errorf("config key cannot be empty")
	}

	// Hierarchical tier key: snapshot_retention_tiers.<tier>[.<field>]
	if after, ok := strings.CutPrefix(raw, TierKeyPrefix); ok {
		rest := after
		parts := strings.SplitN(rest, ".", 2)
		tier := NormalizeTier(parts[0])
		if tier == "" {
			return ParsedKey{}, fmt.Errorf("tier name cannot be empty in %q", raw)
		}
		pk := ParsedKey{TierName: tier, Raw: raw}
		if len(parts) > 1 {
			sf := parts[1]
			if sf != "older_than" && sf != "keep_min" {
				return ParsedKey{}, fmt.Errorf("unsupported tier field %q in %q", sf, raw)
			}
			pk.SubField = sf
		}
		return pk, nil
	}

	// Top-level key: must match a known key
	if slices.Contains(ConfigKeys, raw) {
		return ParsedKey{TopLevel: raw, Raw: raw}, nil
	}
	return ParsedKey{}, fmt.Errorf("unsupported config key %q", raw)
}

// GetConfigValue reads a config field by its YAML key name.
func GetConfigValue(cfg *ProjectConfig, key string) (string, bool) {
	field, ok := fieldByYAMLTag(reflect.ValueOf(cfg).Elem(), key)
	if !ok {
		return "", false
	}
	return fmt.Sprint(field.Interface()), true
}

// SetConfigValue validates and sets a config field by its YAML key name.
func SetConfigValue(cfg *ProjectConfig, key, value string) error {
	field, ok := fieldByYAMLTag(reflect.ValueOf(cfg).Elem(), key)
	if !ok {
		return fmt.Errorf("unknown config key: %s", key)
	}

	// Set the value using type-aware conversion
	if field.Kind() == reflect.String {
		field.Set(reflect.ValueOf(value).Convert(field.Type()))
	} else {
		tmp := reflect.New(field.Type())
		if err := json.Unmarshal([]byte(value), tmp.Interface()); err != nil {
			return fmt.Errorf("invalid value %q for %s: %w", value, key, err)
		}
		field.Set(tmp.Elem())
	}

	// Validate only the changed field
	fieldName := structFieldNameByYAMLTag(cfg, key)
	if fieldName != "" {
		if err := validate.StructPartial(cfg, fieldName); err != nil {
			// Revert on validation failure
			field.Set(reflect.Zero(field.Type()))
			return fmt.Errorf("invalid value %q for %s: %w", value, key, err)
		}
	}
	return nil
}

// DeleteConfigValue zeroes a config field by its YAML key name.
func DeleteConfigValue(cfg *ProjectConfig, key string) error {
	field, ok := fieldByYAMLTag(reflect.ValueOf(cfg).Elem(), key)
	if !ok {
		return fmt.Errorf("unknown config key: %s", key)
	}
	field.Set(reflect.Zero(field.Type()))
	return nil
}

// SetTierValue sets a retention tier field.
func SetTierValue(cfg *ProjectConfig, tierName, subField, value string) error {
	if cfg.RetentionTiers == nil {
		cfg.RetentionTiers = make(map[string]retention.TierConfig)
	}
	tc := cfg.RetentionTiers[tierName]
	if subField == "" {
		subField = "older_than"
	}
	switch subField {
	case "older_than":
		if _, err := kernel.ParseDuration(value); err != nil {
			return fmt.Errorf("invalid duration %q for tier %s: %w", value, tierName, err)
		}
		tc.OlderThan = value
	case "keep_min":
		tmp := 0
		if err := json.Unmarshal([]byte(value), &tmp); err != nil || tmp < 0 {
			return fmt.Errorf("keep_min must be a non-negative integer")
		}
		tc.KeepMin = tmp
	default:
		return fmt.Errorf("unsupported tier field %q", subField)
	}
	cfg.RetentionTiers[tierName] = tc
	return nil
}

// DeleteTierValue removes a retention tier.
func DeleteTierValue(cfg *ProjectConfig, tierName string) {
	delete(cfg.RetentionTiers, tierName)
}

// ResolveKey calls the appropriate Evaluator.Resolve*() method by key name.
func ResolveKey(eval *Evaluator, key string) (Value[string], bool) {
	methodName := "Resolve" + pascalCase(key)
	method := reflect.ValueOf(eval).MethodByName(methodName)
	if !method.IsValid() {
		return Value[string]{}, false
	}
	results := method.Call(nil)
	if len(results) == 0 {
		return Value[string]{}, false
	}
	v, ok := results[0].Interface().(Value[string])
	return v, ok
}

// BuildKeyCompletions generates shell completion strings for config keys.
func BuildKeyCompletions(tiers []string) []string {
	completions := make([]string, 0, len(ConfigKeys)+len(tiers)*3)
	completions = append(completions, ConfigKeys...)
	for _, t := range tiers {
		completions = append(completions,
			TierKeyPrefix+t,
			TierKeyPrefix+t+".older_than",
			TierKeyPrefix+t+".keep_min",
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

func structFieldNameByYAMLTag(cfg *ProjectConfig, yamlKey string) string {
	t := reflect.TypeFor[ProjectConfig]()
	for field := range t.Fields() {
		tag := strings.Split(field.Tag.Get("yaml"), ",")[0]
		if tag == yamlKey {
			return field.Name
		}
	}
	return ""
}

func pascalCase(s string) string {
	words := strings.Split(s, "_")
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, "")
}
