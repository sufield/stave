# Plan: Thin Core — Aggressive De-Bloating

Deviation from hexagonal architecture: favor less code over layer purity.
The CLI is a view of the core. They share data structures. Reflection
is the correct tool for config string-to-field mapping.

Target: -330 lines from the config/CLI layer.

---

## Step 1: Struct Unification (-180 lines)

### Problem

The CLI currently holds flag values in local variables, then copies them
into `appconfig.ProjectConfig` through intermediate layers. This creates
mapping code that exists only to shuttle data between identical shapes.

### Execution

1. In `cmd/apply/`, `cmd/enforce/`, and other command handlers that
   construct evaluation configs: bind Cobra flags directly to
   `appconfig.ProjectConfig` fields using `f.StringVar(&cfg.MaxUnsafe, ...)`.

2. Delete local flag variables that duplicate config fields.

3. Delete `configservice` package entirely — it exists only to mediate
   between CLI and appconfig. The CLI should talk to `appconfig.Evaluator`
   directly for resolution, and write to `appconfig.ProjectConfig` directly
   for mutation.

4. Move `stave config get/set/delete` logic into `cmd/initcmd/config/`
   as thin handlers that read/write `ProjectConfig` fields directly,
   using reflection for key-to-field mapping (Step 2).

5. Delete `cmd/cmdutil/projconfig/config_bridge.go` (41 remaining lines).

### What gets deleted

| File/Code | Lines | Why it exists |
|-----------|------:|---------------|
| `internal/configservice/config.go` | 106 | Service + validation + resolution helpers |
| `internal/configservice/config_mutate.go` | 105 | Switch dispatch for set/delete |
| `internal/configservice/config_resolve.go` | 75 | Switch dispatch for resolve |
| `internal/configservice/config_keys.go` | 63 | Key parsing + completion |
| `internal/configservice/view.go` | 30 | Key completions |
| `internal/configservice/config_test.go` | ~100 | Tests for deleted code |
| `cmd/cmdutil/projconfig/config_bridge.go` | 41 | Remaining bridge singleton |
| **Total deletable** | **~520** | |

### What replaces it

A single `cmd/initcmd/config/configops.go` (~80 lines) that uses
reflection to get/set/delete fields on `ProjectConfig` by YAML tag name,
plus `go-playground/validator` for validation. See Steps 2 and 3.

**Net: ~-440 lines** (520 deleted, ~80 added).

---

## Step 2: Reflection-Based Key Resolution (-90 lines within Step 1)

### Problem

Every config key (`max_unsafe`, `ci_failure_policy`, etc.) has:
- A resolution method (5 methods, ~20 lines)
- A switch case in resolveTopLevel (~20 lines)
- A switch case in SetConfigKeyValue (~50 lines)
- A switch case in DeleteConfigKeyValue (~20 lines)

Adding a new config key requires editing 4 switch statements.

### Execution

Replace all switch dispatch with a single reflection-based resolver:

```go
// configops.go — replaces configservice entirely

// fieldByYAMLTag finds a struct field by its yaml tag name.
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

// GetConfigValue reads a config field by its YAML key name.
func GetConfigValue(cfg *appconfig.ProjectConfig, key string) (string, bool) {
    field, ok := fieldByYAMLTag(reflect.ValueOf(cfg).Elem(), key)
    if !ok { return "", false }
    return fmt.Sprint(field.Interface()), true
}

// SetConfigValue sets a config field by its YAML key name.
// Uses reflect.Convert to handle named string types (GatePolicy, etc.)
// and json.Unmarshal for non-string types (int, bool).
func SetConfigValue(cfg *appconfig.ProjectConfig, key, value string) error {
    field, ok := fieldByYAMLTag(reflect.ValueOf(cfg).Elem(), key)
    if !ok { return fmt.Errorf("unknown config key: %s", key) }
    if field.Kind() == reflect.String {
        field.Set(reflect.ValueOf(value).Convert(field.Type()))
    } else {
        // Handle int, bool, etc. via JSON unmarshal
        tmp := reflect.New(field.Type())
        if err := json.Unmarshal([]byte(value), tmp.Interface()); err != nil {
            return fmt.Errorf("invalid value %q for %s: %w", value, key, err)
        }
        field.Set(tmp.Elem())
    }
    return nil
}

// DeleteConfigValue zeroes a config field by its YAML key name.
func DeleteConfigValue(cfg *appconfig.ProjectConfig, key string) error {
    field, ok := fieldByYAMLTag(reflect.ValueOf(cfg).Elem(), key)
    if !ok { return fmt.Errorf("unknown config key: %s", key) }
    field.Set(reflect.Zero(field.Type()))
    return nil
}
```

This replaces ~110 lines of switch statements with ~30 lines of reflection.
Adding a new config key requires only adding a field to `ProjectConfig`
with a `yaml` tag — zero switch updates.

### Resolution cascade

The `appconfig.Evaluator` already owns the resolution logic (env > project >
user > default). For `stave config get`, the handler calls
`evaluator.WithProject(cfg, path).ResolveMaxUnsafe()` directly — no
configservice indirection. The key-to-method mapping uses reflection on
the Evaluator:

```go
// resolveByKey calls Evaluator.Resolve<Key>() by convention.
func resolveByKey(eval *appconfig.Evaluator, key string) (string, string, error) {
    methodName := "Resolve" + pascalCase(key) // "max_unsafe" → "ResolveMaxUnsafe"
    method := reflect.ValueOf(eval).MethodByName(methodName)
    if !method.IsValid() { return "", "", fmt.Errorf("no resolver for %s", key) }
    results := method.Call(nil)
    v := results[0].Interface().(appconfig.Value[string])
    return v.Value, v.Source, nil
}

// pascalCase converts snake_case to PascalCase.
func pascalCase(s string) string {
    words := strings.Split(s, "_")
    for i, w := range words {
        if len(w) > 0 {
            words[i] = strings.ToUpper(w[:1]) + w[1:]
        }
    }
    return strings.Join(words, "")
}
```

**Safety: fields without yaml tags are skipped.** The `fieldByYAMLTag`
function only matches fields that have an explicit `yaml:"..."` tag.
Internal fields (Exceptions, EnabledControlPacks, ExcludeControls, etc.)
without simple string get/set semantics are not exposed to `stave config`.
The key parser and completion list are derived from the yaml tags, ensuring
only tagged fields appear in the CLI.
```

---

## Step 3: Declarative Validation with go-playground/validator (-60 lines within Step 1)

### Problem

`config_mutate.go` has manual validation for every field:
```go
case KeyMaxUnsafe:
    if err := parseDuration(val); err != nil { return err }
    cfg.MaxUnsafe = val
```

Three standalone validator functions (`parseDuration`, `normalizeTier`,
`normalizePolicy`) exist only to be called from these switch cases.

### Execution

Add `validate` tags to `ProjectConfig`:

```go
type ProjectConfig struct {
    MaxUnsafe                string `yaml:"max_unsafe"          validate:"omitempty,stave_duration"`
    SnapshotRetention        string `yaml:"snapshot_retention"  validate:"omitempty,stave_duration"`
    RetentionTier            string `yaml:"default_retention_tier" validate:"omitempty,min=1"`
    CIFailurePolicy          string `yaml:"ci_failure_policy"   validate:"omitempty,stave_policy"`
    CaptureCadence           string `yaml:"capture_cadence"     validate:"omitempty,stave_cadence"`
    SnapshotFilenameTemplate string `yaml:"snapshot_filename_template" validate:"omitempty,min=1"`
    // ... other fields unchanged
}
```

Register custom validators once:

```go
var validate = validator.New()

func init() {
    validate.RegisterValidation("stave_duration", func(fl validator.FieldLevel) bool {
        _, err := kernel.ParseDuration(fl.Field().String())
        return err == nil
    })
    validate.RegisterValidation("stave_policy", func(fl validator.FieldLevel) bool {
        _, err := appconfig.ParseGatePolicy(fl.Field().String())
        return err == nil
    })
    validate.RegisterValidation("stave_cadence", func(fl validator.FieldLevel) bool {
        return fl.Field().String() == "daily" || fl.Field().String() == "hourly"
    })
}
```

The `SetConfigValue` function becomes:

```go
func SetConfigValue(cfg *appconfig.ProjectConfig, key, value string) error {
    if err := SetFieldByTag(cfg, key, value); err != nil { return err }
    return validate.StructPartial(cfg, fieldNameByTag(cfg, key))
}
```

This replaces the 50-line switch + 3 validator functions with ~20 lines
of tag registration.

---

## Execution Order

1. **Add go-playground/validator dependency** and register custom validators
2. **Add validate tags** to `ProjectConfig` struct
3. **Create `cmd/initcmd/config/configops.go`** (~80 lines) with reflection-based
   get/set/delete + validator integration
4. **Rewrite `cmd/initcmd/config/handlers.go`** to use configops directly
   instead of configservice
5. **Rewrite `cmd/initcmd/config/store.go`** to use configops
6. **Delete `internal/configservice/`** entirely (379 lines + tests)
7. **Delete `cmd/cmdutil/projconfig/config_bridge.go`** (41 lines)
8. **Update `cmd/root.go`** to remove ConfigKeyService initialization
9. **Update `cmd/flags.go`** to bind directly where possible
10. **Verify:** `make test`, `make e2e`, `make lint`

---

## Expected Result

| Component | Before | After | Delta |
|-----------|-------:|------:|------:|
| `internal/configservice/` | 379 | 0 | -379 |
| `configservice` tests | ~100 | 0 | -100 |
| `config_bridge.go` | 41 | 0 | -41 |
| `cmd/initcmd/config/configops.go` | 0 | ~80 | +80 |
| Validator registration | 0 | ~20 | +20 |
| `ProjectConfig` validate tags | 0 | ~10 | +10 |
| **Net** | **520** | **110** | **-410** |

---

## Trade-offs Accepted

- **Reflection in CLI config path** — correct trade-off for a CLI tool.
  Config operations run once at startup; nanosecond overhead is irrelevant.
  Eliminates ~110 lines of switch statements that must be manually updated
  for every new config key.

- **CLI imports internal config types** — the CLI IS the view of the core.
  Maintaining a separate CLI config struct that mirrors the internal one
  creates mapping code. Sharing the struct eliminates it.

- **No configservice abstraction** — the `stave config` command talks to
  `ProjectConfig` + `Evaluator` directly. The config service layer existed
  only to enforce interface boundaries that created more code than they saved.

- **go-playground/validator dependency** — well-maintained, widely used,
  eliminates manual validation functions. Custom validators for domain
  types (duration, policy) are registered once, not repeated per field.
