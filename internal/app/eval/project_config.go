package eval

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// ErrConfigConflict is returned when project configuration contains
// conflicting settings (e.g. explicit --controls with enabled_control_packs).
var ErrConfigConflict = errors.New("config conflict")

// ExceptionInput holds exception rule data ready for promotion to a
// policy.ExceptionRule. Expires is already a parsed policy.ExpiryDate
// — config-loader paths run policy.ParseExpiryDate (or YAML
// unmarshal, which delegates there) at the boundary so this struct
// carries a validated date, not a raw string awaiting reparse.
type ExceptionInput struct {
	ControlID kernel.ControlID
	AssetID   asset.ID
	Reason    string
	Expires   policy.ExpiryDate
}

// PackRegistry resolves built-in control packs from the embedded registry.
type PackRegistry interface {
	ResolveEnabledPacks(names []string) ([]kernel.ControlID, error)
	RegistryVersion() (string, error)
	RegistryHash() (string, error)
}

// ProjectConfigInput holds project configuration from stave.yaml.
type ProjectConfigInput struct {
	Exceptions          []ExceptionInput
	EnabledControlPacks []string
	ExcludeControls     []kernel.ControlID
	ControlsFlagSet     bool
	BuiltinLoader       func() ([]policy.ControlDefinition, error)
	PackRegistry        PackRegistry
}

// ResolvedProjectConfig holds pre-resolved project configuration.
// All parsing and I/O has already occurred; the result consists
// only of domain types suitable for option assignment.
type ResolvedProjectConfig struct {
	ExceptionConfig   *policy.ExceptionConfig
	PreloadedControls []policy.ControlDefinition
	ControlSource     evaluation.ControlSourceInfo
}

// ResolveProjectConfig validates and resolves project configuration.
// It parses exception rules, resolves enabled packs, and loads
// built-in controls. All I/O happens here, not in options.
func ResolveProjectConfig(in ProjectConfigInput) (ResolvedProjectConfig, error) {
	var result ResolvedProjectConfig

	if len(in.Exceptions) > 0 {
		result.ExceptionConfig = policy.NewExceptionConfig(resolveExceptionRules(in.Exceptions))
	}

	if len(in.EnabledControlPacks) == 0 {
		return result, nil
	}
	if in.ControlsFlagSet {
		// Explicit --controls flag overrides enabled_control_packs from
		// stave.yaml. The user's CLI flag takes precedence over config.
		return result, nil
	}

	packNames := slices.Clone(in.EnabledControlPacks)
	slices.Sort(packNames)

	if in.PackRegistry == nil {
		return ResolvedProjectConfig{}, errors.New("pack registry is required when enabled_control_packs is set")
	}
	if in.BuiltinLoader == nil {
		// Without a loader we cannot satisfy the user's
		// `enabled_control_packs` request — fail loudly rather
		// than silently producing zero controls (which would
		// make every run pass with no findings, the worst
		// possible failure mode for a security tool).
		return ResolvedProjectConfig{}, errors.New("builtin loader is required when enabled_control_packs is set")
	}
	resolvedIDs, err := in.PackRegistry.ResolveEnabledPacks(packNames)
	if err != nil {
		return ResolvedProjectConfig{}, fmt.Errorf("resolve enabled_control_packs: %w", err)
	}
	loaded, err := loadBuiltInControlsByID(in.BuiltinLoader, resolvedIDs, in.ExcludeControls)
	if err != nil {
		return ResolvedProjectConfig{}, err
	}

	// Registry metadata enriches evaluation output but does not affect correctness.
	v, vErr := in.PackRegistry.RegistryVersion()
	if vErr != nil {
		slog.Debug("registry version unavailable", "error", vErr)
	}
	h, hErr := in.PackRegistry.RegistryHash()
	if hErr != nil {
		slog.Debug("registry hash unavailable", "error", hErr)
	}
	result.PreloadedControls = loaded
	result.ControlSource = evaluation.ControlSourceInfo{
		Source:             evaluation.ControlSourcePacks,
		EnabledPacks:       toPackNames(packNames),
		ResolvedControlIDs: resolvedIDs,
		RegistryVersion:    v,
		RegistryHash:       kernel.Digest(h),
	}
	return result, nil
}

// resolveExceptionRules promotes the parsed ExceptionInput shape
// into the engine's policy.ExceptionRule layout. Total — every
// component is already validated at YAML unmarshal time, so the
// function cannot fail and returns a plain slice.
func resolveExceptionRules(in []ExceptionInput) []policy.ExceptionRule {
	rules := make([]policy.ExceptionRule, len(in))
	for i, s := range in {
		rules[i] = policy.ExceptionRule{
			ControlID: s.ControlID,
			AssetID:   s.AssetID,
			Reason:    s.Reason,
			Expires:   s.Expires,
		}
	}
	return rules
}

func loadBuiltInControlsByID(
	loader func() ([]policy.ControlDefinition, error),
	controlIDs []kernel.ControlID,
	excludeIDs []kernel.ControlID,
) ([]policy.ControlDefinition, error) {
	allBuiltIns, err := loader()
	if err != nil {
		return nil, fmt.Errorf("load built-in controls: %w", err)
	}

	unseen := make(map[kernel.ControlID]struct{}, len(controlIDs))
	for _, id := range controlIDs {
		unseen[id] = struct{}{}
	}
	var excluded map[kernel.ControlID]struct{}
	if len(excludeIDs) > 0 {
		excluded = make(map[kernel.ControlID]struct{}, len(excludeIDs))
		for _, item := range excludeIDs {
			excluded[item] = struct{}{}
		}
	}

	// Single pass: select allowed controls, mark as seen.
	selected := make([]policy.ControlDefinition, 0, len(controlIDs))
	for i := range allBuiltIns {
		ctl := &allBuiltIns[i]
		if _, ok := unseen[ctl.ID]; !ok {
			continue
		}
		delete(unseen, ctl.ID) // mark seen
		if _, ok := excluded[ctl.ID]; ok {
			continue
		}
		selected = append(selected, *ctl)
	}

	if len(unseen) > 0 {
		missing := collectMissingIDs(unseen)
		return nil, fmt.Errorf("pack registry references missing embedded controls: %s", strings.Join(missing, ", "))
	}

	slices.SortFunc(selected, func(a, b policy.ControlDefinition) int {
		return cmp.Compare(a.ID, b.ID)
	})
	return selected, nil
}

// collectMissingIDs returns sorted IDs that remain marked as unseen in the unseen map.
func collectMissingIDs(unseen map[kernel.ControlID]struct{}) []string {
	missing := make([]string, 0, len(unseen))
	for id := range unseen {
		missing = append(missing, string(id))
	}
	slices.Sort(missing)
	return missing
}

func toPackNames(ss []string) []kernel.PackName {
	if ss == nil {
		return nil
	}
	out := make([]kernel.PackName, len(ss))
	for i, s := range ss {
		out[i] = kernel.PackName(s)
	}
	return out
}
