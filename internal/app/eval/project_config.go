package eval

import (
	"cmp"
	"errors"
	"fmt"
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

// ExceptionInput holds raw exception rule data before parsing.
type ExceptionInput struct {
	ControlID kernel.ControlID
	AssetID   asset.ID
	Reason    string
	Expires   string
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
		rules, err := resolveExceptionRules(in.Exceptions)
		if err != nil {
			return ResolvedProjectConfig{}, err
		}
		result.ExceptionConfig = policy.NewExceptionConfig(rules)
	}

	if len(in.EnabledControlPacks) == 0 {
		return result, nil
	}
	if in.ControlsFlagSet {
		return ResolvedProjectConfig{}, fmt.Errorf(
			"%w: cannot combine explicit --controls with enabled_control_packs",
			ErrConfigConflict,
		)
	}

	packNames := slices.Clone(in.EnabledControlPacks)
	slices.Sort(packNames)

	if in.PackRegistry == nil {
		return ResolvedProjectConfig{}, fmt.Errorf("pack registry is required when enabled_control_packs is set")
	}
	resolvedIDs, err := in.PackRegistry.ResolveEnabledPacks(packNames)
	if err != nil {
		return ResolvedProjectConfig{}, fmt.Errorf("resolve enabled_control_packs: %w", err)
	}
	loaded, err := loadBuiltInControlsByID(in.BuiltinLoader, resolvedIDs, in.ExcludeControls)
	if err != nil {
		return ResolvedProjectConfig{}, err
	}

	// Best-effort: registry metadata is informational, not on the critical path.
	// Version and hash enrich evaluation output but do not affect correctness.
	v, _ := in.PackRegistry.RegistryVersion()
	h, _ := in.PackRegistry.RegistryHash()
	result.PreloadedControls = loaded
	result.ControlSource = evaluation.ControlSourceInfo{
		Source:             evaluation.ControlSourcePacks,
		EnabledPacks:       packNames,
		ResolvedControlIDs: resolvedIDs,
		RegistryVersion:    v,
		RegistryHash:       kernel.Digest(h),
	}
	return result, nil
}

func resolveExceptionRules(in []ExceptionInput) ([]policy.ExceptionRule, error) {
	rules := make([]policy.ExceptionRule, len(in))
	for i, s := range in {
		expires, err := policy.ParseExpiryDate(s.Expires)
		if err != nil {
			return nil, fmt.Errorf("invalid exception expiry at index %d: %w", i, err)
		}
		rules[i] = policy.ExceptionRule{
			ControlID: s.ControlID,
			AssetID:   s.AssetID,
			Reason:    s.Reason,
			Expires:   expires,
		}
	}
	return rules, nil
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

	// allowed doubles as a "seen" tracker: true = wanted but unseen.
	allowed := make(map[kernel.ControlID]bool, len(controlIDs))
	for _, id := range controlIDs {
		allowed[id] = true
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
	foundCount := 0
	for _, ctl := range allBuiltIns {
		if !allowed[ctl.ID] {
			continue
		}
		allowed[ctl.ID] = false // mark seen
		foundCount++
		if _, ok := excluded[ctl.ID]; ok {
			continue
		}
		selected = append(selected, ctl)
	}

	if foundCount < len(controlIDs) {
		missing := collectMissingIDs(allowed)
		return nil, fmt.Errorf("pack registry references missing embedded controls: %s", strings.Join(missing, ", "))
	}

	slices.SortFunc(selected, func(a, b policy.ControlDefinition) int {
		return cmp.Compare(a.ID, b.ID)
	})
	return selected, nil
}

// collectMissingIDs returns sorted IDs that remain marked as unseen in the allowed map.
func collectMissingIDs(allowed map[kernel.ControlID]bool) []string {
	var missing []string
	for id, unseen := range allowed {
		if unseen {
			missing = append(missing, string(id))
		}
	}
	slices.Sort(missing)
	return missing
}
