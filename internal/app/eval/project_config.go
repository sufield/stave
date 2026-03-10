package eval

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/pkg/fp"
)

// ErrConfigConflict is returned when project configuration contains
// conflicting settings (e.g. explicit --controls with enabled_control_packs).
var ErrConfigConflict = errors.New("config conflict")

// SuppressionInput holds raw suppression rule data before parsing.
type SuppressionInput struct {
	ControlID kernel.ControlID
	AssetID   asset.ID
	Reason    string
	Expires   string
}

// ProjectConfigInput holds project configuration from stave.yaml.
type ProjectConfigInput struct {
	Suppressions        []SuppressionInput
	EnabledControlPacks []string
	ExcludeControls     []kernel.ControlID
	ControlsFlagSet     bool
	BuiltinLoader       func(ctx context.Context) ([]policy.ControlDefinition, error)
}

// ResolvedProjectConfig holds pre-resolved project configuration.
// All parsing and I/O has already occurred; the result consists
// only of domain types suitable for option assignment.
type ResolvedProjectConfig struct {
	SuppressionConfig *policy.SuppressionConfig
	PreloadedControls []policy.ControlDefinition
	ControlSource     evaluation.ControlSourceInfo
}

// ResolveProjectConfig validates and resolves project configuration.
// It parses suppression rules, resolves enabled packs, and loads
// built-in controls. All I/O happens here, not in options.
func ResolveProjectConfig(ctx context.Context, in ProjectConfigInput) (ResolvedProjectConfig, error) {
	var result ResolvedProjectConfig

	if len(in.Suppressions) > 0 {
		rules, err := resolveSuppressionRules(in.Suppressions)
		if err != nil {
			return ResolvedProjectConfig{}, err
		}
		result.SuppressionConfig = policy.NewSuppressionConfig(rules)
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

	resolvedIDs, err := packs.ResolveEnabledPacks(packNames)
	if err != nil {
		return ResolvedProjectConfig{}, fmt.Errorf("resolve enabled_control_packs: %w", err)
	}
	loaded, err := loadBuiltInControlsByID(ctx, in.BuiltinLoader, resolvedIDs, in.ExcludeControls)
	if err != nil {
		return ResolvedProjectConfig{}, err
	}

	v, _ := packs.RegistryVersion()
	h, _ := packs.RegistryHash()
	result.PreloadedControls = loaded
	result.ControlSource = evaluation.ControlSourceInfo{
		Source:             evaluation.ControlSourcePacks,
		EnabledPacks:       packNames,
		ResolvedControlIDs: resolvedIDs,
		RegistryVersion:    v,
		RegistryHash:       h,
	}
	return result, nil
}

func resolveSuppressionRules(in []SuppressionInput) ([]policy.SuppressionRule, error) {
	rules := make([]policy.SuppressionRule, len(in))
	for i, s := range in {
		expires, err := policy.ParseExpiryDate(s.Expires)
		if err != nil {
			return nil, fmt.Errorf("invalid suppression expiry at index %d: %w", i, err)
		}
		rules[i] = policy.SuppressionRule{
			ControlID: s.ControlID,
			AssetID:   s.AssetID,
			Reason:    s.Reason,
			Expires:   expires,
		}
	}
	return rules, nil
}

func loadBuiltInControlsByID(
	ctx context.Context,
	loader func(ctx context.Context) ([]policy.ControlDefinition, error),
	controlIDs []string,
	excludeIDs []kernel.ControlID,
) ([]policy.ControlDefinition, error) {
	allBuiltIns, err := loader(ctx)
	if err != nil {
		return nil, fmt.Errorf("load built-in controls: %w", err)
	}

	// allowed doubles as a "seen" tracker: true = wanted but unseen.
	allowed := make(map[kernel.ControlID]bool, len(controlIDs))
	for _, id := range controlIDs {
		allowed[kernel.ControlID(id)] = true
	}
	excluded := fp.ToSet(excludeIDs)

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
