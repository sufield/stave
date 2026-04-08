package convert

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

// ToControlIDs converts a string slice to validated kernel.ControlID values.
// Returns an error if any entry is non-empty but fails format validation.
func ToControlIDs(raw []string) ([]kernel.ControlID, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]kernel.ControlID, 0, len(raw))
	for _, s := range raw {
		trimmed := strings.TrimSpace(s)
		if trimmed == "" {
			continue
		}
		id, err := kernel.NewControlID(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid control ID %q: %w", trimmed, err)
		}
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// ToAssetTypes converts a string slice to kernel.AssetType slice.
// It uses the domain constructor and excludes empty results.
func ToAssetTypes(raw []string) []kernel.AssetType {
	return parseStringSlice(raw, func(s string) kernel.AssetType {
		return kernel.NewAssetType(s)
	})
}

// parseStringSlice is a generic internal helper that handles the boilerplate
// of pre-allocating a slice and filtering out "zero-value" results.
func parseStringSlice[T comparable](raw []string, transform func(string) T) []T {
	if len(raw) == 0 {
		return nil
	}

	var zero T
	out := make([]T, 0, len(raw))

	for _, s := range raw {
		val := transform(s)
		if val != zero {
			out = append(out, val)
		}
	}

	if len(out) == 0 {
		return nil
	}
	return out
}
