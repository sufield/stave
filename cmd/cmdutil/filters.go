package cmdutil

import (
	"strings"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// ToControlIDs converts a string slice to kernel.ControlID slice.
// It trims whitespace and excludes any entries that result in an empty ID.
func ToControlIDs(raw []string) []kernel.ControlID {
	return parseStringSlice(raw, func(s string) kernel.ControlID {
		return kernel.ControlID(strings.TrimSpace(s))
	})
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
