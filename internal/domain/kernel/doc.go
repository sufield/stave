// Package kernel defines shared value objects and contracts used across the
// domain layer.
//
// Key types include [ControlID] for parsed control identifiers (CTL. prefix),
// [AssetType] for infrastructure asset classification, [TimeWindow] for
// time-range and unsafe-duration calculations, [PrincipalScope] for access
// scopes (Public, Authenticated, etc.), and schema version constants for
// observations, controls, and output formats.
//
// The package also defines the [Sanitizer] interface contract and
// [SanitizableMap] for tracking sensitive fields during output sanitization.
package kernel
