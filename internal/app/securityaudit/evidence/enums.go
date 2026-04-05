package evidence

import (
	"fmt"
	"time"
)

// SBOMFormat identifies the SBOM output standard.
type SBOMFormat string

// SBOMFormatSPDX values.
const (
	SBOMFormatSPDX      SBOMFormat = "spdx"
	SBOMFormatCycloneDX SBOMFormat = "cyclonedx"
)

// VulnSource identifies the vulnerability evidence strategy.
type VulnSource string

// VulnSourceHybrid values.
const (
	VulnSourceHybrid VulnSource = "hybrid"
	VulnSourceLocal  VulnSource = "local"
	VulnSourceCI     VulnSource = "ci"
)

// VulnSourceUsed identifies the actual evidence source outcome (vs VulnSource which is the strategy).
type VulnSourceUsed string

// VulnSourceUsedLive values.
const (
	VulnSourceUsedLive       VulnSourceUsed = "local_live_check"
	VulnSourceUsedFailed     VulnSourceUsed = "live_check_failed"
	VulnSourceUsedNone       VulnSourceUsed = "none"
	VulnSourceUsedLocalCache VulnSourceUsed = "local_cache"
	VulnSourceUsedCIArtifact VulnSourceUsed = "ci_artifact"
)

// VulnFreshness describes the age/provenance of vulnerability evidence.
// Values are either named tokens or RFC3339 timestamps from file stat.
type VulnFreshness string

// FreshnessUnknown values.
const (
	FreshnessUnknown VulnFreshness = "unknown"
	FreshnessLive    VulnFreshness = "live"
	FreshnessCached  VulnFreshness = "cached"
)

// FreshnessFromTime creates a VulnFreshness from a file modification time.
func FreshnessFromTime(t time.Time) VulnFreshness {
	return VulnFreshness(t.UTC().Format(time.RFC3339))
}

// AllSBOMFormats returns all supported SBOM format strings in stable order.
func AllSBOMFormats() []string {
	return []string{string(SBOMFormatCycloneDX), string(SBOMFormatSPDX)}
}

// AllVulnSources returns all supported vulnerability source strings in stable order.
func AllVulnSources() []string {
	return []string{string(VulnSourceCI), string(VulnSourceHybrid), string(VulnSourceLocal)}
}

// ParseSBOMFormat validates and returns an SBOMFormat.
func ParseSBOMFormat(s string) (SBOMFormat, error) {
	switch SBOMFormat(s) {
	case SBOMFormatSPDX, SBOMFormatCycloneDX:
		return SBOMFormat(s), nil
	default:
		return "", fmt.Errorf("unsupported --sbom-format %q (supported: spdx, cyclonedx)", s)
	}
}

// ParseVulnSource validates and returns a VulnSource.
func ParseVulnSource(s string) (VulnSource, error) {
	switch VulnSource(s) {
	case VulnSourceHybrid, VulnSourceLocal, VulnSourceCI:
		return VulnSource(s), nil
	default:
		return "", fmt.Errorf("unsupported --vuln-source %q (supported: hybrid, local, ci)", s)
	}
}

// DefaultDiagnosticsService represents a defaultdiagnosticsservice value.
type DefaultDiagnosticsService struct {
	Run func(cwd, binaryPath, staveVersion string)
}
