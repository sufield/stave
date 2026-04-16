// Package enrich provides local CVE/NVD enrichment for stave inventory
// output. Matches CPE strings against a locally-provided NVD feed to
// annotate assets with known vulnerabilities. No network calls.
package enrich

import (
	"strings"

	"github.com/sufield/stave/internal/app/inventory"
)

// CVEEntry is a vulnerability from the NVD feed.
type CVEEntry struct {
	CVEID            string   `json:"cve_id"`
	CVSSScore        float64  `json:"cvss_score"`
	CVSSVector       string   `json:"cvss_vector,omitempty"`
	Description      string   `json:"description"`
	ExploitAvailable bool     `json:"exploit_available"`
	Remediation      string   `json:"remediation,omitempty"`
	AffectedCPEs     []string `json:"affected_cpes"`
}

// NVDFeed is the local NVD feed format.
type NVDFeed struct {
	Entries []CVEEntry `json:"cve_items"`
}

// EnrichedAsset pairs an inventory asset with matched CVEs.
type EnrichedAsset struct {
	AssetID   string     `json:"asset_id"`
	AssetType string     `json:"asset_type"`
	Version   string     `json:"version"`
	CPE       string     `json:"cpe"`
	CVEs      []CVEMatch `json:"cves,omitempty"`
}

// CVEMatch is a CVE that matched an asset's CPE.
type CVEMatch struct {
	CVEID            string  `json:"cve_id"`
	CVSSScore        float64 `json:"cvss_score"`
	CVSSVector       string  `json:"cvss_vector,omitempty"`
	Description      string  `json:"description"`
	ExploitAvailable bool    `json:"exploit_available"`
	Remediation      string  `json:"remediation,omitempty"`
}

// Result holds the enrichment output.
type Result struct {
	Assets []EnrichedAsset `json:"assets"`
}

// Input configures the enrichment.
type Input struct {
	Inventory []inventory.AssetVersion
	Feed      NVDFeed
	MinCVSS   float64
}

// Enrich matches inventory assets against the NVD feed by CPE.
func Enrich(in Input) *Result {
	result := &Result{}

	for i := range in.Inventory {
		asset := &in.Inventory[i]
		if asset.CPE == "" {
			continue
		}

		var matches []CVEMatch
		for j := range in.Feed.Entries {
			cve := &in.Feed.Entries[j]
			if cve.CVSSScore < in.MinCVSS {
				continue
			}
			if matchesCPE(asset.CPE, cve.AffectedCPEs) {
				matches = append(matches, CVEMatch{
					CVEID:            cve.CVEID,
					CVSSScore:        cve.CVSSScore,
					CVSSVector:       cve.CVSSVector,
					Description:      cve.Description,
					ExploitAvailable: cve.ExploitAvailable,
					Remediation:      cve.Remediation,
				})
			}
		}

		enriched := EnrichedAsset{
			AssetID:   asset.AssetID,
			AssetType: asset.AssetType,
			Version:   asset.Version,
			CPE:       asset.CPE,
			CVEs:      matches,
		}
		result.Assets = append(result.Assets, enriched)
	}

	return result
}

// matchesCPE checks if an asset CPE matches any of the affected CPEs.
// Uses prefix matching: a CVE with affected CPE "cpe:2.3:a:kubernetes:kubernetes:1.27"
// matches an asset CPE "cpe:2.3:a:kubernetes:kubernetes:1.27.4:*".
func matchesCPE(assetCPE string, affectedCPEs []string) bool {
	assetParts := parseCPEParts(assetCPE)
	if len(assetParts) < 5 {
		return false
	}

	for _, affected := range affectedCPEs {
		affectedParts := parseCPEParts(affected)
		if len(affectedParts) < 5 {
			continue
		}

		// Match vendor and product (parts 3 and 4).
		if assetParts[3] != affectedParts[3] || assetParts[4] != affectedParts[4] {
			continue
		}

		// Match version: affected version matches if it's a prefix of asset version,
		// or if affected uses wildcard.
		if len(affectedParts) > 5 && affectedParts[5] != "*" && len(assetParts) > 5 {
			if !strings.HasPrefix(assetParts[5], affectedParts[5]) {
				continue
			}
		}

		return true
	}
	return false
}

func parseCPEParts(cpe string) []string {
	return strings.Split(cpe, ":")
}
