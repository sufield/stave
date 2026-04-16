// Package inventory exports versioned asset data for external CVE join.
package inventory

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
)

// AssetVersion is a versioned asset for CVE correlation.
type AssetVersion struct {
	AssetID          string `json:"asset_id"`
	AssetType        string `json:"asset_type"`
	Vendor           string `json:"vendor"`
	VersionField     string `json:"version_field"`
	Version          string `json:"version"`
	CPE              string `json:"cpe"`
	PackageEcosystem string `json:"package_ecosystem"`
	Engine           string `json:"engine,omitempty"`
}

// Report holds the inventory export.
type Report struct {
	GeneratedAt string         `json:"generated_at"`
	Snapshot    string         `json:"snapshot"`
	Assets      []AssetVersion `json:"assets"`
}

// Extract pulls version information from snapshot assets.
func Extract(snapshots []asset.Snapshot) []AssetVersion {
	var versions []AssetVersion
	for _, snap := range snapshots {
		for i := range snap.Assets {
			a := &snap.Assets[i]
			extracted := extractVersions(a)
			versions = append(versions, extracted...)
		}
	}
	return versions
}

func extractVersions(a *asset.Asset) []AssetVersion {
	var results []AssetVersion
	assetType := string(a.Type)

	switch {
	case strings.Contains(assetType, "eks"):
		if v := getNestedString(a.Properties, "k8s", "cluster", "version"); v != "" {
			results = append(results, AssetVersion{
				AssetID: string(a.ID), AssetType: assetType, Vendor: string(a.Vendor),
				VersionField: "kubernetes_version", Version: v,
				CPE:              fmt.Sprintf("cpe:2.3:a:kubernetes:kubernetes:%s:*:*:*:*:*:*:*", v),
				PackageEcosystem: "kubernetes",
			})
		}
	case strings.Contains(assetType, "lambda"):
		if v := getNestedString(a.Properties, "compute", "runtime", "name"); v != "" {
			results = append(results, AssetVersion{
				AssetID: string(a.ID), AssetType: assetType, Vendor: string(a.Vendor),
				VersionField: "runtime", Version: v,
				CPE: runtimeToCPE(v), PackageEcosystem: runtimeEcosystem(v),
			})
		}
	case strings.Contains(assetType, "rds"):
		engine := getNestedString(a.Properties, "database", "engine")
		version := getNestedString(a.Properties, "database", "engine_version")
		if version != "" {
			results = append(results, AssetVersion{
				AssetID: string(a.ID), AssetType: assetType, Vendor: string(a.Vendor),
				VersionField: "engine_version", Version: version, Engine: engine,
				CPE: engineToCPE(engine, version), PackageEcosystem: engine,
			})
		}
	}
	return results
}

func getNestedString(m map[string]any, keys ...string) string {
	current := m
	for i, k := range keys {
		v, ok := current[k]
		if !ok {
			return ""
		}
		if i == len(keys)-1 {
			s, isStr := v.(string)
			if isStr {
				return s
			}
			return ""
		}
		next, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		current = next
	}
	return ""
}

func runtimeToCPE(runtime string) string {
	parts := strings.SplitN(runtime, ".", 2)
	lang := strings.ToLower(parts[0])
	ver := ""
	if len(parts) > 1 {
		ver = parts[1]
	}
	switch {
	case strings.HasPrefix(lang, "python"):
		return fmt.Sprintf("cpe:2.3:a:python:python:%s:*:*:*:*:*:*:*", ver)
	case strings.HasPrefix(lang, "nodejs"), strings.HasPrefix(lang, "node"):
		return fmt.Sprintf("cpe:2.3:a:nodejs:node.js:%s:*:*:*:*:*:*:*", ver)
	case strings.HasPrefix(lang, "java"), strings.HasPrefix(lang, "corretto"):
		return fmt.Sprintf("cpe:2.3:a:oracle:jdk:%s:*:*:*:*:*:*:*", ver)
	case strings.HasPrefix(lang, "dotnet"):
		return fmt.Sprintf("cpe:2.3:a:microsoft:.net:%s:*:*:*:*:*:*:*", ver)
	case strings.HasPrefix(lang, "go"):
		return fmt.Sprintf("cpe:2.3:a:golang:go:%s:*:*:*:*:*:*:*", ver)
	case strings.HasPrefix(lang, "ruby"):
		return fmt.Sprintf("cpe:2.3:a:ruby-lang:ruby:%s:*:*:*:*:*:*:*", ver)
	default:
		return fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", lang, ver)
	}
}

func runtimeEcosystem(runtime string) string {
	lower := strings.ToLower(runtime)
	switch {
	case strings.HasPrefix(lower, "python"):
		return "pypi"
	case strings.HasPrefix(lower, "node"):
		return "npm"
	case strings.HasPrefix(lower, "java"), strings.HasPrefix(lower, "corretto"):
		return "maven"
	case strings.HasPrefix(lower, "dotnet"):
		return "nuget"
	case strings.HasPrefix(lower, "go"):
		return "go"
	case strings.HasPrefix(lower, "ruby"):
		return "rubygems"
	default:
		return lower
	}
}

func engineToCPE(engine, version string) string {
	switch strings.ToLower(engine) {
	case "mysql":
		return fmt.Sprintf("cpe:2.3:a:oracle:mysql:%s:*:*:*:*:*:*:*", version)
	case "postgres", "postgresql":
		return fmt.Sprintf("cpe:2.3:a:postgresql:postgresql:%s:*:*:*:*:*:*:*", version)
	case "mariadb":
		return fmt.Sprintf("cpe:2.3:a:mariadb:mariadb:%s:*:*:*:*:*:*:*", version)
	case "sqlserver-ee", "sqlserver-se", "sqlserver-ex", "sqlserver-web":
		return fmt.Sprintf("cpe:2.3:a:microsoft:sql_server:%s:*:*:*:*:*:*:*", version)
	default:
		return fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", engine, version)
	}
}
