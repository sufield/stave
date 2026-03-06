package securityaudit

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type defaultSBOMGenerator struct{}

func (defaultSBOMGenerator) Generate(input buildInfoSnapshot, format string, now time.Time) (sbomSnapshot, error) {
	modules := make([]buildModuleSnapshot, 0, len(input.Deps)+1)
	if input.Main.Path != "" {
		modules = append(modules, input.Main)
	}
	modules = append(modules, input.Deps...)
	if len(modules) == 0 {
		return sbomSnapshot{}, fmt.Errorf("no module metadata available")
	}

	sort.Slice(modules, func(i, j int) bool {
		return modules[i].Path < modules[j].Path
	})

	ts := now.UTC().Format(time.RFC3339)
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "spdx":
		doc := map[string]any{
			"spdxVersion": "SPDX-2.3",
			"SPDXID":      "SPDXRef-DOCUMENT",
			"name":        "stave-security-audit",
			"creationInfo": map[string]any{
				"created":  ts,
				"creators": []string{"Tool: stave security-audit"},
			},
		}
		packages := make([]map[string]any, 0, len(modules))
		for i, module := range modules {
			version := normalizeVersion(module.Version)
			packages = append(packages, map[string]any{
				"SPDXID":           fmt.Sprintf("SPDXRef-Package-%d", i+1),
				"name":             module.Path,
				"versionInfo":      version,
				"downloadLocation": "NOASSERTION",
				"filesAnalyzed":    false,
				"externalRefs": []map[string]any{
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType":     "purl",
						"referenceLocator":  toGoPURL(module.Path, version),
					},
				},
			})
		}
		doc["packages"] = packages
		raw, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return sbomSnapshot{}, fmt.Errorf("marshal spdx sbom: %w", err)
		}
		return sbomSnapshot{
			FileName:        "sbom.spdx.json",
			DependencyCount: len(modules),
			RawJSON:         append(raw, '\n'),
		}, nil
	case "cyclonedx":
		components := make([]map[string]any, 0, len(modules))
		for _, module := range modules {
			version := normalizeVersion(module.Version)
			component := map[string]any{
				"type":    "library",
				"name":    module.Path,
				"version": version,
				"purl":    toGoPURL(module.Path, version),
			}
			if strings.TrimSpace(module.Sum) != "" {
				component["hashes"] = []map[string]string{{
					"alg":     "SHA-256",
					"content": module.Sum,
				}}
			}
			components = append(components, component)
		}
		doc := map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.6",
			"version":     1,
			"metadata": map[string]any{
				"timestamp": ts,
				"tools": []map[string]any{
					{"vendor": "sufield", "name": "stave-security-audit"},
				},
			},
			"components": components,
		}
		raw, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return sbomSnapshot{}, fmt.Errorf("marshal cyclonedx sbom: %w", err)
		}
		return sbomSnapshot{
			FileName:        "sbom.cdx.json",
			DependencyCount: len(modules),
			RawJSON:         append(raw, '\n'),
		}, nil
	default:
		return sbomSnapshot{}, fmt.Errorf("unsupported sbom format %q", format)
	}
}

func normalizeVersion(version string) string {
	if strings.TrimSpace(version) == "" {
		return "unknown"
	}
	return strings.TrimSpace(version)
}

func toGoPURL(path, version string) string {
	return fmt.Sprintf("pkg:golang/%s@%s", strings.TrimSpace(path), strings.TrimSpace(version))
}
