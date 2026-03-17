package evidence

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// --- SPDX 2.3 typed structs ---

type spdxDocument struct {
	SPDXVersion  string        `json:"spdxVersion"`
	SPDXID       string        `json:"SPDXID"`
	Name         string        `json:"name"`
	CreationInfo spdxCreation  `json:"creationInfo"`
	Packages     []spdxPackage `json:"packages"`
}

type spdxCreation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// --- CycloneDX 1.6 typed structs ---

type cycloneDXDocument struct {
	BOMFormat   string               `json:"bomFormat"`
	SpecVersion string               `json:"specVersion"`
	Version     int                  `json:"version"`
	Metadata    cycloneDXMetadata    `json:"metadata"`
	Components  []cycloneDXComponent `json:"components"`
}

type cycloneDXMetadata struct {
	Timestamp string          `json:"timestamp"`
	Tools     []cycloneDXTool `json:"tools"`
}

type cycloneDXTool struct {
	Vendor string `json:"vendor"`
	Name   string `json:"name"`
}

type cycloneDXComponent struct {
	Type    string          `json:"type"`
	Name    string          `json:"name"`
	Version string          `json:"version"`
	PURL    string          `json:"purl"`
	Hashes  []cycloneDXHash `json:"hashes,omitempty"`
}

type cycloneDXHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// --- Generator ---

type DefaultSBOMGenerator struct{}

func (DefaultSBOMGenerator) Generate(input BuildInfoSnapshot, format SBOMFormat, now time.Time) (SBOMSnapshot, error) {
	modules := make([]BuildModuleSnapshot, 0, len(input.Deps)+1)
	if input.Main.Path != "" {
		modules = append(modules, input.Main)
	}
	modules = append(modules, input.Deps...)
	if len(modules) == 0 {
		return SBOMSnapshot{}, fmt.Errorf("no module metadata available")
	}

	sort.Slice(modules, func(i, j int) bool {
		return modules[i].Path < modules[j].Path
	})

	ts := now.UTC().Format(time.RFC3339)
	switch format {
	case SBOMFormatSPDX:
		return generateSPDX(modules, ts)
	case SBOMFormatCycloneDX:
		return generateCycloneDX(modules, ts)
	default:
		return SBOMSnapshot{}, fmt.Errorf("unsupported sbom format %q", format)
	}
}

func generateSPDX(modules []BuildModuleSnapshot, ts string) (SBOMSnapshot, error) {
	packages := make([]spdxPackage, 0, len(modules))
	for i, module := range modules {
		version := normalizeVersion(module.Version)
		packages = append(packages, spdxPackage{
			SPDXID:           fmt.Sprintf("SPDXRef-Package-%d", i+1),
			Name:             module.Path,
			VersionInfo:      version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			ExternalRefs: []spdxExternalRef{
				{
					ReferenceCategory: "PACKAGE-MANAGER",
					ReferenceType:     "purl",
					ReferenceLocator:  toGoPURL(module.Path, version),
				},
			},
		})
	}

	doc := spdxDocument{
		SPDXVersion: "SPDX-2.3",
		SPDXID:      "SPDXRef-DOCUMENT",
		Name:        "stave-security-audit",
		CreationInfo: spdxCreation{
			Created:  ts,
			Creators: []string{"Tool: stave security-audit"},
		},
		Packages: packages,
	}

	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return SBOMSnapshot{}, fmt.Errorf("marshal spdx sbom: %w", err)
	}
	return SBOMSnapshot{
		FileName:        "sbom.spdx.json",
		DependencyCount: len(modules),
		RawJSON:         append(raw, '\n'),
	}, nil
}

func generateCycloneDX(modules []BuildModuleSnapshot, ts string) (SBOMSnapshot, error) {
	components := make([]cycloneDXComponent, 0, len(modules))
	for _, module := range modules {
		version := normalizeVersion(module.Version)
		comp := cycloneDXComponent{
			Type:    "library",
			Name:    module.Path,
			Version: version,
			PURL:    toGoPURL(module.Path, version),
		}
		if strings.TrimSpace(module.Sum) != "" {
			comp.Hashes = []cycloneDXHash{{
				Alg:     "SHA-256",
				Content: module.Sum,
			}}
		}
		components = append(components, comp)
	}

	doc := cycloneDXDocument{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: cycloneDXMetadata{
			Timestamp: ts,
			Tools:     []cycloneDXTool{{Vendor: "sufield", Name: "stave-security-audit"}},
		},
		Components: components,
	}

	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return SBOMSnapshot{}, fmt.Errorf("marshal cyclonedx sbom: %w", err)
	}
	return SBOMSnapshot{
		FileName:        "sbom.cdx.json",
		DependencyCount: len(modules),
		RawJSON:         append(raw, '\n'),
	}, nil
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
