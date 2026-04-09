package evidence

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

var knownInput = BuildInfoSnapshot{
	Main: BuildModuleSnapshot{Path: "github.com/sufield/stave", Version: "v0.1.0"},
	Deps: []BuildModuleSnapshot{
		{Path: "github.com/spf13/cobra", Version: "v1.10.2", Sum: "h1:abc123"},
		{Path: "github.com/spf13/pflag", Version: "v1.0.10"},
		{Path: "gopkg.in/yaml.v3", Version: "v3.0.1", Sum: "h1:def456"},
	},
}

// --- Level 2: Schema structure validation ---

func TestSPDX_SchemaStructure(t *testing.T) {
	gen := DefaultSBOMGenerator{}
	snap, err := gen.Generate(knownInput, SBOMFormatSPDX, fixedTime)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var doc spdxDocument
	if err := json.Unmarshal(snap.RawJSON, &doc); err != nil {
		t.Fatalf("unmarshal SPDX: %v", err)
	}

	// Required top-level fields per SPDX 2.3 spec.
	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("spdxVersion = %q, want SPDX-2.3", doc.SPDXVersion)
	}
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID = %q, want SPDXRef-DOCUMENT", doc.SPDXID)
	}
	if doc.Name == "" {
		t.Error("name is empty")
	}
	if doc.CreationInfo.Created == "" {
		t.Error("creationInfo.created is empty")
	}
	if len(doc.CreationInfo.Creators) == 0 {
		t.Error("creationInfo.creators is empty")
	}

	// Packages must exist.
	if len(doc.Packages) != 4 { // main + 3 deps
		t.Fatalf("packages count = %d, want 4", len(doc.Packages))
	}

	// Every package must have required fields.
	for i, pkg := range doc.Packages {
		if pkg.SPDXID == "" {
			t.Errorf("package[%d].SPDXID is empty", i)
		}
		if !strings.HasPrefix(pkg.SPDXID, "SPDXRef-") {
			t.Errorf("package[%d].SPDXID = %q, must start with SPDXRef-", i, pkg.SPDXID)
		}
		if pkg.Name == "" {
			t.Errorf("package[%d].name is empty", i)
		}
		if pkg.VersionInfo == "" {
			t.Errorf("package[%d].versionInfo is empty", i)
		}
		if pkg.DownloadLocation == "" {
			t.Errorf("package[%d].downloadLocation is empty", i)
		}
		if len(pkg.ExternalRefs) == 0 {
			t.Errorf("package[%d].externalRefs is empty", i)
		}
		for _, ref := range pkg.ExternalRefs {
			if !strings.HasPrefix(ref.ReferenceLocator, "pkg:golang/") {
				t.Errorf("package[%d] PURL = %q, want pkg:golang/ prefix", i, ref.ReferenceLocator)
			}
		}
	}
}

func TestCycloneDX_SchemaStructure(t *testing.T) {
	gen := DefaultSBOMGenerator{}
	snap, err := gen.Generate(knownInput, SBOMFormatCycloneDX, fixedTime)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var doc cycloneDXDocument
	if err := json.Unmarshal(snap.RawJSON, &doc); err != nil {
		t.Fatalf("unmarshal CycloneDX: %v", err)
	}

	// Required top-level fields per CycloneDX 1.6 spec.
	if doc.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", doc.BOMFormat)
	}
	if doc.SpecVersion != "1.6" {
		t.Errorf("specVersion = %q, want 1.6", doc.SpecVersion)
	}
	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
	}
	if doc.Metadata.Timestamp == "" {
		t.Error("metadata.timestamp is empty")
	}
	if len(doc.Metadata.Tools) == 0 {
		t.Error("metadata.tools is empty")
	}

	// Components must exist.
	if len(doc.Components) != 4 {
		t.Fatalf("components count = %d, want 4", len(doc.Components))
	}

	// Every component must have required fields.
	for i, comp := range doc.Components {
		if comp.Type != "library" {
			t.Errorf("component[%d].type = %q, want library", i, comp.Type)
		}
		if comp.Name == "" {
			t.Errorf("component[%d].name is empty", i)
		}
		if comp.Version == "" {
			t.Errorf("component[%d].version is empty", i)
		}
		if !strings.HasPrefix(comp.PURL, "pkg:golang/") {
			t.Errorf("component[%d].purl = %q, want pkg:golang/ prefix", i, comp.PURL)
		}
	}
}

// --- Level 3: Golden content assertions ---

func TestSPDX_GoldenContent(t *testing.T) {
	gen := DefaultSBOMGenerator{}
	snap, err := gen.Generate(knownInput, SBOMFormatSPDX, fixedTime)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var doc spdxDocument
	json.Unmarshal(snap.RawJSON, &doc)

	// Root component.
	assertPackageExists(t, doc.Packages, "github.com/sufield/stave", "v0.1.0")

	// Direct dependencies.
	assertPackageExists(t, doc.Packages, "github.com/spf13/cobra", "v1.10.2")
	assertPackageExists(t, doc.Packages, "github.com/spf13/pflag", "v1.0.10")
	assertPackageExists(t, doc.Packages, "gopkg.in/yaml.v3", "v3.0.1")

	// Sorted order (main first, then deps alphabetically).
	if doc.Packages[0].Name != "github.com/spf13/cobra" {
		t.Errorf("first package = %q, want github.com/spf13/cobra (sorted)", doc.Packages[0].Name)
	}

	// Timestamp matches fixed time.
	if doc.CreationInfo.Created != "2026-06-15T12:00:00Z" {
		t.Errorf("created = %q, want 2026-06-15T12:00:00Z", doc.CreationInfo.Created)
	}
}

func TestCycloneDX_GoldenContent(t *testing.T) {
	gen := DefaultSBOMGenerator{}
	snap, err := gen.Generate(knownInput, SBOMFormatCycloneDX, fixedTime)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var doc cycloneDXDocument
	json.Unmarshal(snap.RawJSON, &doc)

	// Root component.
	assertComponentExists(t, doc.Components, "github.com/sufield/stave", "v0.1.0")

	// Direct dependencies.
	assertComponentExists(t, doc.Components, "github.com/spf13/cobra", "v1.10.2")

	// Hashes present for modules with Sum.
	for _, comp := range doc.Components {
		if comp.Name == "github.com/spf13/cobra" {
			if len(comp.Hashes) == 0 {
				t.Error("cobra should have hashes (Sum was provided)")
			}
		}
		if comp.Name == "github.com/spf13/pflag" {
			if len(comp.Hashes) != 0 {
				t.Error("pflag should not have hashes (no Sum)")
			}
		}
	}

	// Timestamp.
	if doc.Metadata.Timestamp != "2026-06-15T12:00:00Z" {
		t.Errorf("timestamp = %q", doc.Metadata.Timestamp)
	}
}

// --- Level 4: Determinism ---

func TestSPDX_Determinism(t *testing.T) {
	gen := DefaultSBOMGenerator{}
	snap1, _ := gen.Generate(knownInput, SBOMFormatSPDX, fixedTime)
	snap2, _ := gen.Generate(knownInput, SBOMFormatSPDX, fixedTime)

	if string(snap1.RawJSON) != string(snap2.RawJSON) {
		t.Error("SPDX output is not deterministic for same input")
	}
}

func TestCycloneDX_Determinism(t *testing.T) {
	gen := DefaultSBOMGenerator{}
	snap1, _ := gen.Generate(knownInput, SBOMFormatCycloneDX, fixedTime)
	snap2, _ := gen.Generate(knownInput, SBOMFormatCycloneDX, fixedTime)

	if string(snap1.RawJSON) != string(snap2.RawJSON) {
		t.Error("CycloneDX output is not deterministic for same input")
	}
}

func TestDeterminism_DifferentInputOrder(t *testing.T) {
	// Dependencies in different order should produce same output (sorted).
	input1 := BuildInfoSnapshot{
		Main: BuildModuleSnapshot{Path: "example.com/app", Version: "v1.0.0"},
		Deps: []BuildModuleSnapshot{
			{Path: "z-package", Version: "v1.0.0"},
			{Path: "a-package", Version: "v2.0.0"},
		},
	}
	input2 := BuildInfoSnapshot{
		Main: BuildModuleSnapshot{Path: "example.com/app", Version: "v1.0.0"},
		Deps: []BuildModuleSnapshot{
			{Path: "a-package", Version: "v2.0.0"},
			{Path: "z-package", Version: "v1.0.0"},
		},
	}

	gen := DefaultSBOMGenerator{}
	snap1, _ := gen.Generate(input1, SBOMFormatSPDX, fixedTime)
	snap2, _ := gen.Generate(input2, SBOMFormatSPDX, fixedTime)

	if string(snap1.RawJSON) != string(snap2.RawJSON) {
		t.Error("SPDX output differs for same deps in different order")
	}
}

// --- Level 5: Edge cases ---

func TestSBOM_EmptyVersion(t *testing.T) {
	gen := DefaultSBOMGenerator{}
	input := BuildInfoSnapshot{
		Main: BuildModuleSnapshot{Path: "example.com/app", Version: ""},
	}
	snap, err := gen.Generate(input, SBOMFormatSPDX, fixedTime)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !strings.Contains(string(snap.RawJSON), `"unknown"`) {
		t.Error("empty version should normalize to 'unknown'")
	}
}

func TestSBOM_WhitespaceSum(t *testing.T) {
	gen := DefaultSBOMGenerator{}
	input := BuildInfoSnapshot{
		Main: BuildModuleSnapshot{Path: "example.com/app", Version: "v1.0.0", Sum: "  "},
	}
	snap, err := gen.Generate(input, SBOMFormatCycloneDX, fixedTime)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// Whitespace-only sum should not produce hashes.
	if strings.Contains(string(snap.RawJSON), `"hashes"`) {
		t.Error("whitespace sum should not produce hashes")
	}
}

func TestSBOM_SingleModule(t *testing.T) {
	gen := DefaultSBOMGenerator{}
	input := BuildInfoSnapshot{
		Main: BuildModuleSnapshot{Path: "example.com/app", Version: "v1.0.0"},
	}
	snap, err := gen.Generate(input, SBOMFormatCycloneDX, fixedTime)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if snap.DependencyCount != 1 {
		t.Errorf("count = %d, want 1", snap.DependencyCount)
	}
}

// --- Helpers ---

func assertPackageExists(t *testing.T, packages []spdxPackage, name, version string) {
	t.Helper()
	for _, pkg := range packages {
		if pkg.Name == name && pkg.VersionInfo == version {
			return
		}
	}
	t.Errorf("SPDX package %s@%s not found", name, version)
}

func assertComponentExists(t *testing.T, components []cycloneDXComponent, name, version string) {
	t.Helper()
	for _, comp := range components {
		if comp.Name == name && comp.Version == version {
			return
		}
	}
	t.Errorf("CycloneDX component %s@%s not found", name, version)
}
