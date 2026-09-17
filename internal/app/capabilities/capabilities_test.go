package capabilities_test

import (
	"testing"

	"github.com/sufield/stave/internal/adapters/controls/pack"
	"github.com/sufield/stave/internal/app/capabilities"
	"github.com/sufield/stave/internal/core/kernel"
	aws "github.com/sufield/stave/internal/platform/providers/aws"
)

func TestCapabilities_ConnectorCount(t *testing.T) {
	caps := capabilities.Summarize("test-v1")
	got := len(caps.DataIngress.Connectors)
	want := 13
	if got != want {
		t.Errorf("connector count = %d, want %d (update this test when adding connectors)", got, want)
	}
}

func TestCapabilities_ConnectorsExpectedSet(t *testing.T) {
	caps := capabilities.Summarize("test-v1")

	got := make(map[kernel.ObservationSourceType]struct{}, len(caps.DataIngress.Connectors))
	for _, c := range caps.DataIngress.Connectors {
		got[c.Type] = struct{}{}
	}

	want := []kernel.ObservationSourceType{
		aws.SourceTypeAWSS3Snapshot,
	}

	for _, sourceType := range want {
		if _, ok := got[sourceType]; !ok {
			t.Errorf("connector %q missing from capabilities", sourceType)
		}
	}
}

func TestCapabilities_LibraryMatchesEmbeddedRegistry(t *testing.T) {
	reg, err := pack.NewEmbeddedRegistry()
	if err != nil {
		t.Fatalf("load embedded registry: %v", err)
	}
	want, err := reg.ListPacks()
	if err != nil {
		t.Fatalf("ListPacks: %v", err)
	}

	caps := capabilities.Summarize("test-v1")

	if len(caps.PolicyLibrary) != len(want) {
		t.Fatalf("pack count = %d, want %d", len(caps.PolicyLibrary), len(want))
	}
	for i, p := range caps.PolicyLibrary {
		if p.Name != want[i].Name {
			t.Errorf("pack[%d].Name = %q, want %q", i, p.Name, want[i].Name)
		}
		if p.Description != want[i].Description {
			t.Errorf("pack[%d].Description = %q, want %q", i, p.Description, want[i].Description)
		}
	}
}

func TestCapabilities_OfflineField(t *testing.T) {
	caps := capabilities.Summarize("test-v1")
	if !caps.Offline {
		t.Error("capabilities.Offline should be true")
	}
}

func TestCapabilities_S3PackExists(t *testing.T) {
	caps := capabilities.Summarize("test-v1")
	for _, p := range caps.PolicyLibrary {
		if p.Name == "s3" {
			return
		}
	}
	t.Error("s3 pack not found in capabilities")
}

func TestCapabilities_UsesProvidedVersion(t *testing.T) {
	caps := capabilities.Summarize("1.2.3-test")
	if caps.Version != "1.2.3-test" {
		t.Fatalf("version = %q, want %q", caps.Version, "1.2.3-test")
	}
	for _, p := range caps.PolicyLibrary {
		if p.Version != "1.2.3-test" {
			t.Fatalf("pack %q version = %q, want %q", p.Name, p.Version, "1.2.3-test")
		}
	}
}

func TestCapabilities_DefaultVersionFallback(t *testing.T) {
	caps := capabilities.Summarize("")
	if caps.Version != "dev" {
		t.Fatalf("version = %q, want %q", caps.Version, "dev")
	}
}

func TestCapabilities_ComplianceSupport(t *testing.T) {
	caps := capabilities.Summarize("test-v1")
	if !caps.ComplianceSupport.Enabled {
		t.Fatal("compliance.enabled should be true")
	}
	wantFormats := map[string]struct{}{"json": {}, "markdown": {}, "sarif": {}}
	for _, format := range caps.ComplianceSupport.ReportFormats {
		delete(wantFormats, format)
	}
	for missing := range wantFormats {
		t.Fatalf("compliance.report_formats missing %q", missing)
	}
}

func TestCapabilities_CollectionDomainMethods(t *testing.T) {
	packs := capabilities.PolicyPacks{
		{Name: "s3", Description: "S3 Security", Version: "1.0"},
		{Name: "iam", Description: "IAM Governance", Version: "1.0"},
	}

	if packs.Len() != 2 {
		t.Errorf("packs.Len() = %d, want 2", packs.Len())
	}
	if packs.ByName("s3") == nil {
		t.Error("ByName(s3) should not be nil")
	}
	if packs.ByName("nonexistent") != nil {
		t.Error("ByName(nonexistent) should be nil")
	}

	connectors := capabilities.Connectors{
		{Type: kernel.ObservationSourceType("aws-s3-snapshot"), Description: "S3 snapshot"},
	}
	if connectors.Len() != 1 {
		t.Errorf("connectors.Len() = %d, want 1", connectors.Len())
	}
	if connectors.ByType(kernel.ObservationSourceType("aws-s3-snapshot")) == nil {
		t.Error("ByType(aws-s3-snapshot) should not be nil")
	}
	if connectors.ByType(kernel.ObservationSourceType("unknown")) != nil {
		t.Error("ByType(unknown) should be nil")
	}

	var emptyPacks capabilities.PolicyPacks
	if emptyPacks.Len() != 0 {
		t.Errorf("emptyPacks.Len() = %d, want 0", emptyPacks.Len())
	}
	if emptyPacks.ByName("s3") != nil {
		t.Error("emptyPacks.ByName() should return nil")
	}

	var emptyConnectors capabilities.Connectors
	if emptyConnectors.Len() != 0 {
		t.Errorf("emptyConnectors.Len() = %d, want 0", emptyConnectors.Len())
	}
	if emptyConnectors.ByType("test") != nil {
		t.Error("emptyConnectors.ByType() should return nil")
	}
}
