package capabilities_test

import (
	"testing"

	"github.com/sufield/stave/internal/app/capabilities"
	"github.com/sufield/stave/internal/builtin/pack"
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

	got := make(map[kernel.ObservationSourceType]bool, len(caps.DataIngress.Connectors))
	for _, c := range caps.DataIngress.Connectors {
		got[c.Type] = true
	}

	want := []kernel.ObservationSourceType{
		aws.SourceTypeAWSS3Snapshot,
	}

	for _, sourceType := range want {
		if !got[sourceType] {
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
	wantFormats := map[string]bool{"json": true, "markdown": true, "sarif": true}
	for _, format := range caps.ComplianceSupport.ReportFormats {
		delete(wantFormats, format)
	}
	for missing := range wantFormats {
		t.Fatalf("compliance.report_formats missing %q", missing)
	}
}
