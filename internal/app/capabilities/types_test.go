package capabilities_test

import (
	"testing"

	s3 "github.com/sufield/stave/internal/adapters/aws/s3"
	"github.com/sufield/stave/internal/app/capabilities"
	"github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestCapabilities_SourceTypeCount(t *testing.T) {
	caps := capabilities.GetCapabilities("test-v1")
	got := len(caps.Inputs.SourceTypes)
	want := 1
	if got != want {
		t.Errorf("source type count = %d, want %d (update this test when adding source types)", got, want)
	}
}

func TestCapabilities_SourceTypesExpectedSet(t *testing.T) {
	caps := capabilities.GetCapabilities("test-v1")

	got := make(map[kernel.ObservationSourceType]bool, len(caps.Inputs.SourceTypes))
	for _, st := range caps.Inputs.SourceTypes {
		got[st.Type] = true
	}

	want := []kernel.ObservationSourceType{
		s3.SourceTypeAWSS3Snapshot,
	}

	for _, sourceType := range want {
		if !got[sourceType] {
			t.Errorf("source type %q missing from capabilities", sourceType)
		}
	}
}

func TestCapabilities_PacksMatchEmbeddedRegistry(t *testing.T) {
	reg, err := pack.NewEmbeddedRegistry()
	if err != nil {
		t.Fatalf("load embedded registry: %v", err)
	}
	want := reg.ListPacks()

	caps := capabilities.GetCapabilities("test-v1")

	if len(caps.Packs) != len(want) {
		t.Fatalf("pack count = %d, want %d", len(caps.Packs), len(want))
	}
	for i, p := range caps.Packs {
		if p.Name != want[i].Name {
			t.Errorf("pack[%d].Name = %q, want %q", i, p.Name, want[i].Name)
		}
		if p.Description != want[i].Description {
			t.Errorf("pack[%d].Description = %q, want %q", i, p.Description, want[i].Description)
		}
	}
}

func TestCapabilities_OfflineField(t *testing.T) {
	caps := capabilities.GetCapabilities("test-v1")
	if !caps.Offline {
		t.Error("capabilities.Offline should be true")
	}
}

func TestCapabilities_S3PackExists(t *testing.T) {
	caps := capabilities.GetCapabilities("test-v1")
	for _, p := range caps.Packs {
		if p.Name == "s3" {
			return
		}
	}
	t.Error("s3 pack not found in capabilities")
}

func TestCapabilities_UsesProvidedVersion(t *testing.T) {
	caps := capabilities.GetCapabilities("1.2.3-test")
	if caps.Version != "1.2.3-test" {
		t.Fatalf("version = %q, want %q", caps.Version, "1.2.3-test")
	}
	for _, p := range caps.Packs {
		if p.Version != "1.2.3-test" {
			t.Fatalf("pack %q version = %q, want %q", p.Name, p.Version, "1.2.3-test")
		}
	}
}

func TestCapabilities_DefaultVersionFallback(t *testing.T) {
	caps := capabilities.GetCapabilities("")
	if caps.Version != "dev" {
		t.Fatalf("version = %q, want %q", caps.Version, "dev")
	}
}

func TestCapabilities_SecurityAuditSupport(t *testing.T) {
	caps := capabilities.GetCapabilities("test-v1")
	if !caps.SecurityAudit.Enabled {
		t.Fatal("security_audit.enabled should be true")
	}
	wantFormats := map[string]bool{"json": true, "markdown": true, "sarif": true}
	for _, format := range caps.SecurityAudit.Formats {
		delete(wantFormats, format)
	}
	for missing := range wantFormats {
		t.Fatalf("security_audit.formats missing %q", missing)
	}
	wantFailOn := map[string]bool{
		"critical": true,
		"high":     true,
		"medium":   true,
		"low":      true,
		"none":     true,
	}
	for _, level := range caps.SecurityAudit.FailOnLevels {
		delete(wantFailOn, level)
	}
	for missing := range wantFailOn {
		t.Fatalf("security_audit.fail_on_levels missing %q", missing)
	}
}
