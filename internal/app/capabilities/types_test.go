package capabilities_test

import (
	"testing"

	"github.com/sufield/stave/internal/app/capabilities"
)

func TestCapabilities_SourceTypeCount(t *testing.T) {
	caps := capabilities.GetCapabilities("test-v1")
	got := len(caps.Inputs.SourceTypes)
	want := 2
	if got != want {
		t.Errorf("source type count = %d, want %d (update this test when adding source types)", got, want)
	}
}

func TestCapabilities_SourceTypesExpectedSet(t *testing.T) {
	caps := capabilities.GetCapabilities("test-v1")

	got := make(map[string]bool, len(caps.Inputs.SourceTypes))
	for _, st := range caps.Inputs.SourceTypes {
		got[st.Type] = true
	}

	want := []string{
		"terraform.plan_json",
		"aws-s3-snapshot",
	}

	for _, sourceType := range want {
		if !got[sourceType] {
			t.Errorf("source type %q missing from capabilities", sourceType)
		}
	}
}

func TestCapabilities_OnlyS3PackInMVP(t *testing.T) {
	caps := capabilities.GetCapabilities("test-v1")
	if len(caps.Packs) != 1 {
		t.Fatalf("pack count = %d, want 1", len(caps.Packs))
	}
	if caps.Packs[0].Name != "s3" {
		t.Fatalf("only pack = %q, want %q", caps.Packs[0].Name, "s3")
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
	if len(caps.Packs) != 1 || caps.Packs[0].Version != "1.2.3-test" {
		t.Fatalf("pack version = %q, want %q", caps.Packs[0].Version, "1.2.3-test")
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
		"CRITICAL": true,
		"HIGH":     true,
		"MEDIUM":   true,
		"LOW":      true,
		"NONE":     true,
	}
	for _, level := range caps.SecurityAudit.FailOnLevels {
		delete(wantFailOn, level)
	}
	for missing := range wantFailOn {
		t.Fatalf("security_audit.fail_on_levels missing %q", missing)
	}
}
