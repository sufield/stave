package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	staveversion "github.com/sufield/stave/internal/version"
)

func TestCapabilitiesJSONContract(t *testing.T) {
	origVersion := staveversion.Version
	staveversion.Version = "contract-test-version"
	t.Cleanup(func() {
		staveversion.Version = origVersion
	})

	var out bytes.Buffer
	cmd := newCapabilitiesCmd()
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("capabilities command error: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("capabilities output is not valid JSON: %v", err)
	}

	assertStringField(t, got, "version")
	assertBoolField(t, got, "offline")
	assertObjectField(t, got, "observations")
	assertObjectField(t, got, "controls")
	assertObjectField(t, got, "inputs")
	assertArrayField(t, got, "packs")
	assertObjectField(t, got, "security_audit")

	if got["version"] != "contract-test-version" {
		t.Fatalf("version = %v, want %q", got["version"], "contract-test-version")
	}
	if offline, _ := got["offline"].(bool); !offline {
		t.Fatal("offline must be true")
	}

	observations := got["observations"].(map[string]any)
	controls := got["controls"].(map[string]any)
	inputs := got["inputs"].(map[string]any)
	packs := got["packs"].([]any)
	securityAudit := got["security_audit"].(map[string]any)

	schemaVersions := assertArrayField(t, observations, "schema_versions")
	dslVersions := assertArrayField(t, controls, "dsl_versions")
	sourceTypes := assertArrayField(t, inputs, "source_types")
	if len(schemaVersions) == 0 {
		t.Fatal("observations.schema_versions must be non-empty")
	}
	if len(dslVersions) == 0 {
		t.Fatal("controls.dsl_versions must be non-empty")
	}
	if len(sourceTypes) == 0 {
		t.Fatal("inputs.source_types must be non-empty")
	}
	if len(packs) == 0 {
		t.Fatal("packs must be non-empty")
	}
	if enabled, ok := securityAudit["enabled"].(bool); !ok || !enabled {
		t.Fatal("security_audit.enabled must be true")
	}
	if formats := assertArrayField(t, securityAudit, "formats"); len(formats) == 0 {
		t.Fatal("security_audit.formats must be non-empty")
	}
	if sbom := assertArrayField(t, securityAudit, "sbom_formats"); len(sbom) == 0 {
		t.Fatal("security_audit.sbom_formats must be non-empty")
	}
	if vuln := assertArrayField(t, securityAudit, "vuln_sources"); len(vuln) == 0 {
		t.Fatal("security_audit.vuln_sources must be non-empty")
	}
	if failOn := assertArrayField(t, securityAudit, "fail_on_levels"); len(failOn) == 0 {
		t.Fatal("security_audit.fail_on_levels must be non-empty")
	}
	if frameworks := assertArrayField(t, securityAudit, "compliance_frameworks"); len(frameworks) == 0 {
		t.Fatal("security_audit.compliance_frameworks must be non-empty")
	}

	validateSourceTypes(t, sourceTypes)
	validatePacks(t, packs)
}

func validateSourceTypes(t *testing.T, sourceTypes []any) {
	t.Helper()
	foundS3Snapshot := false
	for i, raw := range sourceTypes {
		obj, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("inputs.source_types[%d] must be an object", i)
		}
		typ, ok := obj["type"].(string)
		if !ok || typ == "" {
			t.Fatalf("inputs.source_types[%d].type must be a non-empty string", i)
		}
		if typ == "aws-s3-snapshot" {
			foundS3Snapshot = true
		}
	}
	if !foundS3Snapshot {
		t.Fatal("inputs.source_types missing aws-s3-snapshot")
	}
}

func validatePacks(t *testing.T, packs []any) {
	t.Helper()
	foundS3Pack := false
	for i, raw := range packs {
		obj, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("packs[%d] must be an object", i)
		}
		name, ok := obj["name"].(string)
		if !ok || name == "" {
			t.Fatalf("packs[%d].name must be a non-empty string", i)
		}
		if _, ok := obj["path"].(string); !ok {
			t.Fatalf("packs[%d].path must be a string", i)
		}
		if v, ok := obj["version"].(string); !ok || v != "contract-test-version" {
			t.Fatalf("packs[%d].version = %v, want %q", i, obj["version"], "contract-test-version")
		}
		if name == "s3" {
			foundS3Pack = true
		}
	}
	if !foundS3Pack {
		t.Fatal("packs missing required s3 pack")
	}
}

func assertStringField(t *testing.T, obj map[string]any, key string) string {
	t.Helper()
	val, ok := obj[key]
	if !ok {
		t.Fatalf("missing required field %q", key)
	}
	s, ok := val.(string)
	if !ok || s == "" {
		t.Fatalf("field %q must be a non-empty string", key)
	}
	return s
}

func assertBoolField(t *testing.T, obj map[string]any, key string) bool {
	t.Helper()
	val, ok := obj[key]
	if !ok {
		t.Fatalf("missing required field %q", key)
	}
	b, ok := val.(bool)
	if !ok {
		t.Fatalf("field %q must be a bool", key)
	}
	return b
}

func assertObjectField(t *testing.T, obj map[string]any, key string) map[string]any {
	t.Helper()
	val, ok := obj[key]
	if !ok {
		t.Fatalf("missing required field %q", key)
	}
	m, ok := val.(map[string]any)
	if !ok {
		t.Fatalf("field %q must be an object", key)
	}
	return m
}

func assertArrayField(t *testing.T, obj map[string]any, key string) []any {
	t.Helper()
	val, ok := obj[key]
	if !ok {
		t.Fatalf("missing required field %q", key)
	}
	arr, ok := val.([]any)
	if !ok {
		t.Fatalf("field %q must be an array", key)
	}
	return arr
}
