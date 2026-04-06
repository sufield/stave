package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	staveversion "github.com/sufield/stave/internal/version"
)

func TestCapabilitiesJSONContract(t *testing.T) {
	origVersion := staveversion.String
	staveversion.String = "contract-test-version"
	t.Cleanup(func() {
		staveversion.String = origVersion
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
	assertObjectField(t, got, "inventory_support")
	assertObjectField(t, got, "policy_support")
	assertObjectField(t, got, "data_ingress")
	assertArrayField(t, got, "policy_library")
	assertObjectField(t, got, "compliance_support")

	if got["version"] != "contract-test-version" {
		t.Fatalf("version = %v, want %q", got["version"], "contract-test-version")
	}
	if offline, _ := got["offline"].(bool); !offline {
		t.Fatal("offline must be true")
	}

	inventory := got["inventory_support"].(map[string]any)
	policies := got["policy_support"].(map[string]any)
	ingress := got["data_ingress"].(map[string]any)
	library := got["policy_library"].([]any)
	compliance := got["compliance_support"].(map[string]any)

	schemas := assertArrayField(t, inventory, "schemas")
	policySchemas := assertArrayField(t, policies, "schemas")
	connectors := assertArrayField(t, ingress, "connectors")
	if len(schemas) == 0 {
		t.Fatal("inventory_support.schemas must be non-empty")
	}
	if len(policySchemas) == 0 {
		t.Fatal("policy_support.schemas must be non-empty")
	}
	if len(connectors) == 0 {
		t.Fatal("data_ingress.connectors must be non-empty")
	}
	if len(library) == 0 {
		t.Fatal("policy_library must be non-empty")
	}
	if enabled, ok := compliance["enabled"].(bool); !ok || !enabled {
		t.Fatal("compliance_support.enabled must be true")
	}
	if formats := assertArrayField(t, compliance, "report_formats"); len(formats) == 0 {
		t.Fatal("compliance_support.report_formats must be non-empty")
	}
	if sbom := assertArrayField(t, compliance, "sbom_formats"); len(sbom) == 0 {
		t.Fatal("compliance_support.sbom_formats must be non-empty")
	}
	if vuln := assertArrayField(t, compliance, "vuln_sources"); len(vuln) == 0 {
		t.Fatal("compliance_support.vuln_sources must be non-empty")
	}
	if failOn := assertArrayField(t, compliance, "sla_thresholds"); len(failOn) == 0 {
		t.Fatal("compliance_support.sla_thresholds must be non-empty")
	}
	if frameworks := assertArrayField(t, compliance, "security_frameworks"); len(frameworks) == 0 {
		t.Fatal("compliance_support.security_frameworks must be non-empty")
	}

	validateConnectors(t, connectors)
	validateLibrary(t, library)
}

func validateConnectors(t *testing.T, connectors []any) {
	t.Helper()
	foundS3Snapshot := false
	for i, raw := range connectors {
		obj, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("data_ingress.connectors[%d] must be an object", i)
		}
		typ, ok := obj["type"].(string)
		if !ok || typ == "" {
			t.Fatalf("data_ingress.connectors[%d].type must be a non-empty string", i)
		}
		if typ == "aws-s3-snapshot" {
			foundS3Snapshot = true
		}
	}
	if !foundS3Snapshot {
		t.Fatal("data_ingress.connectors missing aws-s3-snapshot")
	}
}

func validateLibrary(t *testing.T, library []any) {
	t.Helper()
	foundS3Pack := false
	for i, raw := range library {
		obj, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("policy_library[%d] must be an object", i)
		}
		name, ok := obj["name"].(string)
		if !ok || name == "" {
			t.Fatalf("policy_library[%d].name must be a non-empty string", i)
		}
		if _, ok := obj["description"].(string); !ok {
			t.Fatalf("policy_library[%d].description must be a string", i)
		}
		if v, ok := obj["version"].(string); !ok || v != "contract-test-version" {
			t.Fatalf("policy_library[%d].version = %v, want %q", i, obj["version"], "contract-test-version")
		}
		if name == "s3" {
			foundS3Pack = true
		}
	}
	if !foundS3Pack {
		t.Fatal("policy_library missing required s3 pack")
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
