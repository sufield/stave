package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// TestWriteSBOM_CycloneDXSchemaValid covers the smallest useful slice
// of SBOM coverage from sbom-test.md Iteration 1: one fixture, one
// format, existence + schema validation.
//
// Levels 1+2: the writeSBOM helper produces non-empty output that
// parses as JSON and validates against the official CycloneDX 1.5
// JSON Schema (vendored at testdata/sbom/cyclonedx-1.5.schema.json).
//
// Level 3 (golden content) and Level 4 (release wiring) remain
// uncovered; see sbom-test.md for the iteration plan.
func TestWriteSBOM_CycloneDXSchemaValid(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSBOM(&buf, EditionProd); err != nil {
		t.Fatalf("writeSBOM: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("writeSBOM produced empty output")
	}

	var doc any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, buf.String())
	}

	// CycloneDX 1.5 references jsf-0.82 (JSON Signature Format) and
	// spdx.schema.json. Register all three before compiling so the
	// validator stays fully offline.
	c := jsonschema.NewCompiler()
	schemas := []struct {
		path, id string
	}{
		{"cyclonedx-1.5.schema.json", "http://cyclonedx.org/schema/bom-1.5.schema.json"},
		{"jsf-0.82.schema.json", "http://cyclonedx.org/schema/jsf-0.82.schema.json"},
		{"spdx.schema.json", "http://cyclonedx.org/schema/spdx.schema.json"},
	}
	for _, sch := range schemas {
		schemaPath := filepath.Join("testdata", "sbom", sch.path)
		schemaBytes, err := os.ReadFile(schemaPath)
		if err != nil {
			t.Fatalf("reading vendored schema %s: %v", schemaPath, err)
		}
		var schemaDoc any
		if err := json.Unmarshal(schemaBytes, &schemaDoc); err != nil {
			t.Fatalf("%s: invalid JSON: %v", sch.path, err)
		}
		if err := c.AddResource(sch.id, schemaDoc); err != nil {
			t.Fatalf("AddResource %s: %v", sch.id, err)
		}
	}

	s, err := c.Compile("http://cyclonedx.org/schema/bom-1.5.schema.json")
	if err != nil {
		t.Fatalf("schema compile: %v", err)
	}
	if err := s.Validate(doc); err != nil {
		t.Errorf("output failed CycloneDX 1.5 schema validation: %v", err)
	}
}
