package kernel

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestSchemaIsValid(t *testing.T) {
	valid := []Schema{
		SchemaObservation, SchemaControl, SchemaOutput, SchemaDiagnose,
		SchemaDiff, SchemaBaseline, SchemaEnforce, SchemaGate,
		SchemaValidate, SchemaSnapshotPlan, SchemaSnapshotPrune,
		SchemaSnapshotQuality, SchemaSnapshotArchive, SchemaCIDiff,
		SchemaFixLoop, SchemaCrosswalkResolution, SchemaSecurityAudit,
		SchemaSecurityAuditArtifacts, SchemaSecurityAuditRunManifest,
		SchemaBugReport,
	}
	for _, s := range valid {
		if !s.IsValid() {
			t.Errorf("expected %q to be valid", s)
		}
	}
}

func TestSchemaIsValid_RejectsUnknown(t *testing.T) {
	invalid := []Schema{"", "unknown", "obs.v999", "ctrl.v0"}
	for _, s := range invalid {
		if s.IsValid() {
			t.Errorf("expected %q to be invalid", s)
		}
	}
}

func TestSchemaString(t *testing.T) {
	if got := SchemaOutput.String(); got != "out.v0.1" {
		t.Errorf("String() = %q, want %q", got, "out.v0.1")
	}
}

// TestSchemaConstants_AllSupported parses schema.go to find every Schema
// constant and verifies it returns IsValid() == true. This catches the case
// where a new constant is added but not registered in validSchemas.
func TestSchemaConstants_AllSupported(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "schema.go", nil, 0)
	if err != nil {
		t.Fatalf("parse schema.go: %v", err)
	}

	var constants []string
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			// Check if the type is Schema (explicit) or inferred from group
			isSchema := false
			if vs.Type != nil {
				if ident, ok := vs.Type.(*ast.Ident); ok && ident.Name == "Schema" {
					isSchema = true
				}
			}
			if !isSchema {
				continue
			}
			for _, name := range vs.Names {
				if name.Name == "_" || !name.IsExported() {
					continue
				}
				constants = append(constants, name.Name)
			}
		}
	}

	if len(constants) == 0 {
		t.Fatal("found no Schema constants in schema.go — parser may be broken")
	}

	// Map constant names to their values.
	knownConstants := map[string]Schema{
		"SchemaObservation":              SchemaObservation,
		"SchemaControl":                  SchemaControl,
		"SchemaOutput":                   SchemaOutput,
		"SchemaDiagnose":                 SchemaDiagnose,
		"SchemaDiff":                     SchemaDiff,
		"SchemaBaseline":                 SchemaBaseline,
		"SchemaEnforce":                  SchemaEnforce,
		"SchemaGate":                     SchemaGate,
		"SchemaValidate":                 SchemaValidate,
		"SchemaSnapshotPlan":             SchemaSnapshotPlan,
		"SchemaSnapshotPrune":            SchemaSnapshotPrune,
		"SchemaSnapshotQuality":          SchemaSnapshotQuality,
		"SchemaSnapshotArchive":          SchemaSnapshotArchive,
		"SchemaCIDiff":                   SchemaCIDiff,
		"SchemaFixLoop":                  SchemaFixLoop,
		"SchemaCrosswalkResolution":      SchemaCrosswalkResolution,
		"SchemaSecurityAudit":            SchemaSecurityAudit,
		"SchemaSecurityAuditArtifacts":   SchemaSecurityAuditArtifacts,
		"SchemaSecurityAuditRunManifest": SchemaSecurityAuditRunManifest,
		"SchemaBugReport":                SchemaBugReport,
	}

	for _, name := range constants {
		val, ok := knownConstants[name]
		if !ok {
			t.Errorf("Schema constant %s found in source but not in test map — add it to knownConstants", name)
			continue
		}
		if !val.IsValid() {
			t.Errorf("Schema constant %s (%q) is not registered in validSchemas", name, val)
		}
	}
}
