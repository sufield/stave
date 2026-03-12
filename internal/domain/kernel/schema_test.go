package kernel

import "testing"

func TestSchemaIsValid(t *testing.T) {
	valid := []Schema{
		SchemaObservation, SchemaControl, SchemaOutput, SchemaDiagnose,
		SchemaDiff, SchemaBaseline, SchemaEnforce, SchemaGate,
		SchemaValidate, SchemaSnapshotPlan, SchemaSnapshotPrune,
		SchemaSnapshotQuality, SchemaSnapshotArchive, SchemaCIDiff,
		SchemaFixLoop, SchemaCrosswalkResolution, SchemaSecurityAudit,
		SchemaSecurityAuditArtifacts, SchemaSecurityAuditRunManifest,
		SchemaBugReport, SchemaDemoReport,
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
