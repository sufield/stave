package doctor

import (
	"testing"
)

func TestDiagnosticSuite_Execute_HandlesNilProbe(t *testing.T) {
	suite := NewSuite(
		func(env *SystemEnvironment) Diagnostic {
			return Diagnostic{Name: "valid_probe"}
		},
		nil, // nil probe in suite
	)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("DiagnosticSuite.Execute panicked on nil probe: %v", r)
		}
	}()

	diags, ready := suite.Execute(nil)
	if !ready {
		t.Errorf("expected ready=true")
	}
	if len(diags) != 1 {
		t.Errorf("expected 1 valid diagnostic, got %d", len(diags))
	}
}
