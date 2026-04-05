package builtin

import (
	"testing"

	"github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/builtin/predicate"
	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// TestHIPAAControlsExistInPack verifies that all 4 new HIPAA controls
// are registered in the HIPAA pack and loadable from the embedded registry.
func TestHIPAAControlsExistInPack(t *testing.T) {
	reg, err := pack.NewEmbeddedRegistry()
	if err != nil {
		t.Fatalf("NewEmbeddedRegistry: %v", err)
	}

	hipaa, ok := reg.LookupPack("hipaa")
	if !ok {
		t.Fatal("hipaa pack not found")
	}

	required := []kernel.ControlID{
		"CTL.S3.AUDIT.OBJECTLEVEL.001",
		"CTL.S3.NETWORK.VPC.001",
		"CTL.S3.NETWORK.POLICY.001",
		"CTL.S3.PRESIGNED.001",
	}

	controlSet := make(map[kernel.ControlID]bool)
	for _, id := range hipaa.Controls {
		controlSet[id] = true
	}

	for _, id := range required {
		if !controlSet[id] {
			t.Errorf("HIPAA pack missing control %s", id)
		}
	}
}

// TestHIPAAControlsLoadAndParse verifies that each new control can be
// loaded from the embedded filesystem and parsed into a ControlDefinition.
func TestHIPAAControlsLoadAndParse(t *testing.T) {
	byID := loadAllControls(t)

	tests := []struct {
		id       kernel.ControlID
		severity policy.Severity
		hipaa    string
	}{
		{"CTL.S3.NETWORK.VPC.001", policy.SeverityHigh, "164.312(e)(1)"},
		{"CTL.S3.NETWORK.POLICY.001", policy.SeverityHigh, "164.312(e)(1)"},
		{"CTL.S3.PRESIGNED.001", policy.SeverityMedium, "164.312(a)(1)"},
		{"CTL.S3.AUDIT.OBJECTLEVEL.001", policy.SeverityHigh, "164.312(b)"},
	}

	for _, tt := range tests {
		t.Run(string(tt.id), func(t *testing.T) {
			ctl, ok := byID[tt.id]
			if !ok {
				t.Fatalf("control %s not found in embedded registry", tt.id)
			}
			if ctl.Severity != tt.severity {
				t.Errorf("severity = %v, want %v", ctl.Severity, tt.severity)
			}
			if ctl.Compliance.Get("hipaa") != tt.hipaa {
				t.Errorf("hipaa compliance = %q, want %q", ctl.Compliance.Get("hipaa"), tt.hipaa)
			}
		})
	}
}

// TestHIPAAControl_NetworkVPC evaluates CTL.S3.NETWORK.VPC.001 against
// pass and fail observations using the CEL engine.
func TestHIPAAControl_NetworkVPC(t *testing.T) {
	ctl := mustLoadControl(t, "CTL.S3.NETWORK.VPC.001")
	eval := mustCELEval(t)

	tests := []struct {
		name   string
		access map[string]any
		unsafe bool
	}{
		{"vpc condition present", map[string]any{"has_vpc_condition": true, "has_ip_condition": false}, false},
		{"ip condition present", map[string]any{"has_vpc_condition": false, "has_ip_condition": true}, false},
		{"both present", map[string]any{"has_vpc_condition": true, "has_ip_condition": true}, false},
		{"neither present", map[string]any{"has_vpc_condition": false, "has_ip_condition": false}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAsset(map[string]any{
				"storage": map[string]any{"kind": "bucket", "access": tt.access},
			})
			got, err := eval(ctl, a, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if got != tt.unsafe {
				t.Errorf("unsafe = %v, want %v", got, tt.unsafe)
			}
		})
	}
}

// TestHIPAAControl_NetworkPolicy evaluates CTL.S3.NETWORK.POLICY.001.
func TestHIPAAControl_NetworkPolicy(t *testing.T) {
	ctl := mustLoadControl(t, "CTL.S3.NETWORK.POLICY.001")
	eval := mustCELEval(t)

	tests := []struct {
		name    string
		network map[string]any
		unsafe  bool
	}{
		{"restrictive policy", map[string]any{"vpc_endpoint_policy": map[string]any{"attached": true, "is_default_full_access": false}}, false},
		{"default full access", map[string]any{"vpc_endpoint_policy": map[string]any{"attached": true, "is_default_full_access": true}}, true},
		{"not attached", map[string]any{"vpc_endpoint_policy": map[string]any{"attached": false}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAsset(map[string]any{
				"storage": map[string]any{"kind": "bucket", "network": tt.network},
			})
			got, err := eval(ctl, a, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if got != tt.unsafe {
				t.Errorf("unsafe = %v, want %v", got, tt.unsafe)
			}
		})
	}
}

// TestHIPAAControl_PresignedURL evaluates CTL.S3.PRESIGNED.001.
func TestHIPAAControl_PresignedURL(t *testing.T) {
	ctl := mustLoadControl(t, "CTL.S3.PRESIGNED.001")
	eval := mustCELEval(t)

	tests := []struct {
		name   string
		access map[string]any
		unsafe bool
	}{
		{"restricted", map[string]any{"presigned_url_restricted": true}, false},
		{"unrestricted", map[string]any{"presigned_url_restricted": false}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAsset(map[string]any{
				"storage": map[string]any{"kind": "bucket", "access": tt.access},
			})
			got, err := eval(ctl, a, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if got != tt.unsafe {
				t.Errorf("unsafe = %v, want %v", got, tt.unsafe)
			}
		})
	}
}

// TestHIPAAControl_AuditObjectLevel evaluates CTL.S3.AUDIT.OBJECTLEVEL.001.
func TestHIPAAControl_AuditObjectLevel(t *testing.T) {
	ctl := mustLoadControl(t, "CTL.S3.AUDIT.OBJECTLEVEL.001")
	eval := mustCELEval(t)

	tests := []struct {
		name    string
		logging map[string]any
		unsafe  bool
	}{
		{"enabled", map[string]any{"object_level_logging": map[string]any{"enabled": true}}, false},
		{"disabled", map[string]any{"object_level_logging": map[string]any{"enabled": false}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAsset(map[string]any{
				"storage": map[string]any{"kind": "bucket", "logging": tt.logging},
			})
			got, err := eval(ctl, a, nil)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if got != tt.unsafe {
				t.Errorf("unsafe = %v, want %v", got, tt.unsafe)
			}
		})
	}
}

// --- Test helpers ---

func loadAllControls(t *testing.T) map[kernel.ControlID]policy.ControlDefinition {
	t.Helper()
	ctlReg := NewControlStore(EmbeddedFS(), "embedded", WithAliasResolver(predicate.ResolverFunc()))
	controls, err := ctlReg.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	byID := make(map[kernel.ControlID]policy.ControlDefinition, len(controls))
	for _, c := range controls {
		byID[c.ID] = c
	}
	return byID
}

func mustLoadControl(t *testing.T, id kernel.ControlID) policy.ControlDefinition {
	t.Helper()
	byID := loadAllControls(t)
	ctl, ok := byID[id]
	if !ok {
		t.Fatalf("control %s not found in embedded registry", id)
	}
	return ctl
}

func mustCELEval(t *testing.T) policy.PredicateEval {
	t.Helper()
	eval, err := stavecel.NewPredicateEval()
	if err != nil {
		t.Fatalf("NewPredicateEval: %v", err)
	}
	return eval
}

func testAsset(properties map[string]any) asset.Asset {
	return asset.Asset{
		ID:         "test-bucket",
		Type:       "aws_s3_bucket",
		Vendor:     "aws",
		Properties: properties,
	}
}
