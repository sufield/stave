package kernel

import (
	"encoding/json"
	"testing"
)

// Tests for uncovered functions in files that already have test files.

func TestAssetType_MarshalJSON(t *testing.T) {
	at := AssetType("aws_s3_bucket")
	data, err := json.Marshal(at)
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	if string(data) != `"aws_s3_bucket"` {
		t.Errorf("got %s, want %q", data, "aws_s3_bucket")
	}

	// Empty asset type marshals as "unknown".
	empty := AssetType("")
	data, err = json.Marshal(empty)
	if err != nil {
		t.Fatalf("MarshalJSON(empty) error: %v", err)
	}
	if string(data) != `"unknown"` {
		t.Errorf("got %s, want %q", data, "unknown")
	}
}

func TestObservationSourceType_String(t *testing.T) {
	st := SourceTypeAWSS3Snapshot
	if got := st.String(); got != "aws-s3-snapshot" {
		t.Errorf("String() = %q, want %q", got, "aws-s3-snapshot")
	}
	empty := ObservationSourceType("")
	if got := empty.String(); got != "" {
		t.Errorf("empty String() = %q, want empty", got)
	}
}

func TestPrincipalScope_IsPublic(t *testing.T) {
	if !ScopePublic.IsPublic() {
		t.Error("ScopePublic.IsPublic() = false, want true")
	}
	if ScopeAuthenticated.IsPublic() {
		t.Error("ScopeAuthenticated.IsPublic() = true, want false")
	}
	if ScopeUnknown.IsPublic() {
		t.Error("ScopeUnknown.IsPublic() = true, want false")
	}
}

func TestPrincipalScope_MarshalYAML(t *testing.T) {
	got, err := ScopePublic.MarshalYAML()
	if err != nil {
		t.Fatalf("MarshalYAML error: %v", err)
	}
	if got != "public" {
		t.Errorf("MarshalYAML = %v, want %q", got, "public")
	}
}

func TestNetworkScope_MarshalYAML(t *testing.T) {
	got, err := NetworkScopeVPCRestricted.MarshalYAML()
	if err != nil {
		t.Fatalf("MarshalYAML error: %v", err)
	}
	if got != "vpc-restricted" {
		t.Errorf("MarshalYAML = %v, want %q", got, "vpc-restricted")
	}
}

func TestTrustBoundary_MarshalYAML(t *testing.T) {
	got, err := BoundaryExternal.MarshalYAML()
	if err != nil {
		t.Fatalf("MarshalYAML error: %v", err)
	}
	if got != "external" {
		t.Errorf("MarshalYAML = %v, want %q", got, "external")
	}
}

func TestControlID_Category_ShortID(t *testing.T) {
	// Two-part ID like "CTL.S3" has no middle segments.
	id := ControlID("CTL.S3")
	if got := id.Category(); got != "" {
		t.Errorf("Category() for two-part ID = %q, want empty", got)
	}

	// One-part ID.
	id2 := ControlID("CTL")
	if got := id2.Category(); got != "" {
		t.Errorf("Category() for one-part ID = %q, want empty", got)
	}

	// Three-part ID returns the middle.
	id3 := ControlID("CTL.S3.PUBLIC")
	if got := id3.Category(); got != "PUBLIC" {
		t.Errorf("Category() for three-part ID = %q, want %q", got, "PUBLIC")
	}
}

func TestControlID_Provider_ShortID(t *testing.T) {
	id := ControlID("CTL")
	if got := id.Provider(); got != "" {
		t.Errorf("Provider() for single-part ID = %q, want empty", got)
	}
}
