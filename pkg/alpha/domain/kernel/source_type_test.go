package kernel

import "testing"

func TestObservationSourceTypeString(t *testing.T) {
	tests := []struct {
		st   ObservationSourceType
		want string
	}{
		{SourceTypeTerraformPlanJSON, "terraform.plan_json"},
		{SourceTypeAWSS3Snapshot, "aws-s3-snapshot"},
	}
	for _, tt := range tests {
		if got := tt.st.String(); got != tt.want {
			t.Errorf("String() = %q, want %q", got, tt.want)
		}
	}
}

func TestObservationSourceTypeIsEmpty(t *testing.T) {
	if !ObservationSourceType("").IsEmpty() {
		t.Error("empty string should be empty")
	}
	if SourceTypeTerraformPlanJSON.IsEmpty() {
		t.Error("SourceTypeTerraformPlanJSON should not be empty")
	}
}
