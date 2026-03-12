package kernel

import "testing"

func TestClassifyControlID(t *testing.T) {
	tests := []struct {
		name string
		id   ControlID
		want ControlClass
	}{
		{
			name: "public exposure control",
			id:   ControlID("CTL.S3.PUBLIC.001"),
			want: ClassPublicExposure,
		},
		{
			name: "acl write exposure control",
			id:   ControlID("CTL.S3.ACL.WRITE.001"),
			want: ClassPublicExposure,
		},
		{
			name: "encryption control",
			id:   ControlID("CTL.S3.ENCRYPT.001"),
			want: ClassEncryptionMissing,
		},
		{
			name: "baseline violation control",
			id:   ControlID("CTL.S3.LOG.001"),
			want: ClassBaselineViolation,
		},
		{
			name: "unknown control",
			id:   ControlID("CTL.UNKNOWN.001"),
			want: ClassUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.id.Classify(); got != tt.want {
				t.Fatalf("ControlID(%q).Classify() = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}
