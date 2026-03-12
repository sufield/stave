package kernel

import "testing"

func TestClassifyControlID(t *testing.T) {
	tests := []struct {
		name string
		id   ControlID
		want ControlClass
	}{
		{
			name: "S3 public exposure",
			id:   ControlID("CTL.S3.PUBLIC.001"),
			want: ClassPublicExposure,
		},
		{
			name: "ACL write exposure",
			id:   ControlID("CTL.S3.ACL.WRITE.001"),
			want: ClassPublicExposure,
		},
		{
			name: "Azure storage public exposure",
			id:   ControlID("CTL.BLOB.PUBLIC.001"),
			want: ClassPublicExposure,
		},
		{
			name: "takeover exposure",
			id:   ControlID("CTL.DNS.TAKEOVER.001"),
			want: ClassPublicExposure,
		},
		{
			name: "S3 encryption control",
			id:   ControlID("CTL.S3.ENCRYPT.001"),
			want: ClassEncryptionMissing,
		},
		{
			name: "KMS encryption control",
			id:   ControlID("CTL.RDS.KMS.001"),
			want: ClassEncryptionMissing,
		},
		{
			name: "SSE encryption control",
			id:   ControlID("CTL.S3.SSE.001"),
			want: ClassEncryptionMissing,
		},
		{
			name: "baseline violation",
			id:   ControlID("CTL.S3.LOG.001"),
			want: ClassBaselineViolation,
		},
		{
			name: "case insensitive",
			id:   ControlID("ctl.s3.public.001"),
			want: ClassPublicExposure,
		},
		{
			name: "unknown control prefix",
			id:   ControlID("CUSTOM.ALERT"),
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

func TestControlClassString(t *testing.T) {
	tests := []struct {
		class ControlClass
		want  string
	}{
		{ClassPublicExposure, "public_exposure"},
		{ClassEncryptionMissing, "encryption_missing"},
		{ClassBaselineViolation, "baseline_violation"},
		{ClassUnknown, "unknown"},
	}

	for _, tt := range tests {
		if got := tt.class.String(); got != tt.want {
			t.Fatalf("ControlClass(%d).String() = %q, want %q", tt.class, got, tt.want)
		}
	}
}
