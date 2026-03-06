package predicate

import "testing"

func TestS3ControlsCompliance(t *testing.T) {
	tests := []struct {
		name     string
		fieldVal any
		matchVal any
		op       string // "eq", "ne", "gt"
		expected bool
	}{
		// 1. Public Access (CTL.S3.CONTROLS.001)
		{"PAB fully blocked (canonical)", true, true, "eq", true},
		{"PAB fully blocked (stringified)", "true", true, "eq", true},
		{"PAB partially blocked (casing)", " TRUE ", true, "eq", true},
		{"PAB not blocked (ne check)", "false", true, "ne", true},

		// 2. Encryption Flags (CTL.S3.ENCRYPT.001 / 002)
		{"Encryption at_rest_enabled (bool)", true, true, "eq", true},
		{"Encryption at_rest_enabled (string)", "true", true, "eq", true},
		{"In-transit enforced mismatch", false, "true", "eq", false},

		// 3. Algorithms & Object Lock Modes (CTL.S3.ENCRYPT.003 / LOCK.002)
		{"Algorithm AES256 match", "AES256", "aes256", "eq", true},
		{"Algorithm KMS match", "aws:kms", "AWS:KMS", "eq", true},
		{"Lock Mode COMPLIANCE match", "COMPLIANCE", "compliance", "eq", true},
		{"Lock Mode GOVERNANCE ne", "GOVERNANCE", "compliance", "ne", true},

		// 4. Numeric Lifecycle & Retention (CTL.S3.LIFECYCLE.002 / LOCK.003)
		{"Retention days match (string-int)", "90", 90, "eq", true},
		{"Retention days match (padded)", " 7 ", 7, "eq", true},
		{"Retention threshold met", 100, 90, "gt", true},
		{"Versioning count normalization", "5", 5, "eq", true},

		// 5. KMS Key ID & Missing Fields (CTL.S3.ENCRYPT.003)
		{"KMS Key ID present ne check", "arn:aws:kms:...", "", "ne", true},
		{"KMS Key ID missing (nil) ne empty", nil, "", "ne", true},
		{"KMS Key ID empty string eq empty", "", "", "eq", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got bool
			switch tt.op {
			case "eq":
				got = EqualValues(tt.fieldVal, tt.matchVal)
			case "ne":
				got = !EqualValues(tt.fieldVal, tt.matchVal)
			case "gt":
				got = GreaterThan(tt.fieldVal, tt.matchVal)
			default:
				t.Fatalf("unsupported op %q", tt.op)
			}

			if got != tt.expected {
				t.Errorf("[%s] fail: input(%v) %s match(%v) -> got %v, want %v", tt.name, tt.fieldVal, tt.op, tt.matchVal, got, tt.expected)
			}
		})
	}
}
