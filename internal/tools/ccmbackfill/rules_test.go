package ccmbackfill

import (
	"slices"
	"testing"
)

// TestInferAuditAttributions locks in the mappings that the CSA Top-5
// coverage audit (docs/design-notes/csa-top5-coverage-audit.md) anchored
// explicitly. If a directory + ID pair loses its expected CCM here, the
// back-fill rules regressed on a known-good attribution.
func TestInferAuditAttributions(t *testing.T) {
	cases := []struct {
		name     string
		dir      string
		id       string
		expected []string // at minimum — rule may add more
	}{
		// IAM family — Category 2 anchors
		{"root MFA", "iam/root", "CTL.IAM.ROOT.MFA.001", []string{"IAM-14"}},
		{"policy admin", "iam/policy", "CTL.IAM.POLICY.ADMIN.001", []string{"IAM-05", "IAM-16"}},
		{"password policy", "iam/password", "CTL.IAM.PASSWORD.LENGTH.001", []string{"IAM-15"}},
		{"credentials unused", "iam/credentials", "CTL.IAM.CRED.UNUSED.001", []string{"IAM-02", "IAM-08"}},
		{"scp full access", "iam/scp", "CTL.IAM.SCP.FULLACCESS.001", []string{"IAM-10"}},
		{"analyzer monitor (drift)", "iam/analyzer", "CTL.IAM.ANALYZER.MONITOR.001", []string{"IAM-03", "CCC-07"}},
		{"separation of duties", "iam/policy", "CTL.IAM.POLICY.SOD.001", []string{"IAM-04"}},

		// Storage encryption — CEK-03 anchor
		{"s3 encrypt", "s3/encrypt", "CTL.S3.ENCRYPT.001", []string{"CEK-03"}},
		{"rds encrypt", "rds/encrypt", "CTL.RDS.ENCRYPT.001", []string{"CEK-03"}},
		{"efs encrypt", "efs/encrypt", "CTL.EFS.ENCRYPT.001", []string{"CEK-03"}},

		// Storage exposure — DSP-17 anchor
		{"s3 public", "s3/public", "CTL.S3.PUBLIC.001", []string{"DSP-17"}},
		{"s3 access", "s3/access", "CTL.S3.ACCESS.001", []string{"DSP-17"}},
		{"rds public", "rds/public", "CTL.RDS.PUBLIC.001", []string{"DSP-17"}},

		// Network — IVS-03 anchor
		{"vpc sg unrestricted", "vpc/security", "CTL.VPC.SG.UNRESTRICTED.001", []string{"IVS-03"}},
		{"ec2 sg", "ec2/sg", "CTL.EC2.SG.INGRESS.CIDR.001", []string{"IVS-03"}},

		// Logging — LOG-05 / LOG-12 anchors
		{"cloudtrail enabled", "cloudtrail", "CTL.CLOUDTRAIL.ENABLED.001", []string{"LOG-05"}},
		{"s3 log", "s3/logging", "CTL.S3.LOG.001", []string{"LOG-12"}},

		// Change / drift — CCC anchors
		{"cloudformation drift", "cloudformation", "CTL.CLOUDFORMATION.DRIFT.001", []string{"CCC-04", "CCC-07"}},
		{"config rules", "config", "CTL.CONFIG.RULES.001", []string{"CCC-04", "CCC-07"}},

		// Backup — BCR-08
		{"backup encrypt", "backup", "CTL.BACKUP.ENCRYPT.001", []string{"BCR-08"}},

		// K8s hardening — IVS-04
		{"k8s apiserver", "k8s/apiserver", "CTL.K8S.APISERVER.AUTH.MODE.001", []string{"IVS-04"}},

		// Cognito / API Gateway — AIS-01
		{"apigateway auth", "apigateway", "CTL.APIGATEWAY.AUTH.001", []string{"AIS-01"}},
		{"cognito mfa", "cognito/auth", "CTL.COGNITO.MFA.001", []string{"AIS-01", "IAM-14"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Infer(tc.dir, tc.id)
			for _, want := range tc.expected {
				if !slices.Contains(got, want) {
					t.Errorf("Infer(%q, %q) = %v, missing expected CCM %q", tc.dir, tc.id, got, want)
				}
			}
		})
	}
}

// TestInferCapsAtFive enforces the "max 5 CCMs per control" rule. The
// Infer function's upper bound prevents mappings from becoming noise.
func TestInferCapsAtFive(t *testing.T) {
	// Construct a worst-case hit: an IAM policy control with tokens
	// that trigger many add() calls — MFA, BOUNDARY, CROSSCLOUD, SOD.
	got := Infer("iam/policy", "CTL.IAM.POLICY.CROSSCLOUD.MFA.BOUNDARY.SOD.001")
	if len(got) > 5 {
		t.Errorf("Infer returned %d CCMs, want ≤5: %v", len(got), got)
	}
}

// TestInferUnknownServiceReturnsNil exercises the conservative bias:
// when a directory doesn't match any rule, return nil rather than
// guessing.
func TestInferUnknownServiceReturnsNil(t *testing.T) {
	got := Infer("unknown-service", "CTL.UNKNOWN.001")
	if got != nil {
		t.Errorf("Infer(unknown-service) = %v, want nil", got)
	}
}

// TestInferDeduplicates ensures repeated add() calls collapse to unique
// CCM IDs.
func TestInferDeduplicates(t *testing.T) {
	got := Infer("s3/encrypt", "CTL.S3.ENCRYPT.001")
	seen := map[string]bool{}
	for _, c := range got {
		if seen[c] {
			t.Errorf("Infer returned duplicate CCM %q in %v", c, got)
		}
		seen[c] = true
	}
}
