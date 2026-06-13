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
		{"cognito mfa", "cognito/auth", "CTL.COGNITO.MFA.001", []string{"IAM-14"}},
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
	seen := map[string]struct{}{}
	for _, c := range got {
		if _, ok := seen[c]; ok {
			t.Errorf("Infer returned duplicate CCM %q in %v", c, got)
		}
		seen[c] = struct{}{}
	}
}

// --- Regression guards for the three systemic patterns identified in
// the iteration A1 post-back-fill spot-check.

// TestCognitoDoesNotMapToAIS01 locks in the rule inversion: AIS-01 is
// an application-interface-policy CCM, not an identity-provider one.
// Every Cognito control previously inherited AIS-01 unconditionally,
// which made "show me AIS-01 coverage" queries return false positives.
func TestCognitoDoesNotMapToAIS01(t *testing.T) {
	cases := []struct {
		dir, id string
	}{
		{"cognito/auth", "CTL.COGNITO.MFA.001"},
		{"cognito/auth", "CTL.COGNITO.PASSWORD.001"},
		{"cognito/auth", "CTL.COGNITO.ADVANCED.SECURITY.001"},
		{"cognito/misc", "CTL.COGNITO.INCOMPLETE.001"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			got := Infer(tc.dir, tc.id)
			if slices.Contains(got, "AIS-01") {
				t.Errorf("Infer(%q, %q) = %v, should not contain AIS-01", tc.dir, tc.id, got)
			}
		})
	}
}

// TestConfigAuditDoesNotMapToAccessLogs locks in the audit-cascade
// narrowing: Config, Guardrail, SecurityHub, and CloudFormation are
// config-evaluation services. Their "audit/" subdirs are about
// compliance audits, not about producing audit logs, so LOG-05 and
// LOG-12 must not cascade onto them.
func TestConfigAuditDoesNotMapToAccessLogs(t *testing.T) {
	cases := []struct {
		dir, id string
	}{
		{"config/audit", "CTL.CONFIG.RULES.001"},
		{"config/audit", "CTL.CONFIG.ENABLED.001"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			got := Infer(tc.dir, tc.id)
			for _, bad := range []string{"LOG-05", "LOG-12"} {
				if slices.Contains(got, bad) {
					t.Errorf("Infer(%q, %q) = %v, should not contain %s", tc.dir, tc.id, got, bad)
				}
			}
			for _, want := range []string{"CCC-04", "CCC-07"} {
				if !slices.Contains(got, want) {
					t.Errorf("Infer(%q, %q) = %v, missing canonical %s", tc.dir, tc.id, got, want)
				}
			}
		})
	}
}

// TestTruncationPrefersServiceLayer locks in the priority-sort fix for
// cap overflow: when >5 CCMs are candidates, the least-specific layer's
// CCMs must be the ones dropped, not the alphabetically-late canonical
// CCMs. This is exercised by synthesising a control whose service rule
// adds CCC-* (priority 1) and whose subcategory rule would push past
// the cap with LOG-* (priority 2). CCC-04 and CCC-07 must survive.
func TestTruncationPrefersServiceLayer(t *testing.T) {
	// config/audit is the real failure case: service rule adds
	// CCC-04, CCC-07, LOG-03 (priority 1). With the audit-cascade
	// fix applied the subcategory layer no longer fires here, so
	// this test is a defense in depth — even if a future rule
	// change reintroduced noise, CCC-* must remain in the output.
	got := Infer("config/audit", "CTL.CONFIG.RULES.001")
	if len(got) > 5 {
		t.Fatalf("Infer returned %d CCMs, want ≤5: %v", len(got), got)
	}
	for _, want := range []string{"CCC-04", "CCC-07"} {
		if !slices.Contains(got, want) {
			t.Errorf("Infer = %v, missing canonical %s after truncation", got, want)
		}
	}
}
