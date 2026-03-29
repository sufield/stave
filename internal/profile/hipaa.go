package profile

import "github.com/sufield/stave/internal/core/hipaa"

func init() {
	RegisterProfile(&Profile{
		ID:          "hipaa",
		Name:        "HIPAA Security Rule",
		Description: "S3 configuration invariants required for HIPAA compliance covering access control, encryption, audit logging, integrity, and retention.",
		Controls: []ProfileControl{
			// --- CRITICAL ---
			{
				ControlID:     "CONTROLS.001.STRICT",
				ComplianceRef: "§164.312(a)(2)(iv)",
				Rationale:     "CMK required for key revocation during breach response",
			},
			{
				ControlID:     "CONTROLS.004",
				ComplianceRef: "§164.312(e)(2)(ii)",
				Rationale:     "Encryption in transit — deny non-TLS access",
			},
			{
				ControlID:     "AUDIT.001",
				ComplianceRef: "§164.312(b)",
				Rationale:     "All PHI access must be logged — logs cannot be obtained retroactively",
			},
			{
				ControlID:     "ACCESS.001",
				ComplianceRef: "§164.312(a)(1)",
				Rationale:     "Access control — Block Public Access prevents public exposure of ePHI",
			},

			// --- HIGH ---
			{
				ControlID:        "AUDIT.002",
				SeverityOverride: new(hipaa.High),
				ComplianceRef:    "§164.312(b)",
				Rationale:        "Object-level logging for PHI access audit trail",
			},
			{
				ControlID:     "ACCESS.002",
				ComplianceRef: "§164.312(a)(2)(i)",
				Rationale:     "Least privilege — no wildcard actions",
			},
			{
				ControlID:     "GOVERNANCE.001",
				ComplianceRef: "§164.312(a)(1)",
				Rationale:     "ACL control — disable legacy ACL grants",
			},
			{
				ControlID:     "RETENTION.002",
				ComplianceRef: "§164.316(b)(2)",
				Rationale:     "6-year PHI retention via Object Lock",
			},
			{
				ControlID:        "ACCESS.003",
				SeverityOverride: new(hipaa.High),
				ComplianceRef:    "§164.312(e)(1)",
				Rationale:        "Transmission security — VPC endpoint or IP restriction",
			},

			// --- MEDIUM ---
			{
				ControlID:     "CONTROLS.002",
				ComplianceRef: "§164.312(c)(1)",
				Rationale:     "Integrity — versioning protects against accidental deletion",
			},
			{
				ControlID:        "ACCESS.009",
				SeverityOverride: new(hipaa.Medium),
				ComplianceRef:    "§164.312(a)(1)",
				Rationale:        "Presigned URL restriction for PHI buckets",
			},
		},
	})
}
