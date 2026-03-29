package profile

func init() {
	RegisterProfile(&Profile{
		ID:          "hipaa",
		Name:        "HIPAA Security Rule",
		Description: "S3 configuration invariants required for HIPAA compliance covering access control, encryption, audit logging, integrity, and retention.",
		// Controls discovered from registries at Evaluate() time via
		// each control's ComplianceProfiles("hipaa") declaration.
	})
}
