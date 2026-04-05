package compound

import (
	"github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// DefaultRules returns the built-in compound risk detection rules.
func DefaultRules() []CompoundRule {
	return []CompoundRule{
		compound001(),
		compound002(),
		compound003(),
	}
}

// compound001: Public access + overly broad policy.
func compound001() CompoundRule {
	return CompoundRule{
		ID:         "COMPOUND.001",
		Severity:   policy.SeverityCritical,
		TriggerIDs: []string{"ACCESS.001", "ACCESS.002"},
		Message: "Public access with overly broad IAM permissions — the S3 + IAM " +
			"lateral movement pattern present in the majority of documented AWS breaches. " +
			"Remediate both before addressing lower-severity findings.",
		Matches: func(results []compliance.Outcome) bool {
			return resultFailed(results, "ACCESS.001") && resultFailed(results, "ACCESS.002")
		},
	}
}

// compound002: Encryption pass but access fail.
func compound002() CompoundRule {
	return CompoundRule{
		ID:         "COMPOUND.002",
		Severity:   policy.SeverityHigh,
		TriggerIDs: []string{"ACCESS.001", "CONTROLS.001"},
		Message: "Encryption at rest is configured but the bucket is publicly " +
			"accessible. Encryption provides no confidentiality benefit while " +
			"public access is enabled.",
		Matches: func(results []compliance.Outcome) bool {
			return resultFailed(results, "ACCESS.001") && resultPassed(results, "CONTROLS.001")
		},
	}
}

// compound003: VPC endpoint without endpoint policy.
func compound003() CompoundRule {
	return CompoundRule{
		ID:         "COMPOUND.003",
		Severity:   policy.SeverityHigh,
		TriggerIDs: []string{"ACCESS.003", "ACCESS.006"},
		Message: "VPC endpoint restricts this bucket but the endpoint policy " +
			"does not restrict which bucket ARNs are reachable. This creates a " +
			"wormhole: any principal on the VPC can reach any S3 bucket in any " +
			"account via the endpoint, bypassing firewall controls.",
		Matches: func(results []compliance.Outcome) bool {
			return resultPassed(results, "ACCESS.003") && resultFailed(results, "ACCESS.006")
		},
	}
}
