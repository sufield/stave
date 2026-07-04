// Package archetype defines structural defect classifications that group
// controls by the underlying infrastructure failure shape they detect.
//
// When an engineer sees one violation, the archetype identifies every other
// place the same class of defect manifests across their infrastructure and
// names the snapshots needed to find the rest.
package archetype

import "github.com/sufield/stave/internal/core/kernel"

// Archetype is a structural defect classification shared by a family of
// controls. The catalog is the authoritative list (see Catalog).
type Archetype struct {
	ID          kernel.ArchetypeID `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Services    []string           `json:"services"`
	Guidance    string             `json:"guidance"`
}

// init registers the catalog vocabulary with the kernel so
// kernel.ArchetypeID.Validate / IsValid can reject unknown IDs.
func init() {
	ids := make([]string, len(Catalog))
	for i, a := range Catalog {
		ids[i] = string(a.ID)
	}
	kernel.SetArchetypeIDVocabulary(ids)
}

// Catalog enumerates the 12 archetypes recognized by Stave. Order is the
// canonical display order used by `stave expand --list`.
var Catalog = []Archetype{
	{
		ID:   "ghost-reference",
		Name: "Ghost Reference",
		Description: "A resource references a target that no longer exists. " +
			"The reference looks valid — the ARN is present, the configuration " +
			"appears complete. The target was deleted. The reference is a " +
			"pointer to nothing. Operations that depend on the reference fail " +
			"silently or with non-obvious errors.",
		Guidance: "If your decommissioning process missed this reference, it " +
			"likely missed others. Generate snapshots for the services listed " +
			"below and re-run stave apply to find all ghost references across " +
			"your infrastructure.",
		Services: []string{
			"s3", "route53", "cloudfront", "sqs", "sns", "kms",
			"secretsmanager", "lambda", "ecs", "ec2", "iam", "rds",
			"dynamodb", "apigateway", "vpc",
		},
	},
	{
		ID:   "confused-deputy",
		Name: "Confused Deputy",
		Description: "A resource policy allows an AWS service principal to " +
			"perform actions without restricting which specific resource of " +
			"that service can act. Any resource of that service type in any " +
			"AWS account can interact with your resource. An attacker creates " +
			"their own resource of that service type and uses the unrestricted " +
			"policy to inject data or trigger actions.",
		Guidance: "Add aws:SourceArn or aws:SourceAccount conditions to every " +
			"service principal grant. Check all resource policies that allow " +
			"AWS service principals.",
		Services: []string{"sqs", "sns", "lambda"},
	},
	{
		ID:   "encryption-gap",
		Name: "Encryption Gap",
		Description: "A resource is either not encrypted or uses an AWS-managed " +
			"key instead of a customer-managed KMS key. AWS-managed keys " +
			"provide encryption but no key policy control, no usage audit " +
			"trail, and no emergency revocation capability.",
		Guidance: "Migrate to customer-managed KMS keys for resources containing " +
			"sensitive data. Audit all services for encryption configuration.",
		Services: []string{
			"s3", "rds", "dynamodb", "lambda", "sqs", "sns",
			"secretsmanager", "ecs", "ec2",
		},
	},
	{
		ID:   "transport-cleartext",
		Name: "Cleartext Transport",
		Description: "A resource accepts or delivers data over unencrypted " +
			"channels. The resource policy does not enforce HTTPS via " +
			"aws:SecureTransport, or a subscription delivers to an HTTP " +
			"endpoint instead of HTTPS.",
		Guidance: "Add Deny statements with aws:SecureTransport: false to all " +
			"resource policies. Change HTTP subscriptions and integrations to " +
			"HTTPS.",
		Services: []string{"s3", "sqs", "sns", "apigateway"},
	},
	{
		ID:   "dormant-resource",
		Name: "Dormant Resource",
		Description: "A resource has not been used for 90 or more days. The " +
			"resource retains its full configuration — access policies, " +
			"encryption, network access — but processes no traffic. Dormant " +
			"resources are latent attack surfaces with active permissions and " +
			"no monitoring.",
		Guidance: "Review each dormant resource: if truly unused, delete or " +
			"disable. If needed for future use, restrict permissions to " +
			"minimum. Audit all services for dormant resources.",
		Services: []string{"lambda", "iam", "kms", "sqs", "sns", "secretsmanager", "dynamodb"},
	},
	{
		ID:   "notification-chain",
		Name: "Broken Notification Chain",
		Description: "The path from detection to notification is broken. A " +
			"CloudWatch alarm fires but the SNS topic it notifies was deleted. " +
			"Or the SNS topic exists but the SQS subscription queue was " +
			"deleted. Or the DLQ has no consumer. The alarm detects the " +
			"problem. Nobody is notified.",
		Guidance: "Trace every alarm action to its SNS topic, every SNS " +
			"subscription to its endpoint, and every DLQ to its consumer. A " +
			"break at any link makes every upstream detection useless.",
		Services: []string{"sns", "sqs", "cloudwatch"},
	},
	{
		ID:   "false-protection",
		Name: "False Protection",
		Description: "A security control appears configured but provides no " +
			"actual protection. Rotation is enabled but the Lambda was " +
			"deleted. DMARC exists but the policy is p=none. A WAF is " +
			"associated but has no rules. The configuration creates false " +
			"confidence — an auditor sees the control and marks it compliant.",
		Guidance: "Audit every security control for functional effectiveness, " +
			"not just existence. Check rotation is actually rotating, DMARC is " +
			"actually enforcing, WAF rules are actually filtering.",
		Services: []string{"route53", "secretsmanager", "waf", "cloudfront"},
	},
	{
		ID:   "unbounded-cross-account",
		Name: "Unbounded Cross-Account Access",
		Description: "A resource policy grants access to external AWS accounts " +
			"without aws:PrincipalOrgID condition. Any principal in the " +
			"external account can interact with the resource. If the external " +
			"account leaves the organization or is compromised, access " +
			"persists.",
		Guidance: "Add aws:PrincipalOrgID condition to all cross-account policy " +
			"grants. Audit all resource policies for cross-account access " +
			"without organizational boundary.",
		Services: []string{"s3", "sqs", "sns", "secretsmanager", "kms", "iam"},
	},
	{
		ID:   "policy-sprawl",
		Name: "Policy Sprawl",
		Description: "A resource policy has accumulated excessive permission " +
			"statements from multiple service integrations over time. " +
			"Statements are added but rarely removed. The policy becomes " +
			"unauditable — too many grants to review, some referencing " +
			"deleted resources.",
		Guidance: "Audit resource policies for stale statements. Remove " +
			"statements that reference deleted resources. Consolidate " +
			"overlapping grants.",
		Services: []string{"lambda", "sqs", "sns", "secretsmanager"},
	},
	{
		ID:   "missing-safety-net",
		Name: "Missing Safety Net",
		Description: "A processing pipeline has no failure handling. Messages " +
			"that fail processing are either retried indefinitely or silently " +
			"deleted. No dead-letter queue, no failure notification, no " +
			"reprocessing capability.",
		Guidance: "Configure dead-letter queues for all SQS queues, SNS " +
			"subscriptions, and Lambda async invocations. Monitor DLQ depth " +
			"with CloudWatch alarms.",
		Services: []string{"sqs", "sns", "lambda"},
	},
	{
		ID:   "cross-environment",
		Name: "Cross-Environment Sharing",
		Description: "A resource is shared across production and non-production " +
			"environments. A change in one environment affects the other. " +
			"Disabling a key for dev cleanup breaks production. Broadening " +
			"permissions for developer debugging exposes production data.",
		Guidance: "Separate resources by environment. Use independent KMS keys, " +
			"VPCs, and credentials per environment.",
		Services: []string{"kms", "vpc", "rds", "apigateway"},
	},
	{
		ID:   "deletion-cascade",
		Name: "Deletion Cascade",
		Description: "A foundational resource is scheduled for deletion while " +
			"other resources depend on it. When the deletion completes, every " +
			"dependent resource fails simultaneously. One deletion, multiple " +
			"services broken.",
		Guidance: "Before deleting any shared resource (KMS key, secret, SNS " +
			"topic), audit all dependent resources. Use longer deletion " +
			"windows (30 days, not 7) to allow discovery.",
		Services: []string{"kms", "secretsmanager"},
	},
	{
		ID:   "silent-failure",
		Name: "Silent Failure",
		Description: "A monitoring or alerting hook exists but does not trigger " +
			"on the conditions it was meant to surface. Alarms are configured " +
			"but their threshold or filter pattern excludes the failure mode. " +
			"Delivery channels are wired but unmonitored. Logs are written but " +
			"never alerted on. Operators see green dashboards while real " +
			"incidents accumulate unobserved.",
		Guidance: "For each alarm, verify the metric/filter actually fires on " +
			"the failure it claims to detect. Test alarms in staging by " +
			"injecting the failure condition. Audit delivery: a notification " +
			"that lands in an unmanned inbox is a silent failure too.",
		Services: []string{
			"cognito", "config", "cloudtrail", "cloudwatch", "kms",
			"sns", "sqs", "lambda",
		},
	},
}

// Lookup returns the archetype with the given ID, or false if no archetype
// in the catalog has that ID.
func Lookup(id string) (Archetype, bool) {
	target := kernel.ArchetypeID(id)
	for _, a := range Catalog {
		if a.ID == target {
			return a, true
		}
	}
	return Archetype{}, false
}

// IDs returns every archetype ID in catalog order.
func IDs() []string {
	out := make([]string, len(Catalog))
	for i, a := range Catalog {
		out[i] = a.ID.String()
	}
	return out
}
