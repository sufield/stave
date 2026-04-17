// Package ccmbackfill provides directory+function inference rules for
// back-filling CCM v4 mappings onto Stave control YAML files.
//
// The rules are derived from docs/design-notes/csa-top5-coverage-audit.md,
// which attributes ~650 Stave control → CCM v4 relationships by directory
// structure and control function. This package encodes those attributions
// as a pure function so the back-fill is reproducible and reviewable.
//
// Conservative bias: when a control's directory + ID does not clearly
// pattern-match to one or more CCMs, Infer returns nil (leave absent).
// This matches the spec requirement to mark "not yet mapped" rather
// than guess.
package ccmbackfill

import (
	"sort"
	"strings"
)

// Infer returns the CCM v4 control IDs for a control given its directory
// path (relative to the controls root, e.g., "iam/policy") and its
// control ID (e.g., "CTL.IAM.POLICY.ADMIN.001"). Returns nil when no
// confident inference can be made.
//
// At most 5 CCMs are returned per control. Results are sorted by
// rule-layer specificity (service-specific first, then generic
// subcategory, then generic ID-token), and alphabetically within a
// tier. Truncation drops the least-specific CCMs first — an
// alphabetical sort would evict canonical CCMs like CCC-04 in favour
// of broad LOG-* tags when rule layers stack.
func Infer(dir, id string) []string {
	dir = strings.ToLower(strings.Trim(dir, "/"))
	idU := strings.ToUpper(id)
	parts := strings.Split(dir, "/")
	service := ""
	sub := ""
	if len(parts) > 0 {
		service = parts[0]
	}
	if len(parts) > 1 {
		sub = parts[1]
	}

	const (
		prioService = 1
		prioSubcat  = 2
		prioIDToken = 3
	)

	// For each CCM, remember the lowest (most specific) priority at
	// which it was added. A CCM added by both the service layer and
	// the generic subcategory layer keeps the service-layer priority.
	seen := map[string]int{}
	addAt := func(prio int) func(...string) {
		return func(ccms ...string) {
			for _, c := range ccms {
				if c == "" {
					continue
				}
				if existing, ok := seen[c]; ok && existing <= prio {
					continue
				}
				seen[c] = prio
			}
		}
	}

	applyServiceRules(service, sub, idU, addAt(prioService))
	applySubcategoryRules(service, sub, idU, addAt(prioSubcat))
	applyIDTokenRules(service, idU, addAt(prioIDToken))

	if len(seen) == 0 {
		return nil
	}
	type entry struct {
		id   string
		prio int
	}
	entries := make([]entry, 0, len(seen))
	for c, p := range seen {
		entries = append(entries, entry{c, p})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].prio != entries[j].prio {
			return entries[i].prio < entries[j].prio
		}
		return entries[i].id < entries[j].id
	})
	if len(entries) > 5 {
		entries = entries[:5]
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.id)
	}
	// Final output is sorted alphabetically for stable YAML emission;
	// the priority ordering only affects which CCMs survive truncation.
	sort.Strings(out)
	return out
}

// applyServiceRules encodes per-service attributions from the audit.
// Each branch reflects how the service's directory structure aligns
// with CCM v4 controls.
func applyServiceRules(service, sub, id string, add func(...string)) {
	switch service {
	case "iam":
		applyIAMService(sub, id, add)
	case "ad":
		applyADService(sub, id, add)
	case "s3":
		applyS3Service(sub, id, add)
	case "gcs":
		applyGCSService(sub, id, add)
	case "ec2":
		applyEC2Service(sub, id, add)
	case "vpc":
		applyVPCService(sub, id, add)
	case "rds":
		applyRDSService(sub, id, add)
	case "dynamodb":
		applyDynamoDBService(sub, id, add)
	case "efs":
		applyEFSService(sub, id, add)
	case "opensearch":
		applyOpenSearchService(sub, id, add)
	case "kms":
		applyKMSService(sub, id, add)
	case "secretsmanager":
		applySecretsManagerService(sub, id, add)
	case "k8s":
		applyK8sService(sub, id, add)
	case "eks":
		applyEKSService(sub, id, add)
	case "cloudtrail":
		applyCloudTrailService(sub, id, add)
	case "cloudwatch":
		add("LOG-03")
	case "config":
		add("CCC-04", "CCC-07", "LOG-03")
	case "cloudformation":
		add("CCC-04", "CCC-07")
	case "guardduty", "securityhub":
		add("LOG-03")
	case "guardrail":
		add("GRC-05", "CCC-04")
	case "backup":
		add("BCR-08", "CEK-03")
	case "apigateway":
		applyAPIGatewayService(sub, id, add)
	case "cloudfront":
		applyCloudFrontService(sub, id, add)
	case "elb":
		applyELBService(sub, id, add)
	case "elasticache":
		add("DSP-10", "CEK-03")
	case "sns", "sqs":
		applySNSSQSService(sub, id, add)
	case "lambda":
		applyLambdaService(sub, id, add)
	case "ecr":
		applyECRService(sub, id, add)
	case "ecs":
		add("LOG-12", "IVS-06")
	case "cognito":
		applyCognitoService(sub, id, add)
	case "codecommit":
		add("IAM-06", "DCS-07")
	case "waf":
		add("IVS-09", "LOG-12")
	case "shield":
		add("IVS-09")
	case "dns", "route53":
		applyDNSService(sub, id, add)
	case "vsphere":
		applyVSphereService(sub, id, add)
	case "cisco":
		applyCiscoService(sub, id, add)
	case "ssm":
		applySSMService(sub, id, add)
	case "org":
		add("IAM-10", "GRC-02")
	case "exposure":
		add("DSP-17", "IVS-03")
	case "autoscaling":
		add("IVS-02")
	case "acm":
		add("CEK-03", "CEK-04")
	}
}

func applyIAMService(sub, id string, add func(...string)) {
	switch sub {
	case "root":
		add("IAM-14", "IAM-09")
	case "admin":
		add("IAM-09", "IAM-14")
	case "console":
		add("IAM-14")
	case "password":
		add("IAM-15")
	case "credentials":
		add("IAM-02", "IAM-08")
	case "recurrence":
		add("CCC-07", "IAM-08")
	case "policy":
		add("IAM-05", "IAM-16")
	case "nep", "escalation":
		add("IAM-05")
	case "scp":
		add("IAM-10")
	case "vendor":
		add("IAM-07", "IAM-10")
	case "analyzer":
		add("IAM-03", "CCC-07")
	case "trust":
		add("DCS-07", "IAM-16")
	case "federation":
		add("IAM-03", "IAM-16")
	case "identity":
		add("IAM-03")
	case "discovery":
		add("IAM-03", "DCS-06")
	case "entropy":
		add("IAM-02")
	case "role":
		add("IAM-04", "IAM-16")
	case "misc":
		if strings.Contains(id, "ANALYZER") {
			add("IAM-03", "CCC-07")
		}
		if strings.Contains(id, "CERT") {
			add("CEK-05", "IAM-02")
		}
		if strings.Contains(id, "SUPPORT") {
			add("GRC-05")
		}
	}
	// Cross-cutting IAM tokens
	if strings.Contains(id, "MFA") {
		add("IAM-14")
	}
	if strings.Contains(id, "CROSSCLOUD") {
		add("IAM-01")
	}
	if strings.Contains(id, "BOUNDARY") {
		add("IAM-05")
	}
	if strings.Contains(id, "BREAKGLASS") {
		add("IAM-09")
	}
	if strings.Contains(id, "GHOSTREF") || strings.Contains(id, "SHADOW") {
		add("IAM-05", "CCC-04")
	}
	if strings.Contains(id, "SOD") {
		add("IAM-04")
	}
	if strings.Contains(id, "DRIFT") || strings.Contains(id, "INTENTMISMATCH") || strings.Contains(id, "INTENTTAG") {
		add("CCC-07")
	}
	if strings.Contains(id, "STALE") || strings.Contains(id, "UNUSED") || strings.Contains(id, "DORMANT") || strings.Contains(id, "INACTIVE") {
		add("IAM-08")
	}
}

func applyADService(sub, id string, add func(...string)) {
	switch sub {
	case "password":
		add("IAM-15")
	case "accounts":
		add("IAM-08", "IAM-09")
	case "audit":
		add("LOG-05")
	case "ntp":
		add("IVS-04")
	case "kerberos":
		add("CEK-04", "IAM-14")
	case "lockout":
		add("IAM-15")
	case "policy":
		add("IAM-15", "IVS-04")
	case "security":
		add("IVS-04", "IAM-09")
	case "trust":
		add("IAM-07", "DCS-07")
	}
	if strings.Contains(id, "NTLM") || strings.Contains(id, "LDAP") || strings.Contains(id, "SMB") {
		add("CEK-04", "IVS-04")
	}
	if strings.Contains(id, "ADMIN") {
		add("IAM-09")
	}
}

func applyS3Service(sub, id string, add func(...string)) {
	switch sub {
	case "public":
		add("DSP-17", "DSP-07")
	case "access", "acl":
		add("DSP-17", "IAM-16")
	case "encrypt":
		add("CEK-03")
	case "logging":
		add("LOG-12")
	case "audit":
		add("LOG-12", "LOG-05")
	case "versioning", "version":
		add("BCR-08")
	case "replication":
		add("BCR-08", "DSP-05")
	case "network":
		add("IVS-03", "DCS-07")
	case "detect", "detection":
		add("DSP-03", "LOG-03")
	case "macie":
		add("DSP-03")
	case "retention":
		add("DSP-16")
	case "takeover":
		add("CCC-04")
	case "classify":
		add("DSP-03", "DSP-04")
	case "lifecycle":
		add("DSP-16")
	case "ownership":
		add("DSP-07")
	case "tenant", "isolation":
		add("IVS-06")
	case "region", "sovereignty":
		add("DSP-19")
	case "governance":
		add("GRC-05", "DSP-07")
	case "policy":
		add("IAM-16", "DSP-17")
	case "exfil":
		add("DSP-17")
	case "lock":
		add("BCR-08", "DSP-16")
	case "recurrence":
		add("CCC-07", "CCC-04")
	case "write_scope":
		add("DSP-17", "IAM-16")
	case "artifacts":
		add("AIS-06", "DSP-17")
	case "collection":
		add("DCS-06")
	}
	if strings.Contains(id, "MRAP") {
		add("IAM-16", "DCS-07")
	}
	if strings.Contains(id, "DANGLING") || strings.Contains(id, "CDN.EXPOSURE") {
		add("CCC-04")
	}
	if strings.Contains(id, "PAB") {
		add("DSP-07")
	}
	if strings.Contains(id, ".CONTROLS.") {
		add("DSP-07", "DSP-17")
	}
	if strings.Contains(id, ".REGION.") {
		add("DSP-19", "DSP-17")
	}
}

func applyGCSService(sub, id string, add func(...string)) {
	switch sub {
	case "public":
		add("DSP-17", "DSP-07")
	case "encrypt":
		add("CEK-03")
	case "logging":
		add("LOG-12")
	case "versioning":
		add("BCR-08")
	}
}

func applyEC2Service(sub, id string, add func(...string)) {
	switch sub {
	case "sg":
		add("IVS-03")
	case "network":
		add("IVS-03")
	case "ebs":
		add("CEK-03", "DSP-07")
	case "encryption":
		add("CEK-03")
	case "compute":
		add("IVS-04")
	case "detection":
		add("LOG-03")
	case "security":
		add("IVS-04")
	case "governance":
		add("DCS-06")
	case "collection":
		add("DCS-06")
	case "lifecycle":
		add("CCC-04")
	case "runtime":
		add("IVS-04")
	case "execution":
		if strings.Contains(id, "USERDATA") {
			add("DSP-17", "IAM-05")
		}
		if strings.Contains(id, "SESSION.LOGGING") {
			add("LOG-12")
		}
	case "identity":
		add("IAM-04", "IAM-05")
	}
	if strings.Contains(id, "IMDS") {
		add("IVS-04")
	}
	if strings.Contains(id, "AMI") {
		add("IVS-04", "CCC-04")
	}
	if strings.Contains(id, "TERMINATION.PROTECT") {
		add("BCR-08")
	}
	if strings.Contains(id, "PUBLIC") {
		add("IVS-03")
	}
}

func applyVPCService(sub, id string, add func(...string)) {
	switch sub {
	case "sg", "security":
		add("IVS-03")
	case "network":
		add("IVS-03")
	case "peering":
		add("IVS-03", "IVS-06")
	case "routing":
		add("IVS-03")
	case "acl":
		add("IVS-03")
	case "isolation", "tenant":
		add("IVS-06")
	case "endpoint":
		add("DCS-07", "IVS-06")
	case "logging":
		add("LOG-12")
	case "governance":
		add("IVS-08", "DCS-06")
	case "collection":
		add("DCS-06")
	case "default":
		add("IVS-03", "DSP-07")
	case "recurrence":
		add("CCC-07")
	case "misc":
		if strings.Contains(id, "ISOLATION") {
			add("IVS-06")
		}
		if strings.Contains(id, "DEFAULT") {
			add("IVS-03", "DSP-07")
		}
	}
	if strings.Contains(id, "NACL") {
		add("IVS-03")
	}
	if strings.Contains(id, "SG.") || strings.Contains(id, ".SG.") {
		add("IVS-03")
	}
}

func applyRDSService(sub, id string, add func(...string)) {
	switch sub {
	case "encrypt":
		add("CEK-03")
	case "public":
		add("IVS-03", "DSP-17")
	case "backup":
		add("BCR-08")
	case "logging":
		add("LOG-12")
	case "monitoring":
		add("LOG-03")
	case "network":
		add("IVS-03")
	case "audit":
		add("LOG-05")
	case "access":
		add("IAM-16", "DSP-17")
	case "resilience":
		add("BCR-08")
	case "governance":
		add("CCC-04", "IVS-04")
	case "collection":
		add("DSP-05", "DCS-06")
	case "misc":
		if strings.Contains(id, "UPGRADE") {
			add("CCC-04", "IVS-04")
		}
	}
	if strings.Contains(id, "SSL") {
		add("DSP-10")
	}
	if strings.Contains(id, "ENGINE.EOL") {
		add("IVS-04")
	}
	if strings.Contains(id, "DELETE") {
		add("BCR-08")
	}
	if strings.Contains(id, "SNAPSHOT") && strings.Contains(id, "PUBLIC") {
		add("DSP-17")
	}
}

func applyDynamoDBService(sub, id string, add func(...string)) {
	switch sub {
	case "encrypt":
		add("CEK-03")
	case "resilience":
		add("BCR-08")
	case "backup":
		add("BCR-08")
	case "access":
		add("IAM-16", "DSP-17")
	}
	if strings.Contains(id, "PITR") {
		add("BCR-08")
	}
}

func applyEFSService(sub, id string, add func(...string)) {
	switch sub {
	case "encrypt":
		add("CEK-03")
	case "backup":
		add("BCR-08")
	case "access":
		add("IAM-16", "DSP-17")
	case "policy":
		add("IAM-16", "DSP-17")
	case "misc":
		if strings.Contains(id, "LIFECYCLE") {
			add("DSP-16")
		}
	}
	if strings.Contains(id, "TRANSIT") {
		add("DSP-10")
	}
}

func applyOpenSearchService(sub, id string, add func(...string)) {
	switch sub {
	case "encrypt":
		add("CEK-03")
	case "access":
		add("IAM-16", "DSP-17")
	case "logging":
		add("LOG-12", "LOG-05")
	case "collection":
		add("DCS-06")
	}
	if strings.Contains(id, "HTTPS") {
		add("DSP-10")
	}
	if strings.Contains(id, "PUBLIC") {
		add("IVS-03")
	}
	if strings.Contains(id, "SNAPSHOT") {
		add("BCR-08")
	}
}

func applyKMSService(sub, id string, add func(...string)) {
	add("CEK-03")
	if strings.Contains(id, "FIPS") {
		add("CEK-04")
	}
	if strings.Contains(id, "ROTATION") {
		add("CEK-05")
	}
	if strings.Contains(id, "POLICY") {
		add("IAM-16")
	}
	if strings.Contains(id, "ISOLATION") {
		add("IVS-06")
	}
}

func applySecretsManagerService(sub, id string, add func(...string)) {
	switch sub {
	case "encrypt":
		add("CEK-03")
	case "access":
		add("IAM-16", "DSP-17")
	case "blast":
		add("IAM-05", "DSP-17")
	case "collection":
		if strings.Contains(id, "ROTATION") {
			add("CEK-05", "IAM-02")
		} else {
			add("DCS-06")
		}
	}
}

func applyK8sService(sub, id string, add func(...string)) {
	switch sub {
	case "apiserver", "kubelet", "etcd", "controller_manager", "scheduler", "pod_security":
		add("IVS-04")
	case "rbac":
		add("IAM-16", "IAM-05")
	case "network":
		add("IVS-03", "IVS-06")
	case "audit":
		add("LOG-05")
	case "secrets":
		add("CEK-03")
	case "logging":
		add("LOG-12")
	case "discovery":
		add("DCS-06")
	case "jobs":
		add("CCC-04", "IVS-04")
	}
	if strings.Contains(id, "NETPOL") {
		add("IVS-03", "IVS-06")
	}
	if strings.Contains(id, "AUDIT") {
		add("LOG-05")
	}
	if strings.Contains(id, "IMDS") {
		add("IVS-04")
	}
}

func applyEKSService(sub, id string, add func(...string)) {
	switch sub {
	case "audit", "logging":
		add("LOG-05", "LOG-12")
	case "network", "endpoint":
		add("IVS-03")
	case "rbac":
		add("IAM-16")
	case "identity":
		add("IAM-14", "IAM-16")
	case "encryption":
		add("CEK-03")
	case "nodegroup":
		add("IVS-04")
	case "governance":
		add("CCC-04")
	}
	if strings.Contains(id, "VERSION") {
		add("IVS-04")
	}
	if strings.Contains(id, "IRSA") {
		add("IAM-14", "IAM-16")
	}
	if strings.Contains(id, "PUBLIC.ENDPOINT") {
		add("IVS-03")
	}
}

func applyCloudTrailService(sub, id string, add func(...string)) {
	add("LOG-05")
	switch sub {
	case "encrypt":
		add("CEK-03")
	case "audit":
		add("LOG-05")
	case "detection":
		add("LOG-03")
	}
	if strings.Contains(id, "DATAREAD") || strings.Contains(id, "DATAWRITE") || strings.Contains(id, "S3LOG") {
		add("LOG-12")
	}
	if strings.Contains(id, "STOP") || strings.Contains(id, "DISABLE") {
		add("CCC-04")
	}
	if strings.Contains(id, "RETENTION") {
		add("DSP-16")
	}
}

func applyAPIGatewayService(sub, id string, add func(...string)) {
	add("AIS-01")
	if strings.Contains(id, "TLS") || strings.Contains(id, "DOMAIN.TLS") {
		add("DSP-10", "CEK-03")
	}
	if strings.Contains(id, "THROTTLE") {
		add("IVS-09")
	}
	if strings.Contains(id, "AUTH") {
		add("IAM-16")
	}
	if strings.Contains(id, "VALIDATION") {
		add("AIS-04")
	}
	if strings.Contains(id, "LIFECYCLE") || strings.Contains(id, "STAGE.LIFECYCLE") {
		add("CCC-04")
	}
}

func applyCloudFrontService(sub, id string, add func(...string)) {
	switch sub {
	case "waf":
		add("IVS-09")
	case "encrypt":
		add("DSP-10", "CEK-03")
	case "audit", "logging":
		add("LOG-12")
	case "headers":
		add("AIS-04", "DSP-10")
	case "resilience":
		add("IVS-09")
	case "governance":
		add("DCS-06")
	}
	if strings.Contains(id, "TLS") || strings.Contains(id, "HTTPS") {
		add("DSP-10", "CEK-04")
	}
}

func applyELBService(sub, id string, add func(...string)) {
	if strings.Contains(id, "HTTPS") || strings.Contains(id, "TLS") {
		add("DSP-10", "CEK-03")
	}
	if strings.Contains(id, "LOG") {
		add("LOG-12")
	}
	if sub == "availability" || strings.Contains(id, "CROSSZONE") {
		add("BCR-03", "IVS-09")
	}
}

func applySNSSQSService(sub, id string, add func(...string)) {
	if strings.Contains(id, "ENCRYPT") {
		add("CEK-03")
	}
	if strings.Contains(id, "ACCESS") || strings.Contains(id, "POLICY") {
		add("IAM-16", "DSP-17")
	}
	if strings.Contains(id, "DLQ") {
		add("BCR-08")
	}
}

func applyLambdaService(sub, id string, add func(...string)) {
	switch sub {
	case "runtime":
		add("IVS-04")
	case "secrets":
		add("DSP-17", "CEK-03")
	case "identity":
		add("IAM-04", "IAM-05")
	}
	if strings.Contains(id, "RUNTIME") {
		add("IVS-04")
	}
	if strings.Contains(id, "CODESIGN") {
		add("AIS-06", "CCC-04")
	}
	if strings.Contains(id, "ENV.ENCRYPT") {
		add("CEK-03")
	}
	if strings.Contains(id, "ENV.SECRETS") {
		add("DSP-17", "CEK-03")
	}
	if strings.Contains(id, "INVOKE.PUBLIC") || strings.Contains(id, "URL") {
		add("DSP-17", "IVS-03")
	}
	if strings.Contains(id, "ROLE") {
		add("IAM-04", "IAM-05")
	}
	if strings.Contains(id, "UPDATECODE") {
		add("IAM-05", "CCC-04")
	}
	if strings.Contains(id, "LOG") {
		add("LOG-12")
	}
}

func applyECRService(sub, id string, add func(...string)) {
	if strings.Contains(id, "SCAN") {
		add("AIS-06", "TVM-07")
	}
	if strings.Contains(id, "SIGN") {
		add("AIS-06", "CCC-04")
	}
	if strings.Contains(id, "TAG.IMMUTABLE") {
		add("CCC-04")
	}
	if strings.Contains(id, "PUBLIC") {
		add("DSP-17", "DSP-07")
	}
	if strings.Contains(id, "LIFECYCLE") {
		add("CCC-04", "DSP-16")
	}
}

func applyCognitoService(sub, id string, add func(...string)) {
	// AIS-01 ("Application and Interface Security Policy and Procedures")
	// applies to controls that configure an application interface's
	// security posture (API Gateway, CloudFront, ALB, App Runner).
	// Cognito is an identity provider: its controls map to IAM-14 /
	// IAM-15 / IAM-16, not to application-interface policy. AIS-01 is
	// intentionally absent here.
	if strings.Contains(id, "MFA") {
		add("IAM-14")
	}
	if strings.Contains(id, "PASSWORD") || strings.Contains(id, "POLICY") {
		add("IAM-15")
	}
	if strings.Contains(id, "ADVANCED.SECURITY") {
		add("IAM-14", "IVS-09")
	}
}

func applyDNSService(sub, id string, add func(...string)) {
	if strings.Contains(id, "DANGLING") || strings.Contains(id, "TAKEOVER") {
		add("CCC-04")
	}
	if strings.Contains(id, "DNSSEC") {
		add("CCC-04", "DSP-10")
	}
	if strings.Contains(id, "QUERY") || strings.Contains(id, "LOG") {
		add("LOG-12")
	}
	if sub == "health" || strings.Contains(id, "HEALTHCHECK") {
		add("BCR-03", "IVS-08")
	}
}

func applyVSphereService(sub, id string, add func(...string)) {
	switch sub {
	case "esxi", "vcenter":
		add("IVS-04")
	case "vds":
		add("IVS-03")
	case "vm":
		add("IVS-04", "CEK-03")
	case "storage":
		add("CEK-03")
	}
	if strings.Contains(id, "SSO") || strings.Contains(id, "PASSLEN") || strings.Contains(id, "LOCKOUT") {
		add("IAM-15")
	}
	if strings.Contains(id, "ENCRYPT") {
		add("CEK-03")
	}
	if strings.Contains(id, "TRANSIT") {
		add("DSP-10")
	}
	if strings.Contains(id, "SYSLOG") || strings.Contains(id, "PERSISTLOG") {
		add("LOG-12")
	}
}

func applyCiscoService(sub, id string, add func(...string)) {
	switch sub {
	case "mgmt":
		add("IVS-04")
	case "svc":
		add("IVS-04")
	case "acl":
		add("IVS-03")
	case "network":
		add("IVS-03")
	case "ntp":
		add("IVS-04")
	case "routing":
		add("IVS-03", "IVS-04")
	}
	if strings.Contains(id, "BGP") || strings.Contains(id, "OSPF") || strings.Contains(id, "HSRP") {
		add("IVS-03", "IAM-14")
	}
	if strings.Contains(id, "URPF") {
		add("IVS-03")
	}
}

func applySSMService(sub, id string, add func(...string)) {
	switch sub {
	case "collection", "discovery":
		add("DCS-06")
	case "execution":
		add("IAM-05", "LOG-12")
	case "security":
		add("LOG-12")
	}
	if strings.Contains(id, "SESSION.LOGGING") {
		add("LOG-12")
	}
}

// applySubcategoryRules adds CCMs based on generic subcategory names
// regardless of service. These are weaker signals than service-specific
// rules and act as a safety net for uncommon service / subdir pairings.
func applySubcategoryRules(service, sub, id string, add func(...string)) {
	// Skip when service rules already applied heavily; this loop catches
	// the long tail.
	switch sub {
	case "monitoring", "detection", "detect":
		add("LOG-03")
	case "audit":
		// "audit/" has two distinct meanings across services: log
		// producers use it for audit logs (AD audit policies, K8s
		// API server audit, OpenSearch audit), while config-
		// evaluation services use it for compliance auditing (AWS
		// Config Rules, Guardrail checks, SecurityHub, CloudFormation
		// drift). Config-evaluators aren't audit logs — tagging them
		// LOG-05/LOG-12 is wrong and makes "who logs access?" queries
		// return them as false positives.
		configEvaluators := map[string]bool{
			"config":         true,
			"guardrail":      true,
			"securityhub":    true,
			"cloudformation": true,
		}
		if !configEvaluators[service] {
			add("LOG-05", "LOG-12")
		}
	case "logging":
		if service != "s3" && service != "cloudfront" {
			add("LOG-12")
		}
	case "encrypt", "encryption":
		add("CEK-03")
	case "backup", "resilience":
		add("BCR-08")
	case "public", "anon":
		add("DSP-17", "DSP-07")
	case "exposure", "exfil", "sovereignty":
		add("DSP-17")
	case "network":
		add("IVS-03")
	case "isolation", "tenant":
		add("IVS-06")
	case "auth":
		add("IAM-14", "IAM-16")
	case "password":
		add("IAM-15")
	case "validation":
		add("AIS-04")
	case "integrity", "verification":
		add("CCC-04", "CCC-07")
	case "inventory", "discovery":
		add("DCS-06")
	case "ownership":
		add("DSP-06")
	case "retention":
		add("DSP-16")
	case "drift":
		add("CCC-07")
	}
}

// applyIDTokenRules adds CCMs based on tokens in the control ID that
// reliably signal a CCM mapping. Runs last, as a safety net for
// directories that don't fully capture the control's function.
func applyIDTokenRules(service, id string, add func(...string)) {
	if strings.Contains(id, "INCOMPLETE") {
		add("DCS-06")
	}
	if strings.Contains(id, "BLASTRADIUS") {
		add("IAM-03", "IAM-05")
	}
}
