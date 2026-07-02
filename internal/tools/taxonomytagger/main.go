package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

type rule struct {
	pattern  *regexp.Regexp
	category string
}

var rules = []rule{
	// Least privilege (match control IDs/names, not general description text)
	{regexp.MustCompile(`(?i)(POLICY\.WILDCARD|POLICY\.ADMIN|FULLACCESS|overperm|admin[._]access|ADMIN\.001|BLASTRADIUS|BROAD\.001|TOOLACCESS\.BROAD|MODELSCOPE|EXCESSIVE.*PERM|NEP\.ADMIN|NEP\.ESCALATION)`), "least-privilege"},
	// Credential lifecycle
	{regexp.MustCompile(`(?i)(access[._]key|key[._]age|CRED\.ROTATION|CRED\.EXPIRY|CRED\.UNUSED|CRED\.TTL|session[._]duration|MaxSession|LONGTERM|SINGLEKEY|SETUPKEY|ACCESSKEY|credential.*rotat|long.lived.*token|CREDENTIAL|INACTIVE\.001)`), "credential-lifecycle"},
	// Trust boundary
	{regexp.MustCompile(`(?i)(cross[._]account|CrossAccount|CROSSACCOUNT|ExternalId|EXTERNALID|external[._]id|trust[._]policy|TRUST\.|TRUSTPOLICY|wildcard.*principal|ORGBOUNDARY|CROSS\.ENV|CROSS\.PATH)`), "trust-boundary"},
	// Trust decay
	{regexp.MustCompile(`(?i)(STALE|IDLE|GHOST|ORPHAN|orphaned|unused.*role|LIFECYCLE\.DORMANT|DECOMMISSIONED|PENDINGIMPORT|PENDING\.DELETION)`), "trust-decay"},
	// Confused deputy
	{regexp.MustCompile(`(?i)(confused|CONFUSEDDEPUTY|SourceAccount|SourceOrgID|service.*principal.*without|PERIMETER\.CONFUSEDDEPUTY)`), "confused-deputy"},
	// Attribution
	{regexp.MustCompile(`(?i)(SourceIdentity|SESSION\.NAME|SESSION\.SOURCE)`), "attribution"},
	// Identity perimeter
	{regexp.MustCompile(`(?i)(PrincipalOrgID|identity[._]perimeter|PERIMETER\.IDENTITY|CONDITION\.ORGID|ZT\.PERIMETER)`), "identity-perimeter"},
	// Impersonation
	{regexp.MustCompile(`(?i)(impersonat|CreateTokenWithIAM|SSOOAUTH|APP\.ACCOUNTACCESS|SSO\.APP\.SPRAWL|DELEGATED\.ADMIN)`), "impersonation"},
	// Network perimeter
	{regexp.MustCompile(`(?i)(SourceIp|SOURCEIP|VpceOrgID|PUBLIC\.00|public[._]access|0\.0\.0\.0|UNRESTRICTED|SSH|RDP|INGRESS|SG\.DEFAULT|SG\.EGRESS|NACL\.|IGW\.|CIDR\.BROAD|PORTRANGE|AUTOPUBLIC)`), "network-perimeter"},
	// Data perimeter
	{regexp.MustCompile(`(?i)(data[._]perimeter|DATAPERIMETER|PERIMETER\.COMPLETENESS|PERIMETER\.NETWORKBYPASS|PERIMETER\.SERVICEEXEMPTION)`), "data-perimeter"},
	// Encryption at rest
	{regexp.MustCompile(`(?i)(ENCRYPT\.001|encrypt.*rest|volume.*encrypt|EBS.*ENCRYPT|\.ENCRYPT\.|SSE[._-]|storage.*encrypt|KmsKeyId|CMK\.001|CATALOG\.ENCRYPT|JOB\.ENCRYPT|ENDPOINT\.ENCRYPT|SNAPSHOT\.ENCRYPT|DEFAULT\.ENCRYPT|SERVER\.ENCRYPT)`), "encryption-at-rest"},
	// Encryption in transit
	{regexp.MustCompile(`(?i)(transit.*encrypt|\.SSL\.|\.TLS\.|INTERCONTAINER|TRANSIT\.001|HTTPS\.001|\.INSECURE\.TRANSPORT|SECURETYPE\.001)`), "encryption-in-transit"},
	// Key management
	{regexp.MustCompile(`(?i)(^CTL\.KMS\.|kms.*rotation|kms.*policy|key.*rotation|KEY\.ALGORITHM|FIPS\.001)`), "key-management"},
	// Network isolation
	{regexp.MustCompile(`(?i)(VPC\.ENDPOINT|SUBNET|VPN\.|CLIENTVPN|DX\.|TGW\.|FLOWLOG|\.VPC\.001|NETWORK\.PRIVATE|PRIVATEDB)`), "network-isolation"},
	// Compute hardening
	{regexp.MustCompile(`(?i)(privileged|IMDSv2|IMDSV2|IMDS\.|root[._]access|ROOT\.ACCESS|deprecated.*runtime|RUNTIME\.DEPRECATED|read.only.*root|image.*tag|LATEST\.TAG|USERDATA\.CREDS|USERDATA\.SECRETS|AMI\.|CODESIGN)`), "compute-hardening"},
	// Redundancy
	{regexp.MustCompile(`(?i)(multi.az|MultiAZ|MULTIAZ|redundancy|REDUNDANCY|RESILIENCY|single.*az|SINGLEAZ|availability.*zone)`), "redundancy"},
	// Logging
	{regexp.MustCompile(`(?i)(CLOUDTRAIL|CloudTrail|FLOWLOG|flow[._]log|access[._]log|LOG\.001|LOGGING\.001|\.LOG\.|CWLOGS|QUERYLOG|CONNLOG|ACCESSLOG|SERVER\.ACCESS)`), "logging"},
	// Monitoring
	{regexp.MustCompile(`(?i)(GUARDDUTY|GuardDuty|SECURITYHUB|Security.Hub|INSPECTOR\.|MACIE\.|CONFIG\.ENABLED|CONFIG\.RECORDER|MONITOR\.001|ALARM\.)`), "monitoring"},
	// AI guardrails (match Bedrock guardrail controls, not the general word)
	{regexp.MustCompile(`(?i)(BEDROCK\.GUARDRAIL|GUARDRAIL\.CONTENT|GUARDRAIL\.PII|GUARDRAIL\.TOPIC|GUARDRAIL\.PROMPTATTACK|GUARDRAIL\.BLIND|guardrail_blindspot)`), "ai-guardrails"},
	// AI supply chain
	{regexp.MustCompile(`(?i)(ECR\.SCAN|scan.on.push|ENHANCED\.SCANNING|FINDINGS\.UNRESOLVED|SIGNING\.001|GHOST\.MODEL|GHOST\.LAMBDA|GHOST\.KNOWLEDGEBASE|GHOST\.ACTIONGROUP)`), "ai-supply-chain"},
	// Resource sprawl
	{regexp.MustCompile(`(?i)(SPRAWL|SHADOW|\.EXCESSIVE\.|STALE.*agent|TOOLACCESS\.BROAD)`), "resource-sprawl"},
	// Account governance
	{regexp.MustCompile(`(?i)(^CTL\.IAM\.SCP\.|^CTL\.IAM\.RCP\.|^CTL\.ORG\.|ALLFEATURES|TRUSTEDACCESS|STACKSETS|CONFORMANCE|AGGREGATOR)`), "account-governance"},
}

func main() {
	root := "controls"
	if len(os.Args) > 1 {
		root = os.Args[1]
	}

	var total, tagged, alreadyTagged int

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		base := filepath.Base(path)
		if !strings.HasPrefix(base, "CTL.") {
			return nil
		}

		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		content := string(data)
		total++

		if strings.Contains(content, "\ntaxonomy:") {
			alreadyTagged++
			return nil
		}

		// Match against ID + full content
		cats := matchCategories(base, content)
		if len(cats) == 0 {
			fmt.Fprintf(os.Stderr, "UNTAGGED: %s\n", path)
			return nil
		}

		// Insert taxonomy after scope_tags (or after severity if no scope_tags)
		newContent := insertTaxonomy(content, cats)
		if newContent == content {
			fmt.Fprintf(os.Stderr, "SKIP (insert failed): %s\n", path)
			return nil
		}

		if werr := os.WriteFile(path, []byte(newContent), info.Mode()); werr != nil {
			return werr
		}
		tagged++
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Total: %d, Tagged: %d, Already tagged: %d, Untagged: %d\n",
		total, tagged, alreadyTagged, total-tagged-alreadyTagged)
}

func matchCategories(filename, content string) []string {
	seen := map[string]bool{}
	for _, r := range rules {
		if r.pattern.MatchString(filename) || r.pattern.MatchString(content) {
			seen[r.category] = true
		}
	}
	// Add compliance-mapping if the control has compliance mappings
	if strings.Contains(content, "compliance:") &&
		(strings.Contains(content, "nist_800_53") ||
			strings.Contains(content, "pci_dss") ||
			strings.Contains(content, "soc2") ||
			strings.Contains(content, "ccm_v4") ||
			strings.Contains(content, "hipaa") ||
			strings.Contains(content, "fedramp") ||
			strings.Contains(content, "cis_")) {
		seen["compliance-mapping"] = true
	}

	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	// Remove compliance-mapping from multi-tag controls to reduce noise
	// (it's a meta-category, keep it only when it's one of few tags)
	if len(out) > 3 {
		out = slices.DeleteFunc(out, func(s string) bool { return s == "compliance-mapping" })
	}
	return out
}

func insertTaxonomy(content string, cats []string) string {
	var tagLines strings.Builder
	tagLines.WriteString("taxonomy:\n")
	for _, c := range cats {
		tagLines.WriteString("  - " + c + "\n")
	}
	tag := tagLines.String()

	// Try to insert after scope_tags block
	if idx := findBlockEnd(content, "scope_tags:"); idx >= 0 {
		return content[:idx] + tag + content[idx:]
	}
	// Try after severity:
	if idx := findLineEnd(content, "severity:"); idx >= 0 {
		return content[:idx] + tag + content[idx:]
	}
	// Try after domain:
	if idx := findLineEnd(content, "domain:"); idx >= 0 {
		return content[:idx] + tag + content[idx:]
	}
	return content
}

// findBlockEnd finds the end of a YAML block (line starting with key, followed
// by indented lines). Returns the byte offset after the last indented line.
func findBlockEnd(content, key string) int {
	lines := strings.Split(content, "\n")
	var offset int
	inBlock := false
	for i, line := range lines {
		if strings.HasPrefix(line, key) {
			inBlock = true
			offset += len(line) + 1
			continue
		}
		if inBlock {
			if strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "- ") {
				offset += len(line) + 1
				continue
			}
			// End of block
			return offset
		}
		offset += len(line) + 1
		_ = i
	}
	if inBlock {
		return offset
	}
	return -1
}

// findLineEnd finds the end of a single line starting with key.
func findLineEnd(content, key string) int {
	lines := strings.Split(content, "\n")
	var offset int
	for _, line := range lines {
		if strings.HasPrefix(line, key) {
			return offset + len(line) + 1
		}
		offset += len(line) + 1
	}
	return -1
}
