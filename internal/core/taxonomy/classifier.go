package taxonomy

import (
	"regexp"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

type classificationRule struct {
	pattern  *regexp.Regexp
	category kernel.CategoryID
}

// Classifier assigns taxonomy categories to controls based on
// their ID, name, description, and predicate field paths.
type Classifier struct {
	rules []classificationRule
}

// NewClassifier creates a classifier with the standard rule set.
func NewClassifier() *Classifier {
	c := &Classifier{}
	c.add(LeastPrivilege, `(?i)wildcard|overperm|admin[._]access|full[._]access|\bbroad\b`)
	c.add(CredentialLifecycle, `(?i)access[._]key|key[._]age|rotation|session[._]duration|long[._]term|MaxSession|LONGTERM`)
	c.add(TrustBoundary, `(?i)cross[._]account|CrossAccount|ExternalId|trust[._]policy|wildcard[._]principal`)
	c.add(TrustDecay, `(?i)stale|idle|ghost|orphan|unused|dormant`)
	c.add(ConfusedDeputy, `(?i)confused|deputy|SourceAccount|SourceOrgID`)
	c.add(Attribution, `(?i)SourceIdentity|cloudtrail|audit|LOG\.|LOGGING`)
	c.add(NetworkPerimeter, `(?i)SourceIp|VpceOrgID|public[._]access|0\.0\.0\.0|ingress|SSH|RDP|BLOCKPUBLIC`)
	c.add(DataPerimeter, `(?i)data[._]perimeter|PrincipalOrgID|DATAPERIMETER|COMPLETENESS`)
	c.add(EncryptionAtRest, `(?i)encrypt.*rest|volume.*encrypt|EBS.*encrypt|SSE|KmsKeyId|DEFAULT\.ENCRYPT`)
	c.add(EncryptionInTransit, `(?i)transit.*encrypt|SSL|TLS|inter[._]container`)
	c.add(KeyManagement, `(?i)\bKMS\b|\bkms\b|key[._]rotation|key[._]policy`)
	c.add(NetworkIsolation, `(?i)\bVPC\b|\bvpc\b|network[._]isolation|subnet|ENDPOINT`)
	c.add(ComputeHardening, `(?i)privileged|IMDSv2|IMDS|root[._]access|deprecated.*runtime|MICROVM|SERIALCONSOLE`)
	c.add(Redundancy, `(?i)multi[._]az|MultiAZ|redundancy|single[._]point`)
	c.add(Logging, `(?i)CloudTrail|flow[._]log|FlowLog|access[._]log|LOG\.`)
	c.add(Monitoring, `(?i)GuardDuty|Security[._]Hub|Inspector|Macie|Config.*record|ALARM`)
	c.add(AIGuardrails, `(?i)guardrail|content[._]filter|topic[._]policy|PII[._]filter`)
	c.add(AISupplyChain, `(?i)\bECR\b|scan[._]on[._]push|GHOST\.MODEL|GHOST\.LAMBDA`)
	c.add(ResourceSprawl, `(?i)sprawl|SPRAWL|shadow|SHADOW`)
	c.add(AccountGovernance, `(?i)\bSCP\b|\bRCP\b|Control[._]Tower|delegated[._]admin|Organizations|ACCOUNT`)
	c.add(Impersonation, `(?i)CreateTokenWithIAM|account[._]access|SSOOAUTH`)
	c.add(IdentityPerimeter, `(?i)PrincipalOrgID|identity[._]perimeter`)
	c.add(FormalSemantics, `(?i)ForAllValues|ForAnyValue|IfExists|SEMANTICS|vacuous|NotPrincipal.*boundary|SETOP|CONDKEY|INAPPLICABLE`)
	c.add(DetectionEvasion, `(?i)IPSet|traffic[._]mirror|TrafficMirror|IPSET|detection.*evasion`)
	c.add(Deprecation, `(?i)\bEOL\b|deprecated|DEPRECATED|legacy|LEGACY|superseded|retired`)
	c.add(ComplianceMapping, `(?i)compliance|HIPAA|PCI|SOC|CIS|NIST|FedRAMP|GDPR|ISO.27001`)
	c.add(DataProtection, `(?i)deletion[._]protect|backup|PITR|snapshot|SNAPSHOT`)
	return c
}

func (c *Classifier) add(cat kernel.CategoryID, pattern string) {
	c.rules = append(c.rules, classificationRule{
		pattern:  regexp.MustCompile(pattern),
		category: cat,
	})
}

// Classify returns taxonomy categories matching the control text.
// The caller typically concatenates the control's ID, name,
// description, and predicate field paths into a single string.
func (c *Classifier) Classify(controlText string) []kernel.CategoryID {
	if c == nil {
		return nil
	}
	seen := make(map[kernel.CategoryID]bool)
	var result []kernel.CategoryID
	for _, r := range c.rules {
		if r.pattern.MatchString(controlText) && !seen[r.category] {
			seen[r.category] = true
			result = append(result, r.category)
		}
	}
	return result
}

// ClassifyFields builds the text from structured control fields
// and classifies it.
func (c *Classifier) ClassifyFields(id, name, description string, predicateFields []string) []kernel.CategoryID {
	var b strings.Builder
	b.WriteString(id)
	b.WriteByte(' ')
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(description)
	for _, f := range predicateFields {
		b.WriteByte(' ')
		b.WriteString(f)
	}
	return c.Classify(b.String())
}
