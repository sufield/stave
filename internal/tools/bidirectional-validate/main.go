// bidirectional-validate implements Direction 2 of Adam's architecture:
// every control must derive from a universal. Classifies all active
// controls in the catalog into instance/refinement/unmapped categories
// and reports per-universal domain coverage.
//
// Direction 1 (formulas validate controls via Z3) is handled by
// prove-universals, which grounds observations into SMT-LIB and
// runs Z3 subprocess on each formula.
//
// Usage: go run ./internal/tools/bidirectional-validate
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type rule struct {
	Universal string
	Patterns  []string
}

// Ordered by specificity — first match wins.
// Most-specific patterns go first to prevent broad patterns from swallowing
// refinements. E.g. .KMS.ROTATION. must match before .ROTATION. does.
var rules = []rule{
	// U32 — IMDSv2
	{"U32", []string{".IMDSV2.", ".IMDS.V1.", ".IMDS.001", ".IMDS.DISABLED.", ".IMDS.HOPLIMIT."}},
	// U28 — Deletion protection
	{"U28", []string{".DELETEPROT.", ".DELETION.PROTECTION.", ".LOCK."}},
	// U29 — Backup
	{"U29", []string{".PITR.", ".BACKUP.", ".DR.NOSECOND",
		".SNAPSHOT.001", ".SNAPSHOT.NOCROSSREGION.", ".SNAPSHOT.COPY.",
		".DELETE.NOSNAPSHOT.", ".BACKTRACK."}},
	// U10 — KMS key rotation (before generic .ROTATION.)
	{"U10", []string{".KMS.ROTATION.", ".KMS.LIFECYCLE.ROTATION.", ".KMS.NOROTATION."}},
	// U18 — Secrets rotation (before generic .ROTATION.)
	{"U18", []string{".SECRETS.ROTATION.", ".ROTATION.NEVER.", ".ROTATION.STALE.", ".ROTATION.INTERVAL."}},
	// U3 — MFA
	{"U3", []string{".MFA."}},
	// U4 — Root account
	{"U4", []string{".ROOT.ACCESSKEY.", ".ROOT.USAGE.", ".ROOT.MFA.", ".ROOT.HWMFA.", ".ROOT.CENTRALIZED.", ".ROOT.EMAIL."}},
	// U7 — Management ports
	{"U7", []string{".RESTRICTED.PORTS.", ".NONSTANDARD.PORTS.", ".SERIALCONSOLE."}},
	// U13 — Log integrity
	{"U13", []string{".LOG.VALIDATION.", ".OBJECTLOCK.", ".MFADELETE.", ".INTEGRITY.DIGEST.",
		".TRANSPARENCY.", ".UNSIGNED."}},
	// U11 — CloudTrail enabled / isolation
	{"U11", []string{".CLOUDTRAIL.ENABLED.", ".CLOUDTRAIL.REGIONAL.",
		".VPC.ENDPOINTS.", ".MULTIAZ.", ".ISOLATION."}},
	// U14 — Config enabled
	{"U14", []string{".CONFIG.ENABLED.", ".CONFIG.RECORDER.", ".CONFIG.DELIVERY.", ".CONFIG.RULES."}},
	// U15 — Drift detection
	{"U15", []string{".DRIFT.", ".SNAPSHOT.STALE."}},
	// U31 — Version currency
	{"U31", []string{".RUNTIME.EOL.", ".VERSION.UNPINNED.", ".VERSION.VULNERABLE.", ".VERSION.OUTDATED.",
		".ENGINE.EOL.", ".ENGINE.OUTDATED.", ".VERSION.001", ".VERSION.ACCUMULATION.", ".VERSION.OFF.",
		".AMI.001", ".AMI.STALE.", ".FARGATE.VERSION.",
		".UPGRADE.", ".PATCH.", ".DEVENDPOINT.DEPRECATED.", ".RUNTIME.001",
		".ENGINE.001", ".V1.001", ".SELFMANAGED."}},
	// U30 — Plaintext secrets in config (before broader .SECRET.)
	{"U30", []string{".SECRET.PLAIN.", ".SECRET.ENV.", ".SECRET.BROKER.", ".SECRETS.PLAINTEXT.",
		".TOKEN.PLAINTEXT.", ".APIKEY.PLAINTEXT.", ".CONNECTION.BASIC.PLAINTEXT.",
		".CONNECTION.OAUTH.PLAINTEXT.", ".CONNECTION.APIKEY.PLAINTEXT.",
		".STAGE.VARS.CREDENTIALS.", ".CRED.001", ".STOPLOGGING.",
		".SECRET.BLAST.", ".SENSITIVE."}},
	// U1 — Least privilege (before broader .AUTH.)
	{"U1", []string{".ADMIN.001", ".WILDCARD.001", ".SERVICEWILDCARD.", ".OBFUSCATED.ADMIN.",
		".PASSROLE.", ".BOUNDARY.WILDCARD.", ".OVERBROAD.", ".ESCALATE.",
		".OPS.BROAD.", ".ROLE.BROAD.", ".PERMISSIONS.BROAD.", ".STARTEXEC.ALLMACHINE.",
		".PUTRULE.BROAD.", ".PUTTARGETS.BROAD.", ".REMOVETARGETS.BROAD.",
		".DELETEEVENTBUS.BROAD.",
		// Broad privilege patterns
		".BROAD.", ".OVERPERM.", ".FULLACCESS.", ".SCOPING.",
		".RBAC.", ".PRIVILEGED.", ".RUNASROOT.", ".KUBELET.",
		".HOSTACCESS.", ".HOSTPATH.", ".HOSTPID.", ".HOSTNETWORK.",
		".HOSTPORTS.", ".CAPABILITIES.", ".SECCOMP.", ".APPARMOR.",
		".READONLYROOT.", ".NETPOL.", ".POD.NODE.PROFILE.", ".POD.SATOKEN.",
		// IAM policy analysis
		".BOUNDARY.ESCAPE.", ".BOUNDARY.PAYER.", ".ANALYZER.",
		".IAMAUTH.", ".IAM.AUTH.", ".FGAC.", ".AUTHZ.",
		".POLICY.DISCLOSURE.", ".POLICY.SHADOW.", ".ENUMERATION.", ".ACCUMULATED.",
		".ACCOUNT.DELEGATION.", ".GUEST.",
		// Cognito / identity pool
		".CLIENT.ALLFLOWS.", ".CLIENT.ALLSCOPES.", ".CLIENT.CLIENTCREDS.",
		".ADMIN.COUNT.", ".ADMIN.GLOBALADMIN.", ".ADMIN.GROUPS.", ".ADMIN.LOCKBOX.",
		".ROLE.FULLACCESS.", ".ROLE.CROSSSERVICE.", ".ROLE.LAMBDA.", ".ROLE.SHARED.",
		".ALLACCESS.", ".NOSCP.", ".MASTERS.BROAD.", ".MGMT.PRINCIPALS.",
		".METHODAUTH.", ".CROSSENV.", ".CHAIN.SENSITIVE.", ".UPDATE.NONADMIN.",
		".NORESOURCETAG.", ".POLICY.ACCUMULATED.", ".POLICY.DELETE.", ".POLICY.OBJECTSCOPED.",
		".POLICY.UNVERSIONED.", ".POLICY.UPDATECONFIG.", ".POLICY.INVERTED.",
		".POLICY.RI.", ".SELFMODIFY.", ".SELFREMOVAL.", ".ASSUMEROOT.",
		".ACCESS.LONGTERM.", ".ACCESS.MODELSCOPE.", ".ACCESS.POLICY.",
		".NOSOURCE.", ".GRANT.BROAD.", ".PRINCIPAL.", ".ASSUME.", ".ATTACH.",
		".POLICY.INLINE.", ".POLICY.CONDITION.", ".PRIVESC.", ".BLASTRADIUS."}},
	// U9 — Encryption in transit (before broader .ENCRYPT.)
	{"U9", []string{".NOTLS.", ".HTTP.PLAINTEXT.", ".TRANSIT.001", ".TRANSIT.ENCRYPT.",
		".NOENCRYPT.", ".TCP80.NOTLS.", ".ORIGIN.HTTP.", ".TLS.", ".MTLS.",
		".NODETONODE.", ".UNENCRYPTED.CALLBACK.", ".SPLITTUNNEL.",
		".KAFKA.PLAINTEXT.", ".CLIENTCERT.", ".PSK.001",
		".SSL.", ".HTTPS.", ".FIPS.", ".ENCRYPT.TRANSPORT.",
		".ORIGIN.S3.WEBSITE.", ".ORIGIN.OAI.", ".ORIGIN.BYPASS.", ".ORIGIN.NOACCESS.",
		".ORIGIN.SHIELD.", ".VIEWER.CERT.", ".CLB.BACKEND.PLAINTEXT.",
		".HTTPAPI.JWT.", ".FTP.", ".HTTPCALLBACK.", ".NOHTTP2."}},
	// U27 — Endpoint auth (specific patterns to avoid .AUTH. swallowing IAM)
	{"U27", []string{".NOAUTH.", ".URL.AUTH.", ".AUTH.UNAUTHENTICATED.", ".AUTH.APIKEY.",
		".AUTH.COGNITO.", ".AUTH.WEBSOCKET.", ".TRIGGER.APIGATEWAY.NOAUTH.",
		".AUTH.001", ".AUTH.REQUIRED.", ".AUTH.IAM.UNRESTRICTED.", ".AUTH.JWT.",
		".AUTHORIZER.", ".NOIAM.", ".DEFAULT.ROUTE.001",
		".AUTH.MIXED.", ".AUTH.ACCESSKEYMAP.", ".AUTH.AAA.", ".AUTH.ACCOUNTING.",
		".AUTH.ENABLE.", ".AUTH.LOGIN.", ".AUTH.UNRESTRICTED.", ".AUTH.BASIC.",
		".LOCKOUT.", ".PASSWORD.", ".SSPR.", ".PASSWORDBAN.",
		".ADMIN.PASSWORD.", ".DEFAULT.ADMIN.", ".MASTER.PASSWORD.",
		".CA.GUESTS.", ".CA.MOBILE.", ".CA.DEVICECODE.", ".CA.INSIDERRISK.",
		".TENANT.CREATE.", ".APPREG.", ".SIGNINRISK.", ".USERRISK."}},
	// U26 — Service logging
	{"U26", []string{".NOLOGGING.", ".ACCESSLOG.", ".LOG.MISSING.", ".LOG.AUDIT.",
		".LOG.SLOW.", ".FLOWLOG.", ".EXECLOG.", ".SESSION.LOGGING.",
		".AUDIT.DATAEVENTS.", ".LOG.001", ".LOG.LEVEL.", ".LOG.RETENTION.",
		".LOG.APPLICATION.", ".LOG.REQUEST.", ".LOG.GROUP.", ".LOG.NOEXEC.",
		".LOG.EXPRESS.", ".LOG.COST.", ".LOG.UNCORRELATED.", ".LOG.SECRET.",
		".XRAY.OFF.", ".NOTRACING.",
		".AUDIT.001", ".AUDIT.PARAM.OFF.", ".LOG.CLOUDWATCH.", ".LOG.BUCKET.",
		".LOG.EXPORT.", ".LOG.S3.", ".LOG.TARGET.", ".LOG.SOURCE.",
		".LOG.CONNLOG.", ".LOG.PREFIX.", ".MONITORING.001", ".MONITORING.",
		".SLOWLOG.", ".AUDIT.NOBODY.", ".AUDIT.NOINDEX.", ".EVENTS.001",
		".EXPORT.001", ".ACTIVITYLOG.", ".APPINSIGHTS.",
		".AUDIT.ACCTMGMT.", ".AUDIT.LOGON.", ".AUDIT.OBJACCESS.",
		".AUDIT.PRIVUSE.", ".AUDIT.OBJECTLEVEL."}},
	// U33 — Security service enabled (specific services only)
	{"U33", []string{".GUARDDUTY.ENABLED.", ".SECURITYHUB.ENABLED.", ".INSPECTOR.ENABLED.",
		".MACIE.ENABLED.", ".SECURITYLAKE.ENABLED.", ".AUDITMANAGER.ENABLED.",
		".DETECTIVE.ENABLED.", ".FMS.ENABLED.", ".SHIELD.ADVANCED.",
		".ACCESSANALYZER.ENABLED.", ".CONTROLTOWER.ENABLED.", ".IDENTITYCENTER.ENABLED.",
		".SECURITYIR.ENABLED.", ".DEFENDER.", ".WAF.ENABLED.", ".WAF.ASSOCIATION.",
		".WAF.001", ".WAF.MODE.", ".WAF.RATELIMIT.", ".WAF.BYPASS.",
		".WAF.GEORESTRICTION.", ".WAF.PROTECTION.", ".WAF.RULE.",
		".WAF.MANAGED.", ".WAF.CONSISTENCY.", ".WAF.OWASP.",
		".WAF.RULES.", ".WAF.WEBACL.", ".WAF.RULEGROUP.",
		".WAF.IPSET.", ".WAF.METRICS.", ".WAF.LOGGING.",
		".WAF.PARSERLIMIT.", ".WAF.EVASION.", ".WAF.ORIGIN.", ".WAF.CLASSIC.",
		".SCAN.001", ".ENHANCED.SCANNING.", ".GUARDIAN."}},
	// U2 — Credential lifecycle
	{"U2", []string{".CRED.ROTATION.", ".CRED.TTL.", ".CRED.UNUSED", ".CRED.EXPIRY.",
		".OIDC.", ".CICD.SCOPE.", ".CERT.EXPIRY.", ".CERT.RENEWAL.",
		".DEAUTHORIZED.", ".APIKEY.SOURCE.",
		".CERT.VALIDATION.", ".CERT.COVERAGE.", ".CERT.WEAKKEY.", ".CERT.NOTACM.",
		".CERT.SELFSIGNED.", ".KEY.ALGORITHM.", ".SA.KEY.", ".CLIENT.CA.",
		".LONGLIVEDKEYS.", ".SESSION.DURATION.", ".NOEXPIRY.", ".NOPASSWD.",
		".REVENC.", ".DESONLY.", ".TOKEN.REVOCATION.",
		".ACCESSTTL.", ".REFRESHTTL.", ".IDTTL.", ".IMPLICITFLOW.",
		".SP.EXPIRY.", ".SP.SECRET.",
		".IDENTITY.PIM.", ".IDENTITY.MANAGED.", ".IDENTITY.SP.",
		".AGENT.LONGLIVEDKEYS."}},
	// U5 — Public access
	{"U5", []string{".PUBLIC.", ".PAB.", ".BLOCKPUBLIC.", ".ANON.", ".ANONYMOUS.",
		".PRIVATE.", ".EXPOSED.", ".GEORESTRICTION."}},
	// U6 — Network controls
	{"U6", []string{".SG.DEFAULT.", ".SG.INGRESS.", ".SG.RESTRICT", ".SG.BROAD.",
		".NACL.UNRESTRICTED.", ".VPC.DEFAULT.", ".SG.EGRESS.", ".SG.CIDR.",
		".SG.HIGHPORTS.", ".SG.ICMP.", ".SG.IPV6.", ".SG.PORTRANGE.",
		".SG.RECUR.", ".SG.UNRESTRICTED.", ".SG.EASTWEST.", ".SG.SHARED.",
		".SG.ENCLAVE.", ".NACL.CIDR.", ".NACL.DEFAULT.", ".NACL.ENCLAVE.",
		".NACL.RULE.", ".NACL.001", ".EGRESS.UNRESTRICTED.",
		".NETWORK.FIREWALL.", ".DNSFIREWALL.", ".BPA.",
		".NETWORK.001", ".SG.OPEN.", ".ENDPOINT.PRIVATE.", ".VPC.001",
		".VPC.CNI.", ".SUBNET.", ".NODEGROUP.SG.", ".AZ.SAME.",
		".ACL.", ".DESYNC.", ".CROSSZONE.", ".BACKEND.DIRECT.",
		".INGRESS.UNRESTRICTED.", ".INTF.DIRBROADCAST.",
		".PEERING.", ".SEGMENT.", ".TGW.", ".ROUTETABLE.", ".VPN."}},
	// U8 — Encryption at rest (broad — after transit patterns consumed)
	{"U8", []string{".ENCRYPT.001", ".ENCRYPT.CMK.", ".ENCRYPT.SSE.", ".SSE.",
		".EBS.ENCRYPT.", ".ENCRYPT.REST.", ".ENCRYPT.KMS.", ".ENCRYPT.DEFINITION.",
		".ENCRYPT.EXEC.", ".ENCRYPT.REPORTS.", ".ENCRYPT.S3LOGS.",
		".NOTENCRYPTED.", ".NOCMK.", ".AWSOWNED.", ".EBS.UNENCRYPTED.",
		".ENCRYPT.BOOKMARKS.", ".ENCRYPT.S3.", ".ENCRYPT.PASSWORD.",
		".ENCRYPT.CATALOG.", ".ENCRYPT.SESSION.", ".ENCRYPTION.001", ".ENCRYPTION.",
		".EFS.KMS.", ".ENCRYPT.PROV.", ".ENCRYPT.DEFAULT.PARITY.",
		".TRANSITENCRYPT.", ".ACCOUNT.ENCRYPT.", ".DEFAULTCERT."}},
	// U12 — Resource logging (specific services)
	{"U12", []string{".S3.LOG.001", ".S3.LOG.TARGET.", ".CLUSTER.LOGGING.", ".LOGGING.001"}},
	// U19 — SCPs / RCPs / Declarative policies / org governance
	{"U19", []string{".SCP.", ".RCP.", ".DP.",
		".NODELEGATED.", ".ORG.DELEGATED.", ".ORG.NORULES.", ".ORG.AUDIT.",
		".ORG.NOCONFORMANCE.", ".ORG.NOTALLACCOUNTS.", ".ORG.MEMBERCANOVERRIDE.",
		".ORG.REMEDIATION."}},
	// U20 — Cross-account / trust boundaries
	{"U20", []string{".CROSSACCOUNT.", ".CROSS.ENV.", ".CROSSREGION.", ".EXTERNAL.",
		".RAM.EXTERNAL.", ".FEDERATION.",
		".TRUST.001", ".TRUST.CROSSENV.", ".TRUST.EXTERNALID.",
		".TRUST.SCOPED.", ".TRUST.SOURCEARN.", ".IDENTITY.GUEST."}},
	// U17 — Plaintext secrets (broad)
	{"U17", []string{".ENV.ENCRYPT.", ".ECS.SECRETS.", ".CODEBUILD.SECRETS.",
		".USERDATA.CREDS.", ".USERDATA.SECRETS.", ".SSM.DOCUMENT.SECRETS.",
		".STEPFUNCTIONS.SECRETS.", ".GLUE.JOB.SECRETS.", ".PARAM.NOECHO.",
		".CLOUDFORMATION.SECRETS.", ".LAMBDA.ENV.SECRETS.", ".K8S.SECRETS.",
		".FOOTHOLD.CICD.SECRETS."}},
}

// Refinement patterns — operational controls below universal threshold.
// These are valid controls but don't map to a security universal.
var refinementPatterns = []string{
	".GHOST.",       // structural orphan / dangling reference
	".ALARM.",       // monitoring / alerting
	".ORPHAN.",      // orphaned resource
	".INCOMPLETE.",  // incomplete configuration
	".DANGLING.",    // dangling reference
	".IDLE.",        // idle resource
	".ZOMBIE.",      // zombie resource
	".DORMANT.",     // dormant resource
	".NOTAGS.",      // missing tags (governance, not security)
	".TAG.",         // tagging issues
	".STALE.",       // stale resource (operational)
	".LIFECYCLE.",   // lifecycle management
	".COST.",        // cost optimization
	".COMPLIANCE.",  // compliance tagging
	".NAMING.",      // naming convention
	".REGION.",      // region policy
	".MONITOR.",     // monitoring configuration
	".MISSING.",     // missing configuration (generic)
	".MISMATCH.",    // configuration mismatch
	".HEALTH.",      // health check config
	".SEMANTICS.",   // semantic validation
	".COLLISION.",   // naming collision
	".THROTTLE.",    // throttling / rate limit
	".TIMEOUT.",     // timeout configuration
	".RETENTION.",   // data retention (operational)
	".REPLICATION.", // replication config
	".SPRAWL.",      // resource sprawl
	".BREAKGLASS.",  // break-glass procedures
	".FANOUT.",      // fan-out configuration
	".OVERLAP.",     // pattern overlap
	".SELFLOOP.",    // self-referencing loop
	// Infrastructure / availability
	".MICROVM.", ".FAILOVER.", ".CONCENTRATION.",
	".CAPACITY.", ".HA.REPLICA.", ".NOAUTOSCALE.", ".NOREPLICAS.",
	// HTTP / API config
	".CORS.", ".HEADERS.", ".GATEWAYRESPONSE.", ".INTEGRATION.",
	".METHOD.", ".HTTPAPI.", ".RATELIMIT.",
	// Queue / messaging
	".DLQ.", ".QUEUE.", ".TOPIC.",
	// DNS / domain
	".ZONE.", ".DOMAIN.", ".DNS.", ".DMARC.",
	".WILDCARD.CNAME.", ".CNAME.NODNS.", ".MULTIDIST.",
	// Operational config
	".INSIGHTS.", ".NOTIFICATION.", ".PARAM.",
	".CACHE.", ".QUOTA.", ".LIMIT.", ".ARCHIVE.",
	".PROFILING.", ".DEBUG.", ".TELEMETRY.",
	// Service-specific operational
	".MICROVM.", ".ASL.", ".BOT.", ".GEO.",
	".NOSIGNING.", ".LEGACYKEY.", ".ARTIFACT.", ".LINEAGE.",
	".POLLUTION.", ".ADDON.", ".COREDNS.", ".HELMDUAL.",
	".DRAINING.", ".CLONING.", ".DEREGPROTECTION.",
	".NOROOTOBJECT.", ".NOERRORRESPONSES.", ".SHORTPOLLING.",
	".GSI.", ".IDEMPOTENCY.", ".WAITFORTOKEN.",
	".MRAP.", ".AP.POLICY.", ".ACCEL.",
	".RULEGROUP.", ".MODE.001", ".FRAG.", ".APIDEST.",
	// Governance / compliance (non-security)
	".GOVERNANCE.", ".CLASSIFICATION.", ".SENSITIVITY.",
	".POLICY.EXISTS.", ".USERS.EXCESSIVE.", ".ROOTACCOUNT.",
	".ALTERNATECONTACTS.", ".DOMAINTAG.", ".MEMBERSHIP.",
	".ACCOUNT.BOUNDARY.", ".GUARDRAIL.",
	// Platform-specific operational
	".CONNECTOR.", ".ENRICHMENT.", ".EXCHANGE.", ".PURVIEW.",
	".ENTRA.", ".SHAREPOINT.", ".TEAMS.", ".INTUNE.",
	".CONTAINER.", ".POD.", ".NAMESPACE.", ".CLUSTER.", ".NODE.",
	".COMPUTE.", ".DATABASE.", ".STORAGE.", ".CONDITIONAL.",
	".ACCOUNT.", ".CUSTOM.", ".DEPRECATED.", ".DISABLED.",
	".SERVICE.ACTIVE.", ".ENV.ACTIVE.", ".BENCHMARK.",
	// OpenSearch operational
	".ISM.", ".TIERING.", ".SHARD.", ".MASTER.COUNT.",
	".MASTER.NODEDICATED.", ".MASTER.SAME.", ".MASTER.UNDERSIZED.",
	".DATA.NODE.SINGLE.", ".EBS.GP2.", ".AZ.NOSTANDBY.",
	".CUSTOM.CERT.", ".SAML.", ".KIBANA.", ".PURGE.",
	// Access pattern refinements
	".RECEIVEMESSAGE.", ".DELETEBROADLY.", ".PERMISSIVE.",
	".DEFAULT.FRAG.", ".DEFAULT.FULL.",
	// Security operational
	".MALWARE.", ".BREACH.DETECT.", ".UNDERATTACK.",
	".SIGNED.", ".NOLOGOUT.", ".SELFREG.", ".TEMPPASSWORD.",
	".ATTR.", ".NOAPPROVAL.", ".NEWSERVICE.", ".SERVICEROLE.",
	".AGGREGATOR.", ".SILENCEDROPS.", ".METRICS.",
	".SHAREDEXECUTION.", ".EB.SHARED.",
	// Cloud-specific platform
	".COSMOS.", ".KEYVAULT.", ".AKS.", ".STORAGE.NETWORK.",
	".AISEARCH.", ".APIM.", ".MYSQL.", ".POSTGRESQL.",
	".SQL.AUDIT.", ".ACR.", ".ACCESSCONTEXT.",
	".APP.VNET.", ".APP.IDENTITY.", ".APP.RUNTIME.",
	".INSECURE.PORT.", ".ETCD.CERT.",
	// Remaining identity/auth operational
	".FORMAT.INSECURE.", ".INTEGRITY.CONFIG.",
	".AGENTCORE.", ".GW.DEBUG.", ".GW.EGRESS.",
	".IDPOOL.", ".DELETION.PROTECT.",
}

type classification struct {
	ID        string
	Universal string // "" = unmapped
	Category  string // "instance", "refinement", "unmapped"
	Service   string
}

func classifyControl(id string) (universal, category string) {
	for _, r := range rules {
		for _, p := range r.Patterns {
			if strings.Contains(id, p) {
				return r.Universal, "instance"
			}
		}
	}
	for _, p := range refinementPatterns {
		if strings.Contains(id, p) {
			return "", "refinement"
		}
	}
	return "", "unmapped"
}

func extractService(path string) string {
	parts := strings.Split(path, string(filepath.Separator))
	for i, p := range parts {
		if p == "controls" && i+1 < len(parts) {
			svc := parts[i+1]
			if svc == "_triage" || svc == "_scope-overrides.yaml" {
				return ""
			}
			return svc
		}
	}
	return ""
}

func main() {
	controlsDir := "internal/controls"
	if len(os.Args) > 1 {
		controlsDir = os.Args[1]
	}

	var all []classification
	err := filepath.Walk(controlsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if info.Name() == "_triage" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasPrefix(info.Name(), "CTL.") || !strings.HasSuffix(info.Name(), ".yaml") {
			return nil
		}
		id := strings.TrimSuffix(info.Name(), ".yaml")
		svc := extractService(path)
		u, cat := classifyControl(id)
		all = append(all, classification{
			ID:        id,
			Universal: u,
			Service:   svc,
			Category:  cat,
		})
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "walk: %v\n", err)
		os.Exit(4)
	}

	var instances, refinements, unmapped int
	byUniversal := make(map[string]map[string]bool)
	byUniversalCount := make(map[string]int)
	unmappedByService := make(map[string]int)

	for _, c := range all {
		switch c.Category {
		case "instance":
			instances++
			byUniversalCount[c.Universal]++
			if byUniversal[c.Universal] == nil {
				byUniversal[c.Universal] = make(map[string]bool)
			}
			byUniversal[c.Universal][c.Service] = true
		case "refinement":
			refinements++
		default:
			unmapped++
			unmappedByService[c.Service]++
		}
	}

	total := len(all)
	pctInst := float64(instances) * 100 / float64(total)
	pctRef := float64(refinements) * 100 / float64(total)
	pctUnmap := float64(unmapped) * 100 / float64(total)

	fmt.Println("Bidirectional Validation — Direction 2")
	fmt.Println("=======================================")
	fmt.Println("Controls validate formulas: every control derives from a universal")
	fmt.Println()
	fmt.Printf("  Total active controls:  %d\n", total)
	fmt.Printf("  Instance (→ universal): %d (%.0f%%)\n", instances, pctInst)
	fmt.Printf("  Refinement (below threshold): %d (%.0f%%)\n", refinements, pctRef)
	fmt.Printf("  Unmapped (needs review): %d (%.0f%%)\n", unmapped, pctUnmap)
	fmt.Println()

	uNames := map[string]string{
		"U1": "Least privilege", "U2": "Credential lifecycle", "U3": "MFA enforcement",
		"U4": "Root account", "U5": "Public access", "U6": "Network deny",
		"U7": "Management ports", "U8": "Encryption at rest", "U9": "Encryption in transit",
		"U10": "KMS rotation", "U11": "CloudTrail enabled", "U12": "Resource logging",
		"U13": "Log integrity", "U14": "Config enabled", "U15": "Drift detection",
		"U17": "No plaintext secrets", "U18": "Secrets rotation", "U19": "SCPs active",
		"U20": "Cross-account isolation", "U26": "Service logging", "U27": "Endpoint auth",
		"U28": "Deletion protection", "U29": "Backup configured", "U30": "Secrets in config",
		"U31": "Version currency", "U32": "IMDSv2 enforced", "U33": "Security svc enabled",
	}

	uIDs := make([]string, 0, len(byUniversalCount))
	for u := range byUniversalCount {
		uIDs = append(uIDs, u)
	}
	sort.Slice(uIDs, func(i, j int) bool {
		return extractNum(uIDs[i]) < extractNum(uIDs[j])
	})

	fmt.Println("Per-Universal Coverage")
	fmt.Println("──────────────────────")
	fmt.Printf("  %-4s  %-28s  %6s  %8s\n", "ID", "Statement", "Ctrls", "Services")
	for _, u := range uIDs {
		name := uNames[u]
		if name == "" {
			name = "(unknown)"
		}
		fmt.Printf("  %-4s  %-28s  %6d  %8d\n", u, name, byUniversalCount[u], len(byUniversal[u]))
	}
	fmt.Println()

	type svcCount struct {
		svc   string
		count int
	}
	var umSorted []svcCount
	for s, c := range unmappedByService {
		umSorted = append(umSorted, svcCount{s, c})
	}
	sort.Slice(umSorted, func(i, j int) bool { return umSorted[i].count > umSorted[j].count })

	fmt.Printf("Unmapped Controls — Top Services (%d total)\n", unmapped)
	fmt.Println("────────────────────────────────")
	shown := 0
	for _, sc := range umSorted {
		if shown >= 15 {
			remaining := len(umSorted) - 15
			fmt.Printf("  ... and %d more services\n", remaining)
			break
		}
		fmt.Printf("  %-24s %d\n", sc.svc, sc.count)
		shown++
	}
	fmt.Println()

	fmt.Println("Direction 1 — Formulas Validate Controls")
	fmt.Println("─────────────────────────────────────────")
	fmt.Println("  Status: AVAILABLE")
	fmt.Println("  Tool:   make prove-universals ARGS='--observations <dir>'")
	fmt.Println("  Method: Z3 subprocess on grounded SMT-LIB formulas (U26-U33)")
	fmt.Println("  Files:  data/universals/u26-u33 (8 files)")
	fmt.Println("          docs-internal/security/universals.smt2 (U1-U25, not yet grounded)")
}

func extractNum(uid string) int {
	n := 0
	for _, c := range uid {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}
