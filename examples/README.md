# Examples

113 self-contained examples you can run on your machine. Find the
scenario closest to your goal, read its README, and adapt it.

## Prerequisites

```bash
cd stave && make build
```

Most examples run with `./stave apply`. Reasoning engine examples
need external tools (Z3, Soufflé, etc.) — each README lists what
to install.

---

## I want to…

### Detect Public Exposure

| Example | What It Demonstrates |
|---------|---------------------|
| [public-bucket](public-bucket/) | S3 bucket with public read access — simplest starter example |
| [missing-pab](missing-pab/) | S3 bucket without Public Access Block — one policy change from exposure |
| [s3-public-read-policy](s3-public-read-policy/) | Public read via `Principal: "*"` bucket policy |
| [s3-public-list-policy](s3-public-list-policy/) | Public list policy enabling bucket enumeration |
| [s3-dotgit-readable](s3-dotgit-readable/) | Publicly readable `.git` prefix exposing source code |
| [s3-bucket-name-dangling](s3-bucket-name-dangling/) | Bucket-takeover via dangling bucket name |

### Track How Long Something Has Been Unsafe

| Example | What It Demonstrates |
|---------|---------------------|
| [duration](duration/) | Duration-based violation — bucket stays public across 3 snapshots over 9 days |
| [iam-cred-ttl-exceeded](iam-cred-ttl-exceeded/) | Credential TTL exceeded detection (no-expiry, exceeded, valid fixtures) |
| [meta-observation-stale](meta-observation-stale/) | Stale observation detection — are your snapshots fresh enough? |
| [staging-stale-endpoint](staging-stale-endpoint/) | Stale staging endpoint with environment-tag awareness |

### Find Privilege Escalation Paths

| Example | What It Demonstrates |
|---------|---------------------|
| [iam-21-privesc-5-patterns](iam-21-privesc-5-patterns/) | 21 IAM privilege escalation methods mapped to 5 Z3 proof patterns |
| [iam-attach-user-policy-self](iam-attach-user-policy-self/) | Self-attach user policy (Rhino Technique #1) |
| [iam-autoscaling-privesc-bypass](iam-autoscaling-privesc-bypass/) | Auto Scaling privilege escalation bypassing deny policies |
| [iam-overpermission-wildcard](iam-overpermission-wildcard/) | Lambda role with `s3:*` on `*` |
| [shadow-admin-detection](shadow-admin-detection/) | Role with readonly tag but admin-level permissions |
| [batch-escalation-chain](batch-escalation-chain/) | Batch/ECS escalation — job author gets host network access |

### Trace Cross-Service Attack Chains

| Example | What It Demonstrates |
|---------|---------------------|
| [iam-multi-hop-trust](iam-multi-hop-trust/) | Multi-hop IAM trust chain traversal |
| [imds-ssrf-chain](imds-ssrf-chain/) | EC2 IMDS SSRF credential escalation |
| [sns-secrets-compound-chain](sns-secrets-compound-chain/) | SNS secrets cross-service compound chain |
| [shadow-ec2-lateral-movement](shadow-ec2-lateral-movement/) | EC2 lateral movement via shadow permissions |
| [ecs-ssrf-credential-theft](ecs-ssrf-credential-theft/) | ECS SSRF credential theft compound chain |
| [vpc-peering-exfiltration](vpc-peering-exfiltration/) | VPC peering data exfiltration chain |
| [agent-chain-sensitive-reach](agent-chain-sensitive-reach/) | Agent role reaching sensitive resources via graph reachability |
| [cognito-self-register-to-aws-creds](cognito-self-register-to-aws-creds/) | Self-register → self-promote → AWS credentials chain |
| [iam-foothold-internet-reach](iam-foothold-internet-reach/) | Internet-facing compute reaching sensitive resources |

### Audit S3 Data Governance

| Example | What It Demonstrates |
|---------|---------------------|
| [s3-broad-write-scope](s3-broad-write-scope/) | Broad write scope allowing unintended overwrites |
| [s3-tenant-prefix-isolation](s3-tenant-prefix-isolation/) | Tenant prefix isolation failure in multi-tenant buckets |
| [s3-cross-account-replication-overperm](s3-cross-account-replication-overperm/) | Cross-account replication with over-broad permissions |
| [s3-delegation-failure](s3-delegation-failure/) | Vendor delegation failure — vendor can rewrite bucket policy |
| [scp-tag-authorization](scp-tag-authorization/) | Tag-based authorization scheme completeness (4-layer check) |

### Validate Identity & Authentication

| Example | What It Demonstrates |
|---------|---------------------|
| [cognito-ghost-identity](cognito-ghost-identity/) | Ghost identity with privileges via external IdP without PreSignUp gate |
| [cognito-presignup-ghost](cognito-presignup-ghost/) | Pre-sign-up ghost Lambda bypass end-to-end |
| [cognito-iteration1-ghosts](cognito-iteration1-ghosts/) | All 14 ghost controls plus compound invariants |
| [cognito-iteration2-unauth](cognito-iteration2-unauth/) | Identity pool unauthenticated access — anonymous AWS credentials |
| [cognito-iteration3-authbaseline](cognito-iteration3-authbaseline/) | Password policy and MFA authentication baseline |
| [cognito-iteration4-clientconfig](cognito-iteration4-clientconfig/) | App client OAuth flow, token, and callback URL configuration |
| [cognito-iteration5-authrole](cognito-iteration5-authrole/) | Identity pool authenticated role over-privilege |
| [cognito-iteration6-advsec](cognito-iteration6-advsec/) | Advanced security, verification, and custom domain controls |
| [cognito-iteration7-federation](cognito-iteration7-federation/) | Federation provider hygiene (SAML, OIDC, social) |
| [cognito-iteration8-monitoring](cognito-iteration8-monitoring/) | CloudWatch alarm and metric controls for Cognito |
| [cognito-iteration9-orphans](cognito-iteration9-orphans/) | Lifecycle and orphaned resource detection |
| [cognito-iteration10-tokenuicompliance](cognito-iteration10-tokenuicompliance/) | Token, hosted UI, resource servers, and compliance controls |
| [cognito-no-mfa-advanced-security](cognito-no-mfa-advanced-security/) | MFA plus advanced security gap detection |
| [cognito-advsec-tristate](cognito-advsec-tristate/) | Advanced Security feature tri-state (off, audit, enforced) |
| [scim-provisioning-takeover](scim-provisioning-takeover/) | SCIM provisioning takeover via public endpoint |

### Assess AI/ML Security

| Example | What It Demonstrates |
|---------|---------------------|
| [ai-shadow-and-ghosts](ai-shadow-and-ghosts/) | AI agent shadow identities and ghost permissions |
| [bedrock-agent-overpermissioned](bedrock-agent-overpermissioned/) | Bedrock agent with over-privileged execution role |
| [bedrock-agent-tool-phi](bedrock-agent-tool-phi/) | Bedrock agent tool access to PHI data |
| [bedrock-rag-phi-exposure](bedrock-rag-phi-exposure/) | RAG knowledge base exposing PHI via retrieval |
| [rag-retrieval-scope](rag-retrieval-scope/) | Retrieval role reaching beyond declared knowledge base sources |
| [rag-retrieval-vs-embedding](rag-retrieval-vs-embedding/) | Retrieval role broader than embedding role (permission set-difference) |
| [sagemaker-execution-role-overprivileged](sagemaker-execution-role-overprivileged/) | SageMaker execution role with excessive permissions |
| [sagemaker-notebook-prod-escape](sagemaker-notebook-prod-escape/) | SageMaker notebook escaping to production resources |

### Check Network & API Boundaries

| Example | What It Demonstrates |
|---------|---------------------|
| [alb-routing-nlb-bypass](alb-routing-nlb-bypass/) | NLB bypassing ALB-layer security controls at Layer 4 |
| [alb-routing-path-equivalence](alb-routing-path-equivalence/) | Multiple ALB paths to same backend with inconsistent security |
| [alb-routing-rule-shadow](alb-routing-rule-shadow/) | ALB rule shadowing — higher-priority non-auth rule bypasses auth |
| [apigw-private-api-scoped-deny](apigw-private-api-scoped-deny/) | API Gateway private API scoped deny gap |

### Evaluate Compute Security

| Example | What It Demonstrates |
|---------|---------------------|
| [lambda-blast-radius](lambda-blast-radius/) | Lambda blast radius analysis via Datalog |
| [lambda-concurrency](lambda-concurrency/) | Lambda concurrency cascade analysis |
| [lambda-event-source](lambda-event-source/) | Lambda event source exposure analysis |
| [eks-aws-auth-template-injection](eks-aws-auth-template-injection/) | EKS aws-auth ConfigMap template injection |
| [eks-rbac-webhook-config-access](eks-rbac-webhook-config-access/) | EKS RBAC webhook config access |
| [microvm-authtoken-expiry](microvm-authtoken-expiry/) | MicroVM auth-token expiration must be ≤ 30 minutes |
| [microvm-authtoken-portscope](microvm-authtoken-portscope/) | MicroVM auth-token port scoping |
| [microvm-lambda-wildcard](microvm-lambda-wildcard/) | `lambda:*` silently granting MicroVM actions |
| [microvm-observability-roles](microvm-observability-roles/) | Production MicroVM must have execution and build roles |
| [microvm-shell-auth](microvm-shell-auth/) | MicroVM shell authentication restriction |
| [microvm-shell-ingress](microvm-shell-ingress/) | Production MicroVM must not have SHELL_INGRESS connector |
| [az-redundancy](az-redundancy/) | Availability zone redundancy analysis |

### Detect Defense Evasion

| Example | What It Demonstrates |
|---------|---------------------|
| [cloudtrail-stop-logging](cloudtrail-stop-logging/) | CloudTrail stop-logging detection (MITRE ATT&CK T1562.008) |

---

## Prove It With a Reasoning Engine

Use these when CEL detection isn't enough — you need to *prove*
an attack path exists, enumerate reachability, or quantify risk.

| Example | Engine | What It Demonstrates |
|---------|--------|---------------------|
| [z3-public-exposure](z3-public-exposure/) | Z3 | Go program using Stave library + go-z3 for SAT check |
| [z3-forbidden-state](z3-forbidden-state/) | Z3 | User-defined invariants in YAML — auto-generated SMT-LIB |
| [z3-overpermission-fixture](z3-overpermission-fixture/) | Z3 | First end-to-end SMT consumer proving export round-trips |
| [z3-compound-overperm-assumable](z3-compound-overperm-assumable/) | Z3 | First compound query: overpermission + assumable role |
| [z3-multi-hop-can-assume](z3-multi-hop-can-assume/) | Z3 | 1-to-3 hop sts:AssumeRole reachability with reciprocal trust |
| [z3-cognito-auth-chain](z3-cognito-auth-chain/) | Z3 | Registration gate as choke point in Cognito chain |
| [z3-cognito-unauth-chain](z3-cognito-unauth-chain/) | Z3 | First multi-fact cross-service chain query |
| [z3-bybit-tag-aware-compound](z3-bybit-tag-aware-compound/) | Z3 | Developer wildcard prefix-matching production-tagged bucket |
| [z3-rhino-pattern1-self-mutation](z3-rhino-pattern1-self-mutation/) | Z3 | Rhino Pattern 1 — self-mutation via compound query |
| [z3-rhino-pattern2-credential-creation](z3-rhino-pattern2-credential-creation/) | Z3 | Rhino Pattern 2 — credential creation/theft |
| [z3-rhino-pattern3-passrole-compute](z3-rhino-pattern3-passrole-compute/) | Z3 | Rhino Pattern 3 — compute + PassRole (3-asset compound) |
| [z3-rhino-pattern4-indirect-invoke](z3-rhino-pattern4-indirect-invoke/) | Z3 | Rhino Pattern 4 — indirect compute invocation |
| [z3-rhino-pattern5-trust-modification](z3-rhino-pattern5-trust-modification/) | Z3 | Rhino Pattern 5 — role trust modification |
| [souffle-reachability](souffle-reachability/) | Soufflé | Datalog reachability over JSONL fact export |
| [clingo-constraints](clingo-constraints/) | Clingo | ASP constraint enumeration over the fact set |
| [prolog-proof-trees](prolog-proof-trees/) | Prolog | SWI-Prolog reasoning with proof trees as output |
| [sat-control-regression](sat-control-regression/) | PySAT | Boolean compound-of-finding regression check |
| [tlaplus-temporal-safety](tlaplus-temporal-safety/) | TLA+ | State-space exploration over mutable configuration knobs |
| [prism-risk-prioritization](prism-risk-prioritization/) | PRISM | Probabilistic attack-path prioritization |
| [game-theory-cost](game-theory-cost/) | Game theory | Cost-to-compromise and remediation ROI ranking |
| [compare-engines](compare-engines/) | All | Multi-engine comparison harness across all fixtures |
| [engines](engines/) | All | Five external reasoning engines consuming Stave's export |
| [explain](explain/) | SMT | Three human-readable translation layers around the solver |

---

## Demos

Curated scenarios with Docker support. Good for learning without
an AWS account.

| Demo | What It Demonstrates |
|------|---------------------|
| [demo-s3-public-read](demo-s3-public-read/) | Public read via `Principal: "*"` bucket policy with PAB disabled |
| [demo-s3-acl-write](demo-s3-acl-write/) | ACL-based public write that policy-only scanners miss |
| [demo-s3-acl-escalation](demo-s3-acl-escalation/) | ACL grants enabling privilege escalation (WRITE_ACP, READ_ACP, FULL_CONTROL) |
| [demo-s3-data-governance](demo-s3-data-governance/) | Cascading governance failures: missing classification, lifecycle, MFA delete |
| [demo-s3-hipaa-compliance](demo-s3-hipaa-compliance/) | HIPAA multi-violation: no encryption, no logging, no versioning, no object lock |
| [demo-s3-tool-blind-spot](demo-s3-tool-blind-spot/) | Buckets that appear safe to tools relying on APIs the bucket policy denies |
| [demo-s3-upload-hardening](demo-s3-upload-hardening/) | Upload policies allowing prefix-scoped keys or unrestricted content types |
| [demo-ai-security](demo-ai-security/) | AI agent with admin access while scanner says compliant |
| [demo-capital-one](demo-capital-one/) | Capital One breach scenario reconstruction |

---

## Automate & Integrate

| Example | What It Demonstrates |
|---------|---------------------|
| [agents](agents/) | Agent-driven Steampipe integration — collapses capture-to-finding pipeline to minutes |
| [collectors](collectors/) | Minimal AWS collector script (`aws_minimal_collector.py`) |
| [compliance-evidence](compliance-evidence/) | Proof-to-evidence translator for auditor-facing compliance packets |
| [counterfactual-simulate](counterfactual-simulate/) | "What if I fixed these controls?" posture-score simulator |
| [forecast](forecast/) | Posture-score trend forecaster via linear extrapolation |
| [external-forecast](external-forecast/) | External Python reproduction of the forecast math |
| [mutation-testing](mutation-testing/) | Detection coverage verification via single-mutation testing |
| [perturbation-analysis](perturbation-analysis/) | Before/after snapshot diff with impact analysis |
| [compatibility-check](compatibility-check/) | Contradiction detection in requirements via SMT |
| [reasoning-trace](reasoning-trace/) | Unified linker connecting CEL findings to SIR facts with provenance |

## Use Stave as a Go Library

| Example | What It Demonstrates |
|---------|---------------------|
| [lib/graph-export](lib/graph-export/) | Project an assessment into a cross-service relationship graph (assets, findings, chains, edges) |
| [lib/in-process](lib/in-process/) | Run the full pipeline — validate, evaluate, score — in-process without shelling out to the CLI |
| [lib/lab-metrics](lib/lab-metrics/) | Load a CloudGoat lab's findings and display detection metrics using only `pkg/stave` |

---

## Flags Explained

| Flag | Purpose |
|------|---------|
| `--controls` | Directory containing YAML control definitions |
| `--observations` | Directory containing JSON observation snapshots |
| `--max-unsafe` | Maximum time a resource may remain unsafe before violation |
| `--now` | Fixed timestamp for deterministic output |
