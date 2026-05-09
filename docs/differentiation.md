# Differentiation

Stave is a static analysis tool that evaluates cloud infrastructure configurations against system invariants using CEL predicates and exports standardized facts (JSONL triples, SMT-LIB v2) for consumption by external reasoning engines. It operates on air-gapped snapshots with no cloud credentials, no API calls, and no network access.

Stave does two things: **evaluate** (CEL, built-in) and **export** (facts, for external engines). Everything else is delegated.

## The Gap Stave Fills

AWS pioneered formal verification for cloud security on their side of the shared responsibility model. Zelkova verifies IAM policies. Tiros verifies network reachability. s2n verifies TLS correctness. These operate inside AWS's legal boundary — they check individual services, not customer configurations across services.

The customer side — where the breaches actually happen — has relied on pattern-matching scanners that check components individually. Every CSPM in the market asks: "Is this bucket public?" "Is MFA enabled?" "Is this role overpermissioned?" Each check examines one resource against one rule.

Attackers don't check components. They check how configurations across services interact. The Capital One breach exploited five configurations that each passed every individual check. The Bybit breach exploited three. SolarWinds exploited a build pipeline interaction. The vulnerability in each case was not any single setting — it was the interaction between settings across services.

In formal methods, these are **Logical Composition Errors** — security failures that exist only in the interaction between individually valid configurations. A Cognito identity pool that allows unauthenticated access is valid on its own. An IAM role with S3 permissions is valid on its own. The interaction between them — anonymous internet users obtaining AWS credentials and reading confidential data — is the breach. These errors are invisible to tools that check configurations in isolation because the failure is a property of the interaction, not of any individual configuration.

AWS verified the components. The customer is responsible for the interactions between them. In a modern cloud environment with hundreds of services, thousands of roles, and millions of policy statements, the number of possible cross-service interactions explodes combinatorially. This is the **explosion of complexity** gap: the space of interactions grows exponentially while every tool in the market checks linearly, one resource at a time.

No customer-facing tool checks how configurations across services interact to create attack paths. That is the gap.

## What Makes Stave Different

### 1. Compound cross-service detection — finding Logical Composition Errors

Every existing tool evaluates resources independently. Stave evaluates whether findings across multiple resources interact to create an attack path — detecting **Logical Composition Errors** that are invisible to component-level analysis.

A Cognito identity pool allowing unauthenticated access is a finding. An IAM role with broad S3 permissions is a finding. Neither is a breach. The interaction between them — an anonymous internet user obtains AWS credentials via Cognito and uses them to read confidential S3 data — is the breach. Stave detects the interaction. Component checkers cannot, because the vulnerability is a property of the relationship between resources, not a property of any individual resource.

### 2. Ensemble reasoning across multiple independent engines

In formal verification, this approach is known as **Ensemble Logic** — composing multiple reasoning techniques where each technique is strongest for a different class of question. Stave exports configuration facts in standardized formats. Nine external engines consume these facts independently, each answering a different kind of question:

| Engine | Question it answers |
|---|---|
| CEL (built-in) | Does this snapshot violate this rule? |
| Z3, cvc5, Yices | Can an unsafe state exist? (satisfiability proof) |
| Soufflé | What is the full blast radius? (reachability enumeration) |
| Clingo | What configurations violate constraints? (violation enumeration) |
| PySAT | Which control combinations are unsafe? (boolean regression) |
| Prolog | Why is this path reachable? (proof tree derivation) |
| Risk model | How likely is exploitation? (probability) |
| TLA+ | How far from unsafe after remediation? (drift margin) |
| Game theory | What does the attack cost? What is the fix ROI? |

No single engine is the product. The pipeline — Stave exporting facts, nine independent external programs reasoning over them — is the product. When all nine agree on a verdict, the confidence exceeds what any single engine can provide. When they disagree, the disagreement reveals a blind spot that no single engine would have surfaced.

No other tool — commercial, open-source, or academic — composes multiple independent reasoning engines on the same cloud configuration facts. Individual techniques exist in isolation, which forces practitioners to run separate tools with separate data formats, separate configuration, and separate output — the **tool fatigue** problem. Stave's standardized fact export eliminates this: one export, nine engines, one pipeline.

### 3. Mathematical proofs of safety via N-version verification

In mission-critical systems — flight software, nuclear reactor controllers, medical devices — engineers use **N-version programming**: running multiple independent implementations on the same input to eliminate the risk that a bug in one implementation produces a false result.

When three independent solvers (Z3, cvc5, Yices) — external programs consuming Stave's SMT-LIB fact export — all return UNSAT from three independent institutions (Microsoft Research, Stanford/Iowa, SRI International), that is a mathematical proof that the attack path does not exist within the model. Not a scan result. Not a confidence score. Not "no findings detected." A proof — verified by three independent implementations, eliminating the risk of a **solver bug** producing a false pass.

When a solver returns SAT, it produces a constructive counterexample — the specific principal, action, and resource that constitute the attack path. The witness is the exploit.

AWS applies this technique internally with Zelkova. No customer-facing tool exposes it for cross-service configuration verification. Stave's fact export brings the data to the solvers; the solvers bring formal verification to the customer side of the shared responsibility model.

### 4. Security as a financial metric

Every existing tool produces severity ratings: Critical, High, Medium, Low. The game theory engine — an external program consuming Stave's fact export — produces attacker cost and remediation ROI.

Instead of "3 critical findings — remediate within 30 days," the pipeline produces: "The cheapest attack path costs $300. Disabling unauthenticated access costs $50 and blocks the path entirely. ROI: infinite." The risk model — another external program consuming the same export — adds exploitation probability: "P(exploitation) = 41%."

A CISO presents a severity rating to the board and gets a question. A CISO presents "$50 to eliminate a $300 attack with 41% exploitation probability" and gets a budget approval.

### 5. Drift margin measurement

Every existing tool checks whether the current snapshot is safe. The TLA+ temporal engine — an external program consuming Stave's fact export — checks how many valid configuration changes separate the current state from the nearest unsafe state.

A remediated configuration that passes every check but is one developer's config change away from a security violation is fundamentally different from one that is five changes away. No other tool measures this distance. The TLA+ engine quantifies it as the drift margin — the fragility of the security posture, not just its current state.

### 6. Fully air-gapped operation with pre-deployment verification

Every cloud security scanner — Wiz, Orca, Prisma Cloud, AWS Security Hub, Prowler — requires API access to the cloud provider. Most require an agent or a role with read access to the account. This means verification happens after deployment — the resource exists in production before the scanner checks it.

Stave operates on local configuration snapshots. No credentials leave the user's machine. No API calls to any cloud provider. No network access of any kind. Every engine runs locally. This enables **pre-deployment verification**: run Stave against a Terraform plan output or a proposed configuration change in CI/CD and prove safety before a single resource is provisioned. The configuration is verified to be safe by construction, not checked after the fact.

For defense, intelligence, and regulated financial services, air-gapped operation is not a feature preference. It is a procurement requirement. Stave meets it by design, not by adaptation.

### 7. Compliance evidence backed by formal proofs

GRC tools (Drata, Vanta, ServiceNow) collect compliance evidence manually — screenshots, configuration exports, interview notes. Auditors review this evidence to verify that controls are met.

Stave generates evidence packets where each regulatory control (SOC 2, HIPAA, NIST 800-53) cites verdicts from external engines consuming Stave's fact export: a Z3 proof that no unauthorized access path exists, a Soufflé count showing zero unauthorized reachable paths, a risk model result showing exploitation probability at zero percent. The auditor receives a reasoning chain backed by independent external engines, not a screenshot.

## What Stave Does Not Do

Stave does not replace CSPM. It fills the gap CSPM leaves.

Stave does not perform runtime monitoring. It analyzes static snapshots. A configuration change between snapshots is invisible until the next snapshot is taken.

Stave does not scan code, containers, or dependencies. It analyzes infrastructure configuration — IAM policies, S3 bucket settings, Cognito pool configuration, security group rules, CloudTrail settings.

Stave does not run the reasoning engines internally. It exports facts. External programs — Z3, Soufflé, Clingo, Prolog, and others — consume those facts independently. Files are the language boundary. No subprocess calls from Stave to solvers.

## Comparison With Existing Tools

### vs. CSPM tools (Wiz, Orca, Prisma Cloud)

CSPM tools have one evaluation engine, require cloud API access, check components individually, and produce severity ratings. Stave's pipeline includes one built-in engine (CEL) and eight external engines consuming its fact export, requires no cloud access, checks how configurations interact across services, and produces mathematical proofs, probability, attacker cost, and drift margin. CSPM tools excel at asset inventory, runtime threat detection, and vulnerability scanning — capabilities Stave does not attempt.

### vs. Policy-as-code tools (Checkov, OPA/Rego, tfsec)

Policy-as-code tools evaluate individual resource configurations against rules written in their respective languages. They check "does this resource match this pattern?" — the same component-level question as CSPM, expressed in code rather than a UI. They do not detect how findings across resources and services interact to form attack paths. Stave's CEL evaluation is comparable to this layer. The external engine pipeline is additive.

### vs. AWS IAM Access Analyzer

Access Analyzer exposes a subset of Zelkova's capabilities to customers — verifying whether an IAM policy grants public or cross-account access. It checks individual policies, not how configurations across services interact. It cannot tell you whether a Cognito identity pool configuration combined with an IAM role trust policy combined with an S3 bucket policy creates a data exfiltration path. An SMT query consuming Stave's fact export can, because the query spans all three services.

### vs. Prowler / ScoutSuite

Open-source scanners that check AWS configurations against CIS benchmarks and best practices. Component-level checks, single evaluation engine, require AWS credentials. Stave's CEL catalog covers similar ground (2,100+ controls). The external engine pipeline adds capabilities these tools cannot provide without architectural change.

### vs. Batfish (network configuration)

Batfish uses Datalog (via Z3's fixedpoint engine) for network configuration verification — routing, ACLs, firewall rules. It operates on network-layer configurations, not cloud service configurations. Stave and Batfish are complementary — Batfish verifies network reachability, Stave verifies how service-layer configurations interact across cloud services. They could consume each other's facts.

### vs. Academic formal methods tools

Individual research papers have applied model checking, SMT solving, or Datalog to specific cloud security properties. These remain academic artifacts — single-technique, single-property, not packaged for practitioner use. Stave assembles multiple techniques into a unified pipeline with standardized fact export, practitioner-facing output, and open-source distribution.

## The Defensible Claim

AWS pioneered formal verification for cloud security on their side of the shared responsibility model. The customer side — where the explosion of cross-service complexity creates Logical Composition Errors — has relied on pattern-matching scanners that check configurations individually.

Stave brings structured fact export to the customer side, enabling nine independent external reasoning engines to verify how configurations across services interact. The multi-engine approach — where agreement provides N-version verified mathematical certainty and disagreement reveals blind spots — is new to cloud security. The air-gapped, pre-deployment operation model enables verification before provisioning, not scanning after deployment.

The individual techniques are established. The unified pipeline — one fact export, nine independent engines, standardized formats — is novel. The application to customer-side cross-service cloud configuration is novel. The open-source availability with no cloud credentials required is novel.

No other tool produces a nine-engine consensus with formal proofs, blast radius counts, exploitation probability, attacker economics, drift margin, and compliance evidence from the same air-gapped fact export. Stave provides the facts. The engines provide the reasoning. Together they answer questions no single tool can ask.

Next Version

---

# Differentiation

Stave is a static analysis tool that evaluates cloud infrastructure configurations against system invariants using CEL predicates and exports standardized facts (JSONL triples, SMT-LIB v2) for consumption by external reasoning engines. It operates on air-gapped snapshots with no cloud credentials, no API calls, and no network access.

Stave does three things: **evaluate** (CEL predicates, built-in), **export** (standardized facts for external engines), and **trace** (every fact carries a deterministic `fact_id` linking engine verdicts back through the fact export to the specific observation property that produced it). Everything else is delegated.

## The Gap Stave Fills

AWS pioneered formal verification for cloud security on their side of the shared responsibility model. Zelkova verifies IAM policies. Tiros verifies network reachability. s2n verifies TLS correctness. These operate inside AWS's legal boundary — they check individual services, not customer configurations across services.

The customer side — where the breaches actually happen — has relied on pattern-matching scanners that check components individually. Every CSPM in the market asks: "Is this bucket public?" "Is MFA enabled?" "Is this role overpermissioned?" Each check examines one resource against one rule.

Attackers don't check components. They check how configurations across services interact. The Capital One breach exploited five configurations that each passed every individual check. The Bybit breach exploited three. SolarWinds exploited a build pipeline interaction. The vulnerability in each case was not any single setting — it was the interaction between settings across services.

In formal methods, these are **Logical Composition Errors** — security failures that exist only in the interaction between individually valid configurations. A Cognito identity pool that allows unauthenticated access is valid on its own. An IAM role with S3 permissions is valid on its own. The interaction between them — anonymous internet users obtaining AWS credentials and reading confidential data — is the breach. These errors are invisible to tools that check configurations in isolation because the failure is a property of the interaction, not of any individual configuration.

AWS verified the components. The customer is responsible for the interactions between them. In a modern cloud environment with hundreds of services, thousands of roles, and millions of policy statements, the number of possible cross-service interactions explodes combinatorially. This is the **explosion of complexity** gap: the space of interactions grows exponentially while every tool in the market checks linearly, one resource at a time.

No customer-facing tool checks how configurations across services interact to create attack paths. That is the gap.

## What Makes Stave Different

### 1. Compound cross-service detection — finding Logical Composition Errors

Every existing tool evaluates resources independently. Stave evaluates whether findings across multiple resources interact to create an attack path — detecting **Logical Composition Errors** that are invisible to component-level analysis.

A Cognito identity pool allowing unauthenticated access is a finding. An IAM role with broad S3 permissions is a finding. Neither is a breach. The interaction between them — an anonymous internet user obtains AWS credentials via Cognito and uses them to read confidential S3 data — is the breach. Stave detects the interaction. Component checkers cannot, because the vulnerability is a property of the relationship between resources, not a property of any individual resource.

### 2. Ensemble reasoning across multiple independent engines

In formal verification, this approach is known as **Ensemble Logic** — composing multiple reasoning techniques where each technique is strongest for a different class of question. Stave exports configuration facts in standardized formats. Nine external engines consume these facts independently, each answering a different kind of question:

| Engine | Question it answers |
|---|---|
| CEL (built-in) | Does this snapshot violate this rule? |
| Z3, cvc5, Yices | Can an unsafe state exist? (satisfiability proof) |
| Soufflé | What is the full blast radius? (reachability enumeration) |
| Clingo | What configurations violate constraints? (violation enumeration) |
| PySAT | Which control combinations are unsafe? (boolean regression) |
| Prolog | Why is this path reachable? (proof tree derivation) |
| Risk model | How likely is exploitation? (probability) |
| TLA+ | How far from unsafe after remediation? (drift margin) |
| Game theory | What does the attack cost? What is the fix ROI? |

No single engine is the product. The pipeline — Stave exporting facts, nine independent external programs reasoning over them — is the product. When all nine agree on a verdict, the confidence exceeds what any single engine can provide. When they disagree, the disagreement reveals a blind spot that no single engine would have surfaced.

No other tool — commercial, open-source, or academic — composes multiple independent reasoning engines on the same cloud configuration facts. Individual techniques exist in isolation, which forces practitioners to run separate tools with separate data formats, separate configuration, and separate output — the **tool fatigue** problem. Stave's standardized fact export eliminates this: one export, nine engines, one pipeline.

### 3. Mathematical proofs of safety via N-version verification

In mission-critical systems — flight software, nuclear reactor controllers, medical devices — engineers use **N-version programming**: running multiple independent implementations on the same input to eliminate the risk that a bug in one implementation produces a false result.

When three independent solvers (Z3, cvc5, Yices) — external programs consuming Stave's SMT-LIB fact export — all return UNSAT from three independent institutions (Microsoft Research, Stanford/Iowa, SRI International), that is a mathematical proof that the attack path does not exist within the model. Not a scan result. Not a confidence score. Not "no findings detected." A proof — verified by three independent implementations, eliminating the risk of a **solver bug** producing a false pass.

When a solver returns SAT, it produces a constructive counterexample — the specific principal, action, and resource that constitute the attack path. The witness is the exploit.

AWS applies this technique internally with Zelkova. No customer-facing tool exposes it for cross-service configuration verification. Stave's fact export brings the data to the solvers; the solvers bring formal verification to the customer side of the shared responsibility model.

### 4. Security as a financial metric

Every existing tool produces severity ratings: Critical, High, Medium, Low. The game theory engine — an external program consuming Stave's fact export — produces attacker cost and remediation ROI.

Instead of "3 critical findings — remediate within 30 days," the pipeline produces: "The cheapest attack path costs $300. Disabling unauthenticated access costs $50 and blocks the path entirely. ROI: infinite." The risk model — another external program consuming the same export — adds exploitation probability: "P(exploitation) = 41%."

A CISO presents a severity rating to the board and gets a question. A CISO presents "$50 to eliminate a $300 attack with 41% exploitation probability" and gets a budget approval.

### 5. Drift margin measurement

Every existing tool checks whether the current snapshot is safe. The TLA+ temporal engine — an external program consuming Stave's fact export — checks how many valid configuration changes separate the current state from the nearest unsafe state.

A remediated configuration that passes every check but is one developer's config change away from a security violation is fundamentally different from one that is five changes away. No other tool measures this distance. The TLA+ engine quantifies it as the drift margin — the fragility of the security posture, not just its current state.

### 6. Fully air-gapped operation with pre-deployment verification

Every cloud security scanner — Wiz, Orca, Prisma Cloud, AWS Security Hub, Prowler — requires API access to the cloud provider. Most require an agent or a role with read access to the account. This means verification happens after deployment — the resource exists in production before the scanner checks it.

Stave operates on local configuration snapshots. No credentials leave the user's machine. No API calls to any cloud provider. No network access of any kind. Every engine runs locally. This enables **pre-deployment verification**: run Stave against a Terraform plan output or a proposed configuration change in CI/CD and prove safety before a single resource is provisioned. The configuration is verified to be safe by construction, not checked after the fact.

For defense, intelligence, and regulated financial services, air-gapped operation is not a feature preference. It is a procurement requirement. Stave meets it by design, not by adaptation.

### 7. Compliance evidence backed by formal proofs

GRC tools (Drata, Vanta, ServiceNow) collect compliance evidence manually — screenshots, configuration exports, interview notes. Auditors review this evidence to verify that controls are met.

Stave generates evidence packets where each regulatory control (SOC 2, HIPAA, NIST 800-53) cites verdicts from external engines consuming Stave's fact export: a Z3 proof that no unauthorized access path exists, a Soufflé count showing zero unauthorized reachable paths, a risk model result showing exploitation probability at zero percent. The auditor receives a reasoning chain backed by independent external engines, not a screenshot.

### 8. End-to-end traceability across every layer

Cloud infrastructure projects are complex. Hundreds of services, thousands of configurations, millions of policy statements — managed by teams that change quarterly. When something breaks, finding the cause is the most time-consuming step. Every existing tool tells you WHAT is wrong. None tells you WHY, traced from the engine verdict back through every layer to the specific property in the specific configuration file that caused it.

Stave provides full-stack traceability through a single correlation key: the `fact_id`. Every fact exported by Stave carries a deterministic identifier (a hash of its content) that appears in every output format:

- In the JSONL export — alongside provenance (which observation file, which property path, which projector function) and freshness (when the snapshot was taken, how old the fact is)
- In the SMT-LIB export — as a comment above the assertion, linking the solver's input to its source
- In CEL findings — as `contributing_fact_ids`, connecting each finding to the specific facts that describe the configuration it evaluated
- In the unified reasoning trace — linking each engine's verdict to the specific facts that produced it

One `grep` on a fact_id walks the entire chain: engine verdict → SMT-LIB assertion → JSONL fact → observation file → property path → specific configuration value. No manual correlation across files. No reading five outputs to understand one finding.

This traceability chain solves three problems that grow with infrastructure complexity:

**Cause identification.** When a solver returns sat (the attack path exists), the fact_id in the witness traces directly to the observation property that enables it. The developer doesn't search — they grep one ID and see the source. This follows Andreas Zeller's debugging methodology: the fact_id IS the cause chain from failure (engine verdict) through infection (SIR fact) to defect (misconfigured property).

**Projection gap detection.** When a CEL control evaluates a property but the SIR doesn't project a fact for it, the `--validate` flag on `export-sir` warns immediately. Without this, the gap is silent — the control fires, the solver sees nothing, and the SMT query returns the same verdict on both vulnerable and remediated fixtures. The developer discovers the gap only after hours of investigation. Validation catches it in seconds.

**Change impact awareness.** When a developer modifies a control, a projector, or an observation schema, the fact_ids that change are visible in the export diff. The provenance metadata shows which projector produced each fact. The contributing_fact_ids on findings show which controls depend on which facts. The change doesn't propagate silently — every affected layer is traceable.

No other cloud security tool provides this level of traceability. CSPM tools produce findings with no traceable link to the underlying configuration property. Policy-as-code tools evaluate rules but don't connect their verdicts to downstream engines or compliance evidence. The traceability chain is what makes Stave's multi-engine pipeline maintainable as infrastructure grows — without it, nine engines producing separate outputs at scale becomes nine sources of confusion instead of nine sources of confidence.

For teams managing complex cloud infrastructure, the traceability chain is where Stave becomes embedded in the development workflow. Once a team's debugging, compliance, and change management processes depend on fact_id traceability across engines, snapshots, and evidence packets, the value is not in any single engine — it's in the chain that connects all of them to the configuration source. That chain is Stave's core contribution.

## What Stave Does Not Do

Stave does not replace CSPM. It fills the gap CSPM leaves.

Stave does not perform runtime monitoring. It analyzes static snapshots. A configuration change between snapshots is invisible until the next snapshot is taken.

Stave does not scan code, containers, or dependencies. It analyzes infrastructure configuration — IAM policies, S3 bucket settings, Cognito pool configuration, security group rules, CloudTrail settings.

Stave does not run the reasoning engines internally. It exports facts. External programs — Z3, Soufflé, Clingo, Prolog, and others — consume those facts independently. Files are the language boundary. No subprocess calls from Stave to solvers.

## Comparison With Existing Tools

### vs. CSPM tools (Wiz, Orca, Prisma Cloud)

CSPM tools have one evaluation engine, require cloud API access, check components individually, and produce severity ratings. Stave's pipeline includes one built-in engine (CEL) and eight external engines consuming its fact export, requires no cloud access, checks how configurations interact across services, and produces mathematical proofs, probability, attacker cost, and drift margin. CSPM tools excel at asset inventory, runtime threat detection, and vulnerability scanning — capabilities Stave does not attempt.

### vs. Policy-as-code tools (Checkov, OPA/Rego, tfsec)

Policy-as-code tools evaluate individual resource configurations against rules written in their respective languages. They check "does this resource match this pattern?" — the same component-level question as CSPM, expressed in code rather than a UI. They do not detect how findings across resources and services interact to form attack paths. Stave's CEL evaluation is comparable to this layer. The external engine pipeline is additive.

### vs. AWS IAM Access Analyzer

Access Analyzer exposes a subset of Zelkova's capabilities to customers — verifying whether an IAM policy grants public or cross-account access. It checks individual policies, not how configurations across services interact. It cannot tell you whether a Cognito identity pool configuration combined with an IAM role trust policy combined with an S3 bucket policy creates a data exfiltration path. An SMT query consuming Stave's fact export can, because the query spans all three services.

### vs. Prowler / ScoutSuite

Open-source scanners that check AWS configurations against CIS benchmarks and best practices. Component-level checks, single evaluation engine, require AWS credentials. Stave's CEL catalog covers similar ground (2,100+ controls). The external engine pipeline adds capabilities these tools cannot provide without architectural change.

### vs. Batfish (network configuration)

Batfish uses Datalog (via Z3's fixedpoint engine) for network configuration verification — routing, ACLs, firewall rules. It operates on network-layer configurations, not cloud service configurations. Stave and Batfish are complementary — Batfish verifies network reachability, Stave verifies how service-layer configurations interact across cloud services. They could consume each other's facts.

### vs. Academic formal methods tools

Individual research papers have applied model checking, SMT solving, or Datalog to specific cloud security properties. These remain academic artifacts — single-technique, single-property, not packaged for practitioner use. Stave assembles multiple techniques into a unified pipeline with standardized fact export, practitioner-facing output, and open-source distribution.

## The Defensible Claim

AWS pioneered formal verification for cloud security on their side of the shared responsibility model. The customer side — where the explosion of cross-service complexity creates Logical Composition Errors — has relied on pattern-matching scanners that check configurations individually.

Stave brings structured fact export to the customer side, enabling nine independent external reasoning engines to verify how configurations across services interact. The multi-engine approach — where agreement provides N-version verified mathematical certainty and disagreement reveals blind spots — is new to cloud security. The air-gapped, pre-deployment operation model enables verification before provisioning, not scanning after deployment.

The traceability chain — a deterministic fact_id connecting every engine verdict back through the fact export, the projector, and the observation property to the specific configuration value — is what makes the multi-engine pipeline maintainable at scale. Without traceability, nine engines are nine sources of confusion. With traceability, nine engines are nine sources of confidence, each verdict traceable to its root cause in one grep.

The individual techniques are established. The unified pipeline — one fact export, nine independent engines, standardized formats, end-to-end traceability — is novel. The application to customer-side cross-service cloud configuration is novel. The open-source availability with no cloud credentials required is novel.

No other tool produces a nine-engine consensus with formal proofs, blast radius counts, exploitation probability, attacker economics, drift margin, compliance evidence, and end-to-end fact traceability from the same air-gapped fact export. Stave provides the facts. The engines provide the reasoning. The traceability chain connects them. Together they answer questions no single tool can ask — and prove why the answer is correct.

---

Next Version

# Differentiation

Stave is a static analysis tool that evaluates cloud infrastructure configurations against system invariants using CEL predicates and exports standardized facts (JSONL triples, SMT-LIB v2) for consumption by external reasoning engines. It operates on air-gapped snapshots with no cloud credentials, no API calls, and no network access.

Stave does three things: **evaluate** (CEL predicates, built-in), **export** (standardized facts for external engines), and **trace** (every fact carries a deterministic `fact_id` linking engine verdicts back through the fact export to the specific observation property that produced it). Everything else is delegated.

## The Gap Stave Fills

AWS pioneered formal verification for cloud security on their side of the shared responsibility model. Zelkova verifies IAM policies. Tiros verifies network reachability. s2n verifies TLS correctness. These operate inside AWS's legal boundary — they check individual services, not customer configurations across services.

The customer side — where the breaches actually happen — has relied on pattern-matching scanners that check components individually. Every CSPM in the market asks: "Is this bucket public?" "Is MFA enabled?" "Is this role overpermissioned?" Each check examines one resource against one rule.

Attackers don't check components. They check how configurations across services interact. The Capital One breach exploited five configurations that each passed every individual check. The Bybit breach exploited three. SolarWinds exploited a build pipeline interaction. The vulnerability in each case was not any single setting — it was the interaction between settings across services.

In formal methods, these are **Logical Composition Errors** — security failures that exist only in the interaction between individually valid configurations. A Cognito identity pool that allows unauthenticated access is valid on its own. An IAM role with S3 permissions is valid on its own. The interaction between them — anonymous internet users obtaining AWS credentials and reading confidential data — is the breach. These errors are invisible to tools that check configurations in isolation because the failure is a property of the interaction, not of any individual configuration.

AWS verified the components. The customer is responsible for the interactions between them. In a modern cloud environment with hundreds of services, thousands of roles, and millions of policy statements, the number of possible cross-service interactions explodes combinatorially. This is the **explosion of complexity** gap: the space of interactions grows exponentially while every tool in the market checks linearly, one resource at a time.

No customer-facing tool checks how configurations across services interact to create attack paths. That is the gap.

## What Makes Stave Different

### 1. Compound cross-service detection — finding Logical Composition Errors

Every existing tool evaluates resources independently. Stave evaluates whether findings across multiple resources interact to create an attack path — detecting **Logical Composition Errors** that are invisible to component-level analysis.

A Cognito identity pool allowing unauthenticated access is a finding. An IAM role with broad S3 permissions is a finding. Neither is a breach. The interaction between them — an anonymous internet user obtains AWS credentials via Cognito and uses them to read confidential S3 data — is the breach. Stave detects the interaction. Component checkers cannot, because the vulnerability is a property of the relationship between resources, not a property of any individual resource.

### 2. Ensemble reasoning across multiple independent engines

In formal verification, this approach is known as **Ensemble Logic** — composing multiple reasoning techniques where each technique is strongest for a different class of question. Stave exports configuration facts in standardized formats. Nine external engines consume these facts independently, each answering a different kind of question:

| Engine | Question it answers |
|---|---|
| CEL (built-in) | Does this snapshot violate this rule? |
| Z3, cvc5, Yices | Can an unsafe state exist? (satisfiability proof) |
| Soufflé | What is the full blast radius? (reachability enumeration) |
| Clingo | What configurations violate constraints? (violation enumeration) |
| PySAT | Which control combinations are unsafe? (boolean regression) |
| Prolog | Why is this path reachable? (proof tree derivation) |
| Risk model | How likely is exploitation? (probability) |
| TLA+ | How far from unsafe after remediation? (drift margin) |
| Game theory | What does the attack cost? What is the fix ROI? |

No single engine is the product. The pipeline — Stave exporting facts, nine independent external programs reasoning over them — is the product. When all nine agree on a verdict, the confidence exceeds what any single engine can provide. When they disagree, the disagreement reveals a blind spot that no single engine would have surfaced.

No other tool — commercial, open-source, or academic — composes multiple independent reasoning engines on the same cloud configuration facts. Individual techniques exist in isolation, which forces practitioners to run separate tools with separate data formats, separate configuration, and separate output — the **tool fatigue** problem. Stave's standardized fact export eliminates this: one export, nine engines, one pipeline.

### 3. Mathematical proofs of safety via N-version verification

In mission-critical systems — flight software, nuclear reactor controllers, medical devices — engineers use **N-version programming**: running multiple independent implementations on the same input to eliminate the risk that a bug in one implementation produces a false result.

When three independent solvers (Z3, cvc5, Yices) — external programs consuming Stave's SMT-LIB fact export — all return UNSAT from three independent institutions (Microsoft Research, Stanford/Iowa, SRI International), that is a mathematical proof that the attack path does not exist within the model. Not a scan result. Not a confidence score. Not "no findings detected." A proof — verified by three independent implementations, eliminating the risk of a **solver bug** producing a false pass.

When a solver returns SAT, it produces a constructive counterexample — the specific principal, action, and resource that constitute the attack path. The witness is the exploit.

AWS applies this technique internally with Zelkova. No customer-facing tool exposes it for cross-service configuration verification. Stave's fact export brings the data to the solvers; the solvers bring formal verification to the customer side of the shared responsibility model.

### 4. Security as a financial metric

Every existing tool produces severity ratings: Critical, High, Medium, Low. The game theory engine — an external program consuming Stave's fact export — produces attacker cost and remediation ROI.

Instead of "3 critical findings — remediate within 30 days," the pipeline produces: "The cheapest attack path costs $300. Disabling unauthenticated access costs $50 and blocks the path entirely. ROI: infinite." The risk model — another external program consuming the same export — adds exploitation probability: "P(exploitation) = 41%."

A CISO presents a severity rating to the board and gets a question. A CISO presents "$50 to eliminate a $300 attack with 41% exploitation probability" and gets a budget approval.

### 5. Drift margin measurement

Every existing tool checks whether the current snapshot is safe. The TLA+ temporal engine — an external program consuming Stave's fact export — checks how many valid configuration changes separate the current state from the nearest unsafe state.

A remediated configuration that passes every check but is one developer's config change away from a security violation is fundamentally different from one that is five changes away. No other tool measures this distance. The TLA+ engine quantifies it as the drift margin — the fragility of the security posture, not just its current state.

### 6. Fully air-gapped operation with pre-deployment verification

Every cloud security scanner — Wiz, Orca, Prisma Cloud, AWS Security Hub, Prowler — requires API access to the cloud provider. Most require an agent or a role with read access to the account. This means verification happens after deployment — the resource exists in production before the scanner checks it.

Stave operates on local configuration snapshots. No credentials leave the user's machine. No API calls to any cloud provider. No network access of any kind. Every engine runs locally. This enables **pre-deployment verification**: run Stave against a Terraform plan output or a proposed configuration change in CI/CD and prove safety before a single resource is provisioned. The configuration is verified to be safe by construction, not checked after the fact.

For defense, intelligence, and regulated financial services, air-gapped operation is not a feature preference. It is a procurement requirement. Stave meets it by design, not by adaptation.

### 7. Compliance evidence backed by formal proofs

GRC tools (Drata, Vanta, ServiceNow) collect compliance evidence manually — screenshots, configuration exports, interview notes. Auditors review this evidence to verify that controls are met.

Stave generates evidence packets where each regulatory control (SOC 2, HIPAA, NIST 800-53) cites verdicts from external engines consuming Stave's fact export: a Z3 proof that no unauthorized access path exists, a Soufflé count showing zero unauthorized reachable paths, a risk model result showing exploitation probability at zero percent. The auditor receives a reasoning chain backed by independent external engines, not a screenshot.

### 8. End-to-end traceability across every layer

Cloud infrastructure projects are complex. Hundreds of services, thousands of configurations, millions of policy statements — managed by teams that change quarterly. When something breaks, finding the cause is the most time-consuming step. Every existing tool tells you WHAT is wrong. None tells you WHY, traced from the engine verdict back through every layer to the specific property in the specific configuration file that caused it.

Stave provides full-stack traceability through a single correlation key: the `fact_id`. Every fact exported by Stave carries a deterministic identifier (a hash of its content) that appears in every output format:

- In the JSONL export — alongside provenance (which observation file, which property path, which projector function) and freshness (when the snapshot was taken, how old the fact is)
- In the SMT-LIB export — as a comment above the assertion, linking the solver's input to its source
- In CEL findings — as `contributing_fact_ids`, connecting each finding to the specific facts that describe the configuration it evaluated
- In the unified reasoning trace — linking each engine's verdict to the specific facts that produced it

One `grep` on a fact_id walks the entire chain: engine verdict → SMT-LIB assertion → JSONL fact → observation file → property path → specific configuration value. No manual correlation across files. No reading five outputs to understand one finding.

This traceability chain solves three problems that grow with infrastructure complexity:

**Cause identification.** When a solver returns sat (the attack path exists), the fact_id in the witness traces directly to the observation property that enables it. The developer doesn't search — they grep one ID and see the source. This follows Andreas Zeller's debugging methodology: the fact_id IS the cause chain from failure (engine verdict) through infection (SIR fact) to defect (misconfigured property).

**Projection gap detection.** When a CEL control evaluates a property but the SIR doesn't project a fact for it, the `--validate` flag on `export-sir` warns immediately. Without this, the gap is silent — the control fires, the solver sees nothing, and the SMT query returns the same verdict on both vulnerable and remediated fixtures. The developer discovers the gap only after hours of investigation. Validation catches it in seconds.

**Change impact awareness.** When a developer modifies a control, a projector, or an observation schema, the fact_ids that change are visible in the export diff. The provenance metadata shows which projector produced each fact. The contributing_fact_ids on findings show which controls depend on which facts. The change doesn't propagate silently — every affected layer is traceable.

No other cloud security tool provides this level of traceability. CSPM tools produce findings with no traceable link to the underlying configuration property. Policy-as-code tools evaluate rules but don't connect their verdicts to downstream engines or compliance evidence. The traceability chain is what makes Stave's multi-engine pipeline maintainable as infrastructure grows — without it, nine engines producing separate outputs at scale becomes nine sources of confusion instead of nine sources of confidence.

For teams managing complex cloud infrastructure, the traceability chain is where Stave becomes embedded in the development workflow. Once a team's debugging, compliance, and change management processes depend on fact_id traceability across engines, snapshots, and evidence packets, the value is not in any single engine — it's in the chain that connects all of them to the configuration source. That chain is Stave's core contribution.

### Traceability × git: cross-team resolution at scale

Because fact_ids are deterministic and observations are files, the traceability chain extends naturally through git history. This transforms how teams across organizational silos find and fix issues:

**Who introduced the problem.** A finding fires with fact_id `a3f8c2e91b04`. The provenance traces to `cognito-identity-pool.obs.json`, property `identity.access.allow_unauthenticated`. `git blame` on that observation file shows which team member changed the property and when. The security team doesn't file a ticket into a queue — they know exactly who to talk to and what changed.

**How similar issues were fixed before.** A new Cognito pool has `has_mfa_enforced = false`. Searching git history for the same predicate name reveals a previous fix on a different pool last month — the commit message explains the remediation, the observation diff shows exactly what changed, and the engine verdicts before and after confirm the fix worked. The new fix follows the same pattern. Teams don't reinvent remediation — they find proven fixes and apply them.

**When the issue first appeared.** Comparing fact exports across weekly snapshots using fact_ids shows when a fact first appeared. A fact_id that exists in this week's export but not last week's was introduced by a change in that window. The freshness metadata narrows the timeframe. `git log` on the observation files within that window identifies the specific commit.

**Cross-silo coordination without meetings.** The infrastructure team changes a security group. The security team's next Stave run shows a new finding with fact_ids tracing to the changed observation. The compliance team's evidence packet updates automatically — the SOC 2 control status flips from compliant to non-compliant with the specific fact_id cited. Three teams see the same change through three lenses (infrastructure, security, compliance) with one shared identifier. No meeting required — the fact_id is the coordination mechanism.

This is how traceability scales with organizational complexity. Small teams grep fact_ids in a terminal. Large teams integrate fact_ids into their ticketing systems, CI pipelines, and compliance workflows. The identifier is the same. The integration surface grows with the organization.

## What Stave Does Not Do

Stave does not replace CSPM. It fills the gap CSPM leaves.

Stave does not perform runtime monitoring. It analyzes static snapshots. A configuration change between snapshots is invisible until the next snapshot is taken.

Stave does not scan code, containers, or dependencies. It analyzes infrastructure configuration — IAM policies, S3 bucket settings, Cognito pool configuration, security group rules, CloudTrail settings.

Stave does not run the reasoning engines internally. It exports facts. External programs — Z3, Soufflé, Clingo, Prolog, and others — consume those facts independently. Files are the language boundary. No subprocess calls from Stave to solvers.

## Comparison With Existing Tools

### vs. CSPM tools (Wiz, Orca, Prisma Cloud)

CSPM tools have one evaluation engine, require cloud API access, check components individually, and produce severity ratings. Stave's pipeline includes one built-in engine (CEL) and eight external engines consuming its fact export, requires no cloud access, checks how configurations interact across services, and produces mathematical proofs, probability, attacker cost, and drift margin. CSPM tools excel at asset inventory, runtime threat detection, and vulnerability scanning — capabilities Stave does not attempt.

### vs. Policy-as-code tools (Checkov, OPA/Rego, tfsec)

Policy-as-code tools evaluate individual resource configurations against rules written in their respective languages. They check "does this resource match this pattern?" — the same component-level question as CSPM, expressed in code rather than a UI. They do not detect how findings across resources and services interact to form attack paths. Stave's CEL evaluation is comparable to this layer. The external engine pipeline is additive.

### vs. AWS IAM Access Analyzer

Access Analyzer exposes a subset of Zelkova's capabilities to customers — verifying whether an IAM policy grants public or cross-account access. It checks individual policies, not how configurations across services interact. It cannot tell you whether a Cognito identity pool configuration combined with an IAM role trust policy combined with an S3 bucket policy creates a data exfiltration path. An SMT query consuming Stave's fact export can, because the query spans all three services.

### vs. Prowler / ScoutSuite

Open-source scanners that check AWS configurations against CIS benchmarks and best practices. Component-level checks, single evaluation engine, require AWS credentials. Stave's CEL catalog covers similar ground (2,100+ controls). The external engine pipeline adds capabilities these tools cannot provide without architectural change.

### vs. Batfish (network configuration)

Batfish uses Datalog (via Z3's fixedpoint engine) for network configuration verification — routing, ACLs, firewall rules. It operates on network-layer configurations, not cloud service configurations. Stave and Batfish are complementary — Batfish verifies network reachability, Stave verifies how service-layer configurations interact across cloud services. They could consume each other's facts.

### vs. Academic formal methods tools

Individual research papers have applied model checking, SMT solving, or Datalog to specific cloud security properties. These remain academic artifacts — single-technique, single-property, not packaged for practitioner use. Stave assembles multiple techniques into a unified pipeline with standardized fact export, practitioner-facing output, and open-source distribution.

## The Defensible Claim

AWS pioneered formal verification for cloud security on their side of the shared responsibility model. The customer side — where the explosion of cross-service complexity creates Logical Composition Errors — has relied on pattern-matching scanners that check configurations individually.

Stave brings structured fact export to the customer side, enabling nine independent external reasoning engines to verify how configurations across services interact. The multi-engine approach — where agreement provides N-version verified mathematical certainty and disagreement reveals blind spots — is new to cloud security. The air-gapped, pre-deployment operation model enables verification before provisioning, not scanning after deployment.

The traceability chain — a deterministic fact_id connecting every engine verdict back through the fact export, the projector, and the observation property to the specific configuration value — is what makes the multi-engine pipeline maintainable at scale. Without traceability, nine engines are nine sources of confusion. With traceability, nine engines are nine sources of confidence, each verdict traceable to its root cause in one grep.

The individual techniques are established. The unified pipeline — one fact export, nine independent engines, standardized formats, end-to-end traceability — is novel. The application to customer-side cross-service cloud configuration is novel. The open-source availability with no cloud credentials required is novel.

No other tool produces a nine-engine consensus with formal proofs, blast radius counts, exploitation probability, attacker economics, drift margin, compliance evidence, and end-to-end fact traceability from the same air-gapped fact export. Stave provides the facts. The engines provide the reasoning. The traceability chain connects them. Together they answer questions no single tool can ask — and prove why the answer is correct.
