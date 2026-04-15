# E2E EXPERIMENT DESIGN: Graph Ontology Iterations 3–6

## Purpose

Structured experiments using realistic fake data to validate the
complete graph pipeline end-to-end. Each experiment has a defined
scenario, input data, expected outputs, and assertions. All data
is synthetic — no real AWS accounts, no real credentials.

---

## Fake Data Conventions

All experiments use these fictional AWS account IDs and ARN patterns:

```
Production account:   111111111111   alias: acme-production
Data account:         222222222222   alias: acme-data
Development account:  333333333333   alias: acme-development
Security account:     444444444444   alias: acme-security

Region: us-east-1
Organization: o-acme123456
```

---

## Experiment 1: Minimal Single Finding

**Purpose:** Smoke test. Verify the simplest possible graph-json
output contains correct node types, edge types, and properties.

**Scenario:** One S3 bucket with one failing control. No chains.
No compliance citations. Baseline for verifying the schema is
correct before adding complexity.

**Input snapshot (minimal):**
```json
{
  "schema_version": "1",
  "source": "deployed",
  "account_id": "111111111111",
  "captured_at": "2025-11-15T10:00:00Z",
  "resources": {
    "s3_buckets": [
      {
        "arn": "arn:aws:s3:::acme-prod-logs",
        "name": "acme-prod-logs",
        "region": "us-east-1",
        "public_access_block": {
          "block_public_acls": false,
          "block_public_policy": false,
          "ignore_public_acls": false,
          "restrict_public_buckets": false
        }
      }
    ]
  }
}
```

**Expected graph-json output:**

Exactly 3 nodes:
- `Finding` — CTL.S3.PUBLIC.001 on arn:aws:s3:::acme-prod-logs
- `Resource` — arn:aws:s3:::acme-prod-logs, resource_class=storage
- `TenantScope` — account:111111111111

Exactly 2 edges:
- `TARGETS` — Finding → Resource
- `BELONGS_TO_SCOPE` — Resource → TenantScope

**Assertions:**
- [ ] `schema_version: "1"` present
- [ ] `ontology_version: "1.0"` present
- [ ] Finding node has `attack_stage_attck: "TA0001"` (not raw string)
- [ ] Resource node has `resource_class: "storage"` (not "s3_bucket")
- [ ] Resource node has `provider: "aws"`, `provider_type: "s3_bucket"`
- [ ] TenantScope node has `account_id: "111111111111"`
- [ ] `metadata.node_count: 3`, `metadata.edge_count: 2`

---

## Experiment 2: Active Threat Chain

**Purpose:** Verify chain-related nodes and edges are correctly
produced when a chain fires.

**Scenario:** PHI S3 bucket (public) + KMS key not rotating +
CloudTrail disabled. Together these fire the `data_exfiltration_path`
chain. All three controls fail individually. The chain fires
because all three are failing simultaneously.

**Input:** `out.v0.1` assessment output containing:
- 3 failing findings: CTL.S3.PUBLIC.001, CTL.KMS.ROTATION.001,
  CTL.CLOUDTRAIL.ENABLED.001
- 1 chain finding: data_exfiltration_path (active: true)
- chain_membership on each finding referencing data_exfiltration_path

**Expected graph-json output:**

Nodes:
- 3 × `Finding` nodes
- 3 × `Resource` nodes (S3 bucket, KMS key, CloudTrail trail)
- 1 × `ThreatChain` node — data_exfiltration_path (active: true)
- 1 × `AttackerCapability` node
- 1 × `TenantScope` node

Edges:
- 3 × `TARGETS` (each Finding → its Resource)
- 3 × `MEMBER_OF` (each Finding → ThreatChain)
- 1 × `PRODUCES` (ThreatChain → AttackerCapability)
- 3 × `BELONGS_TO_SCOPE` (each Resource → TenantScope)

**Assertions:**
- [ ] ThreatChain node has `active: true`
- [ ] ThreatChain node has `kill_chain_phases` in STIX 2.1 format
- [ ] ThreatChain node has `stage_span_attck` with correct tactic IDs
- [ ] All 3 Finding nodes have `x_stave_chain_membership` populated
- [ ] Each Finding has `attack_stage_attck` correctly translated
- [ ] AttackerCapability node has `chain_id: "data_exfiltration_path"`
- [ ] No duplicate edges (edge deduplication working)

---

## Experiment 3: Compliance Requirements

**Purpose:** Verify MAPS_TO and VIOLATES edges connect controls
and findings to compliance requirements correctly.

**Scenario:** Same 3 failing findings from Experiment 2, but now
with HIPAA and PCI-DSS citations on each control.

**Expected additional nodes:**
- 4 × `ComplianceRequirement` nodes:
  - hipaa:164.312(a)(1)
  - hipaa:164.312(b)
  - pci_dss_v4.0:7.2.1
  - pci_dss_v4.0:10.3.3

**Expected additional edges:**
- 6 × `MAPS_TO` (Control → ComplianceRequirement)
- 6 × `VIOLATES` (Finding → ComplianceRequirement)

**Assertions:**
- [ ] ComplianceRequirement nodes have `framework` and
      `requirement_id` properties
- [ ] MAPS_TO edges connect Control nodes (not Finding nodes)
      to ComplianceRequirement nodes
- [ ] VIOLATES edges connect Finding nodes (not Control nodes)
      to ComplianceRequirement nodes
- [ ] Requirements shared across controls are deduplicated —
      hipaa:164.312(a)(1) appears once even if 2 controls cite it
- [ ] `metadata.node_types.ComplianceRequirement: 4`

---

## Experiment 4: Multi-Control, No Chain

**Purpose:** Verify the graph correctly represents isolated findings
that do not contribute to any chain. This is the "scattered
misconfigurations" baseline — the world before Stave's compound
reasoning.

**Scenario:** 10 findings across 8 different resource types and
services. No chains fire (controls fail individually but not in
combinations that match any chain definition). Mix of severities.

**Resource types covered:**
- S3 bucket (public)
- RDS instance (public)
- Lambda function (over-privileged role)
- VPC security group (unrestricted ingress)
- IAM user (no MFA)
- KMS key (no rotation)
- CloudFront distribution (weak TLS)
- API Gateway stage (no throttling)

**Assertions:**
- [ ] 10 Finding nodes, 8 Resource nodes, 1 TenantScope node
- [ ] resource_class correctly set per resource type:
      s3_bucket→storage, rds_instance→database,
      lambda_function→compute, security_group→network,
      iam_user→identity, kms_key→key, cloudfront→cdn,
      api_gateway→network
- [ ] No ThreatChain nodes (no chains fire)
- [ ] No AttackerCapability nodes
- [ ] No MEMBER_OF edges
- [ ] All 10 findings have `x_stave_chain_membership: []` (empty)

---

## Experiment 5: Multi-Account Organization Graph

**Purpose:** Verify `stave consolidate --format graph-json` produces
a correct multi-account graph with TenantScope nodes per account
and cross-account edges.

**Scenario:** Three accounts — production, data, development.
One cross-account role chain: development account role can assume
data account role which has admin-equivalent permissions on the
production PHI bucket.

**Input:** Three snapshot files + `stave consolidate` output

**Account setup:**
```
acme-development (333333333333):
  IAM role: arn:aws:iam::333:role/dev-pipeline
  Has: sts:AssumeRole on arn:aws:iam::222:role/data-processor

acme-data (222222222222):
  IAM role: arn:aws:iam::222:role/data-processor
  Has: s3:* on arn:aws:s3:::acme-phi-records (admin-equivalent)
  Trust policy: allows arn:aws:iam::333:role/dev-pipeline

acme-production (111111111111):
  S3 bucket: arn:aws:s3:::acme-phi-records
  Tagged: data-classification=phi
```

**Expected graph-json output (with --snapshot for identity layer):**

Nodes:
- 3 × `TenantScope` nodes (one per account)
- 1 × `Resource` node — acme-phi-records (StorageResource)
- 2 × `Identity` nodes — dev-pipeline, data-processor
- Cross-account findings and chain findings

Edges:
- `CAN_IMPERSONATE` — dev-pipeline → data-processor
  (is_cross_account: true)
- `HAS_EFFECTIVE_ACCESS` — data-processor → acme-phi-records
- `BELONGS_TO_SCOPE` — acme-phi-records → TenantScope:111
- `BELONGS_TO_SCOPE` — dev-pipeline → TenantScope:333
- `BELONGS_TO_SCOPE` — data-processor → TenantScope:222

**Assertions:**
- [ ] 3 TenantScope nodes with correct account IDs
- [ ] CAN_IMPERSONATE edge has `is_cross_account: true`
- [ ] CAN_IMPERSONATE edge has `hop_count: 1`
- [ ] Identity nodes have `account_id` matching their TenantScope
- [ ] CTL.IAM.NEP.ESCALATION.001 finding present for dev-pipeline
      (transitive admin via 2 hops)
- [ ] CTL.IAM.NEP.PHI.001 finding present for data-processor
      (non-designated access to PHI)

---

## Experiment 6: Neo4j Round-Trip (Iteration 4)

**Purpose:** Verify the complete pipeline from `stave apply` through
graph-json to Neo4j load and Cypher query execution.

**Pipeline:**
```
Experiment 2 scenario (PHI + chain)
  → stave apply → out.v0.1.json
  → stave graph export --format graph-json → graph.json
  → python3 docs/integrations/neo4j/loader.py → Neo4j
  → run queries from queries.cypher
  → verify expected results
```

**Cypher assertions (run against loaded Neo4j graph):**

```cypher
-- Assert 1: Active chain exists
MATCH (c:ThreatChain {active: true})
RETURN count(c) = 1 AS chain_exists;

-- Assert 2: All 3 findings are chain members
MATCH (f:Finding)-[:MEMBER_OF]->(c:ThreatChain)
RETURN count(f) = 3 AS all_members;

-- Assert 3: HIPAA requirement is violated
MATCH (f:Finding)-[:VIOLATES]->(q:ComplianceRequirement)
WHERE q.framework = 'hipaa'
RETURN count(f) > 0 AS hipaa_violated;

-- Assert 4: Attack stage uses ATT&CK IDs not raw strings
MATCH (f:Finding)
WHERE f.attack_stage_attck STARTS WITH 'TA'
RETURN count(f) = 3 AS attck_ids_present;

-- Assert 5: Resource class is provider-agnostic
MATCH (r:Resource)
WHERE r.resource_class IN ['storage', 'key', 'log']
RETURN count(r) = 3 AS resource_classes_correct;
```

**Idempotency test:**
Run the loader twice on the same graph-json. Assert node and edge
counts are identical after both runs.

```bash
python3 loader.py --input graph.json
BEFORE=$(cypher-shell "MATCH (n) RETURN count(n)")
python3 loader.py --input graph.json  # second run
AFTER=$(cypher-shell "MATCH (n) RETURN count(n)")
assert $BEFORE == $AFTER
```

---

## Experiment 7: GraphML Round-Trip (Iteration 5)

**Purpose:** Verify graph-json converts to valid GraphML that
Gephi can load without errors.

**Pipeline:**
```
Experiment 2 scenario
  → graph.json
  → python3 docs/integrations/graphml/to-graphml.py < graph.json > graph.graphml
  → validate XML structure
  → verify key definitions cover all node properties
  → load in Gephi (manual verification step)
```

**Programmatic assertions:**
```python
import xml.etree.ElementTree as ET
tree = ET.parse('graph.graphml')
root = tree.getroot()

# Assert valid GraphML structure
ns = 'http://graphml.graphdrawing.org/graphml'
assert root.tag == f'{{{ns}}}graphml'

# Assert all node types present
nodes = root.findall(f'.//{{{ns}}}node')
node_types = {n.find(f'.//{{{ns}}}data[@key="type"]').text for n in nodes}
assert 'Finding' in node_types
assert 'ThreatChain' in node_types
assert 'AttackerCapability' in node_types

# Assert edge types present
edges = root.findall(f'.//{{{ns}}}edge')
edge_types = {e.find(f'.//{{{ns}}}data[@key="edge_type"]').text for e in edges}
assert 'MEMBER_OF' in edge_types
assert 'TARGETS' in edge_types
```

---

## Experiment 8: Cytoscape.js Viewer (Iteration 5)

**Purpose:** Verify the self-contained HTML viewer loads graph-json
and renders correctly.

**Test approach:** Automated using a headless browser (Playwright
or Puppeteer). Manual visual verification for layout and color.

**Automated assertions:**
```javascript
// Load viewer.html in headless browser
await page.goto('file://docs/integrations/cytoscape/viewer.html');

// Drop graph-json file
await page.setInputFiles('#file-input', 'graph.json');

// Assert graph renders
await page.waitForSelector('canvas');
const nodeCount = await page.evaluate(
  () => cy.nodes().length
);
assert(nodeCount === 9); // matches Experiment 2 expected count

// Assert highlight button works
await page.click('#highlight-chains-btn');
const highlightedCount = await page.evaluate(
  () => cy.nodes('.highlighted').length
);
assert(highlightedCount > 0);
```

**Manual visual checklist:**
- [ ] ThreatChain node is diamond-shaped
- [ ] Critical finding nodes are red-tinted
- [ ] Clicking a node shows properties in detail panel
- [ ] "Highlight Active Chains" fades non-chain nodes

---

## Experiment 9: stave graph chains Removal (Iteration 6)

**Purpose:** Verify `stave graph chains` is fully removed and
`stave graph coverage` is completely unaffected.

**Assertions:**
```bash
# Assert chains command is gone
stave graph chains 2>&1 | grep -q "unknown command" && echo PASS

# Assert coverage still works
stave graph coverage \
  --controls ./controls/ \
  --snapshot ./testdata/snapshot.json \
  | grep -q "digraph StaveCoverage" && echo PASS

# Assert dotQuote is still available (used by coverage)
grep -r "dotQuote" cmd/enforce/graph/ | grep -v "_test.go" | \
  grep -q "coverage" && echo "dotQuote preserved in coverage"

# Assert no dangling imports
go build ./... 2>&1 | grep -q "cannot find package" && echo FAIL || echo PASS
```

---

## Test Data Directory Structure

All experiment inputs and expected outputs live in:

```
testdata/e2e/graph-ontology/
  experiment-01-minimal/
    snapshot.json           — input snapshot
    out.v0.1.json           — expected assessment output
    expected-graph.json     — expected graph-json output
    assertions.txt          — human-readable assertion list

  experiment-02-active-chain/
    snapshot.json
    out.v0.1.json
    expected-graph.json
    assertions.txt

  experiment-03-compliance/
    out.v0.1.json           — assessment output (no snapshot needed)
    expected-graph.json
    assertions.txt

  experiment-04-no-chain/
    snapshot.json
    out.v0.1.json
    expected-graph.json
    assertions.txt

  experiment-05-multi-account/
    snapshots/
      acme-production.json
      acme-data.json
      acme-development.json
    org.yaml                — account manifest
    out.consolidated.json   — expected consolidated output
    expected-graph.json     — expected graph-json output
    assertions.txt

  experiment-06-neo4j/
    graph.json              — from experiment-02
    cypher-assertions.cypher
    README.md               — manual steps for Neo4j setup

  experiment-07-graphml/
    graph.json              — from experiment-02
    expected-graph.graphml  — expected GraphML structure
    assertions.py           — Python assertion script

  experiment-08-cytoscape/
    graph.json              — from experiment-02
    assertions.js           — Playwright assertions

  experiment-09-removal/
    assertions.sh           — shell assertions for removal
```

---

## Running All Experiments

```bash
# Run all programmatic experiments
go test ./testdata/e2e/graph-ontology/...

# Run Neo4j experiment (requires running Neo4j)
cd testdata/e2e/graph-ontology/experiment-06-neo4j
cat ../experiment-02-active-chain/expected-graph.json | \
  python3 docs/integrations/neo4j/loader.py
cypher-shell < cypher-assertions.cypher

# Run GraphML experiment
cd testdata/e2e/graph-ontology/experiment-07-graphml
python3 docs/integrations/graphml/to-graphml.py \
  < graph.json > actual-graph.graphml
python3 assertions.py actual-graph.graphml

# Run removal assertions
bash testdata/e2e/graph-ontology/experiment-09-removal/assertions.sh
```

---

## Definition of Done

- [ ] All 9 experiment directories created with input data
- [ ] Experiments 1–5 pass as Go E2E tests
- [ ] Experiment 6 Cypher assertions documented and runnable
      against local Neo4j
- [ ] Experiment 7 Python assertions pass against actual GraphML
      output
- [ ] Experiment 8 Playwright assertions pass against actual viewer
- [ ] Experiment 9 shell assertions pass after Iteration 6 removal
- [ ] All fake data uses fictional ARNs and account IDs
      (no real AWS account IDs)
- [ ] README in each experiment directory explains the scenario