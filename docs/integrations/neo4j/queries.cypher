// Stave Graph — Cypher Query Library
// Each query answers a specific security intelligence question.
// Run against a Neo4j instance loaded via loader.py.

// ============================================================
// Section 1: Attack Path Analysis
// ============================================================

// Q1: Find all active attack chains and their member findings
// Use: identify which compound threats are currently firing
MATCH (f:Finding)-[:MEMBER_OF]->(c:ThreatChain)
WHERE c.active = true
RETURN c.chain_id, c.compound_severity, c.narrative,
       collect(f.control_id) AS member_controls,
       collect(f.finding_id) AS finding_ids
ORDER BY c.compound_severity DESC;

// Q2: Find the shortest attack path from any identity to PHI resources
// Use: identify which identities are closest to sensitive data
MATCH path = shortestPath(
  (i:Identity)-[:CAN_IMPERSONATE|HAS_EFFECTIVE_ACCESS*1..5]->(r:Resource)
)
WHERE r.resource_class = 'storage'
RETURN i.principal_arn, i.privilege_level,
       length(path) AS hops,
       [n IN nodes(path) | n.id] AS path_nodes
ORDER BY hops ASC
LIMIT 20;

// Q3: Find all cross-account attack paths
// Use: identify lateral movement between AWS accounts
MATCH (i:Identity)-[e:CAN_IMPERSONATE]->(j:Identity)
WHERE e.is_cross_account = true
MATCH (j)-[:HAS_EFFECTIVE_ACCESS]->(r:Resource)
RETURN i.principal_arn AS source_identity,
       i.account_id AS source_account,
       j.principal_arn AS target_identity,
       j.account_id AS target_account,
       collect(r.resource_arn) AS reachable_resources
ORDER BY source_account, target_account;

// ============================================================
// Section 2: Identity Risk
// ============================================================

// Q4: Rank identities by transitive resource reach
// Use: answer "if compromised, what can this identity reach?"
MATCH (i:Identity)-[:HAS_EFFECTIVE_ACCESS]->(r:Resource)
WITH i, count(r) AS reachable_count,
     collect(r.resource_class) AS resource_classes
RETURN i.principal_arn, i.privilege_level, reachable_count,
       resource_classes
ORDER BY reachable_count DESC
LIMIT 20;

// Q5: Find identities with access to storage resources
// Use: data access governance — who can reach storage?
MATCH (i:Identity)-[:HAS_EFFECTIVE_ACCESS]->(r:StorageResource)
RETURN i.principal_arn, i.identity_type, i.privilege_level,
       collect(r.resource_arn) AS storage_resources
ORDER BY i.privilege_level DESC;

// Q6: Find the minimum identity removals to sever storage attack paths
// Use: minimum cut analysis — what is the cheapest fix?
MATCH (i:Identity)-[:HAS_EFFECTIVE_ACCESS|CAN_IMPERSONATE*1..3]->(r:StorageResource)
WITH i, count(DISTINCT r) AS storage_exposure
MATCH (i)-[:HAS_EFFECTIVE_ACCESS]->(any_r:Resource)
WITH i, storage_exposure, count(DISTINCT any_r) AS total_exposure
RETURN i.principal_arn, storage_exposure, total_exposure,
       round(100.0 * storage_exposure / total_exposure, 1) AS storage_concentration
ORDER BY storage_exposure DESC
LIMIT 10;

// ============================================================
// Section 3: Compliance Intelligence
// ============================================================

// Q7: Find all findings violating HIPAA requirements
// Use: HIPAA audit preparation — which findings affect compliance?
MATCH (f:Finding)-[:VIOLATES]->(q:ComplianceRequirement)
WHERE q.framework = 'hipaa'
RETURN q.requirement_id,
       count(f) AS violation_count,
       collect(f.control_id) AS controls,
       collect(f.finding_id) AS finding_ids
ORDER BY violation_count DESC;

// Q8: Find controls that only produce failing findings
// Use: identify controls that have never passed — coverage gap
MATCH (c:Control)<-[:MAPS_TO]-(f:Finding)
WHERE f.verdict = 'fail'
WITH c, count(f) AS fail_count
RETURN c.control_id, c.control_name, c.severity, fail_count
ORDER BY c.severity DESC;

// Q9: Compliance coverage per framework
// Use: dashboard metric — what percentage of requirements have no violations?
MATCH (q:ComplianceRequirement)
OPTIONAL MATCH (f:Finding)-[:VIOLATES]->(q)
WITH q.framework AS framework,
     count(DISTINCT q) AS total_requirements,
     count(DISTINCT CASE WHEN f IS NULL THEN q END) AS satisfied
RETURN framework,
       total_requirements,
       satisfied,
       round(100.0 * satisfied / total_requirements, 1) AS coverage_percent
ORDER BY coverage_percent ASC;

// ============================================================
// Section 4: Risk Prioritization
// ============================================================

// Q10: Top 10 resources by number of active attack chain findings
// Use: where is the greatest concentration of compound risk?
MATCH (f:Finding)-[:TARGETS]->(r:Resource)
MATCH (f)-[:MEMBER_OF]->(c:ThreatChain)
WHERE c.active = true
RETURN r.resource_arn, r.resource_class,
       count(DISTINCT f) AS chain_finding_count,
       count(DISTINCT c) AS active_chain_count,
       collect(DISTINCT c.chain_id) AS chains
ORDER BY chain_finding_count DESC
LIMIT 10;

// Q11: Findings with SLA breach
// Use: what needs immediate attention — SLA clock has expired
MATCH (f:Finding)-[:TARGETS]->(r:Resource)
WHERE f.sla_breached = true
RETURN f.finding_id, f.control_id, f.severity,
       r.resource_arn, r.resource_class
ORDER BY f.severity DESC;

// Q12: Risk reduction ranking — which resource remediation helps most?
// Use: prioritize remediation by downstream identity exposure
MATCH (f:Finding)-[:TARGETS]->(r:Resource)
OPTIONAL MATCH (i:Identity)-[:HAS_EFFECTIVE_ACCESS]->(r)
WITH f, r, count(DISTINCT i) AS identity_exposure
RETURN f.finding_id, f.control_id, f.severity,
       r.resource_arn, identity_exposure
ORDER BY identity_exposure DESC
LIMIT 20;

// ============================================================
// Section 5: Graph Diagnostics
// ============================================================

// Q13: Graph summary — node and edge counts by label
MATCH (n)
RETURN labels(n) AS node_labels, count(n) AS node_count
ORDER BY node_count DESC;

// Q14: Verify ontology completeness — check for orphaned nodes
MATCH (n)
WHERE NOT EXISTS { MATCH (n)-[]-() }
RETURN labels(n) AS node_type, count(n) AS orphan_count
ORDER BY orphan_count DESC;

// Q15: Edge type distribution
MATCH ()-[r]->()
RETURN type(r) AS edge_type, count(r) AS edge_count
ORDER BY edge_count DESC;
