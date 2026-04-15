// Stave Graph — Neo4j Schema
// Run once against a fresh Neo4j instance before loading data.

// --- Node uniqueness constraints ---

CREATE CONSTRAINT finding_id IF NOT EXISTS
  FOR (f:Finding) REQUIRE f.finding_id IS UNIQUE;

CREATE CONSTRAINT resource_arn IF NOT EXISTS
  FOR (r:Resource) REQUIRE r.resource_arn IS UNIQUE;

CREATE CONSTRAINT control_id IF NOT EXISTS
  FOR (c:Control) REQUIRE c.control_id IS UNIQUE;

CREATE CONSTRAINT chain_id IF NOT EXISTS
  FOR (t:ThreatChain) REQUIRE t.chain_id IS UNIQUE;

CREATE CONSTRAINT requirement_id IF NOT EXISTS
  FOR (q:ComplianceRequirement) REQUIRE q.id IS UNIQUE;

CREATE CONSTRAINT identity_arn IF NOT EXISTS
  FOR (i:Identity) REQUIRE i.principal_arn IS UNIQUE;

CREATE CONSTRAINT account_id IF NOT EXISTS
  FOR (a:TenantScope) REQUIRE a.account_id IS UNIQUE;

CREATE CONSTRAINT capability_id IF NOT EXISTS
  FOR (cap:AttackerCapability) REQUIRE cap.chain_id IS UNIQUE;

CREATE CONSTRAINT remediation_id IF NOT EXISTS
  FOR (rem:RemediationAction) REQUIRE rem.finding_id IS UNIQUE;

// --- Indexes for frequent query patterns ---

CREATE INDEX finding_severity IF NOT EXISTS
  FOR (f:Finding) ON (f.severity);

CREATE INDEX finding_attack_stage IF NOT EXISTS
  FOR (f:Finding) ON (f.attack_stage_attck);

CREATE INDEX finding_sla_breached IF NOT EXISTS
  FOR (f:Finding) ON (f.sla_breached);

CREATE INDEX resource_class IF NOT EXISTS
  FOR (r:Resource) ON (r.resource_class);

CREATE INDEX resource_account IF NOT EXISTS
  FOR (r:Resource) ON (r.account_id);

CREATE INDEX chain_active IF NOT EXISTS
  FOR (t:ThreatChain) ON (t.active);

CREATE INDEX identity_privilege IF NOT EXISTS
  FOR (i:Identity) ON (i.privilege_level);

CREATE INDEX requirement_framework IF NOT EXISTS
  FOR (q:ComplianceRequirement) ON (q.framework);
