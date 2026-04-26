// Stave Graph — Gremlin Query Library for Amazon Neptune
// Five canonical security-graph queries written against the Stave
// graph topology emitted by `stave graph export`.

// Q1: Active attack chains and member findings
g.V().hasLabel('ThreatChain').has('active', true)
  .project('chain_id', 'severity', 'member_findings')
  .by('chain_id')
  .by('compound_severity')
  .by(__.in('MEMBER_OF').values('control_id').fold())
  .order().by(select('severity'), desc)

// Q4: Rank identities by transitive resource reach
g.V().hasLabel('Identity')
  .project('principal', 'privilege', 'reachable_count')
  .by('principal_arn')
  .by('privilege_level')
  .by(__.out('HAS_EFFECTIVE_ACCESS').count())
  .order().by(select('reachable_count'), desc)
  .limit(20)

// Q7: Findings violating HIPAA requirements
g.V().hasLabel('ComplianceRequirement').has('framework', 'hipaa')
  .project('requirement', 'violations', 'controls')
  .by('requirement_id')
  .by(__.in('VIOLATES').count())
  .by(__.in('VIOLATES').values('control_id').dedup().fold())
  .order().by(select('violations'), desc)

// Q10: Top resources by active chain finding count
g.V().hasLabel('Finding')
  .where(__.out('MEMBER_OF').has('active', true))
  .out('TARGETS')
  .groupCount()
  .order(local).by(values, desc)
  .limit(local, 10)

// Q11: Findings with SLA breach
g.V().hasLabel('Finding').has('sla_breached', true)
  .project('finding', 'control', 'severity', 'resource')
  .by('finding_id')
  .by('control_id')
  .by('severity')
  .by(__.out('TARGETS').values('resource_arn').fold())
  .order().by(select('severity'), desc)
