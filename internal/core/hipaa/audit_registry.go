package hipaa

// AuditRegistry is the registry for all AUDIT.* controls.
var AuditRegistry = NewRegistry()

// GovernanceRegistry is the registry for all GOVERNANCE.* controls.
var GovernanceRegistry = NewRegistry()

// RetentionRegistry is the registry for all RETENTION.* controls.
var RetentionRegistry = NewRegistry()
