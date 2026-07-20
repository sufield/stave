package kernel

// AttackStage names a stage in the cyber kill chain. The stave
// catalog assigns one to each control via the params.attack_stage
// field; chains aggregate stages from their member controls into a
// stage span. The closed vocabulary is enforced by the catalog
// linter, not at the type level — this typed alias exists so
// collections (StageSpan, AttackStages) carry their semantic meaning
// across functions instead of decaying to []string.
//
// JSON serialization is identical to a raw string.
type AttackStage string

// String returns the raw stage name.
func (s AttackStage) String() string { return string(s) }

// Recognized attack stage values. The catalog/linter enforces these;
// the constants exist so callers in the engine and graph packages
// can reference them by name rather than open-coding string literals.
const ( //nolint:gosec // G101 false positive: ATT&CK stage names, not credentials
	AttackStageInitialAccess       AttackStage = "initial_access"
	AttackStageCredentialAccess    AttackStage = "credential_access" //nolint:gosec // G101 false positive: ATT&CK stage, not a credential
	AttackStagePersistence         AttackStage = "persistence"
	AttackStageExfiltration        AttackStage = "exfiltration"
	AttackStageDetectionEvasion    AttackStage = "detection_evasion"
	AttackStageResilience          AttackStage = "resilience"
	AttackStagePrivilegeEscalation AttackStage = "privilege_escalation"
	AttackStageLateralMovement     AttackStage = "lateral_movement"
	AttackStageImpact              AttackStage = "impact"
	AttackStageCollection          AttackStage = "collection"
	AttackStageDiscovery           AttackStage = "discovery"
	AttackStageExecution           AttackStage = "execution"
)
