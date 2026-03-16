package retention

// PlanAction represents the action to take on a snapshot in a retention plan.
type PlanAction string

const (
	ActionKeep    PlanAction = "KEEP"
	ActionPrune   PlanAction = "PRUNE"
	ActionArchive PlanAction = "ARCHIVE"
)

// PlanMode represents the execution mode of a snapshot retention plan.
type PlanMode string

const (
	ModePreview PlanMode = "PREVIEW"
	ModePrune   PlanMode = "PRUNE"
	ModeArchive PlanMode = "ARCHIVE"
)
