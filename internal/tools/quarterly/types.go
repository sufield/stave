package main

import "time"

// Gap is a single uncovered security property.
type Gap struct {
	Service     string   `json:"service"`
	Property    string   `json:"property"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity"`
	Taxonomy    []string `json:"taxonomy,omitempty"`
	Source      string   `json:"source"`
	Confidence  string   `json:"confidence"`
}

// EngineResult holds one engine's output.
type EngineResult struct {
	Engine       string        `json:"engine"`
	GapsFound    []Gap         `json:"gaps"`
	Covered      int           `json:"covered"`
	TotalChecked int           `json:"total_checked"`
	Duration     time.Duration `json:"duration_ns"`
	DataSource   string        `json:"data_source"`
	Error        string        `json:"error,omitempty"`
}

// AuditReport is the full quarterly audit output.
type AuditReport struct {
	Quarter       string          `json:"quarter"`
	Timestamp     string          `json:"timestamp"`
	Engines       []EngineResult  `json:"engines"`
	MultiEngine   []Gap           `json:"multi_engine_gaps"`
	SingleEngine  []Gap           `json:"single_engine_gaps"`
	TotalRaw      int             `json:"total_raw_gaps"`
	TotalDeduped  int             `json:"total_deduped_gaps"`
	Diff          *QuarterDiff    `json:"diff,omitempty"`
}

// QuarterDiff shows changes from the previous quarter.
type QuarterDiff struct {
	PreviousQuarter string `json:"previous_quarter"`
	NewGaps         []Gap  `json:"new_gaps"`
	FixedGaps       []Gap  `json:"fixed_gaps"`
	PersistentGaps  []Gap  `json:"persistent_gaps"`
}
