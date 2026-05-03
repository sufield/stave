package sarif

import "github.com/sufield/stave/internal/core/kernel"

type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               kernel.ControlID `json:"id"`
	Name             string           `json:"name"`
	ShortDescription sarifMessage     `json:"shortDescription"`
	Help             *sarifMessage    `json:"help,omitempty"`
	Properties       map[string]any   `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    kernel.ControlID `json:"ruleId"`
	RuleIndex int              `json:"ruleIndex"`
	Level     string           `json:"level"`
	Message   sarifMessage     `json:"message"`
	Locations []sarifLocation  `json:"locations"`
	// Suggestions are rendered using SARIF's "fixes" field for compatibility.
	Suggestions         []sarifSuggestion  `json:"fixes,omitempty"`
	BaselineState       string             `json:"baselineState,omitempty"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
	PartialFingerprints map[string]string  `json:"partialFingerprints,omitempty"`
	Properties          map[string]any     `json:"properties,omitempty"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

type sarifSuggestion struct {
	Description sarifMessage `json:"description"`
	// Changes carries the SARIF 2.1.0 required artifactChanges
	// list — without at least one entry, validators reject the
	// fix object. Stave does not generally know the source-file
	// location to patch, so the writer emits a placeholder change
	// pointing at the asset URI.
	Changes []sarifChange `json:"changes"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

// sarifChange is an artifactChanges entry per SARIF 2.1.0 §3.55.
type sarifChange struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Replacements     []sarifReplacement    `json:"replacements"`
}

// sarifReplacement is a deletedRegion / insertedContent pair.
// Stave emits a synthetic replacement with the remediation text as
// insertedContent — concrete file ranges are not generally
// available because findings target cloud resources, not source
// files.
type sarifReplacement struct {
	DeletedRegion   sarifRegion        `json:"deletedRegion"`
	InsertedContent sarifMessageString `json:"insertedContent"`
}

// sarifMessageString is the SARIF "text" wrapper for replacement content.
type sarifMessageString struct {
	Text string `json:"text"`
}
