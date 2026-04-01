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
}

type sarifResult struct {
	RuleID    kernel.ControlID `json:"ruleId"`
	RuleIndex int              `json:"ruleIndex"`
	Level     string           `json:"level"`
	Message   sarifMessage     `json:"message"`
	Locations []sarifLocation  `json:"locations"`
	// Suggestions are rendered using SARIF's "fixes" field for compatibility.
	Suggestions []sarifSuggestion `json:"fixes,omitempty"`
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
	StartLine int `json:"startLine"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

type sarifSuggestion struct {
	Description sarifMessage `json:"description"`
}

type sarifMessage struct {
	Text string `json:"text"`
}
