package evidence

// Bundle holds all collected evidence snapshots with their error states.
type Bundle struct {
	BuildInfo    BuildInfoSnapshot
	SBOM         SBOMSnapshot
	SBOMErr      error
	Vuln         VulnerabilitySnapshot
	VulnErr      error
	Binary       BinaryInspectionSnapshot
	BinaryErr    error
	Policy       PolicyInspectionSnapshot
	PolicyErr    error
	Crosswalk    CrosswalkSnapshot
	CrosswalkErr error
}
