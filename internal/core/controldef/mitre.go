package controldef

type MitreAttackRef struct {
	ID     string
	Name   string
	Tactic string
}

type LabValidation struct {
	Vendor   string
	Lab      string
	Result   string
	Verified string
}
