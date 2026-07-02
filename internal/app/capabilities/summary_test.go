package capabilities

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"

	policy "github.com/sufield/stave/internal/core/controldef"
)

func ctl(id string, sev policy.Severity) policy.ControlDefinition {
	return policy.ControlDefinition{ID: kernel.ControlID(id), Severity: sev}
}

func sampleControls() []policy.ControlDefinition {
	return []policy.ControlDefinition{
		ctl("CTL.S3.PUBLIC.001", policy.SeverityHigh),
		ctl("CTL.S3.PUBLIC.002", policy.SeverityCritical),
		ctl("CTL.S3.ENCRYPTION.001", policy.SeverityMedium),
		ctl("CTL.IAM.MFA.001", policy.SeverityMedium),
	}
}

func sampleChains() []policy.ChainDefinition {
	return []policy.ChainDefinition{
		{ID: kernel.ChainID("public_exposure")},
		{ID: kernel.ChainID("privilege_escalation")},
	}
}

func TestSummarize_CountsAndHistogram(t *testing.T) {
	s := CatalogSummary(sampleControls(), sampleChains())
	if s.Controls != 4 {
		t.Errorf("Controls = %d, want 4", s.Controls)
	}
	if s.Services != 2 { // s3, iam
		t.Errorf("Services = %d, want 2", s.Services)
	}
	if s.Chains != 2 {
		t.Errorf("Chains = %d, want 2", s.Chains)
	}
	if s.Operational != len(operationalCaps()) {
		t.Errorf("Operational = %d, want %d", s.Operational, len(operationalCaps()))
	}
	// Severity histogram keyed on controldef.Severity.
	if got := s.SeverityHist[policy.SeverityCritical]; got != 1 {
		t.Errorf("Critical = %d, want 1", got)
	}
	if got := s.SeverityHist[policy.SeverityHigh]; got != 1 {
		t.Errorf("High = %d, want 1", got)
	}
	if got := s.SeverityHist[policy.SeverityMedium]; got != 2 {
		t.Errorf("Medium = %d, want 2", got)
	}
	// Sum of the histogram equals the control count — nothing miscounted or
	// dropped into the wrong severity type.
	total := 0
	for _, n := range s.SeverityHist {
		total += n
	}
	if total != s.Controls {
		t.Errorf("histogram sums to %d, want Controls=%d", total, s.Controls)
	}
}

func TestServiceRollup_PerServiceCapsControlsMaxSev(t *testing.T) {
	rows := ServiceRollup(sampleControls())
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	// Sorted by service: iam, s3.
	if rows[0].Service != "iam" || rows[1].Service != "s3" {
		t.Fatalf("rows not sorted by service: %q, %q", rows[0].Service, rows[1].Service)
	}
	iam, s3 := rows[0], rows[1]
	// s3 has two categories (public, encryption) => 2 caps, 3 controls, max=critical.
	if s3.Caps != 2 {
		t.Errorf("s3 Caps = %d, want 2", s3.Caps)
	}
	if s3.Controls != 3 {
		t.Errorf("s3 Controls = %d, want 3", s3.Controls)
	}
	if s3.MaxSev != policy.SeverityCritical {
		t.Errorf("s3 MaxSev = %v, want critical", s3.MaxSev)
	}
	// iam has one category (mfa) => 1 cap, 1 control, max=medium.
	if iam.Caps != 1 || iam.Controls != 1 || iam.MaxSev != policy.SeverityMedium {
		t.Errorf("iam row = %+v, want {iam 1 1 medium}", iam)
	}
	// Per-service severity breakdown (for the wide view): s3 has 1 critical,
	// 1 high, 1 medium.
	if s3.Sev[policy.SeverityCritical] != 1 || s3.Sev[policy.SeverityHigh] != 1 || s3.Sev[policy.SeverityMedium] != 1 {
		t.Errorf("s3 Sev = %v, want {critical:1, high:1, medium:1}", s3.Sev)
	}
}

func TestLeafControls_FilterByServiceCategorySeverity(t *testing.T) {
	all := LeafControls(sampleControls(), "", "", "", "")
	if len(all) != 4 {
		t.Errorf("unfiltered leaf controls = %d, want 4", len(all))
	}
	// Sorted by (service, category, ID): iam first.
	if all[0].Service != "iam" {
		t.Errorf("first leaf service = %q, want iam", all[0].Service)
	}

	s3only := LeafControls(sampleControls(), "s3", "", "", "")
	if len(s3only) != 3 {
		t.Errorf("s3 leaf controls = %d, want 3", len(s3only))
	}

	// Category filter narrows within a service: s3/public has 2 controls.
	pub := LeafControls(sampleControls(), "s3", "public", "", "")
	if len(pub) != 2 {
		t.Errorf("s3/public leaf controls = %d, want 2", len(pub))
	}
	// Category filter without a service still applies.
	enc := LeafControls(sampleControls(), "", "encryption", "", "")
	if len(enc) != 1 || enc[0].ID != "CTL.S3.ENCRYPTION.001" {
		t.Errorf("category=encryption = %+v, want exactly CTL.S3.ENCRYPTION.001", enc)
	}

	// Exact severity match (case-insensitive), control groups only.
	crit := LeafControls(sampleControls(), "", "", "CRITICAL", "")
	if len(crit) != 1 || crit[0].ID != "CTL.S3.PUBLIC.002" {
		t.Errorf("critical leaf controls = %+v, want exactly CTL.S3.PUBLIC.002", crit)
	}
	med := LeafControls(sampleControls(), "", "", "medium", "")
	if len(med) != 2 {
		t.Errorf("medium leaf controls = %d, want 2", len(med))
	}
	// Combined service + category + severity.
	if got := LeafControls(sampleControls(), "s3", "public", "critical", ""); len(got) != 1 || got[0].ID != "CTL.S3.PUBLIC.002" {
		t.Errorf("s3+public+critical = %+v, want exactly CTL.S3.PUBLIC.002", got)
	}

	// Service/category matching is case-insensitive: the summary table prints
	// service names UPPERCASE, so a user types what they see ("S3"/"PUBLIC").
	if up := LeafControls(sampleControls(), "S3", "", "", ""); len(up) != 3 {
		t.Errorf("uppercase service S3 = %d, want 3 (case-insensitive)", len(up))
	}
	if up := LeafControls(sampleControls(), "S3", "PUBLIC", "", ""); len(up) != 2 {
		t.Errorf("uppercase S3/PUBLIC = %d, want 2 (case-insensitive)", len(up))
	}
}

// A control with no CTL.<svc> prefix is excluded from the service grouping and
// the service count, but still counted in the headline total + histogram.
func TestSummarize_UngroupedControlCountedInTotalNotServices(t *testing.T) {
	ctls := append(sampleControls(), ctl("LEGACY-NO-PREFIX", policy.SeverityLow))
	s := CatalogSummary(ctls, nil)
	if s.Controls != 5 {
		t.Errorf("Controls = %d, want 5 (ungrouped still in total)", s.Controls)
	}
	if s.Services != 2 {
		t.Errorf("Services = %d, want 2 (ungrouped excluded)", s.Services)
	}
	rows := ServiceRollup(ctls)
	sum := 0
	for _, r := range rows {
		sum += r.Controls
	}
	if sum != 4 {
		t.Errorf("ServiceRollup controls sum = %d, want 4 (ungrouped excluded)", sum)
	}
}
