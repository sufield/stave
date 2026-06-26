package pack

import (
	"reflect"
	"testing"
)

var cat = []ControlMeta{
	{ID: "CTL.IAM.ROLE.PERMISSIONDRIFT.001", Severity: "high"},
	{ID: "CTL.IAM.USER.PERMISSIONDRIFT.001", Severity: "high"},
	{ID: "CTL.EC2.GHOST.SUBNET.001", Severity: "medium"},
	{ID: "CTL.S3.ORPHAN.BUCKET.001", Severity: "low"},
	{ID: "CTL.IAM.CRED.UNUSED.001", Severity: "medium"},
	{ID: "CTL.S3.PUBLIC.001", Severity: "critical"},
	{ID: "CTL.OTHER.THING.001", Severity: "low"},
}

func TestResolve_IDsAndPatterns(t *testing.T) {
	p := Pack{Controls: Selector{
		IDs:        []string{"CTL.IAM.ROLE.PERMISSIONDRIFT.001"},
		IDPatterns: []string{"CTL.*.GHOST.*", "CTL.*.ORPHAN.*", "CTL.IAM.*.UNUSED*"},
	}}
	got := p.Resolve(cat)
	want := []string{
		"CTL.EC2.GHOST.SUBNET.001",
		"CTL.IAM.CRED.UNUSED.001",
		"CTL.IAM.ROLE.PERMISSIONDRIFT.001",
		"CTL.S3.ORPHAN.BUCKET.001",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolve = %v, want %v", got, want)
	}
}

func TestResolve_MinSeverityAndLimit(t *testing.T) {
	p := Pack{Controls: Selector{MinSeverity: "high", Limit: 2}}
	got := p.Resolve(cat)
	// critical + 2 highs are eligible; limit keeps the 2 highest-severity,
	// then the result is sorted by ID.
	if len(got) != 2 {
		t.Fatalf("limit not applied: %v", got)
	}
	// critical (S3.PUBLIC) must be kept over the highs.
	found := false
	for _, id := range got {
		if id == "CTL.S3.PUBLIC.001" {
			found = true
		}
	}
	if !found {
		t.Errorf("limit dropped the critical control: %v", got)
	}
}

func TestResolve_DedupAcrossSelectors(t *testing.T) {
	p := Pack{Controls: Selector{
		IDs:         []string{"CTL.S3.ORPHAN.BUCKET.001"},
		IDPatterns:  []string{"CTL.*.ORPHAN.*"},
		MinSeverity: "low",
	}}
	got := p.Resolve(cat)
	seen := map[string]bool{}
	for _, id := range got {
		if seen[id] {
			t.Fatalf("duplicate id %s in %v", id, got)
		}
		seen[id] = true
	}
}

func TestMissing(t *testing.T) {
	p := Pack{Controls: Selector{IDs: []string{
		"CTL.IAM.ROLE.PERMISSIONDRIFT.001", // exists
		"CTL.NOT.REAL.001",                 // missing
	}}}
	if got := p.Missing(cat); !reflect.DeepEqual(got, []string{"CTL.NOT.REAL.001"}) {
		t.Fatalf("missing = %v", got)
	}
}

func TestLoadAll_EmbeddedPacks(t *testing.T) {
	all, err := LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"entropy", "quick"} {
		p, ok := all[name]
		if !ok {
			t.Fatalf("pack %q not loaded", name)
		}
		if p.Title == "" || p.Requirements.MinimumPermissions == "" {
			t.Errorf("pack %q missing title/requirements", name)
		}
	}
}
