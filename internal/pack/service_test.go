package pack

import (
	"reflect"
	"testing"
)

func TestServiceForControlID(t *testing.T) {
	cases := map[string]string{
		"CTL.IAM.ESCALATE.PASSROLE.001": "iam",
		"CTL.S3.PUBLIC.001":             "s3",
		"CTL.EC2.IMDS.001":              "ec2",
		"bogus":                         "",
		"NOTCTL.IAM.X":                  "",
	}
	for id, want := range cases {
		if got := ServiceForControlID(id); got != want {
			t.Errorf("ServiceForControlID(%q)=%q want %q", id, got, want)
		}
	}
}

func TestPacksForServices(t *testing.T) {
	catalog := []ControlMeta{
		{ID: "CTL.IAM.ESCALATE.PASSROLE.001", Severity: "high"},
		{ID: "CTL.S3.PUBLIC.001", Severity: "high"},
		{ID: "CTL.EC2.IMDS.001", Severity: "medium"},
	}
	all := map[string]*Pack{
		"iam-only": {Name: "iam-only", Controls: Selector{IDs: []string{"CTL.IAM.ESCALATE.PASSROLE.001"}}},
		"s3-only":  {Name: "s3-only", Controls: Selector{IDs: []string{"CTL.S3.PUBLIC.001"}}},
		"all":      {Name: "all", Controls: Selector{IDPatterns: []string{"CTL.*"}}},
	}
	got := PacksForServices([]string{"iam"}, all, catalog)
	if !reflect.DeepEqual(got, []string{"all", "iam-only"}) {
		t.Errorf("packs for iam = %v", got)
	}
	got = PacksForServices([]string{"S3"}, all, catalog) // case-insensitive
	if !reflect.DeepEqual(got, []string{"all", "s3-only"}) {
		t.Errorf("packs for s3 = %v", got)
	}
}

func TestMergeRequirements(t *testing.T) {
	a := &Pack{Requirements: Requirements{
		AWSAPICalls:        []ServiceCalls{{Service: "iam", Calls: []string{"aws iam list-roles"}, Notes: "n1"}},
		ObservationSignals: []string{"identity.x"},
		MinimumPermissions: "iam:List*\niam:Get*",
	}}
	b := &Pack{Requirements: Requirements{
		AWSAPICalls: []ServiceCalls{
			{Service: "iam", Calls: []string{"aws iam list-roles", "aws iam list-users"}}, // dup + new
			{Service: "s3", Calls: []string{"aws s3api list-buckets"}},
		},
		ObservationSignals: []string{"identity.x", "storage.y"}, // dup + new
		MinimumPermissions: "iam:List*\ns3:GetBucket*",          // dup + new line
	}}
	m := MergeRequirements([]*Pack{a, b})

	if len(m.AWSAPICalls) != 2 {
		t.Fatalf("want 2 services, got %d", len(m.AWSAPICalls))
	}
	// iam comes first (sorted), with deduped calls
	if m.AWSAPICalls[0].Service != "iam" || !reflect.DeepEqual(m.AWSAPICalls[0].Calls,
		[]string{"aws iam list-roles", "aws iam list-users"}) {
		t.Errorf("iam calls merge wrong: %+v", m.AWSAPICalls[0])
	}
	if m.AWSAPICalls[0].Notes != "n1" { // notes preserved from first pack
		t.Errorf("notes lost: %q", m.AWSAPICalls[0].Notes)
	}
	if !reflect.DeepEqual(m.ObservationSignals, []string{"identity.x", "storage.y"}) {
		t.Errorf("signals merge wrong: %v", m.ObservationSignals)
	}
	// permission lines deduped, order preserved
	if m.MinimumPermissions != "iam:List*\niam:Get*\ns3:GetBucket*" {
		t.Errorf("perms merge wrong: %q", m.MinimumPermissions)
	}
}
