package pack

import "testing"

func TestCountByService(t *testing.T) {
	catalog := []ControlMeta{
		{ID: "CTL.IAM.A.001", Severity: "critical"},
		{ID: "CTL.IAM.B.001", Severity: "high"},
		{ID: "CTL.IAM.C.001", Severity: "high"},
		{ID: "CTL.S3.A.001", Severity: "medium"},
		{ID: "CTL.EC2.A.001", Severity: "low"},
	}
	ids := []string{"CTL.IAM.A.001", "CTL.IAM.B.001", "CTL.IAM.C.001", "CTL.S3.A.001", "CTL.EC2.A.001"}

	// No service filter: all services counted.
	all := CountByService(ids, catalog, nil)
	if all["iam"].Total != 3 || all["iam"].Critical != 1 || all["iam"].High != 2 {
		t.Errorf("iam counts wrong: %+v", all["iam"])
	}
	if all["s3"].Medium != 1 || all["ec2"].Low != 1 {
		t.Errorf("s3/ec2 counts wrong: %+v %+v", all["s3"], all["ec2"])
	}

	// Service filter: only iam + s3; ec2 controls excluded.
	filtered := CountByService(ids, catalog, []string{"iam", "s3"})
	if _, ok := filtered["ec2"]; ok {
		t.Error("ec2 should be filtered out")
	}
	if filtered["iam"].Total != 3 || filtered["s3"].Total != 1 {
		t.Errorf("filtered counts wrong: %+v", filtered)
	}
}
