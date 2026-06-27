package apply

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderAllStaged(t *testing.T) {
	doc := `{"findings":[
		{"control_id":"CTL.IAM.ESCALATE.PASSROLE.001","control_severity":"high","asset_id":"arn:aws:iam::1:role/r","control_name":"x"},
		{"control_id":"CTL.IAM.WILDCARD.001","control_severity":"critical","asset_id":"arn:aws:iam::1:user/u","control_name":"y"},
		{"control_id":"CTL.S3.PUBLIC.001","control_severity":"medium","asset_id":"arn:aws:s3:::b","control_name":"z"},
		{"control_id":"CTL.IAM.FOOTHOLD.CICD.001","control_severity":"critical","asset_id":"arn:aws:iam::1:role/ci","control_name":"c"}
	]}`
	var b bytes.Buffer
	if err := renderAllStaged([]byte(doc), &b); err != nil {
		t.Fatal(err)
	}
	out := b.String()

	// per-service stages, sorted; iam before s3
	if !strings.Contains(out, "[iam] 2 findings") || !strings.Contains(out, "[s3] 1 findings") {
		t.Errorf("service stages wrong:\n%s", out)
	}
	if strings.Index(out, "[iam]") > strings.Index(out, "[s3]") {
		t.Error("iam should sort before s3")
	}
	// FOOTHOLD is compound, pulled out of the iam stage
	if !strings.Contains(out, "[compound] 1 additional findings") {
		t.Errorf("compound stage wrong:\n%s", out)
	}
	if strings.Contains(out, "[iam]") && strings.Contains(b.String(), "FOOTHOLD") {
		// FOOTHOLD must appear under [compound], not [iam]
		iamSection := out[strings.Index(out, "[iam]"):strings.Index(out, "[s3]")]
		if strings.Contains(iamSection, "FOOTHOLD") {
			t.Error("FOOTHOLD should be in compound, not iam")
		}
	}
	// criticals first within iam (WILDCARD critical before PASSROLE high)
	if strings.Index(out, "CTL.IAM.WILDCARD.001") > strings.Index(out, "CTL.IAM.ESCALATE.PASSROLE.001") {
		t.Error("critical should sort before high within a stage")
	}
	// grand summary counts all 4 (2 critical, 1 high, 1 medium)
	if !strings.Contains(out, "Summary: 4 total finding(s) (2 critical, 1 high, 1 medium, 0 low)") {
		t.Errorf("summary wrong:\n%s", out)
	}
}

func TestRenderAllStaged_NoFindings(t *testing.T) {
	var b bytes.Buffer
	if err := renderAllStaged([]byte(`{"findings":[]}`), &b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "Summary: 0 total") || !strings.Contains(out, "All evaluated controls passed.") {
		t.Errorf("empty render wrong:\n%s", out)
	}
}
