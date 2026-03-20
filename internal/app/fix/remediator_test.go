package fix

import "testing"

func TestNopRemediator_ConfirmFix(t *testing.T) {
	var r NopRemediator
	if !r.ConfirmFix("CTL.S3.PUBLIC.001", "aws:s3:::bucket") {
		t.Fatal("NopRemediator.ConfirmFix should always return true")
	}
}

func TestNopRemediator_LogProgress(t *testing.T) {
	var r NopRemediator
	r.LogProgress("should not panic") // just verify it doesn't panic
}

// recordingRemediator is a test double that records calls.
type recordingRemediator struct {
	confirmed []string
	messages  []string
}

func (r *recordingRemediator) ConfirmFix(controlID, assetID string) bool {
	r.confirmed = append(r.confirmed, controlID+"@"+assetID)
	return true
}

func (r *recordingRemediator) LogProgress(msg string) {
	r.messages = append(r.messages, msg)
}

func TestRemediatorInterface(t *testing.T) {
	var rem Remediator = &recordingRemediator{}
	rem.ConfirmFix("CTL.TEST.001", "asset-1")
	rem.LogProgress("step 1")

	rec := rem.(*recordingRemediator)
	if len(rec.confirmed) != 1 || rec.confirmed[0] != "CTL.TEST.001@asset-1" {
		t.Fatalf("unexpected confirmed: %v", rec.confirmed)
	}
	if len(rec.messages) != 1 || rec.messages[0] != "step 1" {
		t.Fatalf("unexpected messages: %v", rec.messages)
	}
}
