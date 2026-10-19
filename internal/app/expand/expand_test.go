package expand

import (
	"reflect"
	"testing"
)

func TestServiceIDs_DomainMethods(t *testing.T) {
	var empty ServiceIDs
	if empty.Len() != 0 {
		t.Errorf("empty.Len() = %d, want 0", empty.Len())
	}
	if !empty.IsEmpty() {
		t.Error("empty.IsEmpty() = false, want true")
	}
	if empty.Contains("s3") {
		t.Error("empty.Contains(s3) = true, want false")
	}
	if empty.Strings() != nil {
		t.Error("empty.Strings() should be nil")
	}
	if empty.SnapshotCommands() != nil {
		t.Error("empty.SnapshotCommands() should be nil")
	}

	ids := ServiceIDs{"s3", "iam"}
	if ids.Len() != 2 {
		t.Errorf("ids.Len() = %d, want 2", ids.Len())
	}
	if ids.IsEmpty() {
		t.Error("ids.IsEmpty() = true, want false")
	}
	if !ids.Contains("s3") || !ids.Contains("iam") {
		t.Error("ids should contain s3 and iam")
	}
	if ids.Contains("ec2") {
		t.Error("ids.Contains(ec2) = true, want false")
	}

	wantStrings := []string{"s3", "iam"}
	if !reflect.DeepEqual(ids.Strings(), wantStrings) {
		t.Errorf("ids.Strings() = %v, want %v", ids.Strings(), wantStrings)
	}

	wantCmds := []string{"stave snapshot s3", "stave snapshot iam"}
	if !reflect.DeepEqual(ids.SnapshotCommands(), wantCmds) {
		t.Errorf("ids.SnapshotCommands() = %v, want %v", ids.SnapshotCommands(), wantCmds)
	}
}

func TestSnapshotStatus_DomainMethods(t *testing.T) {
	var nilSnap *SnapshotStatus
	if nilSnap.HasMissing() {
		t.Error("nilSnap.HasMissing() = true, want false")
	}
	if nilSnap.IsComplete() {
		t.Error("nilSnap.IsComplete() = true, want false")
	}
	if nilSnap.IsFound("s3") {
		t.Error("nilSnap.IsFound(s3) = true, want false")
	}
	if nilSnap.AllServices() != nil {
		t.Error("nilSnap.AllServices() should be nil")
	}
	if nilSnap.SnapshotCommands() != nil {
		t.Error("nilSnap.SnapshotCommands() should be nil")
	}

	partial := &SnapshotStatus{
		Found:   ServiceIDs{"s3"},
		Missing: ServiceIDs{"secretsmanager", "iam"},
	}
	if !partial.HasMissing() {
		t.Error("partial.HasMissing() = false, want true")
	}
	if partial.IsComplete() {
		t.Error("partial.IsComplete() = true, want false")
	}
	if !partial.IsFound("s3") {
		t.Error("partial.IsFound(s3) = false, want true")
	}
	if partial.IsFound("iam") {
		t.Error("partial.IsFound(iam) = true, want false")
	}

	wantAll := ServiceIDs{"iam", "s3", "secretsmanager"}
	if !reflect.DeepEqual(partial.AllServices(), wantAll) {
		t.Errorf("partial.AllServices() = %v, want %v", partial.AllServices(), wantAll)
	}

	wantCmds := []string{"stave snapshot secretsmanager", "stave snapshot iam"}
	if !reflect.DeepEqual(partial.SnapshotCommands(), wantCmds) {
		t.Errorf("partial.SnapshotCommands() = %v, want %v", partial.SnapshotCommands(), wantCmds)
	}

	complete := &SnapshotStatus{
		Found:   ServiceIDs{"iam", "s3"},
		Missing: nil,
	}
	if complete.HasMissing() {
		t.Error("complete.HasMissing() = true, want false")
	}
	if !complete.IsComplete() {
		t.Error("complete.IsComplete() = false, want true")
	}
}
