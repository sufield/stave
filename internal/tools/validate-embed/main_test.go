package main

import (
	"strings"
	"testing"
)

func TestCompareIDs_SymmetricDifference(t *testing.T) {
	disk := map[string]bool{
		"CTL.S3.ENCRYPT.001":  true,
		"CTL.S3.ENCRYPT.002":  true,
		"CTL.EBS.ENCRYPT.001": true,
		"CTL.DISK.ONLY.001":   true, // on disk, not compiled
	}
	binary := map[string]bool{
		"CTL.S3.ENCRYPT.001":  true,
		"CTL.S3.ENCRYPT.002":  true,
		"CTL.EBS.ENCRYPT.001": true,
		"CTL.BINARY.ONLY.001": true, // compiled, not on disk
	}

	diskOnly, binaryOnly := compareIDs(disk, binary)

	if len(diskOnly) != 1 || diskOnly[0] != "CTL.DISK.ONLY.001" {
		t.Errorf("disk-only: want [CTL.DISK.ONLY.001], got %v", diskOnly)
	}
	if len(binaryOnly) != 1 || binaryOnly[0] != "CTL.BINARY.ONLY.001" {
		t.Errorf("binary-only: want [CTL.BINARY.ONLY.001], got %v", binaryOnly)
	}
}

func TestCompareIDs_Equal(t *testing.T) {
	ids := map[string]bool{
		"CTL.S3.ENCRYPT.001":  true,
		"CTL.EBS.ENCRYPT.001": true,
	}
	diskOnly, binaryOnly := compareIDs(ids, ids)
	if len(diskOnly) != 0 || len(binaryOnly) != 0 {
		t.Errorf("expected empty diffs, got disk=%v binary=%v", diskOnly, binaryOnly)
	}
}

func TestCompareIDs_NegativeSelfTest(t *testing.T) {
	// Simulates the b9c722e scenario: 1 control on disk but not compiled,
	// 1 compiled but not on disk. Both directions must be detected.
	disk := map[string]bool{
		"CTL.SHARED.001":  true,
		"CTL.SHARED.002":  true,
		"CTL.APPFLOW.001": true, // b9c722e class: on disk, missing embed
	}
	binary := map[string]bool{
		"CTL.SHARED.001":  true,
		"CTL.SHARED.002":  true,
		"CTL.PHANTOM.001": true, // mirror: compiled but no disk file
	}

	diskOnly, binaryOnly := compareIDs(disk, binary)

	if len(diskOnly) == 0 {
		t.Fatal("expected disk-not-compiled violations, got none")
	}
	if len(binaryOnly) == 0 {
		t.Fatal("expected compiled-not-on-disk violations, got none")
	}

	diskStr := strings.Join(diskOnly, ",")
	binaryStr := strings.Join(binaryOnly, ",")
	if !strings.Contains(diskStr, "CTL.APPFLOW.001") {
		t.Errorf("expected CTL.APPFLOW.001 in disk-only, got %s", diskStr)
	}
	if !strings.Contains(binaryStr, "CTL.PHANTOM.001") {
		t.Errorf("expected CTL.PHANTOM.001 in binary-only, got %s", binaryStr)
	}
}
