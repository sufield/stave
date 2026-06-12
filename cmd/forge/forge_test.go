package forge

import (
	"bytes"
	"strings"
	"testing"
)

func TestWizard_ReadLine(t *testing.T) {
	input := strings.NewReader("hello world\n")
	var out bytes.Buffer
	w := newWizard(input, &out)

	got := w.readLine("prompt:")
	if got != "hello world" {
		t.Errorf("readLine = %q, want %q", got, "hello world")
	}
}

func TestWizard_ReadLineDefault(t *testing.T) {
	input := strings.NewReader("\n")
	var out bytes.Buffer
	w := newWizard(input, &out)

	got := w.readLineDefault("prompt:", "default")
	if got != "default" {
		t.Errorf("readLineDefault = %q, want %q", got, "default")
	}
}

func TestWizard_SelectOption(t *testing.T) {
	input := strings.NewReader("2\n")
	var out bytes.Buffer
	w := newWizard(input, &out)

	got := w.selectOption("pick:", []string{"a", "b", "c"})
	if got != "b" {
		t.Errorf("selectOption = %q, want %q", got, "b")
	}
}

func TestWizard_Confirm(t *testing.T) {
	input := strings.NewReader("n\n")
	var out bytes.Buffer
	w := newWizard(input, &out)

	if w.confirm("ok?") {
		t.Error("expected false for 'n' input")
	}
}

func TestWizard_ReadControlID(t *testing.T) {
	input := strings.NewReader("bad\nCTL.S3.TAGS.001\n")
	var out bytes.Buffer
	w := newWizard(input, &out)

	got := w.readControlID()
	if got != "CTL.S3.TAGS.001" {
		t.Errorf("readControlID = %q, want CTL.S3.TAGS.001", got)
	}
}

func TestControlIDPattern(t *testing.T) {
	valid := []string{"CTL.S3.TAGS.001", "CTL.IAM.ROOT.002", "CTL.VPC.SG.123"}
	for _, id := range valid {
		if !controlIDPattern.MatchString(id) {
			t.Errorf("expected %q to be valid", id)
		}
	}
	invalid := []string{"CTL.S3", "ctl.s3.tags.001", "CTL.S3.TAGS", "SOMETHING.ELSE"}
	for _, id := range invalid {
		if controlIDPattern.MatchString(id) {
			t.Errorf("expected %q to be invalid", id)
		}
	}
}
