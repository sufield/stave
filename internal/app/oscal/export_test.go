package oscal

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestARCollection_DomainMethods(t *testing.T) {
	findings := ARFindings{
		{UUID: "f1", Target: ARTarget{TargetID: kernel.ControlID("CTL.A.001")}},
		{UUID: "f2", Target: ARTarget{TargetID: kernel.ControlID("CTL.B.002")}},
		{UUID: "f3", Target: ARTarget{TargetID: kernel.ControlID("CTL.A.001")}},
	}

	if findings.Len() != 3 {
		t.Errorf("findings.Len() = %d, want 3", findings.Len())
	}

	ctlA := findings.ByControl(kernel.ControlID("CTL.A.001"))
	if ctlA.Len() != 2 {
		t.Errorf("ByControl(CTL.A.001).Len() = %d, want 2", ctlA.Len())
	}

	obs := ARObservations{
		{UUID: "o1", Description: "obs 1"},
		{UUID: "o2", Description: "obs 2"},
	}

	if obs.Len() != 2 {
		t.Errorf("obs.Len() = %d, want 2", obs.Len())
	}

	var emptyFindings ARFindings
	if emptyFindings.Len() != 0 {
		t.Errorf("emptyFindings.Len() = %d, want 0", emptyFindings.Len())
	}
	if emptyFindings.ByControl(kernel.ControlID("CTL.A.001")) != nil {
		t.Error("emptyFindings.ByControl() should return nil")
	}

	var emptyObs ARObservations
	if emptyObs.Len() != 0 {
		t.Errorf("emptyObs.Len() = %d, want 0", emptyObs.Len())
	}
}
