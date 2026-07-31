package evidence

import (
	"testing"
)

func TestCitationIndex_NilReceiver(t *testing.T) {
	var idx *CitationIndex

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CitationIndex method panicked on nil receiver: %v", r)
		}
	}()

	idx.Add("nist_800_53", "AC-2", CitationEntry{ControlID: "CTL.1"})

	cites := idx.Lookup("nist_800_53", "AC-2")
	if len(cites) != 0 {
		t.Errorf("expected empty citations, got %v", cites)
	}

	cov := idx.Coverage("nist_800_53", 10)
	if cov.CoveredRequirements != 0 {
		t.Errorf("expected 0 covered requirements")
	}

	fws := idx.Frameworks()
	if len(fws) != 0 {
		t.Errorf("expected 0 frameworks")
	}

	reqs := idx.RequirementsFor("nist_800_53")
	if len(reqs) != 0 {
		t.Errorf("expected 0 requirements")
	}

	if sz := idx.Size(); sz != 0 {
		t.Errorf("expected size 0, got %d", sz)
	}
}
