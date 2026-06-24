package compliancemapping

import "testing"

// Synthetic mapping exercises every coverage class + PASS/FAIL split.
func synthetic() *Mapping {
	return &Mapping{
		Framework: "test", FrameworkVersion: "0", TotalControls: 5,
		Domains: []Domain{{Domain: "D", TotalControls: 5, Controls: []MappedControl{
			{ID: "C-01", Coverage: coverageFull, StaveControls: []string{"CTL.A", "CTL.B"}},    // pass
			{ID: "C-02", Coverage: coveragePartial, StaveControls: []string{"CTL.C", "CTL.D"}}, // fail (CTL.C violated)
			{ID: "C-03", Coverage: coverageNone},                                               // gap
			{ID: "C-04", Coverage: coverageOOSRuntime},                                         // oos runtime
			{ID: "C-05", Coverage: coverageOOSOrgnztnl},                                        // oos organizational
		}}},
	}
}

func TestEvaluate_BucketsAndStatus(t *testing.T) {
	rep := synthetic().Evaluate(map[string]bool{"CTL.C": true})

	if got := len(rep.Covered); got != 2 {
		t.Fatalf("covered: want 2, got %d", got)
	}
	if len(rep.Gaps) != 1 || rep.Gaps[0].ID != "C-03" || rep.Gaps[0].Status != StatusNotVerified {
		t.Fatalf("gaps wrong: %+v", rep.Gaps)
	}
	if len(rep.OutOfScope) != 2 {
		t.Fatalf("oos: want 2, got %d", len(rep.OutOfScope))
	}
	// C-01 passes, C-02 fails on CTL.C.
	byID := map[string]ControlResult{}
	for _, c := range rep.Covered {
		byID[c.ID] = c
	}
	if byID["C-01"].Status != StatusPass {
		t.Errorf("C-01 want PASS, got %s", byID["C-01"].Status)
	}
	if byID["C-02"].Status != StatusFail {
		t.Errorf("C-02 want FAIL, got %s", byID["C-02"].Status)
	}
	if len(byID["C-02"].FailedControls) != 1 || byID["C-02"].FailedControls[0] != "CTL.C" {
		t.Errorf("C-02 failed controls = %v, want [CTL.C]", byID["C-02"].FailedControls)
	}
	if !byID["C-02"].Partial {
		t.Errorf("C-02 should be flagged partial")
	}
	// Out-of-scope kinds.
	kind := map[string]string{}
	for _, c := range rep.OutOfScope {
		kind[c.ID] = c.OutOfScopeKind
	}
	if kind["C-04"] != "RUNTIME" || kind["C-05"] != "ORGANIZATIONAL" {
		t.Errorf("oos kinds wrong: %v", kind)
	}
	// Coverage math: 2 verified / 3 in-scope.
	if rep.InScope != 3 || rep.Verified != 2 || rep.Passed != 1 || rep.Failed != 1 {
		t.Errorf("tallies: inScope=%d verified=%d passed=%d failed=%d", rep.InScope, rep.Verified, rep.Passed, rep.Failed)
	}
	if rep.CoveragePercent < 66.6 || rep.CoveragePercent > 66.7 {
		t.Errorf("coverage%% = %.2f, want ~66.67", rep.CoveragePercent)
	}
	if !rep.HasFailures() {
		t.Error("HasFailures should be true")
	}
}

func TestEvaluate_NoFailuresWhenNothingViolated(t *testing.T) {
	rep := synthetic().Evaluate(map[string]bool{})
	if rep.Failed != 0 || rep.HasFailures() {
		t.Fatalf("want no failures, got %d", rep.Failed)
	}
	if rep.Passed != 2 {
		t.Fatalf("want 2 passed, got %d", rep.Passed)
	}
}

// Real embedded mapping: every control partitions into exactly one bucket,
// and the totals reconcile.
func TestLoadAndEvaluate_RealAICM(t *testing.T) {
	m, err := Load("aicm-v1.1")
	if err != nil {
		t.Fatal(err)
	}
	if m.TotalControls != 247 {
		t.Fatalf("total_controls = %d, want 247", m.TotalControls)
	}
	rep := m.Evaluate(map[string]bool{}) // clean snapshot: all covered = PASS
	partitioned := len(rep.Covered) + len(rep.Gaps) + len(rep.OutOfScope)
	if partitioned != 247 {
		t.Fatalf("buckets sum to %d, want 247", partitioned)
	}
	if rep.InScope != len(rep.Covered)+len(rep.Gaps) {
		t.Fatalf("in-scope mismatch")
	}
	if rep.Failed != 0 {
		t.Fatalf("clean snapshot should have 0 failures, got %d", rep.Failed)
	}
	// A known in-scope-covered control and a known out-of-scope control.
	find := func(id string) (ControlResult, bool) {
		for _, list := range [][]ControlResult{rep.Covered, rep.Gaps, rep.OutOfScope} {
			for _, c := range list {
				if c.ID == id {
					return c, true
				}
			}
		}
		return ControlResult{}, false
	}
	if c, ok := find("IAM-05"); !ok || c.Bucket != BucketCovered {
		t.Errorf("IAM-05 should be covered, got %+v ok=%v", c, ok)
	}
	// MDS-13 (secure model format) is now covered; the model controls closed it.
	if c, ok := find("MDS-13"); !ok || c.Bucket != BucketCovered {
		t.Errorf("MDS-13 should be covered, got %+v ok=%v", c, ok)
	}
	// UEM-11 (endpoint DLP) was reclassified out-of-scope (organizational) —
	// endpoint-device agents have no cloud-config proxy.
	if c, ok := find("UEM-11"); !ok || c.Bucket != BucketOutOfScope || c.OutOfScopeKind != "ORGANIZATIONAL" {
		t.Errorf("UEM-11 should be out-of-scope organizational, got %+v ok=%v", c, ok)
	}
	if c, ok := find("A&A-01"); !ok || c.Bucket != BucketOutOfScope || c.OutOfScopeKind != "ORGANIZATIONAL" {
		t.Errorf("A&A-01 should be out-of-scope organizational, got %+v ok=%v", c, ok)
	}
	// All in-scope AICM controls now have Stave verification — zero gaps.
	if len(rep.Gaps) != 0 {
		t.Errorf("expected 0 in-scope gaps, got %d: %+v", len(rep.Gaps), rep.Gaps)
	}
}

func TestLoad_UnknownFramework(t *testing.T) {
	if _, err := Load("nist-800-53"); err == nil {
		t.Fatal("expected error for unknown framework")
	}
}
