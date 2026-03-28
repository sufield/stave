package snapshot

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// --- Type serialization tests ---

func TestDiffRequest_JSON(t *testing.T) {
	req := DiffRequest{ObservationsDir: "observations", ChangeTypes: []string{"added"}, AssetID: "bucket-a"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got DiffRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ObservationsDir != "observations" {
		t.Errorf("ObservationsDir: got %q", got.ObservationsDir)
	}
}

func TestArchiveRequest_JSON(t *testing.T) {
	req := ArchiveRequest{ObservationsDir: "observations", OlderThan: "14d", KeepMin: 2, DryRun: true}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ArchiveRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.KeepMin != 2 {
		t.Errorf("KeepMin: got %d", got.KeepMin)
	}
}

func TestQualityRequest_JSON(t *testing.T) {
	req := QualityRequest{ObservationsDir: "observations", MinSnapshots: 2, Strict: true}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got QualityRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.Strict {
		t.Error("Strict: got false, want true")
	}
}

func TestPlanRequest_JSON(t *testing.T) {
	req := PlanRequest{ObservationsRoot: "observations", Apply: true}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got PlanRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.Apply {
		t.Error("Apply: got false, want true")
	}
}

// --- Use case mocks ---

type mockDeltaComputer struct {
	data any
	err  error
}

func (m *mockDeltaComputer) ComputeDelta(_ context.Context, _ string, _, _ []string, _ string) (any, error) {
	return m.data, m.err
}

type mockUpcomingComputer struct {
	data any
	err  error
}

func (m *mockUpcomingComputer) ComputeUpcoming(_ context.Context, _ UpcomingRequest) (any, error) {
	return m.data, m.err
}

type mockArchiver struct {
	resp ArchiveResponse
	err  error
}

func (m *mockArchiver) ArchiveSnapshots(_ context.Context, _ ArchiveRequest) (ArchiveResponse, error) {
	return m.resp, m.err
}

type mockCleaner struct {
	resp CleanupResponse
	err  error
}

func (m *mockCleaner) CleanupSnapshots(_ context.Context, _ CleanupRequest) (CleanupResponse, error) {
	return m.resp, m.err
}

type mockHygieneReporter struct {
	resp HygieneResponse
	err  error
}

func (m *mockHygieneReporter) GenerateHygieneReport(_ context.Context, _ HygieneRequest) (HygieneResponse, error) {
	return m.resp, m.err
}

type mockQualityChecker struct {
	resp QualityResponse
	err  error
}

func (m *mockQualityChecker) CheckQuality(_ context.Context, _ QualityRequest) (QualityResponse, error) {
	return m.resp, m.err
}

type mockRetentionPlanner struct {
	resp PlanResponse
	err  error
}

func (m *mockRetentionPlanner) PlanRetention(_ context.Context, _ PlanRequest) (PlanResponse, error) {
	return m.resp, m.err
}

// --- Diff tests ---

func TestDiff(t *testing.T) {
	deps := DiffDeps{DeltaComputer: &mockDeltaComputer{data: map[string]any{"added": 1}}}
	resp, err := Diff(context.Background(), DiffRequest{ObservationsDir: "obs"}, deps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.DeltaData == nil {
		t.Error("DeltaData: got nil")
	}
}

func TestDiff_Error(t *testing.T) {
	deps := DiffDeps{DeltaComputer: &mockDeltaComputer{err: errors.New("fail")}}
	_, err := Diff(context.Background(), DiffRequest{ObservationsDir: "obs"}, deps)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDiff_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	deps := DiffDeps{DeltaComputer: &mockDeltaComputer{}}
	_, err := Diff(ctx, DiffRequest{ObservationsDir: "obs"}, deps)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

// --- Upcoming tests ---

func TestUpcoming(t *testing.T) {
	deps := UpcomingDeps{Computer: &mockUpcomingComputer{data: map[string]any{"count": 3}}}
	resp, err := Upcoming(context.Background(), UpcomingRequest{ControlsDir: "c", ObservationsDir: "o"}, deps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ItemsData == nil {
		t.Error("ItemsData: got nil")
	}
}

func TestUpcoming_Error(t *testing.T) {
	deps := UpcomingDeps{Computer: &mockUpcomingComputer{err: errors.New("fail")}}
	_, err := Upcoming(context.Background(), UpcomingRequest{ControlsDir: "c", ObservationsDir: "o"}, deps)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestUpcoming_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	deps := UpcomingDeps{Computer: &mockUpcomingComputer{}}
	_, err := Upcoming(ctx, UpcomingRequest{}, deps)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

// --- Archive tests ---

func TestArchive(t *testing.T) {
	tests := []struct {
		name    string
		req     ArchiveRequest
		arch    *mockArchiver
		wantErr bool
	}{
		{name: "happy", req: ArchiveRequest{ObservationsDir: "obs", KeepMin: 2}, arch: &mockArchiver{resp: ArchiveResponse{ArchivedCount: 3}}},
		{name: "empty dir", req: ArchiveRequest{ObservationsDir: ""}, arch: &mockArchiver{}, wantErr: true},
		{name: "negative keep", req: ArchiveRequest{ObservationsDir: "obs", KeepMin: -1}, arch: &mockArchiver{}, wantErr: true},
		{name: "error", req: ArchiveRequest{ObservationsDir: "obs", KeepMin: 2}, arch: &mockArchiver{err: errors.New("fail")}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Archive(context.Background(), tc.req, ArchiveDeps{Archiver: tc.arch})
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// --- Cleanup tests ---

func TestCleanup(t *testing.T) {
	tests := []struct {
		name    string
		req     CleanupRequest
		cl      *mockCleaner
		wantErr bool
	}{
		{name: "happy", req: CleanupRequest{ObservationsDir: "obs", KeepMin: 2}, cl: &mockCleaner{resp: CleanupResponse{DeletedCount: 4}}},
		{name: "empty dir", req: CleanupRequest{ObservationsDir: ""}, cl: &mockCleaner{}, wantErr: true},
		{name: "negative keep", req: CleanupRequest{ObservationsDir: "obs", KeepMin: -1}, cl: &mockCleaner{}, wantErr: true},
		{name: "error", req: CleanupRequest{ObservationsDir: "obs", KeepMin: 2}, cl: &mockCleaner{err: errors.New("fail")}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Cleanup(context.Background(), tc.req, CleanupDeps{Cleaner: tc.cl})
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// --- Hygiene tests ---

func TestHygiene(t *testing.T) {
	tests := []struct {
		name    string
		req     HygieneRequest
		rep     *mockHygieneReporter
		wantErr bool
	}{
		{name: "happy", req: HygieneRequest{ObservationsDir: "obs"}, rep: &mockHygieneReporter{resp: HygieneResponse{ReportData: "ok"}}},
		{name: "empty dir", req: HygieneRequest{ObservationsDir: ""}, rep: &mockHygieneReporter{}, wantErr: true},
		{name: "error", req: HygieneRequest{ObservationsDir: "obs"}, rep: &mockHygieneReporter{err: errors.New("fail")}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Hygiene(context.Background(), tc.req, HygieneDeps{Reporter: tc.rep})
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// --- Quality tests ---

func TestQuality(t *testing.T) {
	tests := []struct {
		name    string
		req     QualityRequest
		chk     *mockQualityChecker
		wantErr bool
	}{
		{name: "happy", req: QualityRequest{ObservationsDir: "obs", MinSnapshots: 2}, chk: &mockQualityChecker{resp: QualityResponse{Passed: true}}},
		{name: "empty dir", req: QualityRequest{ObservationsDir: "", MinSnapshots: 2}, chk: &mockQualityChecker{}, wantErr: true},
		{name: "min < 1", req: QualityRequest{ObservationsDir: "obs", MinSnapshots: 0}, chk: &mockQualityChecker{}, wantErr: true},
		{name: "error", req: QualityRequest{ObservationsDir: "obs", MinSnapshots: 2}, chk: &mockQualityChecker{err: errors.New("fail")}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Quality(context.Background(), tc.req, QualityDeps{Checker: tc.chk})
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// --- Plan tests ---

func TestPlan(t *testing.T) {
	tests := []struct {
		name    string
		req     PlanRequest
		pl      *mockRetentionPlanner
		wantErr bool
	}{
		{name: "happy", req: PlanRequest{ObservationsRoot: "obs"}, pl: &mockRetentionPlanner{resp: PlanResponse{PlanData: "ok"}}},
		{name: "empty root", req: PlanRequest{ObservationsRoot: ""}, pl: &mockRetentionPlanner{}, wantErr: true},
		{name: "error", req: PlanRequest{ObservationsRoot: "obs"}, pl: &mockRetentionPlanner{err: errors.New("fail")}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Plan(context.Background(), tc.req, PlanDeps{Planner: tc.pl})
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// --- Context cancellation tests for remaining functions ---

func TestArchive_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Archive(ctx, ArchiveRequest{ObservationsDir: "obs", KeepMin: 2}, ArchiveDeps{Archiver: &mockArchiver{}})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestCleanup_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Cleanup(ctx, CleanupRequest{ObservationsDir: "obs", KeepMin: 2}, CleanupDeps{Cleaner: &mockCleaner{}})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestHygiene_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Hygiene(ctx, HygieneRequest{ObservationsDir: "obs"}, HygieneDeps{Reporter: &mockHygieneReporter{}})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestQuality_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Quality(ctx, QualityRequest{ObservationsDir: "obs", MinSnapshots: 2}, QualityDeps{Checker: &mockQualityChecker{}})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestPlan_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Plan(ctx, PlanRequest{ObservationsRoot: "obs"}, PlanDeps{Planner: &mockRetentionPlanner{}})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
