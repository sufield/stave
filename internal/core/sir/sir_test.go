package sir

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// fixedTime is the canonical "now" for every test case. Hard-coded
// so a regressed Builder that consults time.Now() trips the
// determinism check immediately rather than passing intermittently.
var fixedTime = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

// fakeGrouper returns a fixed slice of resource fact groups.
// Used to exercise the ResourceGroups path without pulling in
// the platform layer.
type fakeGrouper struct {
	groups []ResourceFactGroup
	err    error
}

func (f *fakeGrouper) GroupResources(_ []asset.Snapshot, _ time.Time) ([]ResourceFactGroup, error) {
	return f.groups, f.err
}

func sampleControl() controldef.ControlDefinition {
	ctl := controldef.ControlDefinition{
		ID:       kernel.ControlID("CTL.S3.PUBLIC.001"),
		Type:     controldef.TypeUnsafeState,
		Severity: controldef.SeverityHigh,
		UnsafePredicate: controldef.UnsafePredicate{
			Any: []controldef.PredicateRule{
				{
					Field: predicate.NewFieldPath("acl"),
					Op:    predicate.Operator("eq"),
					Value: controldef.Str("public-read"),
				},
				{
					Field: predicate.NewFieldPath("policy_status.is_public"),
					Op:    predicate.Operator("eq"),
					Value: controldef.Bool(true),
				},
			},
		},
	}
	return ctl
}

func sampleSnapshot(ts time.Time) asset.Snapshot {
	return asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: ts,
		Assets: []asset.Asset{
			{
				ID:     asset.ID("arn:aws:s3:::bucket-a"),
				Type:   kernel.AssetType("aws_s3_bucket"),
				Vendor: kernel.Vendor("aws"),
				Properties: map[string]any{
					"acl":           "public-read",
					"region":        "us-east-1",
					"versioning":    false,
					"creation_date": "2026-04-15T00:00:00Z",
				},
			},
			{
				ID:     asset.ID("arn:aws:s3:::bucket-b"),
				Type:   kernel.AssetType("aws_s3_bucket"),
				Vendor: kernel.Vendor("aws"),
				Properties: map[string]any{
					"acl":    "private",
					"region": "us-east-1",
				},
			},
		},
		Identities: []asset.CloudIdentity{
			{
				ID:     asset.ID("arn:aws:iam::111122223333:role/AppRole"),
				Type:   kernel.AssetType("aws_iam_role"),
				Vendor: kernel.Vendor("aws"),
			},
		},
	}
}

func TestBuilder_BasicShape(t *testing.T) {
	b := NewBuilder()
	doc, err := b.Build(
		[]controldef.ControlDefinition{sampleControl()},
		[]asset.Snapshot{sampleSnapshot(fixedTime.Add(-time.Hour))},
		fixedTime,
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if got := len(doc.Controls); got != 1 {
		t.Fatalf("Controls: want 1, got %d", got)
	}
	if got := doc.Controls[0].ID; got != "CTL.S3.PUBLIC.001" {
		t.Errorf("Control ID: want CTL.S3.PUBLIC.001, got %q", got)
	}
	if got := doc.Controls[0].Type; got != "unsafe_state" {
		t.Errorf("Control Type: want unsafe_state, got %q", got)
	}
	if got := doc.Controls[0].Predicate.Logic; got != "any" {
		t.Errorf("Predicate Logic: want any, got %q", got)
	}
	if got := len(doc.Controls[0].Predicate.Rules); got != 2 {
		t.Errorf("Rules: want 2, got %d", got)
	}

	if got := len(doc.Assets); got != 2 {
		t.Fatalf("Assets: want 2, got %d", got)
	}
	if doc.Assets[0].ID != "arn:aws:s3:::bucket-a" {
		t.Errorf("Asset[0] not first by ID sort: got %q", doc.Assets[0].ID)
	}

	if got := len(doc.Identities); got != 1 {
		t.Fatalf("Identities: want 1, got %d", got)
	}
	if doc.Identities[0].PrincipalID != "arn:aws:iam::111122223333:role/AppRole" {
		t.Errorf("Identity ID: got %q", doc.Identities[0].PrincipalID)
	}

	if got := len(doc.Temporal.Observations); got != 1 {
		t.Errorf("Observations: want 1, got %d", got)
	}
	if !doc.EvaluatedAt.Equal(fixedTime) {
		t.Errorf("EvaluatedAt: want %v, got %v", fixedTime, doc.EvaluatedAt)
	}
}

func TestBuilder_DeterministicOutput(t *testing.T) {
	// Build twice with identical inputs; require byte-identical
	// JSON. A regressed Builder that consults time.Now() or
	// produces non-stable map ordering trips here.
	controls := []controldef.ControlDefinition{sampleControl()}
	snaps := []asset.Snapshot{
		sampleSnapshot(fixedTime.Add(-3 * time.Hour)),
		sampleSnapshot(fixedTime.Add(-time.Hour)),
	}

	b := NewBuilder()
	first, err := b.Build(controls, snaps, fixedTime)
	if err != nil {
		t.Fatalf("Build #1: %v", err)
	}
	second, err := b.Build(controls, snaps, fixedTime)
	if err != nil {
		t.Fatalf("Build #2: %v", err)
	}

	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal #1: %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal #2: %v", err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("non-deterministic JSON output:\n#1: %s\n#2: %s", firstJSON, secondJSON)
	}
}

func TestBuilder_RoundTripJSON(t *testing.T) {
	b := NewBuilder()
	original, err := b.Build(
		[]controldef.ControlDefinition{sampleControl()},
		[]asset.Snapshot{sampleSnapshot(fixedTime.Add(-time.Hour))},
		fixedTime,
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Document
	if uerr := json.Unmarshal(encoded, &decoded); uerr != nil {
		t.Fatalf("unmarshal: %v", uerr)
	}

	reEncoded, err := json.Marshal(&decoded)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}

	if string(encoded) != string(reEncoded) {
		t.Fatalf("round-trip JSON not stable:\n  first: %s\n  again: %s", encoded, reEncoded)
	}
}

// noiseTokens enumerates substrings that must NEVER appear in SIR
// JSON output. The list is phrased to catch the broad shapes of
// infrastructure noise the SIR contract forbids: file paths,
// git/CI metadata, tool versions, source filenames.
var noiseTokens = []string{
	".go:",     // Go source filename + line marker
	".yaml:",   // YAML source filename + line marker
	"git_",     // git_sha, git_ref, git_branch
	"commit_",  // commit_hash, commit_id
	"_version", // tool_version, schema_version (snapshot-side, not SIR)
	"go.mod",
	"/home/",       // absolute home paths
	"/usr/",        // absolute system paths
	"file:///",     // file URIs
	"runtime.now",  // accidental Now() identifier in any tag
	"build_number", // CI metadata
}

func TestBuilder_NoInfrastructureNoise(t *testing.T) {
	// Add a generated_by section that DOES contain tool versions on
	// the snapshot — the SIR must strip these on translation; if
	// any leak through, this test fires.
	snap := sampleSnapshot(fixedTime.Add(-time.Hour))
	snap.GeneratedBy = &asset.GeneratedBy{
		SourceType:   kernel.ObservationSourceType("aws"),
		Tool:         "stave-collector",
		StaveVersion: "v0.99.0-test",
		Provider:     "aws",
	}

	b := NewBuilder()
	doc, err := b.Build(
		[]controldef.ControlDefinition{sampleControl()},
		[]asset.Snapshot{snap},
		fixedTime,
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(encoded)
	for _, tok := range noiseTokens {
		if strings.Contains(body, tok) {
			t.Errorf("SIR JSON contains forbidden infrastructure-noise token %q\nbody: %s", tok, body)
		}
	}
	// Direct check: the snapshot's tool name must not have leaked.
	if strings.Contains(body, "stave-collector") {
		t.Errorf("SIR leaked tool name from snapshot.GeneratedBy: %s", body)
	}
	if strings.Contains(body, "v0.99.0-test") {
		t.Errorf("SIR leaked tool version from snapshot.GeneratedBy: %s", body)
	}
}

func TestBuilder_EveryFactHasNonEmptySource(t *testing.T) {
	b := NewBuilder()
	doc, err := b.Build(
		[]controldef.ControlDefinition{sampleControl()},
		[]asset.Snapshot{sampleSnapshot(fixedTime.Add(-time.Hour))},
		fixedTime,
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	for i := range doc.Controls {
		if doc.Controls[i].Source.IsEmpty() {
			t.Errorf("Controls[%d] empty SourceRef", i)
		}
		assertRulesHaveSource(t, doc.Controls[i].Predicate.Rules, "Controls["+doc.Controls[i].ID+"]")
	}
	for i := range doc.Assets {
		if doc.Assets[i].Source.IsEmpty() {
			t.Errorf("Assets[%d] empty SourceRef", i)
		}
	}
	for i := range doc.Identities {
		if doc.Identities[i].Source.IsEmpty() {
			t.Errorf("Identities[%d] empty SourceRef", i)
		}
	}
}

func assertRulesHaveSource(t *testing.T, rules []RuleFact, prefix string) {
	t.Helper()
	for i := range rules {
		if rules[i].Source.IsEmpty() {
			t.Errorf("%s rule[%d] empty SourceRef", prefix, i)
		}
		if rules[i].Nested != nil {
			assertRulesHaveSource(t, rules[i].Nested.Rules, prefix)
		}
	}
}

func TestBuilder_ResourceGroupsFlowThrough(t *testing.T) {
	// Iter L0: groupers replace the retired
	// PermissionAggregator. Each grouper emits raw
	// ResourceFactGroup rows; the builder concatenates and sorts.
	g := &fakeGrouper{
		groups: []ResourceFactGroup{
			{
				AssetID:     "arn:aws:s3:::bucket-b",
				Vendor:      "aws",
				ServiceArea: "s3",
				Source:      SourceRef{Kind: "asset", ID: "arn:aws:s3:::bucket-b"},
			},
			{
				AssetID:     "arn:aws:s3:::bucket-a",
				Vendor:      "aws",
				ServiceArea: "s3",
				Source:      SourceRef{Kind: "asset", ID: "arn:aws:s3:::bucket-a"},
			},
		},
	}

	b := NewBuilder(WithResourceFactGrouper(g))
	doc, err := b.Build(
		[]controldef.ControlDefinition{sampleControl()},
		[]asset.Snapshot{sampleSnapshot(fixedTime.Add(-time.Hour))},
		fixedTime,
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if got := len(doc.ResourceGroups); got != 2 {
		t.Fatalf("ResourceGroups: want 2, got %d", got)
	}
	// Sort key is (Vendor, ServiceArea, AssetID). bucket-a < bucket-b
	if doc.ResourceGroups[0].AssetID != "arn:aws:s3:::bucket-a" {
		t.Errorf("Groups[0]: want bucket-a (sorted), got %q", doc.ResourceGroups[0].AssetID)
	}
	for i, group := range doc.ResourceGroups {
		if group.Source.IsEmpty() {
			t.Errorf("Groups[%d] empty SourceRef", i)
		}
	}
}

func TestBuilder_GrouperErrorPropagates(t *testing.T) {
	g := &fakeGrouper{err: errSentinel}
	b := NewBuilder(WithResourceFactGrouper(g))
	_, err := b.Build(nil, nil, fixedTime)
	if err == nil {
		t.Fatalf("Build: want error, got nil")
	}
	if !strings.Contains(err.Error(), "grouper 0") {
		t.Errorf("Build error: want grouper-index prefix, got %q", err.Error())
	}
}

func TestBuilder_EmptyInputs(t *testing.T) {
	b := NewBuilder()
	doc, err := b.Build(nil, nil, fixedTime)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if doc == nil {
		t.Fatalf("Build returned nil Document")
	}
	if !doc.EvaluatedAt.Equal(fixedTime) {
		t.Errorf("EvaluatedAt: want %v, got %v", fixedTime, doc.EvaluatedAt)
	}
	if doc.Controls != nil || doc.Assets != nil || doc.Identities != nil {
		t.Errorf("empty inputs should produce nil-typed slices, got: %+v", doc)
	}
}

func TestBuilder_IntentRationaleAndForbiddenStateSurface(t *testing.T) {
	// Iter 5.1: control declares an intent rationale and an
	// invariant predicate (forbidden_state). Both must flow into
	// the SIR's ControlFact so an external solver / AI agent
	// reads them alongside the unsafe predicate.
	ctl := controldef.ControlDefinition{
		ID:              kernel.ControlID("CTL.TEST.INVARIANT.001"),
		Type:            controldef.TypeUnsafeState,
		Severity:        controldef.SeverityHigh,
		IntentRationale: "Public buckets violate data-residency invariants",
		UnsafePredicate: controldef.UnsafePredicate{
			Any: []controldef.PredicateRule{
				{Field: predicate.NewFieldPath("properties.public"), Op: predicate.Operator("eq"), Value: controldef.Bool(true)},
			},
		},
		ForbiddenState: controldef.UnsafePredicate{
			All: []controldef.PredicateRule{
				{Field: predicate.NewFieldPath("properties.principal"), Op: predicate.Operator("eq"), Value: controldef.Str("*")},
				{Field: predicate.NewFieldPath("properties.network"), Op: predicate.Operator("eq"), Value: controldef.Str("public")},
			},
		},
	}

	b := NewBuilder()
	doc, err := b.Build([]controldef.ControlDefinition{ctl}, nil, fixedTime)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(doc.Controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(doc.Controls))
	}
	got := doc.Controls[0]
	if got.IntentRationale != "Public buckets violate data-residency invariants" {
		t.Errorf("IntentRationale: got %q", got.IntentRationale)
	}
	if got.ForbiddenState == nil {
		t.Fatalf("ForbiddenState: want non-nil")
	}
	if got.ForbiddenState.Logic != "all" {
		t.Errorf("ForbiddenState.Logic: want all, got %q", got.ForbiddenState.Logic)
	}
	if len(got.ForbiddenState.Rules) != 2 {
		t.Errorf("ForbiddenState.Rules: want 2, got %d", len(got.ForbiddenState.Rules))
	}
	// Each forbidden-state rule must source-ref the forbidden_state
	// path so a trace can distinguish it from unsafe_predicate.
	for i, r := range got.ForbiddenState.Rules {
		if len(r.Source.Path) == 0 || r.Source.Path[0] != "forbidden_state" {
			t.Errorf("ForbiddenState.Rules[%d].Source.Path[0]: want forbidden_state, got %v", i, r.Source.Path)
		}
	}
}

func TestBuilder_IntentRationaleAbsent_SerializesAsAbsent(t *testing.T) {
	// When the rationale is empty and the invariant is empty, the
	// JSON must omit both fields rather than emitting empty
	// strings / nulls — the SIR contract says optional fields are
	// absent, not zero.
	ctl := controldef.ControlDefinition{
		ID:       kernel.ControlID("CTL.TEST.NOINTENT.001"),
		Type:     controldef.TypeUnsafeState,
		Severity: controldef.SeverityLow,
		UnsafePredicate: controldef.UnsafePredicate{
			Any: []controldef.PredicateRule{
				{Field: predicate.NewFieldPath("x"), Op: predicate.Operator("eq"), Value: controldef.Bool(true)},
			},
		},
	}

	b := NewBuilder()
	doc, err := b.Build([]controldef.ControlDefinition{ctl}, nil, fixedTime)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	encoded, err := json.Marshal(doc.Controls[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(encoded)
	if strings.Contains(body, "intent_rationale") {
		t.Errorf("empty rationale must not serialize: %s", body)
	}
	if strings.Contains(body, "forbidden_state") {
		t.Errorf("empty forbidden_state must not serialize: %s", body)
	}
}

func TestPredicateFact_BothAnyAndAll(t *testing.T) {
	// A pathological control with both Any and All populated.
	// Builder must wrap them in a synthetic outer "all".
	ctl := controldef.ControlDefinition{
		ID:       kernel.ControlID("CTL.MIXED.001"),
		Type:     controldef.TypeUnsafeState,
		Severity: controldef.SeverityMedium,
		UnsafePredicate: controldef.UnsafePredicate{
			Any: []controldef.PredicateRule{
				{Field: predicate.NewFieldPath("a"), Op: predicate.Operator("eq"), Value: controldef.Str("x")},
			},
			All: []controldef.PredicateRule{
				{Field: predicate.NewFieldPath("b"), Op: predicate.Operator("eq"), Value: controldef.Str("y")},
			},
		},
	}
	b := NewBuilder()
	doc, err := b.Build([]controldef.ControlDefinition{ctl}, nil, fixedTime)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got := doc.Controls[0].Predicate
	if got.Logic != "all" {
		t.Fatalf("outer Logic: want all, got %q", got.Logic)
	}
	if len(got.Rules) != 2 {
		t.Fatalf("outer Rules: want 2, got %d", len(got.Rules))
	}
	if got.Rules[0].Nested == nil || got.Rules[0].Nested.Logic != "any" {
		t.Errorf("Rules[0].Nested: want any-logic nested, got %+v", got.Rules[0])
	}
	if got.Rules[1].Nested == nil || got.Rules[1].Nested.Logic != "all" {
		t.Errorf("Rules[1].Nested: want all-logic nested, got %+v", got.Rules[1])
	}
}

// errSentinel is a fixed error returned by the failing aggregator
// fake. Defined as a package-level value so the equality check
// inside TestBuilder_AggregatorErrorPropagates is unambiguous.
var errSentinel = sentinelError("aggregator failed")

type sentinelError string

func (e sentinelError) Error() string { return string(e) }

// ---------- Iteration 1.3 hydration tests ----------

// fakeRoleChainSource returns a fixed map of chains for unit
// testing the role-chain hydration path without pulling in the
// AWS adapter.
type fakeRoleChainSource struct {
	chains map[asset.ID][]RoleChainFact
	err    error
}

func (f *fakeRoleChainSource) RoleChains(_ []asset.Snapshot) (map[asset.ID][]RoleChainFact, error) {
	return f.chains, f.err
}

// fakeLifecycleSource returns a hand-built lifecycle map. Used by
// hydration tests to feed deterministic exposure windows without
// invoking the engine's CEL pipeline.
type fakeLifecycleSource struct {
	source map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle
	err    error
}

func (f *fakeLifecycleSource) Lifecycles(_ []controldef.ControlDefinition, _ []asset.Snapshot) (map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle, error) {
	return f.source, f.err
}

func TestBuilder_FirstSeenLastSeenAcrossSnapshots(t *testing.T) {
	// Asset bucket-a appears in both snapshots; bucket-b only in the
	// later one. FirstSeen/LastSeen must reflect the actual
	// observation grid, not just the latest snapshot.
	earlier := fixedTime.Add(-3 * time.Hour)
	later := fixedTime.Add(-time.Hour)

	snap1 := asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: earlier,
		Assets: []asset.Asset{
			{ID: asset.ID("arn:aws:s3:::bucket-a"), Type: kernel.AssetType("aws_s3_bucket"), Vendor: kernel.Vendor("aws")},
		},
	}
	snap2 := asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: later,
		Assets: []asset.Asset{
			{ID: asset.ID("arn:aws:s3:::bucket-a"), Type: kernel.AssetType("aws_s3_bucket"), Vendor: kernel.Vendor("aws")},
			{ID: asset.ID("arn:aws:s3:::bucket-b"), Type: kernel.AssetType("aws_s3_bucket"), Vendor: kernel.Vendor("aws")},
		},
	}

	b := NewBuilder()
	doc, err := b.Build(nil, []asset.Snapshot{snap1, snap2}, fixedTime)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	byID := map[string]AssetFact{}
	for i := range doc.Assets {
		byID[doc.Assets[i].ID] = doc.Assets[i]
	}

	bucketA := byID["arn:aws:s3:::bucket-a"]
	if bucketA.Lifecycle == nil {
		t.Fatalf("bucket-a missing Lifecycle")
	}
	if !bucketA.Lifecycle.FirstSeen.Equal(earlier) {
		t.Errorf("bucket-a FirstSeen: want %v, got %v", earlier, bucketA.Lifecycle.FirstSeen)
	}
	if !bucketA.Lifecycle.LastSeen.Equal(later) {
		t.Errorf("bucket-a LastSeen: want %v, got %v", later, bucketA.Lifecycle.LastSeen)
	}

	bucketB := byID["arn:aws:s3:::bucket-b"]
	if bucketB.Lifecycle == nil {
		t.Fatalf("bucket-b missing Lifecycle")
	}
	// bucket-b only appears in snap2; FirstSeen and LastSeen both = later.
	if !bucketB.Lifecycle.FirstSeen.Equal(later) {
		t.Errorf("bucket-b FirstSeen: want %v, got %v", later, bucketB.Lifecycle.FirstSeen)
	}
	if !bucketB.Lifecycle.LastSeen.Equal(later) {
		t.Errorf("bucket-b LastSeen: want %v, got %v", later, bucketB.Lifecycle.LastSeen)
	}
	// bucket-b appeared between snapshots → drift PROVISIONED.
	if !bucketB.Lifecycle.Provisioned {
		t.Errorf("bucket-b expected Provisioned=true (appeared in latest snapshot pair)")
	}
}

func TestBuilder_DriftDecommissionedSurfaces(t *testing.T) {
	earlier := fixedTime.Add(-2 * time.Hour)
	later := fixedTime.Add(-time.Hour)

	snap1 := asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: earlier,
		Assets: []asset.Asset{
			{ID: asset.ID("arn:aws:s3:::bucket-x"), Type: kernel.AssetType("aws_s3_bucket"), Vendor: kernel.Vendor("aws")},
		},
	}
	snap2 := asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: later,
		Assets:     []asset.Asset{},
	}

	b := NewBuilder()
	doc, err := b.Build(nil, []asset.Snapshot{snap1, snap2}, fixedTime)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(doc.Assets) != 1 {
		t.Fatalf("expected 1 asset (decommissioned still recorded), got %d", len(doc.Assets))
	}
	lc := doc.Assets[0].Lifecycle
	if lc == nil {
		t.Fatalf("expected Lifecycle on decommissioned asset")
	}
	if !lc.Decommissioned {
		t.Errorf("expected Decommissioned=true, got %+v", lc)
	}
	if lc.Provisioned {
		t.Errorf("Decommissioned and Provisioned must not both be true: %+v", lc)
	}
}

func TestBuilder_RoleChainHydration(t *testing.T) {
	src := &fakeRoleChainSource{
		chains: map[asset.ID][]RoleChainFact{
			"arn:aws:iam::111122223333:role/AppRole": {
				{
					Hops: []RoleHopFact{
						{From: "arn:aws:iam::111122223333:role/AppRole", To: "arn:aws:iam::111122223333:role/Mid", CrossAccount: false},
						{From: "arn:aws:iam::111122223333:role/Mid", To: "arn:aws:iam::444455556666:role/Admin", CrossAccount: true},
					},
					FinalRoleARN:      "arn:aws:iam::444455556666:role/Admin",
					TransitiveLevel:   "admin",
					TerminationReason: "normal",
				},
				{
					Hops: []RoleHopFact{
						{From: "arn:aws:iam::111122223333:role/AppRole", To: "arn:aws:iam::111122223333:role/Other", CrossAccount: false},
					},
					FinalRoleARN:      "arn:aws:iam::111122223333:role/Other",
					TransitiveLevel:   "elevated",
					TerminationReason: "normal",
				},
			},
		},
	}
	b := NewBuilder(WithRoleChainSource(src))
	doc, err := b.Build(
		[]controldef.ControlDefinition{sampleControl()},
		[]asset.Snapshot{sampleSnapshot(fixedTime.Add(-time.Hour))},
		fixedTime,
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if len(doc.Identities) != 1 {
		t.Fatalf("Identities: want 1, got %d", len(doc.Identities))
	}
	id := doc.Identities[0]
	if len(id.RoleChains) != 2 {
		t.Fatalf("RoleChains: want 2, got %d", len(id.RoleChains))
	}
	// Sorted by FinalRoleARN: Admin (444... account) sorts before Other (111... account)
	// only if Admin's full ARN string < Other's full ARN string.
	// "arn:aws:iam::111122223333:role/Other" < "arn:aws:iam::444455556666:role/Admin" lexically,
	// so Other comes first.
	if id.RoleChains[0].FinalRoleARN != "arn:aws:iam::111122223333:role/Other" {
		t.Errorf("RoleChain sort: want Other first, got %q", id.RoleChains[0].FinalRoleARN)
	}
	// Verify cross-account boundary surfaces.
	cross := id.RoleChains[1]
	if cross.FinalRoleARN != "arn:aws:iam::444455556666:role/Admin" {
		t.Errorf("RoleChain[1] FinalRoleARN: got %q", cross.FinalRoleARN)
	}
	if len(cross.Hops) != 2 {
		t.Fatalf("RoleChain[1] Hops: want 2, got %d", len(cross.Hops))
	}
	if !cross.Hops[1].CrossAccount {
		t.Errorf("RoleChain[1] Hops[1] should be CrossAccount=true")
	}
	if cross.Hops[0].CrossAccount {
		t.Errorf("RoleChain[1] Hops[0] is intra-account; CrossAccount should be false")
	}
}

func TestBuilder_RoleChainSourceErrorPropagates(t *testing.T) {
	src := &fakeRoleChainSource{err: errSentinel}
	b := NewBuilder(WithRoleChainSource(src))
	_, err := b.Build(nil, []asset.Snapshot{sampleSnapshot(fixedTime.Add(-time.Hour))}, fixedTime)
	if err == nil {
		t.Fatalf("Build: want error, got nil")
	}
	if !strings.Contains(err.Error(), "role chains") {
		t.Errorf("expected error to wrap with 'role chains', got %q", err.Error())
	}
}

func TestBuilder_LifecycleHydratesTemporalWindows(t *testing.T) {
	// Build a lifecycle with one resolved exposure window (open at
	// t-3h, resolved at t-2h) plus an active window opened at t-1h.
	a := asset.Asset{
		ID:     asset.ID("arn:aws:s3:::bucket-a"),
		Type:   kernel.AssetType("aws_s3_bucket"),
		Vendor: kernel.Vendor("aws"),
	}
	lc, err := asset.NewExposureLifecycle(a)
	if err != nil {
		t.Fatalf("NewExposureLifecycle: %v", err)
	}
	t0 := fixedTime.Add(-3 * time.Hour)
	t1 := fixedTime.Add(-2 * time.Hour)
	t2 := fixedTime.Add(-time.Hour)

	if rerr := lc.RecordCheck(t0, true); rerr != nil {
		t.Fatalf("RecordCheck(t0, exposed): %v", rerr)
	}
	if rerr := lc.RecordCheck(t1, false); rerr != nil {
		t.Fatalf("RecordCheck(t1, secure): %v", rerr)
	}
	if rerr := lc.RecordCheck(t2, true); rerr != nil {
		t.Fatalf("RecordCheck(t2, exposed): %v", rerr)
	}

	src := &fakeLifecycleSource{
		source: map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle{
			kernel.ControlID("CTL.S3.PUBLIC.001"): {
				a.ID: lc,
			},
		},
	}
	b := NewBuilder(WithLifecycleSource(src))
	doc, err := b.Build(
		[]controldef.ControlDefinition{sampleControl()},
		[]asset.Snapshot{sampleSnapshot(fixedTime.Add(-time.Hour))},
		fixedTime,
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	windows := doc.Temporal.Windows
	if len(windows) != 2 {
		t.Fatalf("Windows: want 2 (1 archived + 1 active), got %d", len(windows))
	}
	// Sorted by Start ascending.
	if !windows[0].Start.Equal(t0) {
		t.Errorf("Windows[0].Start: want %v, got %v", t0, windows[0].Start)
	}
	if !windows[0].End.Equal(t1) {
		t.Errorf("Windows[0].End: want %v, got %v", t1, windows[0].End)
	}
	if !windows[0].UnsafePredicateMatched {
		t.Errorf("Windows[0].UnsafePredicateMatched: want true")
	}
	if len(windows[0].ContributingControls) != 1 || windows[0].ContributingControls[0] != "CTL.S3.PUBLIC.001" {
		t.Errorf("Windows[0].ContributingControls: want [CTL.S3.PUBLIC.001], got %v", windows[0].ContributingControls)
	}

	if !windows[1].Start.Equal(t2) {
		t.Errorf("Windows[1].Start (active): want %v, got %v", t2, windows[1].Start)
	}
	if !windows[1].End.Equal(fixedTime) {
		t.Errorf("Windows[1].End (active terminates at now): want %v, got %v", fixedTime, windows[1].End)
	}
}

func TestBuilder_LifecycleSourceErrorPropagates(t *testing.T) {
	src := &fakeLifecycleSource{err: errSentinel}
	b := NewBuilder(WithLifecycleSource(src))
	_, err := b.Build(nil, []asset.Snapshot{sampleSnapshot(fixedTime.Add(-time.Hour))}, fixedTime)
	if err == nil {
		t.Fatalf("Build: want error, got nil")
	}
	if !strings.Contains(err.Error(), "lifecycles") {
		t.Errorf("expected error to wrap with 'lifecycles', got %q", err.Error())
	}
}

func TestBuilder_HydratedDocumentRoundTripsJSON(t *testing.T) {
	// Hydration must not break round-trip stability.
	chainSrc := &fakeRoleChainSource{
		chains: map[asset.ID][]RoleChainFact{
			"arn:aws:iam::111122223333:role/AppRole": {
				{
					Hops:              []RoleHopFact{{From: "arn:aws:iam::111122223333:role/AppRole", To: "arn:aws:iam::111122223333:role/Mid"}},
					FinalRoleARN:      "arn:aws:iam::111122223333:role/Mid",
					TransitiveLevel:   "elevated",
					TerminationReason: "normal",
				},
			},
		},
	}
	a := asset.Asset{ID: asset.ID("arn:aws:s3:::bucket-a"), Type: kernel.AssetType("aws_s3_bucket"), Vendor: kernel.Vendor("aws")}
	lc, _ := asset.NewExposureLifecycle(a)
	_ = lc.RecordCheck(fixedTime.Add(-2*time.Hour), true)
	_ = lc.RecordCheck(fixedTime.Add(-time.Hour), false)
	lcSrc := &fakeLifecycleSource{
		source: map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle{
			kernel.ControlID("CTL.S3.PUBLIC.001"): {a.ID: lc},
		},
	}

	b := NewBuilder(WithRoleChainSource(chainSrc), WithLifecycleSource(lcSrc))
	doc, err := b.Build(
		[]controldef.ControlDefinition{sampleControl()},
		[]asset.Snapshot{sampleSnapshot(fixedTime.Add(-time.Hour))},
		fixedTime,
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded Document
	if uerr := json.Unmarshal(encoded, &decoded); uerr != nil {
		t.Fatalf("unmarshal: %v", uerr)
	}
	reEncoded, err := json.Marshal(&decoded)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if string(encoded) != string(reEncoded) {
		t.Fatalf("round-trip not stable:\n  first: %s\n  again: %s", encoded, reEncoded)
	}
}

// fakeCoverageSource returns a hand-built coverage report. Used to
// exercise the WithCoverageSource path without standing up the
// engine-backed adapter.
type fakeCoverageSource struct {
	report CoverageReport
	err    error
}

func (f *fakeCoverageSource) Coverage(_ []asset.Snapshot, _ map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle) (CoverageReport, error) {
	return f.report, f.err
}

func TestBuilder_CoverageSource_DefaultIsZeroPolicyNoGaps(t *testing.T) {
	// Without WithCoverageSource, Temporal.Coverage is the
	// zero-value policy and Gaps is nil/empty. Existing fixtures
	// must not see surprise rows.
	b := NewBuilder()
	doc, err := b.Build(nil, []asset.Snapshot{sampleSnapshot(fixedTime.Add(-time.Hour))}, fixedTime)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if doc.Temporal.Coverage.MaxAllowedGap != 0 || doc.Temporal.Coverage.MinRequiredSpan != 0 {
		t.Errorf("default Coverage policy should be zero, got %+v", doc.Temporal.Coverage)
	}
	if len(doc.Temporal.Gaps) != 0 {
		t.Errorf("default Gaps should be empty, got %d rows", len(doc.Temporal.Gaps))
	}
}

func TestBuilder_CoverageSource_PopulatesPolicyAndGaps(t *testing.T) {
	gap := CoverageGap{
		AssetID: "arn:aws:s3:::bucket-a",
		Start:   fixedTime.Add(-24 * time.Hour),
		End:     fixedTime.Add(-1 * time.Hour),
		Reason:  "maximum observation gap 23h0m0s exceeds threshold 12h0m0s",
	}
	src := &fakeCoverageSource{
		report: CoverageReport{
			Policy: CoveragePolicy{
				MinRequiredSpan: 12 * time.Hour,
				MaxAllowedGap:   12 * time.Hour,
			},
			Gaps: []CoverageGap{gap},
		},
	}
	b := NewBuilder(WithCoverageSource(src))
	doc, err := b.Build(nil, []asset.Snapshot{sampleSnapshot(fixedTime.Add(-time.Hour))}, fixedTime)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if doc.Temporal.Coverage.MaxAllowedGap != 12*time.Hour {
		t.Errorf("Coverage.MaxAllowedGap: want 12h, got %s", doc.Temporal.Coverage.MaxAllowedGap)
	}
	if doc.Temporal.Coverage.MinRequiredSpan != 12*time.Hour {
		t.Errorf("Coverage.MinRequiredSpan: want 12h, got %s", doc.Temporal.Coverage.MinRequiredSpan)
	}
	if len(doc.Temporal.Gaps) != 1 {
		t.Fatalf("Gaps: want 1, got %d", len(doc.Temporal.Gaps))
	}
	if doc.Temporal.Gaps[0] != gap {
		t.Errorf("Gap row:\n  want %+v\n  got  %+v", gap, doc.Temporal.Gaps[0])
	}
}

func TestBuilder_CoverageSource_SortsGapsDeterministically(t *testing.T) {
	// A source that returns rows in an arbitrary order must be
	// projected into a deterministic (AssetID, Start) order. Two
	// builds of the same input must emit byte-identical Gaps.
	now := fixedTime
	g1 := CoverageGap{AssetID: "arn:aws:s3:::bucket-b", Start: now.Add(-3 * time.Hour), End: now, Reason: "gap"}
	g2 := CoverageGap{AssetID: "arn:aws:s3:::bucket-a", Start: now.Add(-4 * time.Hour), End: now, Reason: "gap"}
	g3 := CoverageGap{AssetID: "arn:aws:s3:::bucket-a", Start: now.Add(-2 * time.Hour), End: now, Reason: "gap"}
	src := &fakeCoverageSource{
		report: CoverageReport{
			Policy: CoveragePolicy{MaxAllowedGap: time.Hour},
			Gaps:   []CoverageGap{g1, g2, g3},
		},
	}
	b := NewBuilder(WithCoverageSource(src))
	doc, err := b.Build(nil, []asset.Snapshot{sampleSnapshot(now.Add(-time.Hour))}, now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := []CoverageGap{g2, g3, g1} // (a, -4h), (a, -2h), (b, -3h)
	if len(doc.Temporal.Gaps) != len(want) {
		t.Fatalf("Gaps len: want %d got %d", len(want), len(doc.Temporal.Gaps))
	}
	for i := range want {
		if doc.Temporal.Gaps[i] != want[i] {
			t.Errorf("Gap[%d]:\n  want %+v\n  got  %+v", i, want[i], doc.Temporal.Gaps[i])
		}
	}
}

func TestBuilder_CoverageSourceErrorPropagates(t *testing.T) {
	src := &fakeCoverageSource{err: errSentinel}
	b := NewBuilder(WithCoverageSource(src))
	_, err := b.Build(nil, []asset.Snapshot{sampleSnapshot(fixedTime.Add(-time.Hour))}, fixedTime)
	if err == nil {
		t.Fatalf("Build: want error, got nil")
	}
	if !strings.Contains(err.Error(), "coverage") {
		t.Errorf("expected error to wrap with 'coverage', got %q", err.Error())
	}
}
