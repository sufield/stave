package exposure

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func newTracker(entries map[EvidenceCategory][]string) *EvidenceTracker {
	t := NewEvidenceTracker()
	for cat, path := range entries {
		t.Record(cat, path)
	}
	return t
}

var policyEvidence = []string{"bucket.policy.statements[0].effect", "bucket.policy.statements[0].principal", "bucket.policy.statements[0].actions"}
var aclEvidence = []string{"bucket.acl.grants[0].grantee", "bucket.acl.grants[0].permission", "bucket.acl.grants[0].scope"}

func TestClassifyExposure_PublicRead(t *testing.T) {
	resources := []NormalizedResourceInput{{
		Name:          "test-bucket",
		Exists:        true,
		IdentityPerms: PermRead,
		Evidence:      newTracker(map[EvidenceCategory][]string{EvIdentityRead: policyEvidence}),
	}}

	findings := ClassifyExposure(resources)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != idPublicRead {
		t.Errorf("expected ID %s, got %s", idPublicRead, f.ID)
	}
	if f.ExposureType != TypePublicRead {
		t.Errorf("expected exposure_type %s, got %s", TypePublicRead, f.ExposureType)
	}
	if f.PrincipalScope != kernel.ScopePublic {
		t.Errorf("expected scope public, got %s", f.PrincipalScope)
	}
}

func TestClassifyExposure_ResourcePublicRead(t *testing.T) {
	resources := []NormalizedResourceInput{{
		Name:          "acl-bucket",
		Exists:        true,
		ResourcePerms: PermRead,
		Evidence:      newTracker(map[EvidenceCategory][]string{EvResourceRead: aclEvidence}),
	}}

	findings := ClassifyExposure(resources)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != idResourcePublicRead {
		t.Errorf("expected ID %s, got %s", idResourcePublicRead, findings[0].ID)
	}
}

func TestClassifyExposure_Takeover(t *testing.T) {
	resources := []NormalizedResourceInput{{
		Name:              "missing-ref",
		Exists:            false,
		ExternalReference: true,
	}}

	findings := ClassifyExposure(resources)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != idResourceTakeover {
		t.Errorf("expected takeover, got %s", findings[0].ID)
	}
	if findings[0].PrincipalScope != kernel.ScopeNotApplicable {
		t.Errorf("expected scope n/a, got %s", findings[0].PrincipalScope)
	}
}

func TestClassifyExposure_List(t *testing.T) {
	resources := []NormalizedResourceInput{{
		Name:          "list-bucket",
		Exists:        true,
		ResourcePerms: PermList,
		Evidence:      newTracker(map[EvidenceCategory][]string{EvDiscovery: aclEvidence}),
	}}

	findings := ClassifyExposure(resources)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != idPublicList {
		t.Errorf("expected list, got %s", findings[0].ID)
	}
	if findings[0].Actions[0] != ActionList {
		t.Errorf("expected action %s, got %s", ActionList, findings[0].Actions[0])
	}
}

func TestClassifyExposure_Write(t *testing.T) {
	resources := []NormalizedResourceInput{{
		Name:          "write-bucket",
		Exists:        true,
		IdentityPerms: PermWrite,
		Evidence:      newTracker(map[EvidenceCategory][]string{EvIdentityWrite: policyEvidence}),
	}}

	findings := ClassifyExposure(resources)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != idPublicWrite {
		t.Errorf("expected write, got %s", findings[0].ID)
	}
	if findings[0].WriteScope != WriteScopeBlind {
		t.Errorf("expected blind write, got %q", findings[0].WriteScope)
	}
}

func TestClassifyExposure_FullWrite(t *testing.T) {
	resources := []NormalizedResourceInput{{
		Name:              "full-write-bucket",
		Exists:            true,
		IdentityPerms:     PermWrite | PermRead,
		WriteSourceHasGet: true,
		Evidence: newTracker(map[EvidenceCategory][]string{
			EvIdentityWrite: policyEvidence,
			EvIdentityRead:  policyEvidence,
		}),
	}}

	findings := ClassifyExposure(resources)

	// Write absorbs read, so only write finding
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].WriteScope != WriteScopeFull {
		t.Errorf("expected full write, got %q", findings[0].WriteScope)
	}
}

func TestClassifyExposure_Delete(t *testing.T) {
	resources := []NormalizedResourceInput{{
		Name:          "delete-bucket",
		Exists:        true,
		IdentityPerms: PermDelete,
		Evidence:      newTracker(map[EvidenceCategory][]string{EvDelete: policyEvidence}),
	}}

	findings := ClassifyExposure(resources)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != idPublicDelete {
		t.Errorf("expected delete, got %s", findings[0].ID)
	}
	if findings[0].Actions[0] != ActionDelete {
		t.Errorf("expected action %s, got %s", ActionDelete, findings[0].Actions[0])
	}
}

func TestClassifyExposure_MetadataRead(t *testing.T) {
	resources := []NormalizedResourceInput{{
		Name:          "admin-bucket",
		Exists:        true,
		IdentityPerms: PermMetadataRead,
		Evidence:      newTracker(map[EvidenceCategory][]string{EvResourceAdminRead: policyEvidence}),
	}}

	findings := ClassifyExposure(resources)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != idPublicAdminRead {
		t.Errorf("expected admin read, got %s", findings[0].ID)
	}
	if findings[0].ExposureType != TypePublicMetaRead {
		t.Errorf("expected public_metadata_read, got %s", findings[0].ExposureType)
	}
}

func TestClassifyExposure_MetadataWrite(t *testing.T) {
	resources := []NormalizedResourceInput{{
		Name:          "admin-write-bucket",
		Exists:        true,
		IdentityPerms: PermMetadataWrite,
		Evidence:      newTracker(map[EvidenceCategory][]string{EvResourceAdminRead: policyEvidence}),
	}}

	findings := ClassifyExposure(resources)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != idPublicAdminWrite {
		t.Errorf("expected admin write, got %s", findings[0].ID)
	}
	if findings[0].ExposureType != TypePublicMetaWrite {
		t.Errorf("expected public_metadata_write, got %s", findings[0].ExposureType)
	}
}

func TestClassifyExposure_WebsitePublic(t *testing.T) {
	resources := []NormalizedResourceInput{{
		Name:           "website-bucket",
		Exists:         true,
		WebsiteEnabled: true,
		ResourcePerms:  PermRead,
		Evidence:       newTracker(map[EvidenceCategory][]string{EvResourceRead: aclEvidence}),
	}}

	findings := ClassifyExposure(resources)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != idWebPublic {
		t.Errorf("expected web public, got %s", findings[0].ID)
	}
}

func TestClassifyExposure_AuthenticatedOnly(t *testing.T) {
	resources := []NormalizedResourceInput{{
		Name:                "auth-bucket",
		Exists:              true,
		IsAuthenticatedOnly: true,
		IdentityPerms:       PermRead,
		Evidence:            newTracker(map[EvidenceCategory][]string{EvIdentityRead: policyEvidence}),
	}}

	findings := ClassifyExposure(resources)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != idAuthenticatedRead {
		t.Errorf("expected authenticated read, got %s", findings[0].ID)
	}
	if findings[0].PrincipalScope != kernel.ScopeAuthenticated {
		t.Errorf("expected scope authenticated, got %s", findings[0].PrincipalScope)
	}
}

func TestClassifyExposure_SortsByResourceThenID(t *testing.T) {
	resources := []NormalizedResourceInput{
		{Name: "z-bucket", Exists: true, IdentityPerms: PermRead,
			Evidence: newTracker(map[EvidenceCategory][]string{EvIdentityRead: policyEvidence})},
		{Name: "a-bucket", Exists: true, IdentityPerms: PermRead,
			Evidence: newTracker(map[EvidenceCategory][]string{EvIdentityRead: policyEvidence})},
	}

	findings := ClassifyExposure(resources)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Resource != "a-bucket" {
		t.Errorf("expected a-bucket first, got %s", findings[0].Resource)
	}
}

func TestClassifyExposure_NoFindings(t *testing.T) {
	resources := []NormalizedResourceInput{{
		Name:     "private-bucket",
		Exists:   true,
		Evidence: NewEvidenceTracker(),
	}}

	findings := ClassifyExposure(resources)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestSelectReadExposure_NilWhenNotReadable(t *testing.T) {
	result := SelectReadExposure(ReadExposureInput{
		ResourceID:           "test",
		IsExternallyReadable: false,
	})
	if result != nil {
		t.Fatal("expected nil when not externally readable")
	}
}

func TestSelectReadExposure_NilWhenWriteAbsorbs(t *testing.T) {
	result := SelectReadExposure(ReadExposureInput{
		ResourceID:           "test",
		IsExternallyReadable: true,
		WriteAbsorbsRead:     true,
	})
	if result != nil {
		t.Fatal("expected nil when write absorbs read")
	}
}

func TestSelectWriteExposure_NilWhenNotWritable(t *testing.T) {
	result := SelectWriteExposure(WriteExposureInput{
		ResourceID:      "test",
		IsPubliclyWrite: false,
	})
	if result != nil {
		t.Fatal("expected nil when not publicly writable")
	}
}

func TestSelectWriteExposure_ResourceWrite(t *testing.T) {
	result := SelectWriteExposure(WriteExposureInput{
		ResourceID:       "test",
		IsPubliclyWrite:  true,
		HasResourceWrite: true,
		WriteScope:       WriteScopeBlind,
		BaseActions:      []string{ActionWrite},
		EvidenceResource: aclEvidence,
	})
	if result == nil {
		t.Fatal("expected finding")
	}
	if result.finding.ID != idResourcePublicWrite {
		t.Errorf("expected resource write, got %s", result.finding.ID)
	}
}

func TestBuildEffectiveActions(t *testing.T) {
	actions := buildEffectiveActions([]string{ActionWrite}, true, true)
	if len(actions) != 3 {
		t.Fatalf("expected 3 actions, got %d: %v", len(actions), actions)
	}
	// Should be sorted: List, Read, Write
	if actions[0] != ActionList || actions[1] != ActionRead || actions[2] != ActionWrite {
		t.Errorf("unexpected action order: %v", actions)
	}
}

func TestCapabilitySetRoundTrip(t *testing.T) {
	mask := PermRead | PermWrite | PermMetadataRead | PermDelete
	cs := capabilitySetFromMask(mask)

	if !cs.Read || !cs.Write || !cs.MetadataRead || !cs.Delete {
		t.Error("expected Read, Write, MetadataRead, Delete true")
	}
	if cs.List || cs.MetadataWrite {
		t.Error("expected List, MetadataWrite false")
	}
	if cs.ToMask() != mask {
		t.Errorf("round-trip mismatch: got %d, want %d", cs.ToMask(), mask)
	}
}

func TestEvidenceTracker_RecordAndGet(t *testing.T) {
	tracker := NewEvidenceTracker()
	path := []string{"a", "b"}
	tracker.Record(EvIdentityRead, path)
	tracker.Record(EvIdentityRead, []string{"c"}) // should not overwrite

	got := tracker.Get(EvIdentityRead)
	if len(got) != 2 || got[0] != "a" {
		t.Errorf("expected first-recorded evidence, got %v", got)
	}

	if tracker.Get(EvDelete) != nil {
		t.Error("expected nil for unrecorded category")
	}
}

func TestEvidenceTracker_RecordIgnoresEmpty(t *testing.T) {
	tracker := NewEvidenceTracker()
	tracker.Record(EvIdentityRead, nil)
	tracker.Record(EvIdentityRead, []string{})

	if tracker.Get(EvIdentityRead) != nil {
		t.Error("expected nil for empty-recorded category")
	}
}

// --- Model tests ---

func TestGovernanceOverrides_IsHardened(t *testing.T) {
	hardened := GovernanceOverrides{
		BlockResourceBoundPublicAccess: true,
		BlockIdentityBoundPublicAccess: true,
		EnforceStrictPublicInheritance: true,
	}
	if !hardened.IsHardened() {
		t.Error("expected hardened")
	}
	partial := GovernanceOverrides{BlockResourceBoundPublicAccess: true}
	if partial.IsHardened() {
		t.Error("expected not hardened")
	}
}

// --- Facts tests ---

func TestFacts_CheckExposure_IdentityGrant(t *testing.T) {
	facts := Facts{
		HasIdentityEvidence: true,
		IdentityGrants:      Grants{{Scope: kernel.WildcardPrefix, SourceID: "stmt-1"}},
	}
	result := facts.CheckExposure(kernel.ObjectPrefix("any-prefix"))
	if !result.Exposed {
		t.Error("expected exposed via identity")
	}
	if result.Source.Kind != SourceIdentity {
		t.Errorf("expected identity source, got %s", result.Source.Kind)
	}
}

func TestFacts_CheckExposure_Resource(t *testing.T) {
	facts := Facts{
		HasResourceEvidence: true,
		ResourceReadAll:     true,
	}
	result := facts.CheckExposure(kernel.ObjectPrefix("any-prefix"))
	if !result.Exposed {
		t.Error("expected exposed via resource")
	}
	if result.Source.Kind != SourceResource {
		t.Errorf("expected resource source, got %s", result.Source.Kind)
	}
}

func TestFacts_CheckExposure_MissingEvidence(t *testing.T) {
	result := Facts{}.CheckExposure(kernel.ObjectPrefix("any-prefix"))
	if !result.Exposed {
		t.Error("expected exposed when missing evidence")
	}
	if result.Source.Kind != SourceMissingEvidence {
		t.Errorf("expected missing_evidence, got %s", result.Source.Kind)
	}
}

func TestFacts_CheckExposure_Safe(t *testing.T) {
	facts := Facts{HasIdentityEvidence: true}
	result := facts.CheckExposure(kernel.ObjectPrefix("no-matching-prefix"))
	if result.Exposed {
		t.Error("expected safe when no grants match")
	}
}

func TestFacts_CheckExposure_IdentityBlocked(t *testing.T) {
	facts := Facts{
		HasIdentityEvidence: true,
		IdentityReadBlocked: true,
		IdentityGrants:      Grants{{Scope: kernel.WildcardPrefix, SourceID: "stmt-1"}},
	}
	result := facts.CheckExposure(kernel.ObjectPrefix("any-prefix"))
	if result.Exposed {
		t.Error("expected safe when identity is blocked")
	}
}

func TestFacts_CheckExposure_ResourceBlocked(t *testing.T) {
	facts := Facts{
		HasResourceEvidence: true,
		ResourceReadAll:     true,
		ResourceReadBlocked: true,
	}
	result := facts.CheckExposure(kernel.ObjectPrefix("any-prefix"))
	if result.Exposed {
		t.Error("expected safe when resource is blocked")
	}
}

func TestFacts_LacksEvidence(t *testing.T) {
	if !(Facts{}).LacksEvidence() {
		t.Error("expected lacks evidence")
	}
	if (Facts{HasIdentityEvidence: true}).LacksEvidence() {
		t.Error("expected has evidence")
	}
}

func TestSource_String(t *testing.T) {
	s := NewSource(SourceIdentity, "stmt-1")
	if s.String() != "identity:stmt-1" {
		t.Errorf("expected identity:stmt-1, got %s", s.String())
	}
	s2 := NewSource(SourceResource, "")
	if s2.String() != "resource" {
		t.Errorf("expected resource, got %s", s2.String())
	}
}

func TestResult_String(t *testing.T) {
	r := Result{Exposed: true, Source: NewSource(SourceResource, "")}
	if r.String() != "resource" {
		t.Errorf("expected resource, got %s", r.String())
	}
}

func TestGrant_Covers(t *testing.T) {
	g := Grant{Scope: kernel.WildcardPrefix, SourceID: "s1"}
	if !g.Covers("anything") {
		t.Error("wildcard grant should cover anything")
	}
}

func TestGrant_Evidence(t *testing.T) {
	g := Grant{Scope: kernel.WildcardPrefix, SourceID: "s1"}
	ev := g.Evidence()
	if ev.Kind != SourceIdentity || ev.ID != "s1" {
		t.Errorf("unexpected evidence: %v", ev)
	}
}

func TestGrants_FindMatch(t *testing.T) {
	gs := Grants{
		{Scope: kernel.ObjectPrefix("invoices"), SourceID: "s1"},
		{Scope: kernel.WildcardPrefix, SourceID: "s2"},
	}
	match := gs.FindMatch("invoices/2026")
	if match == nil || match.SourceID != "s1" {
		t.Error("expected invoices grant to match")
	}
	noMatch := gs.FindMatch("reports")
	if noMatch == nil || noMatch.SourceID != "s2" {
		t.Error("expected wildcard fallback")
	}
}

func TestGrants_FindMatch_NoMatch(t *testing.T) {
	gs := Grants{{Scope: kernel.ObjectPrefix("invoices"), SourceID: "s1"}}
	if gs.FindMatch("reports") != nil {
		t.Error("expected no match")
	}
}

// --- Mapper tests ---

func TestFactsFromStorage_Grants(t *testing.T) {
	props := map[string]any{
		"storage": map[string]any{
			"prefix_exposure": map[string]any{
				"has_identity_evidence":    true,
				"identity_read_scopes":     []any{"*", "invoices/"},
				"identity_source_by_scope": map[string]any{"*": "s1", "invoices/": "s2"},
			},
		},
	}
	facts := FactsFromStorage(props)
	if len(facts.IdentityGrants) != 2 {
		t.Fatalf("expected 2 grants, got %d", len(facts.IdentityGrants))
	}
	if facts.IdentityGrants[0].SourceID != "s1" || facts.IdentityGrants[1].SourceID != "s2" {
		t.Error("unexpected source IDs")
	}
}

func TestFactsFromStorage_Empty(t *testing.T) {
	facts := FactsFromStorage(map[string]any{})
	if facts.IdentityGrants != nil {
		t.Error("expected nil grants for missing storage")
	}
}

// --- Visibility resolver tests ---

func TestBuildVisibilityResult_PublicRead(t *testing.T) {
	result := BuildVisibilityResult(
		Visibility{Public: Capabilities{Read: true}},
		Visibility{},
		GovernanceOverrides{},
	)
	if !result.PublicRead {
		t.Error("expected public read")
	}
	if !result.ReadViaIdentity {
		t.Error("expected read via identity")
	}
}

func TestBuildVisibilityResult_Blocked(t *testing.T) {
	result := BuildVisibilityResult(
		Visibility{Public: Capabilities{Read: true}},
		Visibility{},
		GovernanceOverrides{BlockIdentityBoundPublicAccess: true},
	)
	if result.PublicRead {
		t.Error("expected no public read when blocked")
	}
	if !result.LatentPublicRead {
		t.Error("expected latent read when identity blocked")
	}
}

func TestBuildVisibilityResult_AuthenticatedAccess(t *testing.T) {
	result := BuildVisibilityResult(
		Visibility{Authenticated: Capabilities{Read: true, Write: true, Admin: true}},
		Visibility{},
		GovernanceOverrides{},
	)
	if !result.AuthenticatedRead {
		t.Error("expected authenticated read")
	}
	if !result.AuthenticatedWrite {
		t.Error("expected authenticated write")
	}
	if !result.AuthenticatedAdmin {
		t.Error("expected authenticated admin")
	}
}

func TestBuildVisibilityResult_ResourceFullAccess(t *testing.T) {
	result := BuildVisibilityResult(
		Visibility{},
		Visibility{
			Public:        Capabilities{Read: true, Write: true, List: true, Delete: true, Admin: true},
			Authenticated: Capabilities{Read: true, Write: true, List: true, Delete: true, Admin: true},
		},
		GovernanceOverrides{},
	)
	if !result.WriteViaResource {
		t.Error("expected write via resource")
	}
	if !result.AdminViaResource {
		t.Error("expected admin via resource")
	}
	if !result.PublicDelete {
		t.Error("expected public delete")
	}
	if !result.PublicAdmin {
		t.Error("expected public admin")
	}
	if !result.AuthenticatedAdmin {
		t.Error("expected authenticated admin")
	}
}
