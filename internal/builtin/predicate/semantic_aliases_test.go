package predicate

import (
	"errors"
	"fmt"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/util/suggest"
)

// ── Phase 3.1: Comprehensive Unit Test ───────────────────────────────

func TestListAliases_AllResolvable(t *testing.T) {
	names := ListAliases("")
	if len(names) == 0 {
		t.Fatal("expected at least one alias")
	}
	for _, name := range names {
		pred, err := Resolve(name)
		if err != nil {
			t.Errorf("Resolve(%q) returned error: %v", name, err)
			continue
		}
		if len(pred.Any) == 0 && len(pred.All) == 0 {
			t.Errorf("Resolve(%q) returned empty predicate", name)
		}
	}
}

func TestResolve_ReturnsDeepCopy(t *testing.T) {
	pred1, err := Resolve(S3IsPublicReadable)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", S3IsPublicReadable, err)
	}

	// Mutate the returned slice.
	pred1.Any = append(pred1.Any, policy.PredicateRule{})

	// Resolve again — must be unchanged.
	pred2, err := Resolve(S3IsPublicReadable)
	if err != nil {
		t.Fatalf("second Resolve(%q): %v", S3IsPublicReadable, err)
	}
	if len(pred2.Any) == len(pred1.Any) {
		t.Error("deep clone broken: mutation of first result affected second resolve")
	}
}

func TestResolve_UnknownAlias(t *testing.T) {
	_, err := Resolve("s3.nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown alias")
	}
	var unknownErr *UnknownAliasError
	if !errors.As(err, &unknownErr) {
		t.Fatalf("expected *UnknownAliasError, got %T", err)
	}
	if unknownErr.Name != "s3.nonexistent" {
		t.Errorf("Name = %q, want %q", unknownErr.Name, "s3.nonexistent")
	}
}

func TestResolve_FuzzySuggestion(t *testing.T) {
	// Typo: "readable" → "readble"
	_, err := Resolve("s3.is_public_readble")
	if err == nil {
		t.Fatal("expected error for unknown alias")
	}
	var unknownErr *UnknownAliasError
	if !errors.As(err, &unknownErr) {
		t.Fatalf("expected *UnknownAliasError, got %T", err)
	}
	if unknownErr.Suggestion != S3IsPublicReadable {
		t.Errorf("Suggestion = %q, want %q", unknownErr.Suggestion, S3IsPublicReadable)
	}
}

func TestResolve_NoSuggestionForDistantInput(t *testing.T) {
	_, err := Resolve("iam.totally_different")
	if err == nil {
		t.Fatal("expected error")
	}
	var unknownErr *UnknownAliasError
	if !errors.As(err, &unknownErr) {
		t.Fatalf("expected *UnknownAliasError, got %T", err)
	}
	if unknownErr.Suggestion != "" {
		t.Errorf("expected no suggestion for distant input, got %q", unknownErr.Suggestion)
	}
}

func TestListAliases_CategoryFilter(t *testing.T) {
	all := ListAliases("")
	encryption := ListAliases(CategoryEncryption)
	if len(encryption) == 0 {
		t.Fatal("expected encryption aliases")
	}
	if len(encryption) >= len(all) {
		t.Errorf("filtered list (%d) should be smaller than full list (%d)", len(encryption), len(all))
	}
	for _, name := range encryption {
		if _, err := Resolve(name); err != nil {
			t.Errorf("filtered alias %q not resolvable: %v", name, err)
		}
	}
}

func TestListAliases_UnknownCategoryReturnsEmpty(t *testing.T) {
	names := ListAliases("Nonexistent Category")
	if len(names) != 0 {
		t.Errorf("expected empty list for unknown category, got %d", len(names))
	}
}

func TestListAliases_Sorted(t *testing.T) {
	names := ListAliases("")
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("not sorted: %q comes before %q", names[i-1], names[i])
		}
	}
}

func TestRegistry_AliasResolverFunc(t *testing.T) {
	resolver := ResolverFunc()
	pred, ok := resolver(S3IsPublicReadable)
	if !ok {
		t.Fatalf("AliasResolver returned false for %q", S3IsPublicReadable)
	}
	if len(pred.Any) == 0 {
		t.Error("expected non-empty predicate from AliasResolver")
	}

	_, ok = resolver("s3.nonexistent")
	if ok {
		t.Error("expected false for unknown alias via AliasResolver")
	}
}

func TestRegistry_ListAliasInfo(t *testing.T) {
	infos := DefaultRegistry().ListAliasInfo("")
	if len(infos) == 0 {
		t.Fatal("expected alias info entries")
	}
	for _, info := range infos {
		if info.Name == "" {
			t.Error("AliasInfo has empty Name")
		}
		if info.Description == "" {
			t.Errorf("AliasInfo %q has empty Description", info.Name)
		}
		if info.Category == "" {
			t.Errorf("AliasInfo %q has empty Category", info.Name)
		}
		if info.Service == "" {
			t.Errorf("AliasInfo %q has empty Service", info.Name)
		}
	}
}

func TestConstants_MatchRegistryKeys(t *testing.T) {
	constants := []string{
		S3IsPublicReadable,
		S3IsPublicWritable,
		S3IsPublicListable,
		S3LatentPublicRead,
		S3LatentPublicList,
		S3AuthenticatedUsersRead,
		S3AuthenticatedUsersWrite,
		S3ACLWritable,
		S3ACLReadableByPublic,
		S3HasFullControlGrant,
		S3EncryptionAtRestDisabled,
		S3EncryptionInTransitNotEnforced,
		S3NotUsingKMSCMK,
		S3LoggingDisabled,
		S3VersioningDisabled,
		S3MFADeleteDisabled,
		S3PublicAccessBlockDisabled,
		S3ObjectLockDisabled,
		S3ObjectLockNotComplianceMode,
	}
	all := ListAliases("")
	if len(constants) != len(all) {
		t.Errorf("constant count (%d) != registry count (%d)", len(constants), len(all))
	}
	for _, c := range constants {
		if _, err := Resolve(c); err != nil {
			t.Errorf("constant %q not in registry: %v", c, err)
		}
	}
}

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "", 3},
		{"", "abc", 3},
		{"abc", "abc", 0},
		{"abc", "abd", 1},
		{"kitten", "sitting", 3},
	}
	for _, tt := range tests {
		got := suggest.Distance(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("Distance(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// ── Phase 3.2: Example Documentation ─────────────────────────────────

func ExampleResolve() {
	pred, err := Resolve(S3IsPublicReadable)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	fmt.Printf("rules: %d\n", len(pred.Any))
	// Output:
	// rules: 3
}
