package asset

import (
	"encoding/json"
	"testing"

	"github.com/sufield/stave/internal/domain/kernel"
)

func TestCloudIdentityMap_ReturnsIdentityEnvelope(t *testing.T) {
	id := CloudIdentity{
		ID:     "role-1",
		Type:   kernel.AssetType("iam_role"),
		Vendor: kernel.VendorAWS,
	}

	got := id.Map()
	if got == nil {
		t.Fatalf("Map() returned nil map")
	}
	if got["id"] != ID("role-1") {
		t.Fatalf("id = %v, want role-1", got["id"])
	}
	if got["type"] != kernel.AssetType("iam_role") {
		t.Fatalf("type = %v, want iam_role", got["type"])
	}
	if got["vendor"] != kernel.VendorAWS {
		t.Fatalf("vendor = %v, want aws", got["vendor"])
	}
}

func TestCloudIdentityMap_UsesProperties(t *testing.T) {
	id := CloudIdentity{
		ID:     "role-1",
		Type:   kernel.AssetType("iam_role"),
		Vendor: kernel.VendorAWS,
		Properties: map[string]any{
			"owner":   "team-security",
			"purpose": "runtime",
			"grants": map[string]any{
				"has_wildcard": true,
			},
			"scope": map[string]any{
				"distinct_systems":         2,
				"distinct_resource_groups": 3,
			},
		},
	}

	got := id.Map()
	if got["owner"] != "team-security" {
		t.Fatalf("owner = %v, want team-security", got["owner"])
	}

	grants, ok := got["grants"].(map[string]any)
	if !ok {
		t.Fatalf("grants type = %T, want map[string]any", got["grants"])
	}
	if grants["has_wildcard"] != true {
		t.Fatalf("grants.has_wildcard = %v, want true", grants["has_wildcard"])
	}

	scope, ok := got["scope"].(map[string]any)
	if !ok {
		t.Fatalf("scope type = %T, want map[string]any", got["scope"])
	}
	if scope["distinct_systems"] != 2 {
		t.Fatalf("scope.distinct_systems = %v, want 2", scope["distinct_systems"])
	}
	if scope["distinct_resource_groups"] != 3 {
		t.Fatalf("scope.distinct_resource_groups = %v, want 3", scope["distinct_resource_groups"])
	}
}

func TestCloudIdentityUnmarshalJSON_PropertiesShape(t *testing.T) {
	var id CloudIdentity
	raw := []byte(`{
	  "id": "role-1",
	  "type": "iam_role",
	  "vendor": "aws",
	  "properties": {
	    "owner": "team-security",
	    "purpose": "runtime",
	    "grants": {"has_wildcard": true},
	    "scope": {"distinct_systems": 2, "distinct_resource_groups": 3}
	  }
		}`)
	if err := json.Unmarshal(raw, &id); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	owner, ok := id.Owner()
	if !ok || owner != "team-security" {
		t.Fatalf("Owner() = (%q, %v), want (team-security, true)", owner, ok)
	}
	purpose, ok := id.Purpose()
	if !ok || purpose != "runtime" {
		t.Fatalf("Purpose() = (%q, %v), want (runtime, true)", purpose, ok)
	}
	wildcard, ok := id.HasWildcard()
	if !ok || !wildcard {
		t.Fatalf("HasWildcard() = (%v, %v), want (true, true)", wildcard, ok)
	}
	systems, ok := id.DistinctSystems()
	if !ok || systems != 2 {
		t.Fatalf("DistinctSystems() = (%d, %v), want (2, true)", systems, ok)
	}
	groups, ok := id.DistinctResourceGroups()
	if !ok || groups != 3 {
		t.Fatalf("DistinctResourceGroups() = (%d, %v), want (3, true)", groups, ok)
	}
}
