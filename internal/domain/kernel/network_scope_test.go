package kernel

import (
	"encoding/json"
	"testing"
)

func TestParseNetworkScope(t *testing.T) {
	tests := []struct {
		in      string
		want    NetworkScope
		wantErr bool
	}{
		{in: "public", want: NetworkScopePublic},
		{in: "ip-restricted", want: NetworkScopeIPRestricted},
		{in: "vpc-restricted", want: NetworkScopeVPCRestricted},
		{in: "org-restricted", want: NetworkScopeOrgRestricted},
		{in: "unknown", want: NetworkScopeUnknown},
		{in: "", want: NetworkScopeUnknown},
		{in: "  Public  ", want: NetworkScopePublic},
		{in: "  VPC-Restricted ", want: NetworkScopeVPCRestricted},
		{in: "private", wantErr: true},
		{in: "bad_value", wantErr: true},
	}

	for _, tt := range tests {
		got, err := ParseNetworkScope(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("ParseNetworkScope(%q) error = nil, want error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseNetworkScope(%q) error = %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("ParseNetworkScope(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestNetworkScopeJSON(t *testing.T) {
	var scope NetworkScope
	if err := json.Unmarshal([]byte(`"ip-restricted"`), &scope); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}
	if scope != NetworkScopeIPRestricted {
		t.Fatalf("scope = %v, want %v", scope, NetworkScopeIPRestricted)
	}

	data, err := json.Marshal(NetworkScopeVPCRestricted)
	if err != nil {
		t.Fatalf("json.Marshal error = %v", err)
	}
	if string(data) != `"vpc-restricted"` {
		t.Fatalf("json.Marshal = %s, want %q", data, `"vpc-restricted"`)
	}
}

func TestNetworkScopeJSONRoundTrip(t *testing.T) {
	scopes := []NetworkScope{
		NetworkScopeUnknown,
		NetworkScopePublic,
		NetworkScopeOrgRestricted,
		NetworkScopeIPRestricted,
		NetworkScopeVPCRestricted,
	}
	for _, s := range scopes {
		data, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("json.Marshal(%v) error = %v", s, err)
		}
		var got NetworkScope
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("json.Unmarshal(%s) error = %v", data, err)
		}
		if got != s {
			t.Fatalf("round-trip: got %v, want %v", got, s)
		}
	}
}

func TestNetworkScopeString(t *testing.T) {
	tests := []struct {
		scope NetworkScope
		want  string
	}{
		{NetworkScopeUnknown, ""},
		{NetworkScopePublic, "public"},
		{NetworkScopeOrgRestricted, "org-restricted"},
		{NetworkScopeIPRestricted, "ip-restricted"},
		{NetworkScopeVPCRestricted, "vpc-restricted"},
		{NetworkScope(99), ""},
	}
	for _, tt := range tests {
		if got := tt.scope.String(); got != tt.want {
			t.Errorf("NetworkScope(%d).String() = %q, want %q", tt.scope, got, tt.want)
		}
	}
}

func TestNetworkScopeRank(t *testing.T) {
	if NetworkScopePublic.Rank() >= NetworkScopeOrgRestricted.Rank() {
		t.Error("public should rank lower than org-restricted")
	}
	if NetworkScopeOrgRestricted.Rank() >= NetworkScopeIPRestricted.Rank() {
		t.Error("org-restricted should rank lower than ip-restricted")
	}
	if NetworkScopeIPRestricted.Rank() >= NetworkScopeVPCRestricted.Rank() {
		t.Error("ip-restricted should rank lower than vpc-restricted")
	}
}

func TestNetworkScopeWeakerThan(t *testing.T) {
	if !NetworkScopePublic.WeakerThan(NetworkScopeVPCRestricted) {
		t.Error("public should be weaker than vpc-restricted")
	}
	if NetworkScopeVPCRestricted.WeakerThan(NetworkScopePublic) {
		t.Error("vpc-restricted should not be weaker than public")
	}
	if NetworkScopeIPRestricted.WeakerThan(NetworkScopeIPRestricted) {
		t.Error("scope should not be weaker than itself")
	}
}
