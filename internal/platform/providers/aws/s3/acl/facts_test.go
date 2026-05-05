package acl

import (
	"reflect"
	"testing"
)

func TestExtractACLFacts(t *testing.T) {
	cases := []struct {
		name      string
		input     any
		want      ACLFacts
		wantError bool
	}{
		{
			name: "public_read_on_all_users",
			input: map[string]any{
				"Owner": map[string]any{"ID": "owner-canonical-1"},
				"Grants": []any{
					map[string]any{
						"Grantee": map[string]any{
							"Type": "Group",
							"URI":  GroupURIAllUsers,
						},
						"Permission": "READ",
					},
				},
			},
			want: ACLFacts{
				OwnerID: "owner-canonical-1",
				Grants: []ACLGrant{
					{Index: 0, Kind: GranteeGroup, URI: GroupURIAllUsers, Permission: ACLPermissionRead, IsPublic: true},
				},
			},
		},
		{
			name: "authenticated_users",
			input: map[string]any{
				"Owner": map[string]any{"ID": "owner-2"},
				"Grants": []any{
					map[string]any{
						"Grantee": map[string]any{
							"Type": "Group",
							"URI":  GroupURIAuthenticatedUsers,
						},
						"Permission": "READ",
					},
				},
			},
			want: ACLFacts{
				OwnerID: "owner-2",
				Grants: []ACLGrant{
					{Index: 0, Kind: GranteeGroup, URI: GroupURIAuthenticatedUsers, Permission: ACLPermissionRead, IsAnyAuth: true},
				},
			},
		},
		{
			name: "multiple_grants_same_grantee_different_perms",
			input: map[string]any{
				"Owner": map[string]any{"ID": "owner-3"},
				"Grants": []any{
					map[string]any{
						"Grantee":    map[string]any{"Type": "CanonicalUser", "ID": "user-x"},
						"Permission": "READ",
					},
					map[string]any{
						"Grantee":    map[string]any{"Type": "CanonicalUser", "ID": "user-x"},
						"Permission": "WRITE",
					},
					map[string]any{
						"Grantee":    map[string]any{"Type": "CanonicalUser", "ID": "user-x"},
						"Permission": "READ_ACP",
					},
				},
			},
			want: ACLFacts{
				OwnerID: "owner-3",
				Grants: []ACLGrant{
					{Index: 0, Kind: GranteeCanonicalUser, ID: "user-x", Permission: ACLPermissionRead},
					{Index: 1, Kind: GranteeCanonicalUser, ID: "user-x", Permission: ACLPermissionWrite},
					{Index: 2, Kind: GranteeCanonicalUser, ID: "user-x", Permission: ACLPermissionReadACP},
				},
			},
		},
		{
			name: "missing_grants_array",
			input: map[string]any{
				"Owner": map[string]any{"ID": "owner-4"},
			},
			want: ACLFacts{OwnerID: "owner-4"},
		},
		{
			name:  "nil_input",
			input: nil,
			want:  ACLFacts{},
		},
		{
			name: "log_delivery_group",
			input: map[string]any{
				"Owner": map[string]any{"ID": "owner-5"},
				"Grants": []any{
					map[string]any{
						"Grantee":    map[string]any{"Type": "Group", "URI": GroupURILogDelivery},
						"Permission": "WRITE",
					},
				},
			},
			want: ACLFacts{
				OwnerID: "owner-5",
				Grants: []ACLGrant{
					{Index: 0, Kind: GranteeGroup, URI: GroupURILogDelivery, Permission: ACLPermissionWrite},
				},
			},
		},
		{
			name: "email_grantee",
			input: map[string]any{
				"Owner": map[string]any{"ID": "owner-6"},
				"Grants": []any{
					map[string]any{
						"Grantee":    map[string]any{"Type": "AmazonCustomerByEmail", "EmailAddress": "user@example.com"},
						"Permission": "FULL_CONTROL",
					},
				},
			},
			want: ACLFacts{
				OwnerID: "owner-6",
				Grants: []ACLGrant{
					{Index: 0, Kind: GranteeEmail, Email: "user@example.com", Permission: ACLPermissionFullControl},
				},
			},
		},
		{
			name: "malformed_grant_dropped",
			input: map[string]any{
				"Owner": map[string]any{"ID": "owner-7"},
				"Grants": []any{
					"not a map",
					map[string]any{
						"Grantee":    map[string]any{"Type": "Group", "URI": GroupURIAllUsers},
						"Permission": "READ",
					},
				},
			},
			// Note: Index reflects position in the input array
			// (1, not 0) — the malformed entry is skipped but
			// the surviving grant keeps its original position.
			want: ACLFacts{
				OwnerID: "owner-7",
				Grants: []ACLGrant{
					{Index: 1, Kind: GranteeGroup, URI: GroupURIAllUsers, Permission: ACLPermissionRead, IsPublic: true},
				},
			},
		},
		{
			name:      "non_map_input_errors",
			input:     "not a map at all",
			wantError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExtractACLFacts(tc.input)
			if tc.wantError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ExtractACLFacts: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ExtractACLFacts mismatch:\n  want: %+v\n  got:  %+v", tc.want, got)
			}
		})
	}
}
