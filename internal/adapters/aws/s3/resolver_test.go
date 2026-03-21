package s3

import (
	"testing"

	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
)

func TestResolverExactMatches(t *testing.T) {
	r := NewResolver()
	cases := []struct {
		action string
		want   risk.Permission
	}{
		{"*", risk.PermFullControl},
		{"s3:*", risk.PermFullControl},
		{"s3:getobject", risk.PermRead},
		{"s3:putobject", risk.PermWrite},
		{"s3:listbucket", risk.PermList},
		{"s3:getbucketacl", risk.PermAdminRead},
		{"s3:getobjectacl", risk.PermAdminRead},
		{"s3:putbucketacl", risk.PermAdminWrite},
		{"s3:putobjectacl", risk.PermAdminWrite},
		{"s3:deleteobject", risk.PermDelete},
		{"s3:deletebucket", risk.PermDelete},
		{"s3:listbucketversions", risk.PermList},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			got := r.Resolve(tc.action)
			if got != tc.want {
				t.Errorf("Resolve(%q) = %d, want %d", tc.action, got, tc.want)
			}
		})
	}
}

func TestResolverPrefixFallback(t *testing.T) {
	r := NewResolver()
	cases := []struct {
		action string
		want   risk.Permission
	}{
		{"s3:putfoo", risk.PermWrite},
		{"s3:deletefoo", risk.PermDelete},
		{"s3:putanything", risk.PermWrite},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			got := r.Resolve(tc.action)
			if got != tc.want {
				t.Errorf("Resolve(%q) = %d, want %d", tc.action, got, tc.want)
			}
		})
	}
}

func TestResolverLongestPrefixMatch(t *testing.T) {
	r := NewResolver()
	// s3:putbucketacl should match AdminWrite (exact), NOT Write (prefix)
	got := r.Resolve("s3:putbucketacl")
	if got != risk.PermAdminWrite {
		t.Errorf("Resolve(s3:putbucketacl) = %d, want AdminWrite (%d)", got, risk.PermAdminWrite)
	}
	// s3:putobjectacl should also match AdminWrite
	got = r.Resolve("s3:putobjectacl")
	if got != risk.PermAdminWrite {
		t.Errorf("Resolve(s3:putobjectacl) = %d, want AdminWrite (%d)", got, risk.PermAdminWrite)
	}
}

func TestResolverUnknownAction(t *testing.T) {
	r := NewResolver()
	got := r.Resolve("ec2:runinstances")
	if got != 0 {
		t.Errorf("Resolve(ec2:runinstances) = %d, want 0", got)
	}
}

func TestResolverImplementsInterface(t *testing.T) {
	var _ risk.PermissionResolver = (*Resolver)(nil)
}
