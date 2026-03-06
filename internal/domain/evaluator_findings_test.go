package domain

import (
	"testing"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/engine"
	"github.com/sufield/stave/internal/domain/policy"
)

func TestDeriveRootCauses(t *testing.T) {
	tests := []struct {
		name  string
		props []policy.Misconfiguration
		want  []evaluation.RootCause
	}{
		{
			name:  "policy only",
			props: []policy.Misconfiguration{{Property: "storage.visibility.public_read_via_policy", ActualValue: true}},
			want:  []evaluation.RootCause{evaluation.RootCausePolicy},
		},
		{
			name:  "acl only",
			props: []policy.Misconfiguration{{Property: "storage.visibility.public_read_via_acl", ActualValue: true}},
			want:  []evaluation.RootCause{evaluation.RootCauseACL},
		},
		{
			name: "both policy and acl",
			props: []policy.Misconfiguration{
				{Property: "storage.visibility.public_read_via_acl", ActualValue: true},
				{Property: "storage.visibility.public_read_via_policy", ActualValue: true},
			},
			want: []evaluation.RootCause{evaluation.RootCausePolicy, evaluation.RootCauseACL},
		},
		{
			name:  "no mechanism markers",
			props: []policy.Misconfiguration{{Property: "storage.visibility.public_read", ActualValue: true}},
			want:  nil,
		},
		{
			name:  "empty props",
			props: []policy.Misconfiguration{},
			want:  nil,
		},
		{
			name:  "nil props",
			props: nil,
			want:  nil,
		},
		{
			name: "multiple policy keys deduplicated",
			props: []policy.Misconfiguration{
				{Property: "storage.visibility.public_list_via_policy", ActualValue: true},
				{Property: "storage.visibility.public_read_via_policy", ActualValue: true},
			},
			want: []evaluation.RootCause{evaluation.RootCausePolicy},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.DeriveRootCauses(tt.props)
			if len(got) != len(tt.want) {
				t.Fatalf("deriveRootCauses() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("deriveRootCauses()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
