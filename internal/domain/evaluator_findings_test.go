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
			name:  "identity only",
			props: []policy.Misconfiguration{{Property: "storage.visibility.read_via_identity", ActualValue: true}},
			want:  []evaluation.RootCause{evaluation.RootCauseIdentity},
		},
		{
			name:  "resource only",
			props: []policy.Misconfiguration{{Property: "storage.visibility.read_via_resource", ActualValue: true}},
			want:  []evaluation.RootCause{evaluation.RootCauseResource},
		},
		{
			name: "both identity and resource",
			props: []policy.Misconfiguration{
				{Property: "storage.visibility.read_via_resource", ActualValue: true},
				{Property: "storage.visibility.read_via_identity", ActualValue: true},
			},
			want: []evaluation.RootCause{evaluation.RootCauseIdentity, evaluation.RootCauseResource},
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
			name: "multiple identity keys deduplicated",
			props: []policy.Misconfiguration{
				{Property: "storage.visibility.list_via_identity", ActualValue: true},
				{Property: "storage.visibility.read_via_identity", ActualValue: true},
			},
			want: []evaluation.RootCause{evaluation.RootCauseIdentity},
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
