package enginetest

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/engine"
)

func TestDeriveRootCauses(t *testing.T) {
	tests := []struct {
		name  string
		props []policy.Misconfiguration
		want  []evaluation.RootCause
	}{
		{
			name:  "identity only",
			props: []policy.Misconfiguration{{Property: "storage.access.read_via_identity", ActualValue: true, Category: policy.CategoryIdentity}},
			want:  []evaluation.RootCause{evaluation.RootCauseIdentity},
		},
		{
			name:  "resource only",
			props: []policy.Misconfiguration{{Property: "storage.access.read_via_resource", ActualValue: true, Category: policy.CategoryResource}},
			want:  []evaluation.RootCause{evaluation.RootCauseResource},
		},
		{
			name: "both identity and resource",
			props: []policy.Misconfiguration{
				{Property: "storage.access.read_via_resource", ActualValue: true, Category: policy.CategoryResource},
				{Property: "storage.access.read_via_identity", ActualValue: true, Category: policy.CategoryIdentity},
			},
			want: []evaluation.RootCause{evaluation.RootCauseIdentity, evaluation.RootCauseResource},
		},
		{
			name:  "no mechanism markers (general fallback)",
			props: []policy.Misconfiguration{{Property: "storage.access.public_read", ActualValue: true, Category: policy.CategoryUnknown}},
			want:  []evaluation.RootCause{evaluation.RootCauseGeneral},
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
				{Property: "storage.access.list_via_identity", ActualValue: true, Category: policy.CategoryIdentity},
				{Property: "storage.access.read_via_identity", ActualValue: true, Category: policy.CategoryIdentity},
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
