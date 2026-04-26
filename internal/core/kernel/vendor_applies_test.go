package kernel

import "testing"

func TestAppliesToVendor(t *testing.T) {
	tests := []struct {
		name      string
		scopeTags []string
		vendor    string
		want      bool
	}{
		{
			name:      "tag matches vendor exactly",
			scopeTags: []string{"aws"},
			vendor:    "aws",
			want:      true,
		},
		{
			name:      "short tag matches vendor among other tags",
			scopeTags: []string{"apigateway", "aws", "supply-chain"},
			vendor:    "aws",
			want:      true,
		},
		{
			name:      "all tags long — control is universal",
			scopeTags: []string{"supply-chain", "kubernetes-runtime"},
			vendor:    "aws",
			want:      true,
		},
		{
			name:      "vendor-shaped tags exist but none match — does not apply",
			scopeTags: []string{"aws", "gcp"},
			vendor:    "azure",
			want:      false,
		},
		{
			name:      "no scope tags — universal",
			scopeTags: nil,
			vendor:    "aws",
			want:      true,
		},
		{
			name:      "empty scope tags slice — universal",
			scopeTags: []string{},
			vendor:    "aws",
			want:      true,
		},
		{
			name:      "empty vendor with vendor-shaped tags — no match",
			scopeTags: []string{"aws"},
			vendor:    "",
			want:      false,
		},
		{
			name:      "empty vendor with no scope tags — universal",
			scopeTags: nil,
			vendor:    "",
			want:      true,
		},
		{
			name:      "10-char tag matches (boundary)",
			scopeTags: []string{"kubernetes"},
			vendor:    "kubernetes",
			want:      true,
		},
		{
			name:      "11-char tag is treated as long, control is universal",
			scopeTags: []string{"kubernetes1"},
			vendor:    "aws",
			want:      true,
		},
		{
			name:      "multicloud tag is universal regardless of asset vendor",
			scopeTags: []string{"multicloud", "iam"},
			vendor:    "aws",
			want:      true,
		},
		{
			name:      "multicloud tag is universal for gcp",
			scopeTags: []string{"multicloud", "iam"},
			vendor:    "gcp",
			want:      true,
		},
		{
			name:      "multicloud tag is universal for empty vendor",
			scopeTags: []string{"multicloud"},
			vendor:    "",
			want:      true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := AppliesToVendor(tc.scopeTags, tc.vendor); got != tc.want {
				t.Errorf("AppliesToVendor(%v, %q) = %v, want %v", tc.scopeTags, tc.vendor, got, tc.want)
			}
		})
	}
}
