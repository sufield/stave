package kernel

import "testing"

func TestDigest_String(t *testing.T) {
	d := Digest("abc123")
	if got := d.String(); got != "abc123" {
		t.Errorf("Digest.String() = %q, want %q", got, "abc123")
	}
}

func TestDigest_IsValid(t *testing.T) {
	tests := []struct {
		name string
		d    Digest
		want bool
	}{
		{
			name: "valid 64-char lowercase hex",
			d:    Digest("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
			want: true,
		},
		{
			name: "valid all zeros",
			d:    Digest("0000000000000000000000000000000000000000000000000000000000000000"),
			want: true,
		},
		{
			name: "too short",
			d:    Digest("abc123"),
			want: false,
		},
		{
			name: "too long",
			d:    Digest("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2ff"),
			want: false,
		},
		{
			name: "empty",
			d:    Digest(""),
			want: false,
		},
		{
			name: "uppercase hex rejected",
			d:    Digest("A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2"),
			want: false,
		},
		{
			name: "non-hex character g",
			d:    Digest("g1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.d.IsValid(); got != tt.want {
				t.Errorf("Digest(%q).IsValid() = %v, want %v", tt.d, got, tt.want)
			}
		})
	}
}

func TestSignature_String(t *testing.T) {
	s := Signature("deadbeef")
	if got := s.String(); got != "deadbeef" {
		t.Errorf("Signature.String() = %q, want %q", got, "deadbeef")
	}
}

func TestSignature_IsValid(t *testing.T) {
	tests := []struct {
		name string
		s    Signature
		want bool
	}{
		{
			name: "valid even-length lowercase hex",
			s:    Signature("deadbeef"),
			want: true,
		},
		{
			name: "valid two chars",
			s:    Signature("ab"),
			want: true,
		},
		{
			name: "empty",
			s:    Signature(""),
			want: false,
		},
		{
			name: "odd length",
			s:    Signature("abc"),
			want: false,
		},
		{
			name: "uppercase rejected",
			s:    Signature("DEADBEEF"),
			want: false,
		},
		{
			name: "non-hex character",
			s:    Signature("zzzz"),
			want: false,
		},
		{
			name: "single char (odd)",
			s:    Signature("a"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.IsValid(); got != tt.want {
				t.Errorf("Signature(%q).IsValid() = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestIsLowerHex(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"0123456789abcdef", true},
		{"", true}, // empty is trivially true
		{"0", true},
		{"g", false},
		{"A", false},
		{"0x", false}, // 'x' is not hex
	}

	for _, tt := range tests {
		if got := isLowerHex(tt.in); got != tt.want {
			t.Errorf("isLowerHex(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
