package sanitize

import "testing"

func TestSanitizer_String(t *testing.T) {
	tests := []struct {
		name string
		san  *Sanitizer
		want string
	}{
		{
			name: "nil",
			san:  nil,
			want: "Sanitizer(nil)",
		},
		{
			name: "default zero value",
			san:  &Sanitizer{},
			want: "Sanitizer(ids=false, path=base)",
		},
		{
			name: "ids enabled, base path",
			san:  New(WithIDSanitization(true)),
			want: "Sanitizer(ids=true, path=base)",
		},
		{
			name: "ids enabled, full path",
			san:  New(WithIDSanitization(true), WithPathMode(PathFull)),
			want: "Sanitizer(ids=true, path=full)",
		},
		{
			name: "ids disabled, full path",
			san:  New(WithPathMode(PathFull)),
			want: "Sanitizer(ids=false, path=full)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.san.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPathMode_String(t *testing.T) {
	tests := []struct {
		mode PathMode
		want string
	}{
		{PathBase, "base"},
		{PathFull, "full"},
		{PathMode(""), "base"}, // zero value
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.mode.String()
			if got != tt.want {
				t.Errorf("PathMode(%q).String() = %q, want %q", tt.mode, got, tt.want)
			}
		})
	}
}

func TestSanitizer_ID(t *testing.T) {
	t.Run("nil sanitizer", func(t *testing.T) {
		var s *Sanitizer
		if got := s.ID("test"); got != "test" {
			t.Errorf("nil ID() = %q, want test", got)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		s := New()
		if got := s.ID("test"); got != "test" {
			t.Errorf("disabled ID() = %q, want test", got)
		}
	})

	t.Run("empty string", func(t *testing.T) {
		s := New(WithIDSanitization(true))
		if got := s.ID(""); got != "" {
			t.Errorf("empty ID() = %q, want empty", got)
		}
	})

	t.Run("enabled", func(t *testing.T) {
		s := New(WithIDSanitization(true))
		got := s.ID("my-bucket")
		if got == "my-bucket" {
			t.Error("enabled ID() should sanitize")
		}
		if got == "" {
			t.Error("enabled ID() should not be empty")
		}
	})
}

func TestSanitizer_Value_NilAndDisabled(t *testing.T) {
	t.Run("nil sanitizer", func(t *testing.T) {
		var s *Sanitizer
		if got := s.Value("secret"); got != "secret" {
			t.Errorf("nil Value() = %q, want secret", got)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		s := New()
		if got := s.Value("secret"); got != "secret" {
			t.Errorf("disabled Value() = %q, want secret", got)
		}
	})
}

func TestSanitizer_ScrubMessage_Empty(t *testing.T) {
	s := New(WithIDSanitization(true))
	if got := s.ScrubMessage(""); got != "" {
		t.Errorf("empty ScrubMessage() = %q, want empty", got)
	}
}
