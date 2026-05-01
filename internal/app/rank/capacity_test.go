package rank

import "testing"

func TestParseCapacity(t *testing.T) {
	cases := []struct {
		in      string
		want    float64
		wantErr bool
	}{
		{"40h", 40, false},
		{"5d", 40, false},
		{"24", 24, false},
		{"0.5d", 4, false},
		{"", 0, true},
		{"5x", 0, true},
		{"abc", 0, true},
	}
	for _, c := range cases {
		got, err := ParseCapacity(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseCapacity(%q) want error, got %f", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseCapacity(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseCapacity(%q) = %f, want %f", c.in, got, c.want)
		}
	}
}
