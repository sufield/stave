package asset

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseID(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid arn",
			raw:     "arn:aws:s3:::my-bucket",
			wantErr: false,
		},
		{
			name:      "empty",
			raw:       "",
			wantErr:   true,
			errSubstr: "must not be empty",
		},
		{
			name:      "whitespace only",
			raw:       "   ",
			wantErr:   true,
			errSubstr: "must not be empty",
		},
		{
			name:      "surrounding whitespace",
			raw:       " bucket-a ",
			wantErr:   true,
			errSubstr: "leading or trailing whitespace",
		},
		{
			name:      "control characters",
			raw:       "bucket-\n",
			wantErr:   true,
			errSubstr: "control characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseID(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseID(%q) error = nil, want error", tt.raw)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("ParseID(%q) error = %q, want substring %q", tt.raw, err.Error(), tt.errSubstr)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseID(%q) error = %v, want nil", tt.raw, err)
			}
			if got.String() != tt.raw {
				t.Fatalf("ParseID(%q) = %q, want %q", tt.raw, got.String(), tt.raw)
			}
		})
	}
}

func TestIDUnmarshalJSON(t *testing.T) {
	t.Run("valid string", func(t *testing.T) {
		var id ID
		if err := json.Unmarshal([]byte(`"bucket-123"`), &id); err != nil {
			t.Fatalf("Unmarshal valid id error = %v, want nil", err)
		}
		if id != "bucket-123" {
			t.Fatalf("Unmarshal valid id = %q, want bucket-123", id)
		}
	})

	t.Run("invalid empty", func(t *testing.T) {
		var id ID
		err := json.Unmarshal([]byte(`""`), &id)
		if err == nil {
			t.Fatal("Unmarshal empty id error = nil, want error")
		}
	})

	t.Run("invalid non-string", func(t *testing.T) {
		var id ID
		err := json.Unmarshal([]byte(`123`), &id)
		if err == nil {
			t.Fatal("Unmarshal non-string id error = nil, want error")
		}
	})
}
