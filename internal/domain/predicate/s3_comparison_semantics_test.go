package predicate

import "testing"

func TestS3ComparisonSemantics(t *testing.T) {
	tests := []struct {
		name     string
		a        any
		b        any
		op       string // "eq", "gt", "lt"
		expected bool
	}{
		// Finding #1: Boolean-String Duality (High Risk)
		{"Bool True == String 'true'", true, "true", "eq", true},
		{"Bool False == String 'false'", false, "false", "eq", true},
		{"Bool True == String 'TRUE' (Casing)", true, "TRUE", "eq", true},
		{"Bool True != String 'nopes'", true, "nopes", "eq", false},

		// Finding #3: Case-Insensitive Strings (Medium Risk)
		{"S3 Algorithm AES256 == aes256", "AES256", "aes256", "eq", true},
		{"S3 Status Enabled == enabled", "Enabled", "enabled", "eq", true},
		{"S3 Status Enabled != Disabled", "Enabled", "Disabled", "eq", false},

		// Finding #4 & #5: Numeric Normalization & Trimming (Medium/Low Risk)
		{"Port 80 == String '80'", 80, "80", "eq", true},
		{"Port 443 == String ' 443 ' (Trimmed)", 443, " 443 ", "eq", true},
		{"Retention 90 > '30'", 90, "30", "gt", true},
		{"'100' < 200", "100", 200, "lt", true},

		// Finding #2: Semantic Equality vs Strict DeepEqual
		{"Mixed Type Incomparable", true, "AES256", "eq", false},
		{"Nil Comparison", nil, "AES256", "eq", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got bool
			switch tt.op {
			case "eq":
				got = EqualValues(tt.a, tt.b)
			case "gt":
				got = GreaterThan(tt.a, tt.b)
			case "lt":
				got = LessThan(tt.a, tt.b)
			}

			if got != tt.expected {
				t.Errorf("%s: %v %s %v: got %v, want %v", tt.name, tt.a, tt.op, tt.b, got, tt.expected)
			}
		})
	}
}
