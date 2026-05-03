package kernel

import "testing"

// Vendor-neutral algorithm parsing tests. AWS-specific assertions
// live in internal/platform/providers/aws/aws_test.go where
// aws.AlgorithmAWSKMS is registered with the kernel.
func TestParseAlgorithm(t *testing.T) {
	tests := []struct {
		input   string
		want    EncryptionAlgorithm
		wantErr bool
	}{
		{"aes256", AlgorithmAES256, false},
		{"AES256", AlgorithmAES256, false},
		{"none", AlgorithmNone, false},
		{"NONE", AlgorithmNone, false},
		{"chacha20", "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseAlgorithm(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAlgorithm(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseAlgorithm(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseAlgorithm_RegisteredAlgorithm_RoundTrip(t *testing.T) {
	const sentinel EncryptionAlgorithm = "stave-test:cipher"
	RegisterEncryptionAlgorithm(sentinel)
	got, err := ParseAlgorithm(string(sentinel))
	if err != nil {
		t.Fatalf("ParseAlgorithm(%q) error = %v after registration", sentinel, err)
	}
	if got != sentinel {
		t.Errorf("ParseAlgorithm(%q) = %v, want %v", sentinel, got, sentinel)
	}
}

func TestEncryptionAlgorithm_String(t *testing.T) {
	if AlgorithmAES256.String() != "aes256" {
		t.Errorf("AlgorithmAES256.String() = %q, want %q", AlgorithmAES256.String(), "aes256")
	}
}
