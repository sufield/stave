package kernel

import "testing"

func TestParseAlgorithm(t *testing.T) {
	tests := []struct {
		input   string
		want    EncryptionAlgorithm
		wantErr bool
	}{
		{"aws:kms", AlgorithmAWSKMS, false},
		{"AWS:KMS", AlgorithmAWSKMS, false},
		{"  aws:kms  ", AlgorithmAWSKMS, false},
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

func TestEncryptionAlgorithm_String(t *testing.T) {
	if AlgorithmAWSKMS.String() != "aws:kms" {
		t.Errorf("AlgorithmAWSKMS.String() = %q, want %q", AlgorithmAWSKMS.String(), "aws:kms")
	}
}
