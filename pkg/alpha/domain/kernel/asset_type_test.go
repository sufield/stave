package kernel

import (
	"encoding/json"
	"testing"
)

func TestNewAssetType_Normalizes(t *testing.T) {
	got := NewAssetType("  AWS_S3_BUCKET ")
	if got != AssetType("aws_s3_bucket") {
		t.Fatalf("got %q, want %q", got, "aws_s3_bucket")
	}
}

func TestAssetTypeValidate(t *testing.T) {
	tests := []struct {
		name string
		in   AssetType
		ok   bool
	}{
		{name: "simple", in: AssetType("storage_bucket"), ok: true},
		{name: "dotted", in: AssetType("k8s.clusterrolebinding"), ok: true},
		{name: "hyphenated", in: AssetType("aws-s3-bucket"), ok: true},
		{name: "empty", in: AssetType(""), ok: false},
		{name: "unknown", in: UnknownAsset, ok: false},
		{name: "invalid char", in: AssetType("aws$s3"), ok: false},
		{name: "uppercase", in: AssetType("AWS_S3_BUCKET"), ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.in.Validate()
			if (err == nil) != tt.ok {
				t.Fatalf("Validate() error = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestParseAssetType(t *testing.T) {
	got, err := ParseAssetType("  APP_SIGNER ")
	if err != nil {
		t.Fatalf("ParseAssetType() error = %v", err)
	}
	if got != AssetType("app_signer") {
		t.Fatalf("got %q, want %q", got, "app_signer")
	}
}

func TestAssetTypeDomain(t *testing.T) {
	tests := []struct {
		name string
		in   AssetType
		want string
	}{
		{name: "aws s3", in: AssetType("aws_s3_bucket"), want: "aws_s3"},
		{name: "storage bucket", in: AssetType("storage_bucket"), want: "storage_bucket"},
		{name: "one segment", in: AssetType("custom"), want: "custom"},
		{name: "empty", in: AssetType(""), want: string(UnknownAsset)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.in.Domain()
			if got != tt.want {
				t.Fatalf("Domain() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAssetTypeUnmarshalJSON_Validates(t *testing.T) {
	var rt AssetType
	if err := json.Unmarshal([]byte(`"AWS_S3_BUCKET"`), &rt); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rt != AssetType("aws_s3_bucket") {
		t.Fatalf("got %q, want %q", rt, "aws_s3_bucket")
	}

	if err := json.Unmarshal([]byte(`"bad$type"`), &rt); err == nil {
		t.Fatal("expected error for invalid resource type")
	}

	if err := json.Unmarshal([]byte(`""`), &rt); err != nil {
		t.Fatalf("expected empty JSON type to be accepted, got: %v", err)
	}
	if rt != "" {
		t.Fatalf("expected empty type, got %q", rt)
	}
	if rt.String() != string(UnknownAsset) {
		t.Fatalf("expected empty type String() to return %q, got %q", UnknownAsset, rt.String())
	}
}
