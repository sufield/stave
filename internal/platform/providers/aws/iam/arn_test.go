package iam

import "testing"

func TestExtractAccountID(t *testing.T) {
	cases := []struct {
		arn  string
		want string
	}{
		{"arn:aws:s3:::my-bucket", ""},
		{"arn:aws:iam::123456789012:user/alice", "123456789012"},
		{"arn:aws:ec2:us-east-1:123456789012:instance/i-abc", "123456789012"},
		{"not-an-arn", ""},
		{"", ""},
		{"arn:aws:iam", ""},
	}
	for _, c := range cases {
		got := ExtractAccountID(c.arn)
		if got != c.want {
			t.Errorf("ExtractAccountID(%q) = %q, want %q", c.arn, got, c.want)
		}
	}
}

func TestParseARN(t *testing.T) {
	arn := "arn:aws:ec2:us-east-1:123456789012:instance/i-abc"
	got := ParseARN(arn)
	if got.AccountID != "123456789012" {
		t.Errorf("AccountID = %q, want 123456789012", got.AccountID)
	}
	if got.Region != "us-east-1" {
		t.Errorf("Region = %q, want us-east-1", got.Region)
	}
	if got.Service != "ec2" {
		t.Errorf("Service = %q, want ec2", got.Service)
	}
	if got.Resource != "instance/i-abc" {
		t.Errorf("Resource = %q, want instance/i-abc", got.Resource)
	}
}
