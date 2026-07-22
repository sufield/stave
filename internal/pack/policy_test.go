package pack

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestSynthesizePolicy_ValidJSON(t *testing.T) {
	calls := []ServiceCalls{
		{Service: "ec2", Calls: []string{
			"aws ec2 describe-instances",
			"aws ec2 describe-security-groups",
		}},
		{Service: "s3", Calls: []string{
			"aws s3api get-bucket-policy",
			"aws s3api get-bucket-encryption",
		}},
	}
	data, err := SynthesizePolicy(calls)
	if err != nil {
		t.Fatal(err)
	}

	var doc iamPolicy
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, data)
	}
	if doc.Version != "2012-10-17" {
		t.Errorf("Version = %q, want 2012-10-17", doc.Version)
	}
	if len(doc.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(doc.Statement))
	}
	stmt := doc.Statement[0]
	if stmt.Effect != "Allow" {
		t.Errorf("Effect = %q, want Allow", stmt.Effect)
	}
	if stmt.Resource != "*" {
		t.Errorf("Resource = %q, want *", stmt.Resource)
	}
	want := []string{
		"ec2:DescribeInstances",
		"ec2:DescribeSecurityGroups",
		"s3:GetBucketEncryption",
		"s3:GetBucketPolicy",
	}
	if !slices.Equal(stmt.Action, want) {
		t.Errorf("Action = %v, want %v", stmt.Action, want)
	}
}

func TestSynthesizePolicy_Empty(t *testing.T) {
	data, err := SynthesizePolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc iamPolicy
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(doc.Statement) != 0 {
		t.Errorf("empty input should produce empty Statement, got %d", len(doc.Statement))
	}
}

func TestSynthesizePolicy_Dedup(t *testing.T) {
	calls := []ServiceCalls{
		{Service: "iam", Calls: []string{"aws iam list-roles"}},
		{Service: "iam", Calls: []string{"aws iam list-roles"}},
	}
	data, err := SynthesizePolicy(calls)
	if err != nil {
		t.Fatal(err)
	}
	var doc iamPolicy
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Statement) != 1 || len(doc.Statement[0].Action) != 1 {
		t.Errorf("duplicate actions should be deduped; got %v", doc.Statement)
	}
}

func TestSynthesizePolicy_StripsArguments(t *testing.T) {
	calls := []ServiceCalls{
		{Service: "iam", Calls: []string{
			"aws iam get-role --role-name {ROLE}",
			"aws iam generate-service-last-accessed-details --arn {ARN}",
		}},
	}
	data, err := SynthesizePolicy(calls)
	if err != nil {
		t.Fatal(err)
	}
	var doc iamPolicy
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"iam:GenerateServiceLastAccessedDetails",
		"iam:GetRole",
	}
	if !slices.Equal(doc.Statement[0].Action, want) {
		t.Errorf("Action = %v, want %v", doc.Statement[0].Action, want)
	}
}

func TestCLICallToIAMAction(t *testing.T) {
	tests := []struct {
		service string
		call    string
		want    string
	}{
		{"iam", "aws iam list-roles", "iam:ListRoles"},
		{"ec2", "aws ec2 describe-instances", "ec2:DescribeInstances"},
		{"config", "aws configservice describe-configuration-recorders", "config:DescribeConfigurationRecorders"},
		{"iam", "aws iam get-role --role-name {ROLE}", "iam:GetRole"},
		{"s3", "not-a-cli-call", ""},
	}
	for _, tt := range tests {
		got := cliCallToIAMAction(tt.service, tt.call)
		if got != tt.want {
			t.Errorf("cliCallToIAMAction(%q, %q) = %q, want %q", tt.service, tt.call, got, tt.want)
		}
	}
}
