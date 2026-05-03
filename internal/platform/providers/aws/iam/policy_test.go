package iam

import (
	"testing"
)

func TestParsePolicyDocument_BasicAllow(t *testing.T) {
	raw := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "AllowS3",
			"Effect": "Allow",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	doc, err := ParsePolicyDocument(raw)
	if err != nil {
		t.Fatalf("ParsePolicyDocument: %v", err)
	}
	if len(doc.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(doc.Statement))
	}
	s := doc.Statement[0]
	if s.Effect != EffectAllow {
		t.Fatalf("expected Allow, got %s", s.Effect)
	}
	if len(s.Action) != 1 || s.Action[0] != "s3:GetObject" {
		t.Fatalf("expected [s3:GetObject], got %v", s.Action)
	}
	if len(s.Resource) != 1 || s.Resource[0] != "arn:aws:s3:::my-bucket/*" {
		t.Fatalf("expected [arn:aws:s3:::my-bucket/*], got %v", s.Resource)
	}
}

func TestParsePolicyDocument_ArrayActions(t *testing.T) {
	raw := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["s3:GetObject", "s3:PutObject"],
			"Resource": ["arn:aws:s3:::bucket-a/*", "arn:aws:s3:::bucket-b/*"]
		}]
	}`

	doc, err := ParsePolicyDocument(raw)
	if err != nil {
		t.Fatalf("ParsePolicyDocument: %v", err)
	}
	if len(doc.Statement[0].Action) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(doc.Statement[0].Action))
	}
	if len(doc.Statement[0].Resource) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(doc.Statement[0].Resource))
	}
}

func TestParsePolicyDocument_AdminPolicy(t *testing.T) {
	raw := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "*",
			"Resource": "*"
		}]
	}`

	doc, err := ParsePolicyDocument(raw)
	if err != nil {
		t.Fatalf("ParsePolicyDocument: %v", err)
	}
	allows := doc.Allows()
	if len(allows) != 1 {
		t.Fatalf("expected 1 allow, got %d", len(allows))
	}
	if allows[0].Action[0] != "*" {
		t.Fatalf("expected wildcard action, got %s", allows[0].Action[0])
	}
}

func TestParsePolicyDocument_MixedEffects(t *testing.T) {
	raw := `{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
			{"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"}
		]
	}`

	doc, err := ParsePolicyDocument(raw)
	if err != nil {
		t.Fatalf("ParsePolicyDocument: %v", err)
	}
	if len(doc.Allows()) != 1 {
		t.Fatalf("expected 1 allow, got %d", len(doc.Allows()))
	}
	if len(doc.Denies()) != 1 {
		t.Fatalf("expected 1 deny, got %d", len(doc.Denies()))
	}
}

func TestParsePolicyDocument_Empty(t *testing.T) {
	doc, err := ParsePolicyDocument("")
	if err != nil {
		t.Fatalf("ParsePolicyDocument empty: %v", err)
	}
	if len(doc.Statement) != 0 {
		t.Fatalf("expected 0 statements, got %d", len(doc.Statement))
	}
}
