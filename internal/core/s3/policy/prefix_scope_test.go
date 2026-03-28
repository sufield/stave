package policy

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestPrefixScopeAnalysisWildcardResource(t *testing.T) {
	engine := mustParse(t, `{
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "PublicRead",
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::bucket/*"
		}]
	}`)

	result := engine.AnalyzeScopes()

	if len(result.Scopes) != 1 {
		t.Fatalf("expected 1 scope, got %d", len(result.Scopes))
	}
	if result.Scopes[0] != kernel.WildcardPrefix {
		t.Errorf("expected WildcardPrefix, got %q", result.Scopes[0])
	}
	if result.SourceByScope[kernel.WildcardPrefix] != "sid:PublicRead" {
		t.Errorf("expected source 'sid:PublicRead', got %q", result.SourceByScope[kernel.WildcardPrefix])
	}
}

func TestPrefixScopeAnalysisPrefixedResource(t *testing.T) {
	engine := mustParse(t, `{
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "InvoiceAccess",
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::bucket/invoices/*"
		}]
	}`)

	result := engine.AnalyzeScopes()

	if len(result.Scopes) != 1 {
		t.Fatalf("expected 1 scope, got %d", len(result.Scopes))
	}
	expected := kernel.ObjectPrefix("invoices/")
	if result.Scopes[0] != expected {
		t.Errorf("expected %q, got %q", expected, result.Scopes[0])
	}
	if result.SourceByScope[expected] != "sid:InvoiceAccess" {
		t.Errorf("expected source 'sid:InvoiceAccess', got %q", result.SourceByScope[expected])
	}
}

func TestPrefixScopeAnalysisNonAllowSkipped(t *testing.T) {
	engine := mustParse(t, `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Deny",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::bucket/*"
		}]
	}`)

	result := engine.AnalyzeScopes()

	if len(result.Scopes) != 0 {
		t.Errorf("expected 0 scopes for Deny, got %d", len(result.Scopes))
	}
}

func TestPrefixScopeAnalysisNonPublicPrincipalSkipped(t *testing.T) {
	engine := mustParse(t, `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::bucket/*"
		}]
	}`)

	result := engine.AnalyzeScopes()

	if len(result.Scopes) != 0 {
		t.Errorf("expected 0 scopes for specific account principal, got %d", len(result.Scopes))
	}
}

func TestPrefixScopeAnalysisNonReadActionsSkipped(t *testing.T) {
	engine := mustParse(t, `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:PutObject",
			"Resource": "arn:aws:s3:::bucket/*"
		}]
	}`)

	result := engine.AnalyzeScopes()

	if len(result.Scopes) != 0 {
		t.Errorf("expected 0 scopes for PutObject, got %d", len(result.Scopes))
	}
}

func TestPrefixScopeAnalysisSidAbsentUsesIndex(t *testing.T) {
	engine := mustParse(t, `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::bucket/*"
		}]
	}`)

	result := engine.AnalyzeScopes()

	if len(result.Scopes) != 1 {
		t.Fatalf("expected 1 scope, got %d", len(result.Scopes))
	}
	if result.SourceByScope[kernel.WildcardPrefix] != "idx:0" {
		t.Errorf("expected source 'idx:0', got %q", result.SourceByScope[kernel.WildcardPrefix])
	}
}

func TestPrefixScopeAnalysisS3WildcardAction(t *testing.T) {
	engine := mustParse(t, `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:*",
			"Resource": "arn:aws:s3:::bucket/data/*"
		}]
	}`)

	result := engine.AnalyzeScopes()

	if len(result.Scopes) != 1 {
		t.Fatalf("expected 1 scope, got %d", len(result.Scopes))
	}
	expected := kernel.ObjectPrefix("data/")
	if result.Scopes[0] != expected {
		t.Errorf("expected %q, got %q", expected, result.Scopes[0])
	}
}

func TestPrefixScopeAnalysisFullWildcardAction(t *testing.T) {
	engine := mustParse(t, `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "*",
			"Resource": "arn:aws:s3:::bucket/*"
		}]
	}`)

	result := engine.AnalyzeScopes()

	if len(result.Scopes) != 1 {
		t.Fatalf("expected 1 scope, got %d", len(result.Scopes))
	}
	if result.Scopes[0] != kernel.WildcardPrefix {
		t.Errorf("expected WildcardPrefix, got %q", result.Scopes[0])
	}
}

func TestPrefixScopeAnalysisAWSPrincipalWildcard(t *testing.T) {
	engine := mustParse(t, `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "*"},
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::bucket/*"
		}]
	}`)

	result := engine.AnalyzeScopes()

	if len(result.Scopes) != 1 {
		t.Fatalf("expected 1 scope for AWS:* principal, got %d", len(result.Scopes))
	}
}

func TestPrefixScopeAnalysisDeduplicatesScopes(t *testing.T) {
	engine := mustParse(t, `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "First",
				"Effect": "Allow",
				"Principal": "*",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::bucket/*"
			},
			{
				"Sid": "Second",
				"Effect": "Allow",
				"Principal": "*",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::bucket/*"
			}
		]
	}`)

	result := engine.AnalyzeScopes()

	if len(result.Scopes) != 1 {
		t.Errorf("expected 1 deduplicated scope, got %d", len(result.Scopes))
	}
	if result.SourceByScope[kernel.WildcardPrefix] != "sid:First" {
		t.Errorf("expected first Sid to win, got %q", result.SourceByScope[kernel.WildcardPrefix])
	}
}

func TestPrefixScopeAnalysisEmptyPolicy(t *testing.T) {
	engine := mustParse(t, `{"Version": "2012-10-17", "Statement": []}`)

	result := engine.AnalyzeScopes()

	if len(result.Scopes) != 0 {
		t.Errorf("expected 0 scopes for empty statement list, got %d", len(result.Scopes))
	}
	if result.SourceByScope == nil {
		t.Error("expected non-nil SourceByScope map")
	}
}
