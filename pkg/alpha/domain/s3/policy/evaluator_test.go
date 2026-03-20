package policy

import (
	"testing"

	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
)

func mustParse(t *testing.T, jsonPolicy string) *Document {
	t.Helper()
	doc, err := Parse(jsonPolicy)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	return doc
}

func TestEvaluatorNilDocument(t *testing.T) {
	e := NewEvaluator(nil)
	report := e.Evaluate(nil)

	if report.Score != risk.ScoreSafe {
		t.Fatalf("expected safe score for nil doc, got %d", report.Score)
	}
}

func TestEvaluatorEmptyPolicy(t *testing.T) {
	e := NewEvaluator(nil)
	doc := mustParse(t, "")
	report := e.Evaluate(doc)

	if report.Score != risk.ScoreSafe {
		t.Fatalf("expected safe score for empty policy, got %d", report.Score)
	}
}

func TestEvaluatorPublicWriteUnscoped(t *testing.T) {
	e := NewEvaluator(nil)
	doc := mustParse(t, `{
		"Version":"2012-10-17",
		"Statement":[
			{
				"Effect":"Allow",
				"Principal":"*",
				"Action":["s3:PutObject","s3:PutObjectAcl"],
				"Resource":"arn:aws:s3:::example/*"
			}
		]
	}`)
	report := e.Evaluate(doc)

	if report.Score != risk.ScoreCritical {
		t.Fatalf("expected critical score, got %d", report.Score)
	}
	if !report.IsPublic {
		t.Fatalf("expected IsPublic=true")
	}
	if !report.Permissions.Has(risk.PermWrite | risk.PermAdminWrite) {
		t.Fatalf("expected write+adminwrite permissions, got %v", report.Permissions)
	}
}

func TestEvaluatorPublicReadUnscoped(t *testing.T) {
	e := NewEvaluator(nil)
	doc := mustParse(t, `{
		"Version":"2012-10-17",
		"Statement":[
			{
				"Effect":"Allow",
				"Principal":"*",
				"Action":"s3:GetObject",
				"Resource":"arn:aws:s3:::example/*"
			}
		]
	}`)
	report := e.Evaluate(doc)

	if report.Score != risk.ScoreWarning {
		t.Fatalf("expected warning score, got %d", report.Score)
	}
}

func TestEvaluatorPublicReadNetworkScoped(t *testing.T) {
	e := NewEvaluator(nil)
	doc := mustParse(t, `{
		"Version":"2012-10-17",
		"Statement":[
			{
				"Effect":"Allow",
				"Principal":"*",
				"Action":"s3:GetObject",
				"Resource":"arn:aws:s3:::example/*",
				"Condition":{
					"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}
				}
			}
		]
	}`)
	report := e.Evaluate(doc)

	if report.Score != risk.ScoreSafe {
		t.Fatalf("expected safe score, got %d", report.Score)
	}
}

func TestEvaluatorAuthenticatedFullControl(t *testing.T) {
	e := NewEvaluator(nil)
	doc := mustParse(t, `{
		"Version":"2012-10-17",
		"Statement":[
			{
				"Effect":"Allow",
				"Principal":{"AWS":"arn:aws:iam::*:root"},
				"Action":"s3:*",
				"Resource":"*"
			}
		]
	}`)
	report := e.Evaluate(doc)

	if report.Score != risk.ScoreWarning {
		t.Fatalf("expected warning score, got %d", report.Score)
	}
	if !report.Permissions.Has(risk.PermFullControl) {
		t.Fatalf("expected full control permissions, got %v", report.Permissions)
	}
}

func TestEvaluator_DenyStatementSkipped(t *testing.T) {
	e := NewEvaluator(nil)
	doc := mustParse(t, `{
		"Version":"2012-10-17",
		"Statement":[
			{
				"Effect":"Deny",
				"Principal":"*",
				"Action":"s3:*",
				"Resource":"*"
			}
		]
	}`)
	report := e.Evaluate(doc)

	if report.Score != risk.ScoreSafe {
		t.Fatalf("expected score to remain safe for deny statement, got %d", report.Score)
	}
	if report.IsPublic {
		t.Fatalf("expected IsPublic=false for deny statement")
	}
}
