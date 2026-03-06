package policy

import (
	"testing"

	"github.com/sufield/stave/internal/domain/evaluation/risk"
)

func TestEvaluatorMalformedPolicy(t *testing.T) {
	e := NewEvaluator(nil)
	report := e.Evaluate("{")

	if report.Score != ScoreCatastrophic {
		t.Fatalf("expected catastrophic score, got %d", report.Score)
	}
	if len(report.Findings) != 1 || report.Findings[0] != "Malformed JSON Policy" {
		t.Fatalf("unexpected findings: %#v", report.Findings)
	}
}

func TestEvaluatorPublicWriteUnscoped(t *testing.T) {
	e := NewEvaluator(nil)
	report := e.Evaluate(`{
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

	if report.Score != ScoreCritical {
		t.Fatalf("expected critical score, got %d", report.Score)
	}
	if !report.IsPublic {
		t.Fatalf("expected IsPublic=true")
	}
	if !report.Permissions.Has(PermWrite | PermACLWrite) {
		t.Fatalf("expected write+aclwrite permissions, got %v", report.Permissions)
	}
	if len(report.Findings) != 1 || report.Findings[0] != "Unrestricted Public Write/ACL Access" {
		t.Fatalf("unexpected findings: %#v", report.Findings)
	}
}

func TestEvaluatorPublicReadUnscoped(t *testing.T) {
	e := NewEvaluator(nil)
	report := e.Evaluate(`{
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

	if report.Score != ScoreWarning {
		t.Fatalf("expected warning score, got %d", report.Score)
	}
	if len(report.Findings) != 1 || report.Findings[0] != "Unrestricted Public Read Access" {
		t.Fatalf("unexpected findings: %#v", report.Findings)
	}
}

func TestEvaluatorPublicReadNetworkScoped(t *testing.T) {
	e := NewEvaluator(nil)
	report := e.Evaluate(`{
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

	if report.Score != ScoreSafe {
		t.Fatalf("expected safe score, got %d", report.Score)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("expected no findings, got %#v", report.Findings)
	}
}

func TestEvaluatorAuthenticatedFullControl(t *testing.T) {
	e := NewEvaluator(nil)
	report := e.Evaluate(`{
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

	if report.Score != ScoreWarning {
		t.Fatalf("expected warning score, got %d", report.Score)
	}
	if !report.Permissions.Has(PermFullControl) {
		t.Fatalf("expected full control permissions, got %v", report.Permissions)
	}
	if len(report.Findings) != 1 || report.Findings[0] != "Full Admin access granted to Authenticated Users" {
		t.Fatalf("unexpected findings: %#v", report.Findings)
	}
}

func TestEvaluator_CalculateStatementRisk_DenyAndNilReportGuards(t *testing.T) {
	e := NewEvaluator(nil)

	// nil report with deny — should not panic
	e.calculateStatementRisk(risk.StatementContext{
		Permissions:     PermFullControl,
		IsPublic:        true,
		IsAuthenticated: false,
		IsNetworkScoped: false,
		IsAllow:         false,
		Report:          nil,
	})

	report := risk.Report{}
	e.calculateStatementRisk(risk.StatementContext{
		Permissions:     PermFullControl,
		IsPublic:        true,
		IsAuthenticated: false,
		IsNetworkScoped: false,
		IsAllow:         false,
		Report:          &report,
	})

	if report.Score != ScoreSafe {
		t.Fatalf("expected score to remain safe for deny statement, got %d", report.Score)
	}
	if report.IsPublic {
		t.Fatalf("expected IsPublic=false for deny statement")
	}
	if len(report.Findings) != 0 {
		t.Fatalf("expected no findings for deny statement, got %#v", report.Findings)
	}
}
