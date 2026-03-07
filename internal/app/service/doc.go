// Package service provides cross-cutting application services shared across
// multiple use cases.
//
// Services include evaluation execution (wrapping the domain engine), readiness
// validation (prerequisite checks before evaluation), content validation
// (schema compliance), and finding-detail enrichment (adding traces, exposure
// classification, and remediation guidance to raw findings).
package service
