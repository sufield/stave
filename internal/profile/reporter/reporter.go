// Package reporter produces human-readable and machine-readable output
// from profile evaluation reports. Text format groups findings by severity
// with compliance citations. JSON format provides structured output for
// automation. Both formats include the BAA disclaimer for HIPAA profiles.
package reporter

import (
	"io"

	"github.com/sufield/stave/internal/profile"
)

// Reporter writes a ProfileReport to the given writer.
type Reporter interface {
	Write(w io.Writer, report profile.ProfileReport, meta ReportMeta) error
}

// ReportMeta holds contextual information rendered in the report header.
type ReportMeta struct {
	BucketName string `json:"bucket_name"`
	AccountID  string `json:"account_id"`
	Timestamp  string `json:"timestamp"`
}

const disclaimer = "Stave evaluates technical controls only. A BAA with AWS is a contractual prerequisite for HIPAA compliance that Stave cannot verify."
