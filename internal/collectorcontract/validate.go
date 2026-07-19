package collectorcontract

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
)

// Status classifies the outcome of a single field check.
type Status int

const (
	StatusPass        Status = iota
	StatusNull               // field null/absent, null semantics = not_evaluated
	StatusMissing            // field absent from properties entirely
	StatusWrongType          // e.g. string "true" instead of bool true
	StatusNullNotSafe        // field null where it should be explicit (strict mode)
)

// FieldResult is the outcome of checking one contracted field on one asset.
type FieldResult struct {
	Field     string
	AssetID   string
	AssetType string
	Status    Status
	Detail    string
	FixHint   string
	Consumers []string
}

// Report aggregates contract validation results across all observations.
type Report struct {
	FieldsChecked int
	Pass          int
	Null          int
	Missing       int
	WrongType     int

	Violations []FieldResult
}

// HasViolations returns true if any field is missing or wrong-typed.
func (r *Report) HasViolations() bool {
	return r.Missing > 0 || r.WrongType > 0
}

// HasWarnings returns true if any field was null (not evaluated).
func (r *Report) HasWarnings() bool {
	return r.Null > 0
}

// ViolationCount returns the total number of hard violations.
func (r *Report) ViolationCount() int {
	return r.Missing + r.WrongType
}

// CoveragePercent returns the percentage of checked fields that passed.
func (r *Report) CoveragePercent() int {
	if r.FieldsChecked == 0 {
		return 0
	}
	return r.Pass * 100 / r.FieldsChecked
}

// ValidateSnapshots checks all assets in the provided snapshots against the
// contract. Only checks fields that actually appear in each asset's properties
// or are expected based on the field name pattern.
func ValidateSnapshots(snapshots []asset.Snapshot, contract *Contract) *Report {
	idx := contract.FieldIndex()
	r := &Report{}

	for _, snap := range snapshots {
		for _, a := range snap.Assets {
			checkAsset(a, idx, r)
		}
	}

	return r
}

func checkAsset(a asset.Asset, idx map[string]*Entry, r *Report) {
	for field, entry := range idx {
		val, exists := a.Properties[field]
		r.FieldsChecked++

		if !exists {
			// Only report missing if this asset type could plausibly have
			// the field. Use prefix matching: denies_* fields apply to
			// org/scp/policy asset types, has_public_ip to ec2/rds, etc.
			if !fieldAppliesTo(field, string(a.Type)) {
				r.Pass++
				continue
			}
			r.Missing++
			r.Violations = append(r.Violations, FieldResult{
				Field:     field,
				AssetID:   string(a.ID),
				AssetType: string(a.Type),
				Status:    StatusMissing,
				Detail:    "field absent from observation properties",
				FixHint:   entry.Postcondition,
				Consumers: entry.Consumers,
			})
			continue
		}

		if val == nil {
			r.Null++
			r.Violations = append(r.Violations, FieldResult{
				Field:     field,
				AssetID:   string(a.ID),
				AssetType: string(a.Type),
				Status:    StatusNull,
				Detail:    "field is null (not_evaluated)",
				FixHint:   nullHint(entry),
				Consumers: entry.Consumers,
			})
			continue
		}

		if entry.Type == "boolean" {
			if status, detail := checkBoolean(val); status != StatusPass {
				r.WrongType++
				r.Violations = append(r.Violations, FieldResult{
					Field:     field,
					AssetID:   string(a.ID),
					AssetType: string(a.Type),
					Status:    status,
					Detail:    detail,
					FixHint:   fmt.Sprintf("emit boolean, got %s. %s", detail, entry.Postcondition),
					Consumers: entry.Consumers,
				})
				continue
			}
		}

		r.Pass++
	}
}

func checkBoolean(val any) (Status, string) {
	switch v := val.(type) {
	case bool:
		return StatusPass, ""
	case string:
		return StatusWrongType, fmt.Sprintf("string %q", v)
	case float64:
		return StatusWrongType, fmt.Sprintf("number %v", v)
	case int:
		return StatusWrongType, fmt.Sprintf("number %d", v)
	default:
		return StatusWrongType, fmt.Sprintf("unexpected type %T", val)
	}
}

func nullHint(entry *Entry) string {
	if len(entry.Consumers) == 0 {
		return "field is null (not_evaluated). No controls currently consume this field."
	}
	return fmt.Sprintf(
		"field is null (not_evaluated). Controls %s will produce SILENT_RISK findings.",
		strings.Join(entry.Consumers, ", "),
	)
}

// fieldAppliesTo determines whether a contracted field is expected on a given
// asset type. Conservative: only flags missing fields when the asset type
// clearly should have them.
//
// ponytail: table-driven matching. Replace with contract-declared
// resource_types when the contract YAML grows that field.
func fieldAppliesTo(field, assetType string) bool {
	at := strings.ToLower(assetType)
	for _, rule := range fieldRules {
		if rule.match(field) {
			return rule.applies(at)
		}
	}
	return false
}

type fieldRule struct {
	match   func(string) bool
	applies func(string) bool
}

var fieldRules = []fieldRule{
	{prefix("denies_"), anyOf("organization", "scp", "account", "iam_account")},
	{exact("has_public_ip"), anyOf("ec2_instance", "rds", "elbv2", "elb_")},
	{exact("is_encrypted"), anyOf("ebs", "s3_bucket", "rds", "dynamodb", "sqs", "sns", "kinesis")},
	{anyExact("imdsv2_enforced", "imdsv2_required"), anyOf("ec2_instance", "launch_template")},
	{anyExact("public_read", "account_public_access_fully_blocked"), anyOf("s3")},
	{anyPrefix("has_data_access", "has_credential"), anyOf("iam_policy", "iam_role")},
	{prefix("has_admin"), anyOf("iam")},
	{exact("is_effectively_public"), anyOf("s3", "ec2", "rds")},
	{exact("is_dormant"), anyOf("iam", "ec2", "lambda")},
	{exact("is_orphan"), anyOf("iam", "ec2", "ebs", "lambda")},
	{anyPrefix("ssl_enforced", "tls_enforced", "https_enforced"), anyOf("elb", "cloudfront", "apigateway", "rds")},
}

func prefix(p string) func(string) bool {
	return func(f string) bool { return strings.HasPrefix(f, p) }
}
func exact(s string) func(string) bool { return func(f string) bool { return f == s } }
func anyExact(ss ...string) func(string) bool {
	return func(f string) bool { return slices.Contains(ss, f) }
}
func anyPrefix(ps ...string) func(string) bool {
	return func(f string) bool {
		for _, p := range ps {
			if strings.HasPrefix(f, p) {
				return true
			}
		}
		return false
	}
}
func anyOf(subs ...string) func(string) bool {
	return func(at string) bool {
		for _, s := range subs {
			if strings.Contains(at, s) {
				return true
			}
		}
		return false
	}
}
