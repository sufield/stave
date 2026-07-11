package snapshot

import (
	"strings"

	"github.com/sufield/stave/internal/core/asset"
)

// Summary is a lightweight struct extracted from raw snapshots for the
// recommendation engine. CEL predicates in recommend_when evaluate
// against this struct, not the full snapshot.
type Summary struct {
	Services       []string       `json:"services"`
	AccountCount   int            `json:"account_count"`
	AccountIDs     []string       `json:"account_ids"`
	RegionCount    int            `json:"region_count"`
	Regions        []string       `json:"regions"`
	ResourceCount  int            `json:"resource_count"`
	HasOrgRoot     bool           `json:"has_org_root"`
	HasSCPs        bool           `json:"has_scps"`
	HasCloudTrail  bool           `json:"has_cloudtrail"`
	HasGuardDuty   bool           `json:"has_guardduty"`
	HasFlowLogs    bool           `json:"has_flow_logs"`
	HasFirehose    bool           `json:"has_firehose"`
	HasReplication bool           `json:"has_replication"`
	S3BucketCount  int            `json:"s3_bucket_count"`
	IAMRoleCount   int            `json:"iam_role_count"`
	EvalTimeSet    bool           `json:"eval_time_set"`
	ServiceCounts  map[string]int `json:"service_counts"`
}

// ExtractSummary builds a Summary from loaded snapshots.
func ExtractSummary(snapshots asset.Snapshots, evalTimeSet bool) Summary {
	services := make(map[string]bool)
	accounts := make(map[string]bool)
	regions := make(map[string]bool)
	serviceCounts := make(map[string]int)

	var s Summary
	s.EvalTimeSet = evalTimeSet

	for _, snap := range snapshots {
		for _, a := range snap.Assets {
			s.ResourceCount++

			svc := serviceFromType(string(a.Type))
			if svc != "" {
				services[svc] = true
				serviceCounts[svc]++
			}

			if acct := extractAccount(a); acct != "" {
				accounts[acct] = true
			}
			if region := extractRegion(a); region != "" {
				regions[region] = true
			}

			classifyAsset(&s, a)
		}
	}

	s.Services = keys(services)
	s.AccountIDs = keys(accounts)
	s.AccountCount = len(accounts)
	s.Regions = keys(regions)
	s.RegionCount = len(regions)
	s.ServiceCounts = serviceCounts

	return s
}

func classifyAsset(s *Summary, a asset.Asset) {
	t := string(a.Type)
	switch {
	case t == "storage_bucket":
		s.S3BucketCount++
	case t == "iam_role":
		s.IAMRoleCount++
	case strings.Contains(t, "cloudtrail"):
		s.HasCloudTrail = true
	case strings.Contains(t, "guardduty"):
		s.HasGuardDuty = true
	case strings.Contains(t, "flow_log"):
		s.HasFlowLogs = true
	case strings.Contains(t, "firehose"):
		s.HasFirehose = true
	case strings.Contains(t, "organization"):
		s.HasOrgRoot = true
	case strings.Contains(t, "scp"):
		s.HasSCPs = true
	case strings.Contains(t, "replication"):
		s.HasReplication = true
	}
}

func serviceFromType(assetType string) string {
	parts := strings.SplitN(assetType, "_", 2)
	if len(parts) == 0 {
		return ""
	}
	switch parts[0] {
	case "storage":
		return "s3"
	case "iam":
		return "iam"
	case "aws":
		if len(parts) > 1 {
			return parts[1]
		}
		return "aws"
	default:
		return parts[0]
	}
}

func extractAccount(a asset.Asset) string {
	if id, ok := a.Properties["account_id"].(string); ok {
		return id
	}
	return ""
}

func extractRegion(a asset.Asset) string {
	if r, ok := a.Properties["region"].(string); ok {
		return r
	}
	return ""
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
