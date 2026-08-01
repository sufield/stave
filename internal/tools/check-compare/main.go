// Command check-compare validates Stave's IAM escalation detection against
// AWS Access Analyzer Check APIs. Currently implements CheckAccessNotGranted.
//
// Usage:
//
//	go run ./internal/tools/check-compare
//	go run ./internal/tools/check-compare --skip-aws
//	go run ./internal/tools/check-compare --fixture testdata/e2e/e2e-iam-escalate-self-cluster/
//	go run ./internal/tools/check-compare --format json
//	go run ./internal/tools/check-compare --only-disagreements
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/internal/platform/providers/aws/iam"
)

// escalationActions are the IAM actions Stave checks for privilege escalation.
var escalationActions = []string{
	"iam:PassRole",
	"iam:AttachUserPolicy",
	"iam:AttachRolePolicy",
	"iam:AttachGroupPolicy",
	"iam:PutUserPolicy",
	"iam:PutRolePolicy",
	"iam:PutGroupPolicy",
	"iam:CreateAccessKey",
	"iam:CreateLoginProfile",
	"iam:UpdateLoginProfile",
	"iam:AddUserToGroup",
	"iam:UpdateAssumeRolePolicy",
}

func main() {
	skipAWS := flag.Bool("skip-aws", false, "skip AWS API calls (resolver-only mode)")
	format := flag.String("format", "text", "output format: text or json")
	onlyDisagree := flag.Bool("only-disagreements", false, "show only disagreements")
	fixture := flag.String("fixture", "", "path to fixture directory (extracts policies from observations)")
	flag.Parse()

	var cases []TestCase
	if *fixture != "" {
		var err error
		cases, err = extractFromFixture(*fixture)
		if err != nil {
			fmt.Fprintf(os.Stderr, "extract fixture: %v\n", err)
			os.Exit(2)
		}
	} else {
		cases = buildTestCases()
	}
	results := run(cases, *skipAWS)

	switch *format {
	case "json":
		printJSON(results)
	default:
		printText(results, *onlyDisagree)
	}

	for _, r := range results {
		if !r.Agree && r.AWSResult != "" {
			os.Exit(3)
		}
	}
}

// TestCase is one policy tested against multiple escalation actions.
type TestCase struct {
	Name         string
	PolicyJSON   string
	SCPJSON      string
	BoundaryJSON string
	Actions      []string // escalation actions to check
	Notes        string
}

// Result is the comparison output for a single action check.
type Result struct {
	CaseName     string `json:"case"`
	Action       string `json:"action"`
	StavePresent bool   `json:"stave_present"`
	StaveLevel   string `json:"stave_level"`
	AWSResult    string `json:"aws_result,omitempty"` // PASS or FAIL
	AWSGranted   bool   `json:"aws_granted"`          // true if FAIL (access might be granted)
	Agree        bool   `json:"agree"`
	DisagreeType string `json:"disagree_type,omitempty"` // false_positive, false_negative
	Notes        string `json:"notes,omitempty"`
}

func run(cases []TestCase, skipAWS bool) []Result {
	var results []Result
	for _, tc := range cases {
		staveResult := resolveWithStave(tc)

		for _, action := range tc.Actions {
			stavePresent := actionInGrants(strings.ToLower(action), staveResult.EffectiveAllow)

			r := Result{
				CaseName:     tc.Name,
				Action:       action,
				StavePresent: stavePresent,
				StaveLevel:   string(staveResult.PrivilegeLevel),
				Notes:        tc.Notes,
			}

			if !skipAWS {
				awsResult := checkAccessNotGranted(tc.PolicyJSON, action)
				r.AWSResult = awsResult
				r.AWSGranted = awsResult == "FAIL"
				r.Agree = r.StavePresent == r.AWSGranted
				if !r.Agree {
					if r.AWSGranted && !r.StavePresent {
						r.DisagreeType = "false_negative"
					} else {
						r.DisagreeType = "false_positive"
					}
				}
			} else {
				r.Agree = true
			}

			results = append(results, r)
		}
	}
	return results
}

func resolveWithStave(tc TestCase) iam.ResolvedPermissions {
	doc, err := iam.ParsePolicyDocument(tc.PolicyJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARN: %s: parse identity policy: %v\n", tc.Name, err)
		return iam.ResolvedPermissions{Incomplete: true}
	}

	input := iam.ResolutionInput{
		PrincipalARN:     "arn:aws:iam::111122223333:user/test-user",
		IdentityPolicies: []iam.PolicyDocument{doc},
		SCPPresent:       true,
	}

	if tc.SCPJSON != "" {
		scp, err := iam.ParsePolicyDocument(tc.SCPJSON)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: %s: parse SCP: %v\n", tc.Name, err)
		} else {
			input.SCPHierarchy = []iam.PolicyDocument{scp}
		}
	}

	if tc.BoundaryJSON != "" {
		boundary, err := iam.ParsePolicyDocument(tc.BoundaryJSON)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: %s: parse boundary: %v\n", tc.Name, err)
		} else {
			input.BoundaryPresent = true
			input.BoundaryPolicy = &boundary
		}
	}

	return iam.Resolve(input)
}

func actionInGrants(action string, grants []iam.ActionGrant) bool {
	for _, g := range grants {
		grantAction := strings.ToLower(g.Action)
		if grantAction == action || grantAction == "*" {
			return true
		}
		if strings.HasSuffix(grantAction, ":*") {
			prefix := grantAction[:len(grantAction)-1]
			if strings.HasPrefix(action, prefix) {
				return true
			}
		}
	}
	return false
}

func checkAccessNotGranted(policyJSON, action string) string {
	accessJSON := fmt.Sprintf(`[{"actions":[%q],"resources":["*"]}]`, action)

	cmd := exec.Command("aws", "accessanalyzer", "check-access-not-granted",
		"--policy-document", policyJSON,
		"--access", accessJSON,
		"--policy-type", "IDENTITY_POLICY",
		"--output", "json",
	)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			fmt.Fprintf(os.Stderr, "WARN: check-access-not-granted failed: %s\n", exitErr.Stderr)
		}
		return "error"
	}

	var resp struct {
		Result  string `json:"result"`
		Message string `json:"message"`
		Reasons []struct {
			Description    string `json:"description"`
			StatementID    string `json:"statementId"`
			StatementIndex int    `json:"statementIndex"`
		} `json:"reasons"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return "parse_error"
	}
	return resp.Result
}

func printText(results []Result, onlyDisagree bool) {
	caseOrder := []string{}
	byCase := map[string][]Result{}
	for _, r := range results {
		if _, seen := byCase[r.CaseName]; !seen {
			caseOrder = append(caseOrder, r.CaseName)
		}
		byCase[r.CaseName] = append(byCase[r.CaseName], r)
	}

	total, agree, disagree := 0, 0, 0
	var fn, fp int

	fmt.Println("═══════════════════════════════════════════════════")
	fmt.Println(" CheckAccessNotGranted Comparison Report")
	fmt.Println("═══════════════════════════════════════════════════")
	fmt.Println()

	for _, name := range caseOrder {
		rs := byCase[name]
		if onlyDisagree {
			hasDisagree := false
			for _, r := range rs {
				if !r.Agree {
					hasDisagree = true
				}
			}
			if !hasDisagree {
				total += len(rs)
				agree += len(rs)
				continue
			}
		}

		fmt.Printf("Case: %s\n", name)
		if rs[0].Notes != "" {
			fmt.Printf("      %s\n", rs[0].Notes)
		}
		fmt.Printf("  Privilege level: %s\n\n", rs[0].StaveLevel)

		fmt.Printf("  %-40s %-14s %-14s %-6s\n", "Action", "Stave", "AWS", "Match")
		fmt.Printf("  %-40s %-14s %-14s %-6s\n",
			strings.Repeat("─", 40),
			strings.Repeat("─", 14),
			strings.Repeat("─", 14),
			strings.Repeat("─", 6))

		for _, r := range rs {
			total++
			staveLabel := "absent"
			if r.StavePresent {
				staveLabel = "present"
			}
			awsLabel := r.AWSResult
			if awsLabel == "" {
				awsLabel = "(skipped)"
			}
			matchLabel := "✓"
			if !r.Agree {
				matchLabel = "✗ " + r.DisagreeType
				disagree++
				if r.DisagreeType == "false_negative" {
					fn++
				} else {
					fp++
				}
			} else {
				agree++
			}
			fmt.Printf("  %-40s %-14s %-14s %s\n", r.Action, staveLabel, awsLabel, matchLabel)
		}
		fmt.Println()
	}

	fmt.Println("═══════════════════════════════════════════════════")
	fmt.Printf(" Actions tested:     %d\n", total)
	fmt.Printf(" Agreements:         %d (%d%%)\n", agree, pct(agree, total))
	fmt.Printf(" Disagreements:      %d\n", disagree)
	if disagree > 0 {
		fmt.Printf("   False negatives:  %d (AWS says granted, Stave misses)\n", fn)
		fmt.Printf("   False positives:  %d (AWS says not granted, Stave over-reports)\n", fp)
	}
	fmt.Println("═══════════════════════════════════════════════════")
}

func printJSON(results []Result) {
	agree, disagree, fn, fp := 0, 0, 0, 0
	for _, r := range results {
		if r.Agree {
			agree++
		} else {
			disagree++
			if r.DisagreeType == "false_negative" {
				fn++
			} else {
				fp++
			}
		}
	}

	out := map[string]any{
		"api":             "CheckAccessNotGranted",
		"tested":          len(results),
		"agree":           agree,
		"disagree":        disagree,
		"false_negatives": fn,
		"false_positives": fp,
		"agreement_rate":  float64(agree) / float64(max(len(results), 1)),
		"details":         results,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

func pct(n, total int) int {
	if total == 0 {
		return 0
	}
	return n * 100 / total
}

// extractFromFixture loads observation JSON files from a fixture
// directory and extracts IAM policy documents, testing each against
// the escalation action set.
func extractFromFixture(dir string) ([]TestCase, error) {
	obsDir := filepath.Join(dir, "observations")
	if _, err := os.Stat(obsDir); err != nil {
		obsDir = dir
	}

	files, err := filepath.Glob(filepath.Join(obsDir, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no JSON files in %s", obsDir)
	}

	seen := map[string]bool{}
	var cases []TestCase

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var obs struct {
			Assets []struct {
				ID         string         `json:"id"`
				Type       string         `json:"type"`
				Properties map[string]any `json:"properties"`
			} `json:"assets"`
		}
		if err := json.Unmarshal(data, &obs); err != nil {
			continue
		}

		for _, a := range obs.Assets {
			if seen[a.ID] {
				continue
			}
			seen[a.ID] = true

			identity, _ := a.Properties["identity"].(map[string]any)
			if identity == nil {
				continue
			}

			policyJSON, _ := identity["policies_json"]
			if policyJSON == nil {
				continue
			}

			var policyStr string
			switch v := policyJSON.(type) {
			case string:
				policyStr = v
			case map[string]any:
				b, _ := json.Marshal(v)
				policyStr = string(b)
			default:
				continue
			}

			if policyStr == "" {
				continue
			}

			cases = append(cases, TestCase{
				Name:       sanitizeID(a.ID),
				PolicyJSON: policyStr,
				Actions:    escalationActions,
				Notes:      fmt.Sprintf("extracted from %s (%s)", filepath.Base(f), a.Type),
			})
		}
	}

	if len(cases) == 0 {
		return nil, fmt.Errorf("no IAM policies found in %s", dir)
	}
	return cases, nil
}

func sanitizeID(id string) string {
	s := strings.ReplaceAll(id, "arn:aws:", "")
	s = strings.ReplaceAll(s, "::", "_")
	for _, c := range []string{"/", ":", " "} {
		s = strings.ReplaceAll(s, c, "_")
	}
	if len(s) > 60 {
		s = s[len(s)-60:]
	}
	return s
}

// buildTestCases returns the curated test corpus for CheckAccessNotGranted.
// Each case is a policy + the escalation actions to test against it.
func buildTestCases() []TestCase {
	return []TestCase{
		{
			Name: "admin-all-escalation",
			PolicyJSON: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": "*",
					"Resource": "*"
				}]
			}`,
			Actions: escalationActions,
			Notes:   "Full admin — all escalation actions should be present (AWS FAIL for all)",
		},
		{
			Name: "s3-only-no-escalation",
			PolicyJSON: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": "s3:*",
					"Resource": "*"
				}]
			}`,
			Actions: escalationActions,
			Notes:   "S3 full access — no escalation actions should be present (AWS PASS for all)",
		},
		{
			Name: "passrole-only",
			PolicyJSON: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": "iam:PassRole",
					"Resource": "*"
				}]
			}`,
			Actions: []string{"iam:PassRole", "iam:PutUserPolicy", "iam:AttachUserPolicy"},
			Notes:   "PassRole only — PassRole present, others absent",
		},
		{
			Name: "passrole-with-condition",
			PolicyJSON: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": "iam:PassRole",
					"Resource": "*",
					"Condition": {
						"StringEquals": {
							"iam:PassedToService": "lambda.amazonaws.com"
						}
					}
				}]
			}`,
			Actions: []string{"iam:PassRole"},
			Notes:   "Conditional PassRole — Stave says present (condition COULD be met), AWS FAIL (conditionally granted)",
		},
		{
			Name: "scp-blocks-escalation",
			PolicyJSON: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": "*",
					"Resource": "*"
				}]
			}`,
			SCPJSON: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": "s3:*",
					"Resource": "*"
				}]
			}`,
			Actions: []string{"iam:PassRole", "iam:PutUserPolicy"},
			Notes:   "SCP blocks IAM — known semantic difference: CheckAccessNotGranted evaluates identity policy alone (no SCP context)",
		},
		{
			Name: "boundary-blocks-escalation",
			PolicyJSON: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": ["iam:*", "s3:*"],
					"Resource": "*"
				}]
			}`,
			BoundaryJSON: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": ["s3:*", "iam:PassRole"],
					"Resource": "*"
				}]
			}`,
			Actions: []string{"iam:PassRole", "iam:PutUserPolicy", "iam:AttachUserPolicy"},
			Notes:   "Boundary allows only S3+PassRole — PutUserPolicy should be blocked by boundary (Stave resolves, AWS does not see boundary)",
		},
		{
			Name: "explicit-deny-passrole",
			PolicyJSON: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": ["iam:PutUserPolicy", "iam:AttachUserPolicy", "iam:PassRole"],
						"Resource": "*"
					},
					{
						"Effect": "Deny",
						"Action": "iam:PassRole",
						"Resource": "*"
					}
				]
			}`,
			Actions: []string{"iam:PassRole", "iam:PutUserPolicy", "iam:AttachUserPolicy"},
			Notes:   "Explicit deny on PassRole — both should agree PassRole is denied",
		},
		{
			Name: "multiple-escalation-vectors",
			PolicyJSON: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": [
						"iam:PassRole",
						"lambda:CreateFunction",
						"iam:CreateAccessKey",
						"iam:UpdateLoginProfile"
					],
					"Resource": "*"
				}]
			}`,
			Actions: escalationActions,
			Notes:   "Multiple vectors — PassRole, CreateAccessKey, UpdateLoginProfile present; others absent",
		},
	}
}
