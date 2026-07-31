// Command simulate-compare validates Stave's IAM policy resolver against
// AWS SimulateCustomPolicy. It feeds raw IAM policy documents to both
// systems and reports per-action agreement/disagreement.
//
// Usage:
//
//	go run ./internal/tools/simulate-compare
//	go run ./internal/tools/simulate-compare --skip-aws
//	go run ./internal/tools/simulate-compare --fixture testdata/e2e/e2e-iam-recon-victim-selection/
//	go run ./internal/tools/simulate-compare --format json
//	go run ./internal/tools/simulate-compare --only-disagreements
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

	// Exit non-zero on disagreements.
	for _, r := range results {
		if !r.Agree && r.AWSDecision != "" {
			os.Exit(3)
		}
	}
}

// TestCase is one policy → action check.
type TestCase struct {
	Name         string
	PolicyJSON   string   // raw IAM policy document
	SCPJSON      string   // optional SCP; empty = no org constraint
	BoundaryJSON string   // optional boundary; empty = none
	Actions      []string // actions to test
	ResourceARN  string   // resource to evaluate against (default "*")
	Notes        string   // why this case matters
}

// Result is the comparison output for a single action.
type Result struct {
	CaseName     string `json:"case"`
	Action       string `json:"action"`
	Resource     string `json:"resource"`
	StaveAllows  bool   `json:"stave_allows"`
	StaveLevel   string `json:"stave_level"`
	AWSDecision  string `json:"aws_decision,omitempty"` // allowed, implicitDeny, explicitDeny
	AWSAllows    bool   `json:"aws_allows"`
	Agree        bool   `json:"agree"`
	DisagreeType string `json:"disagree_type,omitempty"` // false_positive, false_negative
	Notes        string `json:"notes,omitempty"`
}

func run(cases []TestCase, skipAWS bool) []Result {
	var results []Result
	for _, tc := range cases {
		resource := tc.ResourceARN
		if resource == "" {
			resource = "*"
		}

		staveResult := resolveWithStave(tc)

		for _, action := range tc.Actions {
			actionLower := strings.ToLower(action)
			staveAllows := actionInGrants(actionLower, staveResult.EffectiveAllow)

			r := Result{
				CaseName:    tc.Name,
				Action:      action,
				Resource:    resource,
				StaveAllows: staveAllows,
				StaveLevel:  string(staveResult.PrivilegeLevel),
				Notes:       tc.Notes,
			}

			if !skipAWS {
				decision := simulateWithAWS(tc.PolicyJSON, action, resource)
				r.AWSDecision = decision
				r.AWSAllows = decision == "allowed"
				r.Agree = r.StaveAllows == r.AWSAllows
				if !r.Agree {
					if r.AWSAllows && !r.StaveAllows {
						r.DisagreeType = "false_negative"
					} else {
						r.DisagreeType = "false_positive"
					}
				}
			} else {
				r.Agree = true // no AWS comparison; just report Stave
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
		// Wildcard: iam:* matches iam:PutUserPolicy
		if strings.HasSuffix(grantAction, ":*") {
			prefix := grantAction[:len(grantAction)-1]
			if strings.HasPrefix(action, prefix) {
				return true
			}
		}
	}
	return false
}

func simulateWithAWS(policyJSON, action, resource string) string {
	args := []string{
		"iam", "simulate-custom-policy",
		"--policy-input-list", policyJSON,
		"--action-names", action,
		"--output", "json",
	}
	if resource != "*" {
		args = append(args, "--resource-arns", resource)
	}

	cmd := exec.Command("aws", args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			fmt.Fprintf(os.Stderr, "WARN: aws simulate-custom-policy failed: %s\n", exitErr.Stderr)
		}
		return "error"
	}

	var resp struct {
		EvaluationResults []struct {
			EvalDecision string `json:"EvalDecision"`
		} `json:"EvaluationResults"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return "parse_error"
	}
	if len(resp.EvaluationResults) == 0 {
		return "no_result"
	}
	return resp.EvaluationResults[0].EvalDecision
}

func printText(results []Result, onlyDisagree bool) {
	// Group by case name.
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
	fmt.Println(" SimulateCustomPolicy Comparison Report")
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
			if r.StaveAllows {
				staveLabel = "present"
			}
			awsLabel := r.AWSDecision
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
		fmt.Printf("   False negatives:  %d (AWS allows, Stave misses)\n", fn)
		fmt.Printf("   False positives:  %d (AWS denies, Stave over-reports)\n", fp)
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
// directory and extracts IAM policy documents. It returns test cases
// for each principal that has policies_json or trust_policy_json.
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

			actions := extractActionsFromPolicy(policyStr)
			if len(actions) == 0 {
				continue
			}

			cases = append(cases, TestCase{
				Name:       sanitizeID(a.ID),
				PolicyJSON: policyStr,
				Actions:    actions,
				Notes:      fmt.Sprintf("extracted from %s (%s)", filepath.Base(f), a.Type),
			})
		}
	}

	if len(cases) == 0 {
		return nil, fmt.Errorf("no IAM policies found in %s", dir)
	}
	return cases, nil
}

// extractActionsFromPolicy parses a policy document and returns all
// actions mentioned in Allow statements, plus a set of probe actions
// that should NOT be allowed (for negative testing).
func extractActionsFromPolicy(policyJSON string) []string {
	doc, err := iam.ParsePolicyDocument(policyJSON)
	if err != nil {
		return nil
	}

	actionSet := map[string]bool{}
	for _, stmt := range doc.Statement {
		for _, a := range stmt.Action {
			actionSet[a] = true
		}
	}

	actions := make([]string, 0, len(actionSet)+3)
	for a := range actionSet {
		actions = append(actions, a)
	}

	// Add probe actions that should be denied (negative test).
	probes := []string{"iam:DeleteAccountAlias", "ec2:TerminateInstances", "lambda:DeleteFunction"}
	for _, p := range probes {
		if !actionSet[p] {
			actions = append(actions, p)
		}
	}
	return actions
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

// buildTestCases returns the curated test corpus. Each case is a
// realistic IAM policy document paired with the specific actions to
// test. Cases progress from trivial (admin wildcard) through the edge
// cases that trip up policy evaluators (NotAction, conditions,
// multi-statement deny+allow, resource scoping).
func buildTestCases() []TestCase {
	return []TestCase{
		adminWildcard(),
		singleServiceFullAccess(),
		putUserPolicyUnrestricted(),
		passRoleCreateFunction(),
		attachUserPolicySelf(),
		createPolicyVersion(),
		addUserToGroup(),
		notActionDeny(),
		conditionalAllow(),
		multiStatementDenyOverride(),
		wildcardWithResourceScope(),
		scpBlocksAdmin(),
		boundaryConstrainsElevated(),
	}
}

func adminWildcard() TestCase {
	return TestCase{
		Name: "admin-wildcard",
		PolicyJSON: `{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": "*",
				"Resource": "*"
			}]
		}`,
		Actions: []string{
			"iam:PutUserPolicy",
			"iam:AttachUserPolicy",
			"iam:PassRole",
			"s3:GetObject",
			"lambda:CreateFunction",
			"sts:AssumeRole",
			"ec2:RunInstances",
		},
		Notes: "Full admin — everything should be allowed",
	}
}

func singleServiceFullAccess() TestCase {
	return TestCase{
		Name: "s3-full-access",
		PolicyJSON: `{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": "s3:*",
				"Resource": "*"
			}]
		}`,
		Actions: []string{
			"s3:GetObject",
			"s3:PutObject",
			"s3:DeleteBucket",
			"iam:PutUserPolicy",
			"lambda:CreateFunction",
		},
		Notes: "S3 full access — IAM/Lambda should be denied",
	}
}

func putUserPolicyUnrestricted() TestCase {
	return TestCase{
		Name: "put-user-policy-unrestricted",
		PolicyJSON: `{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": [
					"iam:PutUserPolicy",
					"iam:ListUsers",
					"iam:GetUser"
				],
				"Resource": "*"
			}]
		}`,
		Actions: []string{
			"iam:PutUserPolicy",
			"iam:ListUsers",
			"iam:GetUser",
			"iam:AttachUserPolicy",
			"iam:CreateUser",
			"s3:GetObject",
		},
		Notes: "PutUserPolicy escalation vector — only listed actions should be allowed",
	}
}

func passRoleCreateFunction() TestCase {
	return TestCase{
		Name: "passrole-createfunction",
		PolicyJSON: `{
			"Version": "2012-10-17",
			"Statement": [
				{
					"Effect": "Allow",
					"Action": [
						"iam:PassRole",
						"lambda:CreateFunction",
						"lambda:InvokeFunction"
					],
					"Resource": "*"
				}
			]
		}`,
		Actions: []string{
			"iam:PassRole",
			"lambda:CreateFunction",
			"lambda:InvokeFunction",
			"lambda:DeleteFunction",
			"iam:AttachRolePolicy",
		},
		Notes: "PassRole+CreateFunction escalation — only the three listed actions should be allowed",
	}
}

func attachUserPolicySelf() TestCase {
	return TestCase{
		Name: "attach-user-policy-self",
		PolicyJSON: `{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": "iam:AttachUserPolicy",
				"Resource": "arn:aws:iam::111122223333:user/test-user"
			}]
		}`,
		ResourceARN: "arn:aws:iam::111122223333:user/test-user",
		Actions: []string{
			"iam:AttachUserPolicy",
		},
		Notes: "Self-attach — scoped to own ARN",
	}
}

func createPolicyVersion() TestCase {
	return TestCase{
		Name: "create-policy-version",
		PolicyJSON: `{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": [
					"iam:CreatePolicyVersion",
					"iam:SetDefaultPolicyVersion",
					"iam:ListPolicyVersions"
				],
				"Resource": "arn:aws:iam::111122223333:policy/DevPolicy"
			}]
		}`,
		ResourceARN: "arn:aws:iam::111122223333:policy/DevPolicy",
		Actions: []string{
			"iam:CreatePolicyVersion",
			"iam:SetDefaultPolicyVersion",
			"iam:ListPolicyVersions",
			"iam:DeletePolicyVersion",
			"iam:GetPolicy",
		},
		Notes: "Policy version manipulation — only the three listed actions should be allowed",
	}
}

func addUserToGroup() TestCase {
	return TestCase{
		Name: "add-user-to-group",
		PolicyJSON: `{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": [
					"iam:AddUserToGroup",
					"iam:ListGroups"
				],
				"Resource": "*"
			}]
		}`,
		Actions: []string{
			"iam:AddUserToGroup",
			"iam:ListGroups",
			"iam:RemoveUserFromGroup",
			"iam:CreateGroup",
		},
		Notes: "AddUserToGroup escalation — RemoveUserFromGroup and CreateGroup should be denied",
	}
}

func notActionDeny() TestCase {
	return TestCase{
		Name: "not-action-deny",
		PolicyJSON: `{
			"Version": "2012-10-17",
			"Statement": [
				{
					"Effect": "Allow",
					"Action": "*",
					"Resource": "*"
				},
				{
					"Sid": "DenyAllExceptS3",
					"Effect": "Deny",
					"NotAction": [
						"s3:*",
						"iam:ListUsers"
					],
					"Resource": "*"
				}
			]
		}`,
		Actions: []string{
			"s3:GetObject",
			"s3:PutObject",
			"iam:ListUsers",
			"iam:PutUserPolicy",
			"lambda:CreateFunction",
			"ec2:RunInstances",
		},
		Notes: "NotAction deny — known overapproximation: Stave's deny kills the * grant entirely rather than per-action",
	}
}

func conditionalAllow() TestCase {
	return TestCase{
		Name: "conditional-allow",
		PolicyJSON: `{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": [
					"iam:PassRole",
					"lambda:CreateFunction"
				],
				"Resource": "*",
				"Condition": {
					"StringEquals": {
						"iam:PassedToService": "lambda.amazonaws.com"
					}
				}
			}]
		}`,
		Actions: []string{
			"iam:PassRole",
			"lambda:CreateFunction",
		},
		Notes: "Conditional — Stave should flag as present (condition COULD be met); AWS without context returns implicitDeny",
	}
}

func multiStatementDenyOverride() TestCase {
	return TestCase{
		Name: "multi-statement-deny-override",
		PolicyJSON: `{
			"Version": "2012-10-17",
			"Statement": [
				{
					"Effect": "Allow",
					"Action": [
						"iam:PutUserPolicy",
						"iam:AttachUserPolicy",
						"iam:PassRole"
					],
					"Resource": "*"
				},
				{
					"Sid": "DenyPassRole",
					"Effect": "Deny",
					"Action": "iam:PassRole",
					"Resource": "*"
				}
			]
		}`,
		Actions: []string{
			"iam:PutUserPolicy",
			"iam:AttachUserPolicy",
			"iam:PassRole",
		},
		Notes: "Explicit deny overrides allow — PassRole should be denied despite the allow statement",
	}
}

func wildcardWithResourceScope() TestCase {
	return TestCase{
		Name: "wildcard-with-resource-scope",
		PolicyJSON: `{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": "iam:*",
				"Resource": "arn:aws:iam::111122223333:user/*"
			}]
		}`,
		ResourceARN: "arn:aws:iam::111122223333:user/alice",
		Actions: []string{
			"iam:PutUserPolicy",
			"iam:AttachUserPolicy",
			"iam:DeleteUser",
			"iam:CreateUser",
		},
		Notes: "Wildcard action scoped to user resources — all IAM user actions should be allowed on user ARNs",
	}
}

func scpBlocksAdmin() TestCase {
	return TestCase{
		Name: "scp-blocks-admin",
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
				"Action": [
					"s3:*",
					"ec2:Describe*"
				],
				"Resource": "*"
			}]
		}`,
		Actions: []string{
			"s3:GetObject",
			"s3:PutObject",
			"ec2:DescribeInstances",
			"iam:PutUserPolicy",
			"lambda:CreateFunction",
		},
		Notes: "SCP ceiling — known overapproximation: Stave kills * grant entirely rather than computing intersection with SCP",
	}
}

func boundaryConstrainsElevated() TestCase {
	return TestCase{
		Name: "boundary-constrains-elevated",
		PolicyJSON: `{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": [
					"iam:PutUserPolicy",
					"iam:AttachUserPolicy",
					"iam:PassRole",
					"s3:GetObject"
				],
				"Resource": "*"
			}]
		}`,
		BoundaryJSON: `{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": [
					"s3:GetObject",
					"s3:PutObject",
					"iam:PassRole"
				],
				"Resource": "*"
			}]
		}`,
		Actions: []string{
			"s3:GetObject",
			"iam:PassRole",
			"iam:PutUserPolicy",
			"iam:AttachUserPolicy",
		},
		Notes: "Boundary allows only S3+PassRole — PutUserPolicy and AttachUserPolicy should be blocked",
	}
}
