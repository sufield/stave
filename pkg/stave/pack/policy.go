package pack

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// iamPolicy is the JSON structure for an AWS IAM policy document.
type iamPolicy struct {
	Version   string         `json:"Version"`
	Statement []iamStatement `json:"Statement"`
}

type iamStatement struct {
	Sid      string   `json:"Sid"`
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource string   `json:"Resource"`
}

// SynthesizePolicy produces a valid IAM policy JSON document from
// the AWS API calls declared in pack requirements. Each CLI
// invocation (e.g., "aws iam list-roles") is converted to its IAM
// action (e.g., "iam:ListRoles"). The resulting policy grants
// least-privilege read-only access for Stave's collection needs.
func SynthesizePolicy(apiCalls []ServiceCalls) ([]byte, error) {
	actions := extractIAMActions(apiCalls)
	if len(actions) == 0 {
		return json.MarshalIndent(iamPolicy{
			Version:   "2012-10-17",
			Statement: []iamStatement{},
		}, "", "  ")
	}
	doc := iamPolicy{
		Version: "2012-10-17",
		Statement: []iamStatement{{
			Sid:      "StaveCollectionPolicy",
			Effect:   "Allow",
			Action:   actions,
			Resource: "*",
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

// extractIAMActions converts CLI calls to IAM actions, deduplicates,
// and sorts. "aws iam list-roles --arg val" → "iam:ListRoles".
// Uses the ServiceCalls.Service field as the IAM service prefix
// (not the CLI service name from the command string).
func extractIAMActions(apiCalls []ServiceCalls) []string {
	seen := map[string]struct{}{}
	var actions []string
	for _, sc := range apiCalls {
		for _, call := range sc.Calls {
			action := cliCallToIAMAction(sc.Service, call)
			if action == "" {
				continue
			}
			if _, dup := seen[action]; !dup {
				seen[action] = struct{}{}
				actions = append(actions, action)
			}
		}
	}
	slices.Sort(actions)
	return actions
}

// cliCallToIAMAction converts an AWS CLI call string to an IAM
// action. Example: service="iam", call="aws iam list-roles --role-name {ROLE}"
// → "iam:ListRoles".
func cliCallToIAMAction(service, call string) string {
	parts := strings.Fields(call)
	if len(parts) < 3 || parts[0] != "aws" {
		return ""
	}
	// parts[1] is the CLI service name (may differ from IAM service)
	// parts[2] is the CLI action (hyphenated)
	return fmt.Sprintf("%s:%s", service, kebabToPascal(parts[2]))
}

// kebabToPascal converts "list-roles" to "ListRoles".
func kebabToPascal(s string) string {
	var b strings.Builder
	for seg := range strings.SplitSeq(s, "-") {
		if seg == "" {
			continue
		}
		b.WriteString(strings.ToUpper(seg[:1]))
		b.WriteString(seg[1:])
	}
	return b.String()
}
