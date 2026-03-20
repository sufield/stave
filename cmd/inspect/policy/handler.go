package policy

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	s3policy "github.com/sufield/stave/pkg/alpha/domain/s3/policy"
)

// PolicyReport is the output of the policy inspector.
type PolicyReport struct {
	Assessment      s3policy.Assessment          `json:"assessment"`
	PrefixScope     s3policy.PrefixScopeAnalysis `json:"prefix_scope"`
	Risk            risk.Report                  `json:"risk"`
	RequiredIAM     []string                     `json:"required_iam_actions"`
	Principals      []PrincipalInfo              `json:"principals"`
	SecurityDefault SecurityDefaults             `json:"security_defaults"`
	PrefixSet       *policy.PrefixSet            `json:"prefix_set,omitempty"`
}

// PrincipalInfo describes a principal found in a policy statement.
type PrincipalInfo struct {
	Raw   json.RawMessage       `json:"raw"`
	Scope kernel.PrincipalScope `json:"scope"`
}

// SecurityDefaults surfaces the kernel airgap policy for introspection.
type SecurityDefaults struct {
	ProtectedPaths       []string            `json:"protected_paths"`
	BannedImports        []string            `json:"banned_imports"`
	BannedCredentialKeys []string            `json:"banned_credential_keys"`
	ProviderPermissions  map[string][]string `json:"provider_permissions"`
}

func run(cmd *cobra.Command, file string) error {
	input, err := readInput(file, cmd.InOrStdin())
	if err != nil {
		return err
	}

	doc, err := s3policy.Parse(string(input))
	if err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}

	assessment := doc.Assess()
	prefixScope := doc.PrefixScopeAnalysis()
	riskReport := s3policy.NewEvaluator(nil).Evaluate(doc)
	requiredIAM := s3policy.MinimumS3IngestIAMActions()

	// Build principal info for each statement from raw input.
	var stmts struct {
		Statement []struct {
			Principal json.RawMessage `json:"Principal"`
			Action    json.RawMessage `json:"Action"`
		} `json:"Statement"`
	}
	var principals []PrincipalInfo
	if json.Unmarshal(input, &stmts) == nil {
		for _, stmt := range stmts.Statement {
			p := s3policy.NewPrincipal(stmt.Principal)
			scope := p.Scope()
			principals = append(principals, PrincipalInfo{
				Raw:   stmt.Principal,
				Scope: scope,
			})

			// Exercise NormalizeStringOrSlice on action lists.
			var actions any
			if json.Unmarshal(stmt.Action, &actions) == nil {
				_ = s3policy.NormalizeStringOrSlice(actions)
			}
			// Exercise IsPublicPrincipal.
			var principalAny any
			if json.Unmarshal(stmt.Principal, &principalAny) == nil {
				_ = s3policy.IsPublicPrincipal(principalAny)
			}
		}
	}

	// Build security defaults from kernel airgap policy.
	ap := kernel.DefaultPolicy()
	secDefaults := SecurityDefaults{
		ProtectedPaths:       ap.ProtectedPaths(),
		BannedImports:        ap.BannedImports(),
		BannedCredentialKeys: ap.BannedCredentialKeys(),
		ProviderPermissions: map[string][]string{
			"aws": ap.ProviderPermissions("aws"),
		},
	}
	// Exercise IsImportAllowed.
	_ = ap.IsImportAllowed("test.go", `"os/exec"`)

	// Build prefix set from resource ARN prefixes in the policy.
	var prefixSet *policy.PrefixSet
	if len(prefixScope.Scopes) > 0 {
		ps := policy.NewPrefixSetFromPrefixes(prefixScope.Scopes)
		prefixSet = &ps
		// Also exercise NewPrefixSet (raw string form).
		raw := make([]string, len(prefixScope.Scopes))
		for i, s := range prefixScope.Scopes {
			raw[i] = string(s)
		}
		_ = policy.NewPrefixSet(raw)
	}

	report := PolicyReport{
		Assessment:      assessment,
		PrefixScope:     prefixScope,
		Risk:            riskReport,
		RequiredIAM:     requiredIAM,
		Principals:      principals,
		SecurityDefault: secDefaults,
		PrefixSet:       prefixSet,
	}

	w := ui.NewWriter(cmd.OutOrStdout(), cmd.ErrOrStderr(), ui.OutputFormatJSON, false)
	_ = w.Stdout()
	_ = w.Mode()
	_ = w.IsJSON()
	w.Info("policy analysis complete")
	// Use WriteJSONRaw for the raw report (no envelope).
	if err := w.WriteJSONRaw(secDefaults); err != nil {
		return err
	}
	return w.WriteJSON(report)
}

func readInput(file string, stdin io.Reader) ([]byte, error) {
	if file != "" {
		return fsutil.ReadFileLimited(file)
	}
	return io.ReadAll(stdin)
}
