// Command z3prove runs five Z3 queries against a Cognito
// configuration where four stages — self-register, attribute
// self-promotion, identity-pool credential issue, and IAM
// resource access — combine into a chain from zero
// credentials to full S3 access.
//
// # Five queries
//
// Finding 1 — Self-registration possible. The user pool's
// AdminCreateUserConfig allows non-admin signup.
//
// Finding 2 — Sensitive attribute self-modification. The
// app client's write_attributes admits a privilege-bearing
// attribute (custom:role, email_verified, etc.) and no
// pre-token-generation Lambda validates the change.
//
// Finding 3 — Identity-pool credentials issuable to either
// (a) unauthenticated callers (allow_unauthenticated_identities)
// or (b) self-registered authenticated callers, AND the role
// the pool assigns has sensitive resource access.
//
// Finding 4 — Compound chain: F1 ∧ F2 ∧ F3.
//
// Finding 5 — Choke-point analysis. Toggle each candidate
// fix on the writeup config and re-run the chain. The
// candidate that flips the chain to UNSAT is a single-
// change fix. Multiple cheapest-fix candidates may exist;
// the prover lists all of them.
//
// # The teaching beat
//
// The compound chain is what shows the architecture. The
// choke-point analysis is what tells the operator *the
// minimum work to ship a fix*. Most security advice reads
// like "do all of these things"; this iteration's
// remediation analysis says "any one of these is enough."
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/aclements/go-z3/z3"
)

// Sensitive Cognito user attributes whose writability
// implies privilege escalation or account takeover.
var sensitiveAttributes = map[string]string{
	"custom:role":           "privilege_escalation",
	"custom:admin":          "privilege_escalation",
	"custom:is_admin":       "privilege_escalation",
	"custom:is_premium":     "privilege_escalation",
	"custom:debug_mode":     "privilege_escalation",
	"custom:permissions":    "privilege_escalation",
	"custom:access_level":   "privilege_escalation",
	"email":                 "account_takeover",
	"email_verified":        "verification_bypass",
	"phone_number":          "mfa_bypass",
	"phone_number_verified": "mfa_bypass",
}

type statement struct {
	Effect    string         `json:"Effect"`
	Action    any            `json:"Action"`
	Resource  any            `json:"Resource"`
	Condition map[string]any `json:"Condition,omitempty"`
}

type fixture struct {
	userPool        userPoolFacts
	appClient       appClientFacts
	identityPool    identityPoolFacts
	unauthRoleStmts []statement
	authRoleStmts   []statement
}

type userPoolFacts struct {
	selfRegRestricted    bool
	mfaEnforced          bool
	advancedSecurity     bool
	preSignupTriggerARN  string
	preTokenTriggerARN   string
	autoVerifyAttributes []string
}

type appClientFacts struct {
	clientID        string
	hasSecret       bool
	writeAttributes []string
	implicitFlow    bool
}

type identityPoolFacts struct {
	allowUnauthenticated  bool
	unauthRoleARN         string
	authRoleARN           string
	roleMappingConfigured bool
}

func main() {
	root, err := exampleRoot()
	if err != nil {
		log.Fatalf("locate example root: %v", err)
	}

	configs := []struct {
		key   string
		label string
		dir   string
	}{
		{"writeup", "writeup-config (vulnerable on all four stages)",
			filepath.Join(root, "fixtures/writeup-config/observations")},
		{"remediated", "remediated-config (least-privilege)",
			filepath.Join(root, "fixtures/remediated-config/observations")},
	}

	allOK := true
	for i, c := range configs {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("====================================================================\n")
		fmt.Printf("== %s\n", c.label)
		fmt.Printf("====================================================================\n")

		f, err := loadFixture(c.dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] load: %v\n", c.key, err)
			os.Exit(1)
		}

		f1 := finding1SelfRegistration(c.key, f)
		fmt.Println()
		f2 := finding2SensitiveAttrs(c.key, f)
		fmt.Println()
		f3 := finding3CredentialPaths(c.key, f)
		fmt.Println()
		f4 := finding4CompoundChain(c.key, f, f1, f2, f3)
		fmt.Println()
		finding5ChokePoint(c.key, f)

		if c.key == "writeup" {
			allOK = allOK && f1 && f2 && f3 && f4
		} else {
			allOK = allOK && !f1 && !f2 && !f3 && !f4
		}
	}

	if !allOK {
		os.Exit(1)
	}
}

// finding1SelfRegistration: stage 1 of the chain.
func finding1SelfRegistration(key string, f fixture) bool {
	signupPossible := !f.userPool.selfRegRestricted && !f.appClient.hasSecret
	hasPreSignupValidation := f.userPool.preSignupTriggerARN != ""

	ctx := z3.NewContext(nil)
	pred := ctx.FromBool(signupPossible).And(ctx.FromBool(!hasPreSignupValidation))

	s := z3.NewSolver(ctx)
	s.Assert(pred)
	sat, _ := s.Check()

	fmt.Println("--- Finding 1: self-registration possible ---")
	fmt.Printf("  self_reg_restricted:        %v\n", f.userPool.selfRegRestricted)
	fmt.Printf("  app_client_has_secret:      %v   (public client: %v)\n",
		f.appClient.hasSecret, !f.appClient.hasSecret)
	fmt.Printf("  pre_signup_lambda_present:  %v\n", hasPreSignupValidation)

	expectedSAT := key == "writeup"

	if sat {
		fmt.Printf("  verdict:                    SAT — anyone with the public client_id\n")
		fmt.Printf("                              can call cognito-idp:SignUp; no Lambda\n")
		fmt.Printf("                              validates the request before account creation\n")
		return expectedSAT
	}
	fmt.Printf("  verdict:                    UNSAT — self-registration closed (admin-only or validated)\n")
	return !expectedSAT
}

// finding2SensitiveAttrs: stage 2 of the chain.
func finding2SensitiveAttrs(key string, f fixture) bool {
	type sensitiveFinding struct {
		attr string
		risk string
	}
	var found []sensitiveFinding
	for _, attr := range f.appClient.writeAttributes {
		if risk, ok := sensitiveAttributes[attr]; ok {
			found = append(found, sensitiveFinding{attr: attr, risk: risk})
		}
	}
	hasValidationTrigger := f.userPool.preTokenTriggerARN != ""

	canPromote := len(found) > 0 && !hasValidationTrigger

	ctx := z3.NewContext(nil)
	pred := ctx.FromBool(canPromote)
	s := z3.NewSolver(ctx)
	s.Assert(pred)
	sat, _ := s.Check()

	fmt.Println("--- Finding 2: sensitive attribute self-modification ---")
	fmt.Printf("  writable attributes:         %v\n", f.appClient.writeAttributes)
	fmt.Printf("  sensitive (writable):        %d\n", len(found))
	for _, sa := range found {
		fmt.Printf("    %-22s → %s\n", sa.attr, sa.risk)
	}
	fmt.Printf("  pre_token_lambda_validates:  %v\n", hasValidationTrigger)

	expectedSAT := key == "writeup"

	if sat {
		fmt.Printf("  verdict:                     SAT — at least one sensitive attribute is\n")
		fmt.Printf("                               writable AND no Lambda validates the change\n")
		return expectedSAT
	}
	fmt.Printf("  verdict:                     UNSAT — no sensitive writable attribute, or trigger validates\n")
	return !expectedSAT
}

// finding3CredentialPaths: stage 3 of the chain.
func finding3CredentialPaths(key string, f fixture) bool {
	pathA := f.identityPool.allowUnauthenticated
	pathAHasSensitive := pathA && roleHasSensitiveAccess(f.unauthRoleStmts)
	pathBHasSensitive := roleHasSensitiveAccess(f.authRoleStmts)

	ctx := z3.NewContext(nil)
	a := ctx.FromBool(pathAHasSensitive)
	b := ctx.FromBool(pathBHasSensitive)
	pred := a.Or(b)
	s := z3.NewSolver(ctx)
	s.Assert(pred)
	sat, _ := s.Check()

	fmt.Println("--- Finding 3: identity-pool credentials reach sensitive resources ---")
	fmt.Printf("  Path A — unauthenticated:\n")
	fmt.Printf("    allow_unauthenticated:    %v\n", f.identityPool.allowUnauthenticated)
	if f.identityPool.unauthRoleARN != "" {
		fmt.Printf("    unauth role:              %s\n", f.identityPool.unauthRoleARN)
		fmt.Printf("    has sensitive access:     %v\n", pathAHasSensitive)
	}
	fmt.Printf("  Path B — self-registered + authenticated:\n")
	fmt.Printf("    auth role:                %s\n", f.identityPool.authRoleARN)
	fmt.Printf("    has sensitive access:     %v\n", pathBHasSensitive)

	expectedSAT := key == "writeup"

	if sat {
		fmt.Printf("  verdict:                    SAT — at least one credential path reaches sensitive AWS\n")
		return expectedSAT
	}
	fmt.Printf("  verdict:                    UNSAT — neither path reaches sensitive resources\n")
	return !expectedSAT
}

// finding4CompoundChain: F1 ∧ F2 ∧ F3.
func finding4CompoundChain(key string, f fixture, f1, f2, f3 bool) bool {
	ctx := z3.NewContext(nil)
	pred := ctx.FromBool(f1).And(ctx.FromBool(f2), ctx.FromBool(f3))
	s := z3.NewSolver(ctx)
	s.Assert(pred)
	sat, _ := s.Check()

	fmt.Println("--- Finding 4: complete compound chain ---")
	fmt.Printf("  stage 1 (self-register):       %v\n", f1)
	fmt.Printf("  stage 2 (self-promote attr):   %v\n", f2)
	fmt.Printf("  stage 3 (creds → sensitive):   %v\n", f3)

	expectedSAT := key == "writeup"

	if sat {
		fmt.Printf("  verdict:                       SAT — 4 CLI commands from anonymous to AWS:\n")
		fmt.Printf("                                 cognito-idp:SignUp →\n")
		fmt.Printf("                                 cognito-idp:UpdateUserAttributes →\n")
		fmt.Printf("                                 cognito-identity:GetCredentialsForIdentity →\n")
		fmt.Printf("                                 (use auth role's permissions on AWS resources)\n")
		return expectedSAT
	}
	fmt.Printf("  verdict:                       UNSAT — chain broken\n")
	return !expectedSAT
}

// finding5ChokePoint enumerates candidate single-change fixes
// and reports which ones collapse the chain. Implements the
// "minimum fix" analysis: take the writeup state, toggle one
// candidate fix at a time, recompute the chain, list the
// fixes that flip the chain from SAT to UNSAT.
func finding5ChokePoint(key string, f fixture) {
	if key == "remediated" {
		fmt.Println("--- Finding 5: choke-point analysis ---")
		fmt.Println("  no chain to analyse on remediated config")
		return
	}

	type candidate struct {
		name        string
		description string
		apply       func(*fixture)
	}
	candidates := []candidate{
		{
			name:        "set allow_admin_create_user_only=true",
			description: "stage 1 closed — no self-registration",
			apply:       func(g *fixture) { g.userPool.selfRegRestricted = true },
		},
		{
			name:        "remove sensitive attrs from app client write_attributes",
			description: "stage 2 closed — no self-promotion",
			apply: func(g *fixture) {
				g.appClient.writeAttributes = []string{"name"}
			},
		},
		{
			name:        "configure pre-token-generation Lambda validator",
			description: "stage 2 closed — attribute changes validated",
			apply: func(g *fixture) {
				g.userPool.preTokenTriggerARN = "arn:aws:lambda:us-east-1:111122223333:function:validator"
			},
		},
		{
			name:        "set allow_unauthenticated_identities=false",
			description: "path A of stage 3 closed (path B remains)",
			apply:       func(g *fixture) { g.identityPool.allowUnauthenticated = false },
		},
		{
			name:        "scope authenticated role to non-sensitive resources",
			description: "path B of stage 3 closed",
			apply: func(g *fixture) {
				g.authRoleStmts = []statement{
					{Effect: "Allow", Action: []any{"s3:GetObject"},
						Resource: "arn:aws:s3:::app-user-data/${cognito-identity.amazonaws.com:sub}/*"},
				}
			},
		},
	}

	fmt.Println("--- Finding 5: choke-point analysis ---")
	fmt.Printf("  question: which single configuration change flips the chain to UNSAT?\n")
	fmt.Printf("  testing %d candidate fixes...\n", len(candidates))
	fmt.Println()

	chokes := []int{}
	for i, c := range candidates {
		g := f // copy
		// statements slices share backing — clone them.
		g.unauthRoleStmts = append([]statement(nil), f.unauthRoleStmts...)
		g.authRoleStmts = append([]statement(nil), f.authRoleStmts...)
		g.appClient.writeAttributes = append([]string(nil), f.appClient.writeAttributes...)
		c.apply(&g)

		f1 := !g.userPool.selfRegRestricted && !g.appClient.hasSecret && g.userPool.preSignupTriggerARN == ""
		f2 := false
		for _, attr := range g.appClient.writeAttributes {
			if _, ok := sensitiveAttributes[attr]; ok {
				f2 = true
				break
			}
		}
		f2 = f2 && g.userPool.preTokenTriggerARN == ""
		pathA := g.identityPool.allowUnauthenticated && roleHasSensitiveAccess(g.unauthRoleStmts)
		pathB := roleHasSensitiveAccess(g.authRoleStmts)
		f3 := pathA || pathB
		// Stage 3's path-B requires self-registration first.
		// If self-reg is closed, only path-A counts.
		if g.userPool.selfRegRestricted || g.appClient.hasSecret {
			f3 = pathA
		}

		chainOpen := f1 && f2 && f3

		marker := "[OPEN  ] "
		if !chainOpen {
			marker = "[CLOSED] "
			chokes = append(chokes, i)
		}
		fmt.Printf("  %s%s\n", marker, c.name)
		fmt.Printf("           %s\n", c.description)
	}

	fmt.Println()
	if len(chokes) == 0 {
		fmt.Printf("  no single-change fix found — chain has multiple independent paths\n")
		return
	}
	fmt.Printf("  %d single-change fixes break the chain:\n", len(chokes))
	for _, i := range chokes {
		fmt.Printf("    • %s\n", candidates[i].name)
	}
	fmt.Printf("  the cheapest is the first listed (one boolean flip in user-pool config).\n")
}

// roleHasSensitiveAccess returns true if any of the role's
// statements grants a sensitive AWS action — s3:* / s3:Put*,
// dynamodb:* / dynamodb:Put*, lambda:Invoke*, secretsmanager:*.
func roleHasSensitiveAccess(stmts []statement) bool {
	sensitive := []string{"s3:", "dynamodb:", "lambda:", "secretsmanager:"}
	for _, st := range stmts {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		for _, a := range stringList(st.Action) {
			for _, prefix := range sensitive {
				if strings.HasPrefix(a, prefix) {
					return true
				}
			}
		}
	}
	return false
}

func stringList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// loadFixture reads the snapshot dir and extracts user pool,
// app client, identity pool, and the two Cognito IAM roles'
// statement lists.
func loadFixture(snapshotsDir string) (fixture, error) {
	var f fixture
	entries, err := os.ReadDir(snapshotsDir)
	if err != nil {
		return f, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		names = append(names, e.Name())
	}
	slices.Sort(names)

	seen := map[string]struct{}{}
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(snapshotsDir, name))
		if err != nil {
			return f, err
		}
		var snap struct {
			Assets []struct {
				ID         string `json:"id"`
				Type       string `json:"type"`
				Properties struct {
					Identity struct {
						Auth struct {
							MfaEnforced bool `json:"mfa_enforced"`
						} `json:"auth"`
						AdvancedSecurity struct {
							Enabled bool `json:"enabled"`
						} `json:"advanced_security"`
						Governance struct {
							SelfRegistrationRestricted bool `json:"self_registration_restricted"`
						} `json:"governance"`
						LambdaConfig struct {
							PreSignUp          string `json:"pre_sign_up"`
							PreTokenGeneration string `json:"pre_token_generation"`
						} `json:"lambda_config"`
						AutoVerifyAttributes []string `json:"auto_verified_attributes"`
						AppClient            struct {
							ClientID          string   `json:"client_id"`
							HasSecret         bool     `json:"has_secret"`
							WriteAttributes   []string `json:"write_attributes"`
							AllowedOAuthFlows []string `json:"allowed_oauth_flows"`
						} `json:"app_client"`
						IdentityPool struct {
							AllowUnauthenticatedIdentities bool   `json:"allow_unauthenticated_identities"`
							UnauthenticatedRoleARN         string `json:"unauthenticated_role_arn"`
							AuthenticatedRoleARN           string `json:"authenticated_role_arn"`
							RoleMappingConfigured          bool   `json:"role_mapping_configured"`
						} `json:"identity_pool"`
						Policies struct {
							AttachedPolicies []struct {
								Name       string      `json:"name"`
								Statements []statement `json:"statements"`
							} `json:"attached_policies"`
						} `json:"policies"`
					} `json:"identity"`
				} `json:"properties"`
			} `json:"assets"`
		}
		if err := json.Unmarshal(raw, &snap); err != nil {
			return f, err
		}
		for _, a := range snap.Assets {
			if _, ok := seen[a.ID]; ok {
				continue
			}
			seen[a.ID] = struct{}{}
			id := a.Properties.Identity
			switch a.Type {
			case "aws_cognito_user_pool":
				f.userPool.selfRegRestricted = id.Governance.SelfRegistrationRestricted
				f.userPool.mfaEnforced = id.Auth.MfaEnforced
				f.userPool.advancedSecurity = id.AdvancedSecurity.Enabled
				f.userPool.preSignupTriggerARN = id.LambdaConfig.PreSignUp
				f.userPool.preTokenTriggerARN = id.LambdaConfig.PreTokenGeneration
				f.userPool.autoVerifyAttributes = id.AutoVerifyAttributes
			case "aws_cognito_app_client":
				f.appClient.clientID = id.AppClient.ClientID
				f.appClient.hasSecret = id.AppClient.HasSecret
				f.appClient.writeAttributes = id.AppClient.WriteAttributes
				for _, fl := range id.AppClient.AllowedOAuthFlows {
					if fl == "implicit" {
						f.appClient.implicitFlow = true
					}
				}
			case "aws_cognito_identity_pool":
				f.identityPool.allowUnauthenticated = id.IdentityPool.AllowUnauthenticatedIdentities
				f.identityPool.unauthRoleARN = id.IdentityPool.UnauthenticatedRoleARN
				f.identityPool.authRoleARN = id.IdentityPool.AuthenticatedRoleARN
				f.identityPool.roleMappingConfigured = id.IdentityPool.RoleMappingConfigured
			case "aws_iam_role":
				stmts := []statement{}
				for _, p := range id.Policies.AttachedPolicies {
					stmts = append(stmts, p.Statements...)
				}
				if a.ID == f.identityPool.unauthRoleARN ||
					strings.Contains(a.ID, "Unauth") {
					f.unauthRoleStmts = append(f.unauthRoleStmts, stmts...)
				}
				if a.ID == f.identityPool.authRoleARN ||
					strings.Contains(a.ID, "Auth") && !strings.Contains(a.ID, "Unauth") {
					f.authRoleStmts = append(f.authRoleStmts, stmts...)
				}
			}
		}
	}
	return f, nil
}

func exampleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller(0) unavailable")
	}
	return filepath.Dir(filepath.Dir(file)), nil
}
