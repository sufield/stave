// Facts projection layer over sir.Document.
//
// The SIR carries Stave's canonical fact set as nested structs
// designed for the Z3 / SMT translator. Some downstream engines
// — Datalog/Soufflé, ASP/Clingo, and SMT solvers consuming raw
// declarations — prefer flat (subject, predicate, object)
// triples over the nested form. This file projects the SIR
// document into triples and serialises them as JSONL or
// SMT-LIB v2.
//
// Discipline: the projection writes only what is OBSERVABLY
// TRUE about the configuration. It never writes rules
// ("anonymous_can_read(B) :- public_read_via_policy(B)") —
// rules belong to the reasoning program, facts belong to
// Stave.
//
// Determinism: every collection is produced in a stable
// order (sort.Strings on subjects/objects, slice index on
// nested children) so the same SIR document yields
// byte-identical output across runs.
package exportsir

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/sufield/stave/internal/core/sir"
)

// factID returns a deterministic 12-hex-character correlation ID
// for a (subject, predicate, object) triple. The ID is the first
// 6 bytes of SHA-256 over a pipe-joined canonical form.
//
// Properties:
//   - Deterministic — same input always produces the same ID.
//   - Stable across projector refactors — depends on the fact's
//     content, not which Go function emitted it.
//   - Collision-resistant — 48 bits ≈ 281 trillion buckets;
//     negligible collision probability for a single export.
//   - Greppable — short enough to copy-paste, no special chars.
//
// One ID flows through every layer: JSONL triple, SMT-LIB
// assertion comment, CEL finding's contributing_fact_ids,
// per-engine output row → enabling end-to-end traceability
// from a Z3 witness back to the originating observation
// property without ad-hoc grep recipes.
func factID(subject, predicate, object string) string {
	h := sha256.Sum256([]byte(subject + "|" + predicate + "|" + object))
	return hex.EncodeToString(h[:6])
}

// Fact is one (subject, predicate, object) triple plus
// provenance fields for engines that want to trace back to
// the originating SIR slot. Source names the SIR fact category
// the triple was projected from; Evidence is a short SIR path
// (e.g. "controls[0].id", "identities[0].role_chains[0]") so
// downstream code can correlate triples back to the nested
// document without a separate index.
// Provenance carries machine-readable origin metadata for one
// fact. Additive over Evidence; new consumers should prefer
// Provenance because property_path is observation-relative (no
// "assets[N]." prefix) and is greppable directly against the
// raw observation JSON.
//
//	{
//	  "property_path": "properties.identity.policies.attached_policies[0].statements[0].Action",
//	  "captured_at":   "2026-01-08T00:00:00Z",
//	  "projector":     "iamPolicyFacts"
//	}
//
// observation_file (a per-property source-file reference) is not
// populated this iteration — the SIR loader merges multiple
// snapshots into a single AssetFact and does not track per-
// property file origin. Adding it would require an SIR schema
// extension and is left as future work. Downstream consumers
// that need file origin can correlate captured_at with the
// snapshot directory's filenames.
type Provenance struct {
	PropertyPath string `json:"property_path"`
	CapturedAt   string `json:"captured_at,omitempty"`
	Projector    string `json:"projector"`
}

type Fact struct {
	// FactID is a deterministic 12-hex-character correlation ID
	// derived from sha256(subject|predicate|object). One ID flows
	// through every export layer (JSONL triple, SMT-LIB comment,
	// CEL finding's contributing_fact_ids, per-engine output) so
	// a Z3 witness traces back to the originating observation
	// property in one grep. Set at the ExtractFacts boundary —
	// individual projector functions don't compute it.
	FactID     string      `json:"fact_id"`
	Subject    string      `json:"subject"`
	Predicate  string      `json:"predicate"`
	Object     string      `json:"object"`
	Source     string      `json:"source"`
	Evidence   string      `json:"evidence"`
	Provenance *Provenance `json:"provenance,omitempty"`
}

// stripIndexPrefix turns a SIR-relative path like
// "assets[2].properties.identity.kind" into the observation-
// relative "properties.identity.kind" by removing a leading
// indexed-collection prefix. Recognised forms:
//
//	assets[N].             →  ""
//	controls[N].           →  ""
//	identities[N].         →  ""
//	temporal.windows[N].   →  ""  (note: the prefix contains a dot)
//
// Strategy: find the first "]." substring; everything up to and
// including it is the prefix. Falls back to the original path
// when no bracketed index is present.
func stripIndexPrefix(p string) string {
	if i := strings.Index(p, "]."); i >= 0 {
		return p[i+2:]
	}
	return p
}

// annotateProvenance walks a slice of facts produced by one
// projector and stamps Provenance on each. captured_at is
// looked up from assetByID by Subject equality; non-asset
// subjects (control IDs, principal IDs) leave it empty. This
// keeps the per-projector code free of provenance plumbing —
// they emit Fact{Evidence: ...} as before; provenance is
// applied at the boundary.
func annotateProvenance(facts []Fact, projector string, assetByID map[string]*sir.AssetFact) []Fact {
	for i := range facts {
		var capturedAt string
		if a := assetByID[facts[i].Subject]; a != nil && a.Lifecycle != nil && !a.Lifecycle.LastSeen.IsZero() {
			capturedAt = a.Lifecycle.LastSeen.UTC().Format("2006-01-02T15:04:05Z")
		}
		facts[i].Provenance = &Provenance{
			PropertyPath: stripIndexPrefix(facts[i].Evidence),
			CapturedAt:   capturedAt,
			Projector:    projector,
		}
		// Stamp the deterministic correlation ID in the same
		// boundary pass; per-projector code is unaffected.
		if facts[i].FactID == "" {
			facts[i].FactID = factID(facts[i].Subject, facts[i].Predicate, facts[i].Object)
		}
	}
	return facts
}

// ExtractFacts projects a SIR document into the flat triple
// form. The mapping is intentionally lossy: rich SIR fields
// like nested predicate trees and per-rule source refs are
// summarised as boolean flags ("has_forbidden_state=true")
// rather than serialised verbatim, because triple consumers
// — Datalog and ASP especially — work in flat namespaces.
// Consumers who need the full nesting use --format json.
func ExtractFacts(doc *sir.Document) []Fact {
	if doc == nil {
		return nil
	}
	// Pre-build the asset lookup so each annotateProvenance call is
	// a constant-time map probe rather than O(N) over the asset
	// slice. The projector name is the Go function name as it
	// appears in source — easy to grep when a fact's provenance
	// points at a wrong projector.
	assetByID := make(map[string]*sir.AssetFact, len(doc.Assets))
	for i := range doc.Assets {
		assetByID[doc.Assets[i].ID] = &doc.Assets[i]
	}

	var facts []Fact
	facts = append(facts, annotateProvenance(controlFacts(doc.Controls), "controlFacts", assetByID)...)
	facts = append(facts, annotateProvenance(assetFacts(doc.Assets), "assetFacts", assetByID)...)
	facts = append(facts, annotateProvenance(cognitoMappingFacts(doc.Assets), "cognitoMappingFacts", assetByID)...)
	facts = append(facts, annotateProvenance(cognitoUserPoolFacts(doc.Assets), "cognitoUserPoolFacts", assetByID)...)
	facts = append(facts, annotateProvenance(iamPolicyFacts(doc.Assets), "iamPolicyFacts", assetByID)...)
	facts = append(facts, annotateProvenance(denyPolicyFacts(doc.Assets), "denyPolicyFacts", assetByID)...)
	facts = append(facts, annotateProvenance(conditionFacts(doc.Assets), "conditionFacts", assetByID)...)
	facts = append(facts, annotateProvenance(stringifiedPolicyFacts(doc.Assets), "stringifiedPolicyFacts", assetByID)...)
	facts = append(facts, annotateProvenance(dataEventLoggingFacts(doc.Assets), "dataEventLoggingFacts", assetByID)...)
	facts = append(facts, annotateProvenance(propertyFacts(doc.Assets), "propertyFacts", assetByID)...)
	facts = append(facts, annotateProvenance(tagFacts(doc.Assets), "tagFacts", assetByID)...)
	facts = append(facts, annotateProvenance(trustPolicyFacts(doc.Assets), "trustPolicyFacts", assetByID)...)
	facts = append(facts, annotateProvenance(assumeEdgeFacts(doc.Assets), "assumeEdgeFacts", assetByID)...)
	facts = append(facts, annotateProvenance(identityFacts(doc.Identities), "identityFacts", assetByID)...)
	facts = append(facts, annotateProvenance(exposureFacts(doc.Temporal.Windows), "exposureFacts", assetByID)...)
	return facts
}

func controlFacts(controls []sir.ControlFact) []Fact {
	out := make([]Fact, 0, len(controls)*3)
	for i := range controls {
		c := &controls[i]
		evid := fmt.Sprintf("controls[%d]", i)
		if c.Severity != "" {
			out = append(out, Fact{Subject: c.ID, Predicate: "has_severity", Object: c.Severity, Source: "control", Evidence: evid + ".severity"})
		}
		if c.Type != "" {
			out = append(out, Fact{Subject: c.ID, Predicate: "has_type", Object: c.Type, Source: "control", Evidence: evid + ".type"})
		}
		if strings.TrimSpace(c.IntentRationale) != "" {
			out = append(out, Fact{Subject: c.ID, Predicate: "has_intent_rationale", Object: "true", Source: "control", Evidence: evid + ".intent_rationale"})
		}
		if c.ForbiddenState != nil && len(c.ForbiddenState.Rules) > 0 {
			out = append(out, Fact{Subject: c.ID, Predicate: "has_forbidden_state", Object: "true", Source: "control", Evidence: evid + ".forbidden_state"})
		}
	}
	return out
}

func assetFacts(assets []sir.AssetFact) []Fact {
	out := make([]Fact, 0, len(assets)*3)
	for i, a := range assets {
		evid := fmt.Sprintf("assets[%d]", i)
		if a.Type != "" {
			out = append(out, Fact{Subject: a.ID, Predicate: "has_type", Object: a.Type, Source: "asset", Evidence: evid + ".type"})
		}
		if a.Vendor != "" {
			out = append(out, Fact{Subject: a.ID, Predicate: "has_vendor", Object: a.Vendor, Source: "asset", Evidence: evid + ".vendor"})
		}
		if a.Lifecycle != nil {
			lc := a.Lifecycle
			if !lc.FirstSeen.IsZero() {
				out = append(out, Fact{Subject: a.ID, Predicate: "first_seen_at", Object: lc.FirstSeen.UTC().Format("2006-01-02T15:04:05Z"), Source: "lifecycle", Evidence: evid + ".lifecycle.first_seen"})
			}
			if !lc.LastSeen.IsZero() {
				out = append(out, Fact{Subject: a.ID, Predicate: "last_seen_at", Object: lc.LastSeen.UTC().Format("2006-01-02T15:04:05Z"), Source: "lifecycle", Evidence: evid + ".lifecycle.last_seen"})
			}
			if lc.Provisioned {
				out = append(out, Fact{Subject: a.ID, Predicate: "is_provisioned", Object: "true", Source: "lifecycle", Evidence: evid + ".lifecycle.provisioned"})
			}
			if lc.Decommissioned {
				out = append(out, Fact{Subject: a.ID, Predicate: "is_decommissioned", Object: "true", Source: "lifecycle", Evidence: evid + ".lifecycle.decommissioned"})
			}
		}
	}
	return out
}

func identityFacts(identities []sir.IdentityFact) []Fact {
	var out []Fact
	for i, id := range identities {
		evid := fmt.Sprintf("identities[%d]", i)
		for ci, chain := range id.RoleChains {
			cevid := fmt.Sprintf("%s.role_chains[%d]", evid, ci)
			for hi, hop := range chain.Hops {
				hevid := fmt.Sprintf("%s.hops[%d]", cevid, hi)
				pred := "can_assume"
				if hop.HopType != "" && hop.HopType != "assume_role" {
					pred = "can_" + hop.HopType
				}
				out = append(out, Fact{Subject: hop.From, Predicate: pred, Object: hop.To, Source: "role_chain", Evidence: hevid})
				if hop.CrossAccount {
					out = append(out, Fact{Subject: hop.From, Predicate: "cross_account_assumes", Object: hop.To, Source: "role_chain", Evidence: hevid + ".cross_account"})
				}
			}
			if chain.TransitiveLevel != "" {
				out = append(out, Fact{Subject: chain.FinalRoleARN, Predicate: "has_privilege_level", Object: chain.TransitiveLevel, Source: "role_chain", Evidence: cevid + ".transitive_level"})
			}
		}
		for vi := range id.Validity {
			vw := &id.Validity[vi]
			vevid := fmt.Sprintf("%s.validity[%d]", evid, vi)
			for pi := range vw.Permissions {
				perm := &vw.Permissions[pi]
				pevid := fmt.Sprintf("%s.permissions[%d]", vevid, pi)
				if perm.Action != "" {
					out = append(out, Fact{Subject: id.PrincipalID, Predicate: "has_permission_action", Object: perm.Action, Source: "permission", Evidence: pevid + ".action"})
				}
				if perm.Resource != "" {
					out = append(out, Fact{Subject: id.PrincipalID, Predicate: "has_permission_resource", Object: perm.Resource, Source: "permission", Evidence: pevid + ".resource"})
				}
			}
		}
	}
	return out
}

// cognitoMappingFacts walks Cognito identity-pool assets and
// emits the unauthenticated/authenticated role-mapping edges
// plus the allow_unauthenticated_identities flag. These are
// the chain edges that link an anonymous Cognito session to
// an IAM role; without them, no Z3 reachability query over
// "unauth user → IAM role → resource" is expressible.
//
//	Property path: properties.identity.identity_pool.{
//	  allow_unauthenticated_identities,
//	  unauthenticated_role_arn,
//	  authenticated_role_arn
//	}
//
// The fact is emitted only when the source field is present
// and non-zero — an identity pool with allow_unauthenticated=
// false produces no positive `allows_unauthenticated` fact, so
// the closed-world axiom correctly reports the predicate false
// for that asset.
func cognitoMappingFacts(assets []sir.AssetFact) []Fact {
	var out []Fact
	for i := range assets {
		a := &assets[i]
		if a.Type != "aws_cognito_identity_pool" {
			continue
		}
		ip, ok := navMap(a.Properties, "identity", "identity_pool")
		if !ok {
			continue
		}
		evid := fmt.Sprintf("assets[%d].properties.identity.identity_pool", i)
		if v, ok := ip["allow_unauthenticated_identities"].(bool); ok && v {
			out = append(out, Fact{
				Subject: a.ID, Predicate: "allows_unauthenticated", Object: "true",
				Source: "cognito", Evidence: evid + ".allow_unauthenticated_identities",
			})
		}
		if r, ok := ip["unauthenticated_role_arn"].(string); ok && r != "" {
			out = append(out, Fact{
				Subject: a.ID, Predicate: "maps_unauth_to", Object: r,
				Source: "cognito", Evidence: evid + ".unauthenticated_role_arn",
			})
		}
		if r, ok := ip["authenticated_role_arn"].(string); ok && r != "" {
			out = append(out, Fact{
				Subject: a.ID, Predicate: "maps_auth_to", Object: r,
				Source: "cognito", Evidence: evid + ".authenticated_role_arn",
			})
		}
	}
	return out
}

// cognitoUserPoolFacts walks Cognito user-pool assets and emits
// `self_registration_unrestricted(pool, "true")` exactly when the
// pool's governance settings allow self-sign-up — the gate
// step in the Cognito self-register-to-AWS-creds chain.
//
// The fact is named after the UNSAFE state, not the source
// boolean: the source is `governance.self_registration_restricted`
// (true == safe; false == unsafe), so we emit the predicate only
// when the source is false. The closed-world axiom restricts the
// predicate to false everywhere it isn't asserted, which gives
// the chain query the right semantics: SAT iff at least one pool
// is unrestricted.
//
// Property path:
//
//	properties.identity.governance.self_registration_restricted (bool)
//
// A pool with restricted=true (or absent governance block)
// produces no positive fact, and queries asking "is any pool
// unrestricted?" correctly return UNSAT.
func cognitoUserPoolFacts(assets []sir.AssetFact) []Fact {
	var out []Fact
	for i := range assets {
		a := &assets[i]
		if a.Type != "aws_cognito_user_pool" {
			continue
		}
		gov, ok := navMap(a.Properties, "identity", "governance")
		if !ok {
			continue
		}
		restricted, ok := gov["self_registration_restricted"].(bool)
		if !ok || restricted {
			continue
		}
		out = append(out, Fact{
			Subject: a.ID, Predicate: "self_registration_unrestricted", Object: "true",
			Source: "cognito", Evidence: fmt.Sprintf("assets[%d].properties.identity.governance.self_registration_restricted", i),
		})
	}
	return out
}

// iamPolicyFacts walks IAM role / IAM user attached_policies and
// emits one (principal, has_action, action) and (principal,
// has_resource, resource) per Allow statement. Deny statements
// and other effects are skipped — the chain queries only need
// the Allow surface today.
//
// The encoding is deliberately lossy: actions and resources are
// emitted as separate predicates, so a query asking "does role R
// allow s3:GetObject on arn:aws:s3:::bucket?" gets an over-
// approximation (R has both actions and resources somewhere in
// its policies, but Z3 can't tell which Allow statement bound
// them together). For chain reachability that's enough — false
// positives are bounded to "the principal has these grants
// somewhere," and the witness is still solver-extractable.
//
// A future ternary fact (statement_grants(principal, action,
// resource)) would tighten the binding; ternary predicates
// require a serializer extension and aren't required for the
// first chain query.
//
// Property path: properties.identity.policies.attached_policies
//
//	[]{ statements: []{ Effect, Action (string|[]string),
//	                    Resource (string|[]string) } }
func iamPolicyFacts(assets []sir.AssetFact) []Fact {
	var out []Fact
	for i := range assets {
		a := &assets[i]
		if a.Type != "aws_iam_role" && a.Type != "aws_iam_user" {
			continue
		}
		policies, ok := navMap(a.Properties, "identity", "policies")
		if !ok {
			continue
		}
		attached, ok := policies["attached_policies"].([]any)
		if !ok {
			continue
		}
		for pi, p := range attached {
			policy, ok := p.(map[string]any)
			if !ok {
				continue
			}
			stmts, ok := policy["statements"].([]any)
			if !ok {
				continue
			}
			for si, s := range stmts {
				stmt, ok := s.(map[string]any)
				if !ok {
					continue
				}
				if effect, _ := stmt["Effect"].(string); effect != "Allow" {
					continue
				}
				evid := fmt.Sprintf("assets[%d].policies.attached_policies[%d].statements[%d]", i, pi, si)
				for _, action := range coerceStringList(stmt["Action"]) {
					out = append(out, Fact{
						Subject: a.ID, Predicate: "has_action", Object: action,
						Source: "iam_policy", Evidence: evid + ".Action",
					})
				}
				for _, resource := range coerceStringList(stmt["Resource"]) {
					out = append(out, Fact{
						Subject: a.ID, Predicate: "has_resource", Object: resource,
						Source: "iam_policy", Evidence: evid + ".Resource",
					})
				}
			}
		}
	}
	return out
}

// propertyPath is one entry in the propertyAllowlist. It declares
// a per-asset configuration property whose value is projected as
// a flat fact triple. The encoding is intentionally raw — bool
// values become "true" / "false", strings pass through verbatim.
// External engines decide which value is unsafe; this projector
// stays value-neutral.
type propertyPath struct {
	blockKey      string   // top-level key under properties: "storage", "identity", "k8s", "auth", "trail", "s3_ref", "s3_upload"
	keys          []string // remaining path segments to the leaf scalar
	predicateName string   // SMT predicate (must start with "has_")
	assetTypes    []string // asset.Type allowlist; empty = all
}

// propertyAllowlist enumerates per-asset configuration properties
// to project as has_<leaf>(asset, value) triples. Each entry is
// added explicitly — this is governance, not a kitchen sink.
//
// Convention: predicate name = "has_" + leaf-property-name.
// One predicate per leaf (no overlaps with the hand-written
// projectors below).
//
// To add a new entry, populate the four fields and append to the
// slice; remember to register the predicate name in
// baselineSMT2Predicates so the closed-world axiom is emitted.
var propertyAllowlist = []propertyPath{
	// S3 bucket access booleans (public-read, public-list policy fixtures)
	{blockKey: "storage", keys: []string{"access", "public_read"}, predicateName: "has_public_read", assetTypes: []string{"aws_s3_bucket"}},
	{blockKey: "storage", keys: []string{"access", "public_list"}, predicateName: "has_public_list", assetTypes: []string{"aws_s3_bucket"}},
	{blockKey: "storage", keys: []string{"access", "read_via_resource"}, predicateName: "has_read_via_resource", assetTypes: []string{"aws_s3_bucket"}},
	{blockKey: "storage", keys: []string{"access", "list_via_resource"}, predicateName: "has_list_via_resource", assetTypes: []string{"aws_s3_bucket"}},
	{blockKey: "storage", keys: []string{"controls", "public_access_fully_blocked"}, predicateName: "has_public_access_blocked", assetTypes: []string{"aws_s3_bucket"}},
	// S3 .git / repo-artifact exposure (s3-dotgit-readable fixture)
	{blockKey: "storage", keys: []string{"content", "exposed_repo_artifacts"}, predicateName: "has_exposed_repo_artifacts", assetTypes: []string{"aws_s3_bucket"}},
	// S3 dangling-bucket reference (s3-bucket-name-dangling fixture)
	{blockKey: "s3_ref", keys: []string{"bucket_exists"}, predicateName: "has_bucket_exists"},
	{blockKey: "s3_ref", keys: []string{"bucket_owned"}, predicateName: "has_bucket_owned"},
	// S3 upload-scope mode (s3-broad-write-scope fixture)
	{blockKey: "s3_upload", keys: []string{"allowed_key_mode"}, predicateName: "has_upload_key_mode"},
	// Cognito user-pool MFA + advanced security (cognito-no-mfa-advanced-security)
	{blockKey: "identity", keys: []string{"auth", "mfa_enforced"}, predicateName: "has_mfa_enforced", assetTypes: []string{"aws_cognito_user_pool"}},
	{blockKey: "identity", keys: []string{"advanced_security", "enabled"}, predicateName: "has_advanced_security_enabled", assetTypes: []string{"aws_cognito_user_pool"}},
	// EKS RBAC webhook-config write access (eks-rbac-webhook-config-access)
	{blockKey: "k8s", keys: []string{"rbac", "has_webhook_config_access"}, predicateName: "has_webhook_config_access"},
	// EKS aws-auth ConfigMap template-injection vector (eks-aws-auth-template-injection)
	{blockKey: "auth", keys: []string{"webhook", "identity_mapping", "uses_access_key_id"}, predicateName: "has_uses_access_key_id"},
	// CloudTrail trail logging state (cloudtrail-stop-logging mgmt-events fixtures)
	{blockKey: "trail", keys: []string{"is_logging"}, predicateName: "has_logging_enabled", assetTypes: []string{"aws_cloudtrail_trail"}},
}

// propertyFacts walks the propertyAllowlist for every asset and
// emits one has_<leaf>(asset, value) fact per matching rule. The
// projector is value-neutral: a bool emits "true" or "false", a
// string emits its value verbatim. The query decides which value
// is the unsafe one; closed-world axioms make absence-of-fact
// equivalent to "this property was not present" — distinct from
// "this property was present and false".
//
// Determinism: the allowlist order is fixed in source; iteration
// over assets follows the SIR document's asset order; no map
// iteration drives the output.
func propertyFacts(assets []sir.AssetFact) []Fact {
	var out []Fact
	for i := range assets {
		a := &assets[i]
		for _, rule := range propertyAllowlist {
			if len(rule.assetTypes) > 0 {
				match := false
				for _, t := range rule.assetTypes {
					if a.Type == t {
						match = true
						break
					}
				}
				if !match {
					continue
				}
			}
			block, ok := a.Properties[rule.blockKey].(map[string]any)
			if !ok {
				continue
			}
			var value any = block
			for _, k := range rule.keys {
				m, ok := value.(map[string]any)
				if !ok {
					value = nil
					break
				}
				value = m[k]
			}
			if value == nil {
				continue
			}
			// Reject nested maps / slices — only scalars project.
			switch value.(type) {
			case map[string]any, []any:
				continue
			}
			obj := fmt.Sprintf("%v", value)
			if obj == "" {
				continue
			}
			evid := fmt.Sprintf("assets[%d].properties.%s.%s", i, rule.blockKey, strings.Join(rule.keys, "."))
			out = append(out, Fact{
				Subject: a.ID, Predicate: rule.predicateName, Object: obj,
				Source: "property", Evidence: evid,
			})
		}
	}
	return out
}

// denyPolicyFacts walks IAM Deny statements on role / user
// attached_policies and emits has_deny_action / has_deny_resource.
// iamPolicyFacts intentionally only walks Allow statements
// (the chain queries' Allow surface); this projector adds the
// Deny side so external solvers can compute effective
// Allow ∩ ¬Deny without re-reading the raw policy JSON.
//
// Property path: properties.identity.policies.attached_policies
//
//	[]{ statements: []{ Effect="Deny", Action, Resource } }
//
// Statements without Effect="Deny" are skipped; absence of any
// Deny on a principal yields no facts and the closed-world axiom
// reports has_deny_action(p, a) = false for every (p, a).
func denyPolicyFacts(assets []sir.AssetFact) []Fact {
	var out []Fact
	for i := range assets {
		a := &assets[i]
		if a.Type != "aws_iam_role" && a.Type != "aws_iam_user" {
			continue
		}
		policies, ok := navMap(a.Properties, "identity", "policies")
		if !ok {
			continue
		}
		attached, ok := policies["attached_policies"].([]any)
		if !ok {
			continue
		}
		for pi, p := range attached {
			policy, ok := p.(map[string]any)
			if !ok {
				continue
			}
			stmts, ok := policy["statements"].([]any)
			if !ok {
				continue
			}
			for si, s := range stmts {
				stmt, ok := s.(map[string]any)
				if !ok {
					continue
				}
				if effect, _ := stmt["Effect"].(string); effect != "Deny" {
					continue
				}
				evid := fmt.Sprintf("assets[%d].policies.attached_policies[%d].statements[%d]", i, pi, si)
				for _, action := range coerceStringList(stmt["Action"]) {
					out = append(out, Fact{
						Subject: a.ID, Predicate: "has_deny_action", Object: action,
						Source: "iam_policy", Evidence: evid + ".Action",
					})
				}
				for _, resource := range coerceStringList(stmt["Resource"]) {
					out = append(out, Fact{
						Subject: a.ID, Predicate: "has_deny_resource", Object: resource,
						Source: "iam_policy", Evidence: evid + ".Resource",
					})
				}
			}
		}
	}
	return out
}

// conditionFacts walks IAM policy statements (Allow OR Deny) and
// emits one has_condition per (principal, "operator:key") pair
// for any statement that carries a Condition block. The encoding
// is binary with a colon-joined object so existing SMT-LIB
// serialization works without ternary-arity support:
//
//	has_condition(principal, "StringEquals:iam:PassedToService")
//	has_condition(principal, "StringLike:s3:RequestObjectTagKeys")
//
// Statements without a Condition block emit nothing; closed-world
// axioms then report "is principal P scoped by some condition?"
// as false everywhere absence holds.
//
// Property path:
//
//	properties.identity.policies.attached_policies[].statements[].Condition
//
// Determinism: operator and key iteration are sorted before
// emission so the same SIR document yields byte-identical output.
func conditionFacts(assets []sir.AssetFact) []Fact {
	var out []Fact
	for i := range assets {
		a := &assets[i]
		if a.Type != "aws_iam_role" && a.Type != "aws_iam_user" {
			continue
		}
		policies, ok := navMap(a.Properties, "identity", "policies")
		if !ok {
			continue
		}
		attached, ok := policies["attached_policies"].([]any)
		if !ok {
			continue
		}
		for pi, p := range attached {
			policy, ok := p.(map[string]any)
			if !ok {
				continue
			}
			stmts, ok := policy["statements"].([]any)
			if !ok {
				continue
			}
			for si, s := range stmts {
				stmt, ok := s.(map[string]any)
				if !ok {
					continue
				}
				cond, ok := stmt["Condition"].(map[string]any)
				if !ok || len(cond) == 0 {
					continue
				}
				evid := fmt.Sprintf("assets[%d].policies.attached_policies[%d].statements[%d].Condition", i, pi, si)
				ops := make([]string, 0, len(cond))
				for op := range cond {
					ops = append(ops, op)
				}
				sort.Strings(ops)
				for _, op := range ops {
					keys, ok := cond[op].(map[string]any)
					if !ok {
						continue
					}
					keyNames := make([]string, 0, len(keys))
					for k := range keys {
						keyNames = append(keyNames, k)
					}
					sort.Strings(keyNames)
					for _, k := range keyNames {
						out = append(out, Fact{
							Subject: a.ID, Predicate: "has_condition", Object: op + ":" + k,
							Source: "iam_policy", Evidence: evid,
						})
						// Ternary (asset, key, value) compressed into the
						// binary "<op>:<key>=<value>" form. Same key=value
						// concatenation pattern as has_tag — `=` is not a
						// valid character in IAM condition keys, so the
						// split point is unambiguous. Emits one fact per
						// value (conditions can carry array values).
						for _, val := range coerceStringList(keys[k]) {
							out = append(out, Fact{
								Subject: a.ID, Predicate: "has_condition_value",
								Object: op + ":" + k + "=" + val,
								Source: "iam_policy", Evidence: evid,
							})
						}
					}
				}
			}
		}
	}
	return out
}

// stringifiedPolicyPath names one observation property whose
// scalar value is a stringified JSON policy document. AWS APIs
// commonly return resource policies (API Gateway resource
// policies, S3 bucket policies, KMS key policies) as JSON
// strings rather than parsed structures; the structured-map
// projectors above can't cross that string boundary, so a
// dedicated parser re-emits each statement's Condition block
// through has_condition / has_condition_value.
//
// Adding a new path is governance, not a kitchen sink — only
// fields confirmed in real fixtures belong here. The parser
// fails silently on invalid JSON (some scalar string fields
// happen to share a name with a real policy field on a
// different asset type).
type stringifiedPolicyPath struct {
	blockKey   string // top-level key under properties
	keys       []string
	dotPath    string   // human-readable joined path for evidence
	assetTypes []string // empty = all asset types
}

var stringifiedPolicyAllowlist = []stringifiedPolicyPath{
	// API Gateway resource policy (apigw-private-api-scoped-deny):
	// the aws:sourceVpc / aws:sourceVpce condition lives here.
	{
		blockKey: "api", keys: []string{"network", "resource_policy_json"},
		dotPath:    "api.network.resource_policy_json",
		assetTypes: []string{"aws_apigateway_rest_api"},
	},
	// S3 bucket resource policy (s3-cross-account-replication-overperm
	// and similar). Most cross-account fixtures express their
	// discriminating Conditions here.
	{
		blockKey: "storage", keys: []string{"policy_json"},
		dotPath:    "storage.policy_json",
		assetTypes: []string{"aws_s3_bucket"},
	},
	// KMS key policy.
	{
		blockKey: "encryption", keys: []string{"key_policy_json"},
		dotPath:    "encryption.key_policy_json",
		assetTypes: []string{"aws_kms_key"},
	},
}

// stringifiedPolicyFacts parses JSON strings embedded in
// observation properties and re-emits their Condition blocks
// through has_condition / has_condition_value. The parser walks
// the same statement → Condition → operator → key → value
// shape that conditionFacts walks for structured policies; the
// only difference is the json.Unmarshal step that bridges the
// string boundary.
//
// Determinism: operators and keys are sorted before emission;
// values are emitted in source order (the policy author's
// chosen order is the canonical order). Statement order
// follows the parsed JSON's array index — Go's encoding/json
// preserves array order.
//
// Failure modes that produce zero facts (and no error):
//   - Field is absent on the asset.
//   - Field is present but not a string (schema variation).
//   - Field is a string but not valid JSON.
//   - Parsed JSON has no Statement[] or no Condition blocks.
//
// These are all expected on fixtures where the path doesn't
// apply; raising errors would noise the export with non-issues.
func stringifiedPolicyFacts(assets []sir.AssetFact) []Fact {
	var out []Fact
	for i := range assets {
		a := &assets[i]
		for _, rule := range stringifiedPolicyAllowlist {
			if len(rule.assetTypes) > 0 {
				match := false
				for _, t := range rule.assetTypes {
					if a.Type == t {
						match = true
						break
					}
				}
				if !match {
					continue
				}
			}
			block, ok := a.Properties[rule.blockKey].(map[string]any)
			if !ok {
				continue
			}
			var raw any = block
			for _, k := range rule.keys {
				m, ok := raw.(map[string]any)
				if !ok {
					raw = nil
					break
				}
				raw = m[k]
			}
			jsonStr, ok := raw.(string)
			if !ok || jsonStr == "" {
				continue
			}
			var policy map[string]any
			if err := json.Unmarshal([]byte(jsonStr), &policy); err != nil {
				continue
			}
			stmts, ok := policy["Statement"].([]any)
			if !ok {
				continue
			}
			for si, sRaw := range stmts {
				stmt, ok := sRaw.(map[string]any)
				if !ok {
					continue
				}
				stmtBase := fmt.Sprintf("assets[%d].properties.%s → (parsed JSON) → Statement[%d]",
					i, rule.dotPath, si)
				// Resource-policy principal + action extraction
				// (PR 5). Emitted regardless of whether the
				// Statement carries a Condition block. The
				// "resource_policy_*" predicate names are
				// distinct from has_action / has_resource so a
				// reader can tell which trust model produced the
				// fact (resource policy attached to the bucket
				// vs. identity policy attached to the role).
				if p, hasP := stmt["Principal"]; hasP {
					for _, principal := range extractResourcePolicyPrincipals(p) {
						out = append(out, Fact{
							Subject: a.ID, Predicate: "resource_policy_principal",
							Object: principal, Source: "stringified_policy",
							Evidence: stmtBase + ".Principal",
						})
					}
				}
				for _, action := range coerceStringList(stmt["Action"]) {
					out = append(out, Fact{
						Subject: a.ID, Predicate: "resource_policy_action",
						Object: action, Source: "stringified_policy",
						Evidence: stmtBase + ".Action",
					})
				}
				// Condition extraction (PR 4 behavior).
				cond, ok := stmt["Condition"].(map[string]any)
				if !ok || len(cond) == 0 {
					continue
				}
				evid := stmtBase + ".Condition"
				ops := make([]string, 0, len(cond))
				for op := range cond {
					ops = append(ops, op)
				}
				sort.Strings(ops)
				for _, op := range ops {
					keys, ok := cond[op].(map[string]any)
					if !ok {
						continue
					}
					keyNames := make([]string, 0, len(keys))
					for k := range keys {
						keyNames = append(keyNames, k)
					}
					sort.Strings(keyNames)
					for _, k := range keyNames {
						out = append(out, Fact{
							Subject: a.ID, Predicate: "has_condition", Object: op + ":" + k,
							Source: "stringified_policy", Evidence: evid,
						})
						for _, val := range coerceStringList(keys[k]) {
							out = append(out, Fact{
								Subject: a.ID, Predicate: "has_condition_value",
								Object: op + ":" + k + "=" + val,
								Source: "stringified_policy", Evidence: evid,
							})
						}
					}
				}
			}
		}
	}
	return out
}

// dataEventLoggingFacts walks CloudTrail trail assets and emits
// has_data_event_logging(bucket_arn, "true") for every S3 bucket
// listed in event_selectors[].data_resources[].values[]. The
// trailing "/" in CloudTrail's data-resource ARN form (e.g.
// "arn:aws:s3:::my-bucket/") is stripped so the subject matches
// has_type(bucket, "aws_s3_bucket") downstream.
//
// CEL evaluates per-bucket coverage at runtime by walking the
// same nested structure; this projector makes the per-bucket
// boolean visible to external SMT solvers so queries like
//
//	"is there a bucket tagged confidential WITHOUT data event
//	 logging?" — has_tag(b, "data_classification=...") AND NOT
//	             has_data_event_logging(b, "true")
//
// are expressible. Closed-world axioms make the absence side
// (no positive fact for an uncovered bucket) report false
// without an explicit "is_logging_disabled" projector.
//
// Property path:
//
//	properties.trail.event_selectors[].data_resources[].values[]
//
// Trails without data-event coverage produce no facts; trails
// with empty event_selectors / data_resources also produce
// nothing.
func dataEventLoggingFacts(assets []sir.AssetFact) []Fact {
	var out []Fact
	for i := range assets {
		a := &assets[i]
		if a.Type != "aws_cloudtrail_trail" {
			continue
		}
		trail, ok := a.Properties["trail"].(map[string]any)
		if !ok {
			continue
		}
		selectors, ok := trail["event_selectors"].([]any)
		if !ok {
			continue
		}
		for ei, sel := range selectors {
			s, ok := sel.(map[string]any)
			if !ok {
				continue
			}
			dr, ok := s["data_resources"].([]any)
			if !ok {
				continue
			}
			for di, raw := range dr {
				resource, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				values, ok := resource["values"].([]any)
				if !ok {
					continue
				}
				evid := fmt.Sprintf("assets[%d].properties.trail.event_selectors[%d].data_resources[%d].values", i, ei, di)
				for _, v := range values {
					bucketARN, ok := v.(string)
					if !ok || bucketARN == "" {
						continue
					}
					bucketARN = strings.TrimSuffix(bucketARN, "/")
					out = append(out, Fact{
						Subject: bucketARN, Predicate: "has_data_event_logging", Object: "true",
						Source: "cloudtrail", Evidence: evid,
					})
				}
			}
		}
	}
	return out
}

// tagFacts walks every asset and emits one `has_tag` per
// (key, value) pair in the asset's tags blocks. Tags can sit
// at any depth-2 path under properties — different services
// nest differently:
//
//	S3 (bybit fixture):  properties.bucket.tags.<key>
//	S3 (other controls): properties.storage.tags.<key>
//	IAM:                 properties.identity.tags.<key>
//	API Gateway:         properties.api.tags.<key>
//	CloudFront:          properties.cdn.tags.<key>
//
// Rather than hard-code the per-service path list, the
// extractor scans every top-level property block for a
// `tags` sub-map. This catches the bybit convention
// (properties.bucket.tags) and the older convention
// (properties.storage.tags) and any new asset type that
// follows the same shallow shape, with no per-service plumbing.
//
// The has_tag predicate is BINARY:
//
//	has_tag(asset_id, "key=value")
//
// rather than ternary (subject, key, value). The current
// SMT-LIB serializer assumes binary predicates throughout;
// supporting a ternary `has_tag` would require multi-arity
// declare-fun + closed-world axiom support across every
// other predicate. Encoding "key=value" as a single object
// string keeps the serializer simple at a small cost in
// query ergonomics: callers write
//
//	(has_tag bucket "environment=production")
//
// instead of (has_tag bucket "environment" "production").
// The semantic is identical — the asserted tuple uniquely
// identifies the (asset, key, value) triple.
//
// Determinism: tag map iteration order is randomised in Go;
// the slice of (key, value) pairs is sorted before emission
// so the same SIR document yields byte-identical output
// across runs.
func tagFacts(assets []sir.AssetFact) []Fact {
	var out []Fact
	for i := range assets {
		a := &assets[i]
		// Stable order across the asset's property blocks.
		blockNames := make([]string, 0, len(a.Properties))
		for name := range a.Properties {
			blockNames = append(blockNames, name)
		}
		sort.Strings(blockNames)
		for _, blockName := range blockNames {
			block, ok := a.Properties[blockName].(map[string]any)
			if !ok {
				continue
			}
			tags, ok := block["tags"].(map[string]any)
			if !ok {
				continue
			}
			keys := make([]string, 0, len(tags))
			for k := range tags {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				value, ok := tags[k].(string)
				if !ok || value == "" {
					continue
				}
				out = append(out, Fact{
					Subject:   a.ID,
					Predicate: "has_tag",
					Object:    k + "=" + value,
					Source:    "tag",
					Evidence:  fmt.Sprintf("assets[%d].properties.%s.tags.%s", i, blockName, k),
				})
			}
		}
	}
	return out
}

// trustPolicyFacts walks IAM role assets and emits one
// `trusts_service` fact per service principal in
// `properties.identity.trusted_services`. The fact answers
// "which compute / control-plane service can assume this role
// via sts:AssumeRole?" — a different question from
// `can_assume` (role-to-role hops in the SIR's role-chain
// graph). Both predicates coexist; queries pick whichever
// matches the question.
//
// Compound queries combining `trusts_service` with
// `contributed_by` (overpermission finding) detect the
// canonical PassRole exploit shape: role is overpermissioned
// AND assumable by a compute service the attacker controls.
//
// Property path: properties.identity.trusted_services []string
//
// Empty / absent / wrong-shape trusted_services yields no
// facts; the closed-world axiom then restricts the predicate
// to false everywhere on that role.
func trustPolicyFacts(assets []sir.AssetFact) []Fact {
	var out []Fact
	for i := range assets {
		a := &assets[i]
		if a.Type != "aws_iam_role" {
			continue
		}
		identity, ok := a.Properties["identity"].(map[string]any)
		if !ok {
			continue
		}
		services, ok := identity["trusted_services"].([]any)
		if !ok {
			continue
		}
		evid := fmt.Sprintf("assets[%d].properties.identity.trusted_services", i)
		for si, raw := range services {
			service, ok := raw.(string)
			if !ok || service == "" {
				continue
			}
			out = append(out, Fact{
				Subject: a.ID, Predicate: "trusts_service", Object: service,
				Source: "trust_policy", Evidence: fmt.Sprintf("%s[%d]", evid, si),
			})
		}
	}
	return out
}

// assumeEdgeFacts emits one `can_assume(from, to)` fact per
// reciprocal sts:AssumeRole edge between IAM principals in the
// snapshot. The edge requires both halves of the IAM contract:
//
//  1. The assumer's policies grant Allow + sts:AssumeRole on the
//     target ARN (read from properties.identity.policies.attached_policies).
//  2. The target role's trust_policy_json admits the assumer
//     under Allow + sts:AssumeRole (read from properties.identity.trust_policy_json).
//
// The kernel's IAM resolver enforces the same contract; this
// extractor shadows it on the SMT side because the obs.v0.1
// loader does not populate snap.Identities, so the kernel
// resolver never runs against on-disk fixtures and IdentityFact-
// sourced can_assume facts never appear. Authoring this
// extractor here keeps the SMT export self-contained against
// the obs.v0.1 wire shape.
//
// Multi-hop reachability is the SMT solver's job. The extractor
// emits flat per-hop edges; transitive closure is left to the
// query (existential quantification over intermediate nodes).
type assumeRequest struct {
	assumer string
	target  string
	evid    string
}

// scanAssumeGrants walks one identity's attached_policies and
// returns every (assumer, target) pair where the policy grants
// Allow + sts:AssumeRole on a specific target ARN. Wildcard
// resources are skipped — they don't ground a witness.
func scanAssumeGrants(assetIdx int, assumerID string, identity map[string]any) []assumeRequest {
	policies, ok := identity["policies"].(map[string]any)
	if !ok {
		return nil
	}
	attached, ok := policies["attached_policies"].([]any)
	if !ok {
		return nil
	}
	var out []assumeRequest
	for pi, p := range attached {
		policy, ok := p.(map[string]any)
		if !ok {
			continue
		}
		stmts, ok := policy["statements"].([]any)
		if !ok {
			continue
		}
		for si, s := range stmts {
			out = append(out, scanAssumeStatement(assetIdx, pi, si, assumerID, s)...)
		}
	}
	return out
}

func scanAssumeStatement(assetIdx, policyIdx, stmtIdx int, assumerID string, raw any) []assumeRequest {
	stmt, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	if effect, _ := stmt["Effect"].(string); effect != "Allow" {
		return nil
	}
	hasAssume := false
	for _, act := range coerceStringList(stmt["Action"]) {
		if act == "sts:AssumeRole" || act == "sts:*" || act == "*" {
			hasAssume = true
			break
		}
	}
	if !hasAssume {
		return nil
	}
	var out []assumeRequest
	for _, target := range coerceStringList(stmt["Resource"]) {
		if target == "*" || target == "" {
			continue
		}
		out = append(out, assumeRequest{
			assumer: assumerID,
			target:  target,
			evid:    fmt.Sprintf("assets[%d].policies.attached_policies[%d].statements[%d]", assetIdx, policyIdx, stmtIdx),
		})
	}
	return out
}

func assumeEdgeFacts(assets []sir.AssetFact) []Fact {
	var requests []assumeRequest
	trustAdmits := make(map[string]map[string]string) // target → assumer → evid
	for i := range assets {
		a := &assets[i]
		if a.Type != "aws_iam_user" && a.Type != "aws_iam_role" {
			continue
		}
		identity, ok := a.Properties["identity"].(map[string]any)
		if !ok {
			continue
		}
		// Assumer side: scan attached_policies for sts:AssumeRole grants.
		requests = append(requests, scanAssumeGrants(i, a.ID, identity)...)
		// Target side: parse trust_policy_json for admitted principals.
		if a.Type != "aws_iam_role" {
			continue
		}
		trustJSON, _ := identity["trust_policy_json"].(string)
		trimmed := strings.TrimSpace(trustJSON)
		if trimmed == "" {
			continue
		}
		var doc struct {
			Statement []struct {
				Effect    string `json:"Effect"`
				Action    any    `json:"Action"`
				Principal any    `json:"Principal"`
			} `json:"Statement"`
		}
		if err := json.Unmarshal([]byte(trimmed), &doc); err != nil {
			continue
		}
		evidBase := fmt.Sprintf("assets[%d].properties.identity.trust_policy_json", i)
		admitted := trustAdmits[a.ID]
		if admitted == nil {
			admitted = make(map[string]string)
		}
		for si, stmt := range doc.Statement {
			if !strings.EqualFold(stmt.Effect, "Allow") {
				continue
			}
			hasAssume := false
			for _, act := range coerceStringList(stmt.Action) {
				if act == "sts:AssumeRole" || act == "sts:*" || act == "*" {
					hasAssume = true
					break
				}
			}
			if !hasAssume {
				continue
			}
			pmap, ok := stmt.Principal.(map[string]any)
			if !ok {
				continue
			}
			for _, principal := range coerceStringList(pmap["AWS"]) {
				if principal == "" || principal == "*" {
					continue
				}
				admitted[principal] = fmt.Sprintf("%s.Statement[%d]", evidBase, si)
			}
		}
		if len(admitted) > 0 {
			trustAdmits[a.ID] = admitted
		}
	}
	// Cross-reference: emit only when both sides agree.
	var out []Fact
	for _, req := range requests {
		admit, ok := trustAdmits[req.target]
		if !ok {
			continue
		}
		if _, admitted := admit[req.assumer]; !admitted {
			continue
		}
		out = append(out, Fact{
			Subject:   req.assumer,
			Predicate: "can_assume",
			Object:    req.target,
			Source:    "trust_edge",
			Evidence:  req.evid,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		return out[i].Object < out[j].Object
	})
	return out
}

// navMap walks a nested map[string]any path. Returns the final
// map plus true on success; nil + false if any intermediate key
// is missing or not a map. Used by the property-path extractors
// to navigate the SIR's free-form Properties bag.
func navMap(props map[string]any, keys ...string) (map[string]any, bool) {
	cur := props
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// extractResourcePolicyPrincipals normalises the four shapes a
// resource-policy Statement.Principal value can take into a
// flat, deterministically ordered list of principal ARNs (or
// service names, or "*"):
//
//	"*"                                         → ["*"]
//	"arn:aws:iam::123:root"                     → ["arn:aws:iam::123:root"]
//	{"AWS": "arn:..."}                          → ["arn:..."]
//	{"AWS": ["arn:1", "arn:2"], "Service":"ec2"}→ ["arn:1", "arn:2", "ec2"]
//
// The ARN-prefix-by-key form ({"AWS": ...}, {"Service": ...},
// {"Federated": ...}, {"CanonicalUser": ...}) is flattened —
// the principal value is what matters for trust-scope queries;
// re-emitting per-key would require either ternary predicates
// or a per-key prefix encoding, neither of which the existing
// SMT serializer supports cleanly. Determinism is enforced
// with sort.Strings.
func extractResourcePolicyPrincipals(principal any) []string {
	switch v := principal.(type) {
	case string:
		return []string{v}
	case map[string]any:
		var result []string
		for _, val := range v {
			result = append(result, coerceStringList(val)...)
		}
		sort.Strings(result)
		return result
	}
	return nil
}

// coerceStringList accepts the IAM-policy convention where a
// list-typed field can be either a single string or an array of
// strings. JSON-parsed values arrive as []any when arrays;
// elements are strings. Anything else returns nil.
func coerceStringList(v any) []string {
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
	}
	return nil
}

func exposureFacts(windows []sir.ExposureWindow) []Fact {
	var out []Fact
	for i, w := range windows {
		if !w.UnsafePredicateMatched {
			continue
		}
		evid := fmt.Sprintf("temporal.windows[%d]", i)
		out = append(out, Fact{Subject: w.AssetID, Predicate: "has_exposure_window", Object: "true", Source: "exposure", Evidence: evid})
		for _, ctrl := range w.ContributingControls {
			out = append(out, Fact{Subject: w.AssetID, Predicate: "contributed_by", Object: ctrl, Source: "exposure", Evidence: evid + ".contributing_controls"})
		}
	}
	return out
}

// serializeJSONL writes one JSON object per line. The order
// reflects ExtractFacts' deterministic walk of the SIR document.
func serializeJSONL(facts []Fact, w io.Writer) error {
	enc := json.NewEncoder(w)
	for i := range facts {
		if err := enc.Encode(&facts[i]); err != nil {
			return fmt.Errorf("encode fact %d: %w", i, err)
		}
	}
	return nil
}

// baselineSMT2Predicates is the stable set of binary predicates
// the projection may emit. The SMT-LIB serializer ALWAYS declares
// every baseline predicate, regardless of whether the current
// fact set populates it, so query files can reference any of them
// portably. Without this baseline, a query that mentions
// `has_exposure_window` against a fixture where no exposure
// window fired would error with "unknown function" before
// reasoning ever started.
//
// Adding a new predicate to ExtractFacts means adding it here.
// The compile-time list is intentional: the SMT contract is
// stable, not implicit.
var baselineSMT2Predicates = []string{
	"allows_unauthenticated",
	"can_assume",
	"contributed_by",
	"cross_account_assumes",
	"first_seen_at",
	"has_action",
	"has_advanced_security_enabled",
	"has_bucket_exists",
	"has_bucket_owned",
	"has_condition",
	"has_condition_value",
	"has_data_event_logging",
	"has_deny_action",
	"has_deny_resource",
	"has_exposed_repo_artifacts",
	"has_exposure_window",
	"has_forbidden_state",
	"has_intent_rationale",
	"has_list_via_resource",
	"has_logging_enabled",
	"has_mfa_enforced",
	"has_permission_action",
	"has_permission_resource",
	"has_privilege_level",
	"has_public_access_blocked",
	"has_public_list",
	"has_public_read",
	"has_read_via_resource",
	"has_resource",
	"has_severity",
	"has_tag",
	"has_type",
	"has_upload_key_mode",
	"has_uses_access_key_id",
	"has_vendor",
	"has_webhook_config_access",
	"is_decommissioned",
	"is_provisioned",
	"last_seen_at",
	"maps_auth_to",
	"maps_unauth_to",
	"resource_policy_action",
	"resource_policy_principal",
	"self_registration_unrestricted",
	"trusts_service",
}

// serializeSMT2 writes SMT-LIB v2 declarations, fact assertions,
// and per-predicate closed-world axioms.
//
// Predicates are declared as binary Bool functions over String
// args. Each fact becomes an assertion using string literals for
// subject and object. After the positive facts, one closed-world
// axiom per predicate restricts the predicate to be true ONLY
// for the asserted tuples — for all other (s, o) inputs, the
// predicate is false.
//
// Why closed-world: SMT-LIB's open-world default makes
// uninstantiated predicates trivially satisfiable, which would
// make every existential query SAT regardless of fixture
// content. The closed-world axiom is what gives the fact base
// the "Datalog-like" semantics solver consumers expect: queries
// asking "does X hold?" return SAT iff the configuration
// actually exhibits X.
//
// The output contains NO (check-sat), NO (get-model), NO
// query-specific assertions — only declarations, facts, and
// per-predicate closed-world axioms. Reasoning programs append
// their own queries.
//
// SMT-LIB symbols are restricted to a printable charset; predicate
// names are pre-validated by the SIR schema (snake_case ASCII)
// so no escaping is needed for predicate symbols. String literals
// follow SMT-LIB v2.6 string theory: surrounded by ", embedded "
// escaped as "" (per the standard).
func serializeSMT2(facts []Fact, w io.Writer) error {
	bw := newBufferedWriter(w)
	bw.writeLine("; Stave SIR facts export — SMT-LIB v2")
	bw.writeLine("; Predicates declared as Bool functions over String args.")
	bw.writeLine("; Closed-world axioms emitted per predicate: the predicate is true")
	bw.writeLine("; ONLY for the (subject, object) pairs explicitly asserted; for")
	bw.writeLine("; every other input it is false. This is the standard fact-base")
	bw.writeLine("; encoding for SAT/SMT consumers.")
	bw.writeLine("; This file contains FACTS ONLY. Append your query (check-sat / get-model / etc.) before invoking the solver.")
	bw.writeLine("(set-logic ALL)")
	bw.writeLine("")

	predicates := allDeclaredPredicates(facts)
	bw.writeLine("; --- Predicate declarations ---")
	for _, p := range predicates {
		bw.writeLine(fmt.Sprintf("(declare-fun %s (String String) Bool)", p))
	}
	bw.writeLine("")

	bw.writeLine("; --- Facts ---")
	for _, f := range facts {
		// Correlation comments — the solver ignores `;` lines, so
		// verdicts are unaffected. Humans and tooling tracing a
		// witness back to its originating fact / projector / file
		// read these. fact_id leads the block because it's the
		// canonical correlation key.
		if f.FactID != "" {
			bw.writeLine(fmt.Sprintf(";; fact_id: %s", f.FactID))
		}
		if f.Provenance != nil {
			bw.writeLine(fmt.Sprintf(";; projector: %s", f.Provenance.Projector))
			if f.Provenance.PropertyPath != "" {
				bw.writeLine(fmt.Sprintf(";; path: %s", f.Provenance.PropertyPath))
			}
			if f.Provenance.CapturedAt != "" {
				bw.writeLine(fmt.Sprintf(";; captured: %s", f.Provenance.CapturedAt))
			}
		}
		bw.writeLine(fmt.Sprintf("(assert (%s %s %s))", f.Predicate, smt2Quote(f.Subject), smt2Quote(f.Object)))
	}

	bw.writeLine("")
	bw.writeLine("; --- Closed-world axioms ---")
	bw.writeLine("; Each axiom restricts the predicate to its asserted positive facts.")
	bw.writeLine("; For predicates with no facts, the axiom asserts the predicate is")
	bw.writeLine("; false everywhere.")
	for _, p := range predicates {
		bw.writeLine(closedWorldAxiom(p, factsByPredicate(facts, p)))
	}
	return bw.err
}

// allDeclaredPredicates returns the sorted union of the baseline
// predicates plus any predicate names appearing in the facts
// slice that aren't already in the baseline. The baseline keeps
// queries portable across fixtures; the dynamic addition handles
// future projections that introduce predicates the baseline
// hasn't been updated for.
func allDeclaredPredicates(facts []Fact) []string {
	seen := make(map[string]struct{}, len(baselineSMT2Predicates)+len(facts))
	for _, p := range baselineSMT2Predicates {
		seen[p] = struct{}{}
	}
	for _, f := range facts {
		seen[f.Predicate] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// uniquePredicates returns the sorted unique set of predicate
// names appearing in the facts slice. Used by tests to enumerate
// the per-fixture predicate set.
func uniquePredicates(facts []Fact) []string {
	seen := make(map[string]struct{}, len(facts))
	for _, f := range facts {
		seen[f.Predicate] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// factsByPredicate filters the slice to the facts whose predicate
// matches. Order is preserved from the input slice.
func factsByPredicate(facts []Fact, predicate string) []Fact {
	var out []Fact
	for _, f := range facts {
		if f.Predicate == predicate {
			out = append(out, f)
		}
	}
	return out
}

// closedWorldAxiom builds the SMT-LIB universal axiom that
// restricts a binary predicate to be true only for the asserted
// tuples.
//
//	No tuples → (assert (forall ((x String) (y String)) (not (P x y))))
//	One tuple → (assert (forall (...) (=> (P x y) (and (= x A) (= y B)))))
//	N tuples  → (assert (forall (...) (=> (P x y) (or (and ...) ...))))
//
// The axiom's quantifier-free body is a finite disjunction so
// even Z3's default solver instantiates it efficiently for the
// tuple counts the SIR projection produces (typically tens to
// low hundreds per predicate).
func closedWorldAxiom(predicate string, tuples []Fact) string {
	if len(tuples) == 0 {
		return fmt.Sprintf("(assert (forall ((x String) (y String)) (not (%s x y))))", predicate)
	}
	disjuncts := make([]string, 0, len(tuples))
	for _, t := range tuples {
		disjuncts = append(disjuncts,
			fmt.Sprintf("(and (= x %s) (= y %s))", smt2Quote(t.Subject), smt2Quote(t.Object)))
	}
	body := disjuncts[0]
	if len(disjuncts) > 1 {
		body = "(or " + strings.Join(disjuncts, " ") + ")"
	}
	return fmt.Sprintf("(assert (forall ((x String) (y String)) (=> (%s x y) %s)))", predicate, body)
}

// smt2Quote renders a Go string as an SMT-LIB v2 string
// literal: surrounded by ", embedded " escaped as "".
func smt2Quote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// bufferedWriter is a minimal error-sticky line writer so the
// serialiser can emit many lines without checking err on each
// call. The first error halts subsequent writes; the final
// err is returned by serializeSMT2.
type bufferedWriter struct {
	w   io.Writer
	err error
}

func newBufferedWriter(w io.Writer) *bufferedWriter { return &bufferedWriter{w: w} }

func (b *bufferedWriter) writeLine(s string) {
	if b.err != nil {
		return
	}
	if _, err := io.WriteString(b.w, s+"\n"); err != nil {
		b.err = err
	}
}
