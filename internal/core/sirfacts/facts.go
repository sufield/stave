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
package sirfacts

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

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
	Freshness  *Freshness  `json:"freshness,omitempty"`
	Provenance *Provenance `json:"provenance,omitempty"`
}

// Freshness annotates a fact with the snapshot timestamp it was
// projected from and the elapsed time since that snapshot was
// captured. Surfaces what is buried in Provenance.CapturedAt as
// a top-level, sortable field so consumers can filter by recency
// without parsing the provenance object:
//
//	jq 'select(.freshness.age_seconds < 86400)' facts.jsonl
//	jq -s 'sort_by(.freshness.age_seconds) | .[]' facts.jsonl
//
// AgeSeconds is computed against an export-time `now` supplied
// by the caller (export-sir's --eval-time flag, falling back to the
// system clock). Pinning --eval-time produces byte-stable freshness
// fields across runs — required for golden tests and CI diffs.
//
// Negative ages (captured_at after now — clock skew between the
// snapshot collector and the export host) clamp to zero rather
// than reporting a negative duration; the field is informational,
// not a clock-correctness assertion.
type Freshness struct {
	CapturedAt time.Time `json:"captured_at"`
	AgeSeconds int64     `json:"age_seconds"`
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
	if _, after, ok := strings.Cut(p, "]."); ok {
		return after
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
	facts = append(facts, annotateProvenance(delegationPrincipalFacts(doc.Assets), "delegationPrincipalFacts", assetByID)...)
	facts = append(facts, annotateProvenance(unusedServiceFacts(doc.Assets), "unusedServiceFacts", assetByID)...)
	facts = append(facts, annotateProvenance(incompatiblePairFacts(doc.Assets), "incompatiblePairFacts", assetByID)...)
	facts = append(facts, annotateProvenance(forbiddenCategoryFacts(doc.Assets), "forbiddenCategoryFacts", assetByID)...)
	facts = append(facts, annotateProvenance(trustPolicyFacts(doc.Assets), "trustPolicyFacts", assetByID)...)
	facts = append(facts, annotateProvenance(assumeEdgeFacts(doc.Assets), "assumeEdgeFacts", assetByID)...)
	facts = append(facts, annotateProvenance(identityFacts(doc.Identities), "identityFacts", assetByID)...)
	facts = append(facts, annotateProvenance(purposeFlagFacts(doc.Assets, doc.Identities), "purposeFlagFacts", assetByID)...)
	facts = append(facts, annotateProvenance(exposureFacts(doc.Temporal.Windows), "exposureFacts", assetByID)...)
	return facts
}

// AnnotateFreshness stamps a Freshness block on every fact whose
// Provenance.CapturedAt is non-empty. The captured_at string in
// Provenance is RFC3339 (formatted at annotateProvenance time
// from the asset's Lifecycle.LastSeen); this pass parses it back
// into a time.Time and computes age = now - captured_at,
// clamping negative ages (clock skew) to zero.
//
// Kept as a separate boundary pass rather than folded into
// ExtractFacts so callers that don't surface freshness — e.g.
// pkg/stave/internal/applycore building fact-id correlations —
// don't pay the parse cost. The export-sir command runs both;
// applycore runs only ExtractFacts.
//
// Determinism: when --eval-time is pinned, all facts produce
// byte-stable AgeSeconds across runs. Without --eval-time the
// system clock supplies `now` and AgeSeconds drifts by the
// elapsed wall-clock time between exports, but CapturedAt
// stays stable.
func AnnotateFreshness(facts []Fact, now time.Time) {
	nowUTC := now.UTC()
	for i := range facts {
		p := facts[i].Provenance
		if p == nil || p.CapturedAt == "" {
			continue
		}
		captured, err := time.Parse(time.RFC3339, p.CapturedAt)
		if err != nil {
			continue
		}
		age := max(nowUTC.Sub(captured), 0)
		facts[i].Freshness = &Freshness{
			CapturedAt: captured.UTC(),
			AgeSeconds: int64(age.Seconds()),
		}
	}
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
	// Index loop (rather than range-by-value) because IdentityFact
	// now carries a Properties map and the per-iter copy crosses
	// gocritic's rangeValCopy threshold. Pointer indexing keeps the
	// hot path allocation-free.
	for i := range identities {
		id := &identities[i]
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
				evid := fmt.Sprintf("assets[%d].properties.identity.policies.attached_policies[%d].statements[%d]", i, pi, si)
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
	// Tri-state mode (OFF | AUDIT | ENFORCED). Enabled alone collapses
	// AUDIT and ENFORCED into one bucket; mode preserves the
	// "visibility without enforcement" distinction the AUDITONLY
	// control flags.
	{blockKey: "identity", keys: []string{"advanced_security", "mode"}, predicateName: "has_advanced_security_mode", assetTypes: []string{"aws_cognito_user_pool"}},
	// Cognito user-pool Lambda trigger ghost references (CTL.COGNITO.GHOST.* family).
	// trigger_type carries the trigger name (pre_sign_up, pre_authentication, …)
	// so a single SMT-LIB predicate covers all 10 trigger variants; the query
	// disambiguates with (= (trigger_type asset) "pre_sign_up").
	{blockKey: "identity", keys: []string{"cognito", "trigger_type"}, predicateName: "has_trigger_type", assetTypes: []string{"aws_cognito_user_pool"}},
	{blockKey: "identity", keys: []string{"cognito", "trigger_lambda_exists"}, predicateName: "has_trigger_lambda_exists", assetTypes: []string{"aws_cognito_user_pool"}},
	{blockKey: "identity", keys: []string{"cognito", "has_ghost_trigger"}, predicateName: "has_ghost_trigger", assetTypes: []string{"aws_cognito_user_pool"}},
	// EKS RBAC webhook-config write access (eks-rbac-webhook-config-access)
	{blockKey: "k8s", keys: []string{"rbac", "has_webhook_config_access"}, predicateName: "has_webhook_config_access"},
	// EKS aws-auth ConfigMap template-injection vector (eks-aws-auth-template-injection)
	{blockKey: "auth", keys: []string{"webhook", "identity_mapping", "uses_access_key_id"}, predicateName: "has_uses_access_key_id"},
	// CloudTrail trail logging state (cloudtrail-stop-logging mgmt-events fixtures)
	{blockKey: "trail", keys: []string{"is_logging"}, predicateName: "has_logging_enabled", assetTypes: []string{"aws_cloudtrail_trail"}},

	// ── AI Agent (Bedrock) ────────────────────────────────────
	// Covers the bedrock agent overpermissioned + governance fixtures
	// under examples/demo-ai-security/. Properties land at
	// properties.ai.agent.* on aws_bedrock_agent assets.
	{blockKey: "ai", keys: []string{"agent", "guardrail_associated"}, predicateName: "has_agent_guardrail", assetTypes: []string{"aws_bedrock_agent"}},
	{blockKey: "ai", keys: []string{"agent", "invocation_logging_enabled"}, predicateName: "has_agent_invocation_logging", assetTypes: []string{"aws_bedrock_agent"}},
	{blockKey: "ai", keys: []string{"agent", "lambda_invoke_scope_broad"}, predicateName: "has_agent_lambda_scope_broad", assetTypes: []string{"aws_bedrock_agent"}},
	{blockKey: "ai", keys: []string{"agent", "s3_access_scope_broad"}, predicateName: "has_agent_s3_scope_broad", assetTypes: []string{"aws_bedrock_agent"}},
	{blockKey: "ai", keys: []string{"agent", "managed_by_iac"}, predicateName: "has_agent_iac_managed", assetTypes: []string{"aws_bedrock_agent"}},
	{blockKey: "ai", keys: []string{"agent", "action_group_count"}, predicateName: "has_agent_action_group_count", assetTypes: []string{"aws_bedrock_agent"}},
	// Bedrock knowledge base — target bucket ARN is the chain
	// scope_field for bedrock_rag_phi_exposure and
	// intent_expiry_unclassified_ai_datasource.
	{blockKey: "ai", keys: []string{"knowledge_base", "target_bucket_arn"}, predicateName: "has_kb_target_bucket", assetTypes: []string{"aws_bedrock_knowledge_base"}},
	{blockKey: "ai", keys: []string{"knowledge_base", "data_source_encrypted"}, predicateName: "has_kb_source_encrypted", assetTypes: []string{"aws_bedrock_knowledge_base"}},

	// ── VPC Peering (vpc-peering-exfiltration demo) ───────────
	// The chain vpc_peering_exposure groups by
	// properties.network.peering.id (scope_field), which both the
	// peering connection asset and the route table asset carry.
	{blockKey: "network", keys: []string{"peering", "id"}, predicateName: "has_peering_id", assetTypes: []string{"aws_vpc_peering_connection", "aws_vpc_route_table"}},
	{blockKey: "network", keys: []string{"peering", "status"}, predicateName: "has_peering_status", assetTypes: []string{"aws_vpc_peering_connection"}},
	{blockKey: "network", keys: []string{"peering", "peer_account_in_org"}, predicateName: "has_peering_peer_in_org", assetTypes: []string{"aws_vpc_peering_connection"}},
	{blockKey: "network", keys: []string{"peering", "dns_resolution_from_remote"}, predicateName: "has_peering_dns_resolution", assetTypes: []string{"aws_vpc_peering_connection"}},
	{blockKey: "network", keys: []string{"peering", "peer_account_id"}, predicateName: "has_peering_peer_account", assetTypes: []string{"aws_vpc_peering_connection"}},
	{blockKey: "network", keys: []string{"peering", "peer_vpc_id"}, predicateName: "has_peering_peer_vpc", assetTypes: []string{"aws_vpc_peering_connection"}},
	{blockKey: "network", keys: []string{"peering_route", "has_broad_destination"}, predicateName: "has_peering_route_broad", assetTypes: []string{"aws_vpc_route_table"}},
	{blockKey: "network", keys: []string{"peering_route", "peer_connection_id"}, predicateName: "has_peering_route_target", assetTypes: []string{"aws_vpc_route_table"}},

	// ── EC2 Instance (shadow-ec2-lateral-movement demo) ────────
	// The shadow_ec2_lateral_movement chain composes three of these
	// scalars on a single aws_ec2_instance asset.
	{blockKey: "compute", keys: []string{"instance", "state"}, predicateName: "has_instance_state", assetTypes: []string{"aws_ec2_instance"}},
	{blockKey: "compute", keys: []string{"instance", "stopped_age_exceeds_threshold"}, predicateName: "has_instance_stopped_aged", assetTypes: []string{"aws_ec2_instance"}},
	{blockKey: "compute", keys: []string{"instance", "stopped_age_days"}, predicateName: "has_instance_stopped_age_days", assetTypes: []string{"aws_ec2_instance"}},
	{blockKey: "compute", keys: []string{"instance", "spans_security_zones"}, predicateName: "has_instance_dual_homed", assetTypes: []string{"aws_ec2_instance"}},
	{blockKey: "compute", keys: []string{"instance_profile", "is_overprivileged"}, predicateName: "has_instance_profile_overprivileged", assetTypes: []string{"aws_ec2_instance"}},
	{blockKey: "compute", keys: []string{"instance_profile", "arn"}, predicateName: "has_instance_profile_arn", assetTypes: []string{"aws_ec2_instance"}},
	{blockKey: "compute", keys: []string{"ec2", "vpc_id"}, predicateName: "has_instance_vpc", assetTypes: []string{"aws_ec2_instance"}},

	// ── IAM Role drift / Shadow Admin ───────────────────────────
	// Five-control entropy family at controls/iam/entropy/ —
	// PERMISSIONDRIFT, CATEGORYMIX, INTENTMISMATCH, INTENTTAG,
	// ENTROPY.INCOMPLETE. All scalars are collector-computed
	// booleans / numerics layered on top of raw Access Advisor.
	{blockKey: "identity", keys: []string{"role_age_days"}, predicateName: "has_role_age_days", assetTypes: []string{"aws_iam_role"}},
	{blockKey: "identity", keys: []string{"access_advisor", "available"}, predicateName: "has_access_advisor_available", assetTypes: []string{"aws_iam_role"}},
	{blockKey: "identity", keys: []string{"intent_match", "has_intent_mismatch"}, predicateName: "has_intent_mismatch", assetTypes: []string{"aws_iam_role"}},
	{blockKey: "identity", keys: []string{"intent_match", "declared_role_type"}, predicateName: "has_declared_role_type", assetTypes: []string{"aws_iam_role"}},
	{blockKey: "identity", keys: []string{"permission_categories", "has_incompatible_categories"}, predicateName: "has_incompatible_categories", assetTypes: []string{"aws_iam_role"}},
	{blockKey: "identity", keys: []string{"permission_drift", "threshold_exceeded"}, predicateName: "has_permission_drift_threshold_exceeded", assetTypes: []string{"aws_iam_role"}},
	{blockKey: "identity", keys: []string{"permission_drift", "unused_service_ratio"}, predicateName: "has_unused_service_ratio", assetTypes: []string{"aws_iam_role"}},
	{blockKey: "identity", keys: []string{"permission_drift", "total_services_accessible"}, predicateName: "has_total_services_accessible", assetTypes: []string{"aws_iam_role"}},

	// ── S3 Delegation (s3-delegation-failure demo) ──────────────
	// Five-control delegation family at controls/s3/delegation/.
	// All scalars are collector-stamped after comparing the bucket
	// policy against vendor_registry.yaml.
	{blockKey: "delegation", keys: []string{"has_unknown_external_principal"}, predicateName: "has_unknown_delegation", assetTypes: []string{"aws_s3_bucket"}},
	{blockKey: "delegation", keys: []string{"has_scope_exceeded"}, predicateName: "has_delegation_scope_exceeded", assetTypes: []string{"aws_s3_bucket"}},
	{blockKey: "delegation", keys: []string{"has_expired_review"}, predicateName: "has_delegation_review_expired", assetTypes: []string{"aws_s3_bucket"}},
	{blockKey: "delegation", keys: []string{"customer_can_revoke"}, predicateName: "has_customer_can_revoke", assetTypes: []string{"aws_s3_bucket"}},
	{blockKey: "delegation", keys: []string{"vendor_can_make_public"}, predicateName: "has_vendor_can_make_public", assetTypes: []string{"aws_s3_bucket"}},
	{blockKey: "delegation", keys: []string{"has_external_principals_with_control"}, predicateName: "has_delegation_external_principals", assetTypes: []string{"aws_s3_bucket"}},
	{blockKey: "delegation", keys: []string{"vendor_has_put_bucket_policy"}, predicateName: "has_vendor_put_bucket_policy", assetTypes: []string{"aws_s3_bucket"}},
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
				match := slices.Contains(rule.assetTypes, a.Type)
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
			obj := scalarString(value)
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
				slices.Sort(ops)
				for _, op := range ops {
					keys, ok := cond[op].(map[string]any)
					if !ok {
						continue
					}
					keyNames := make([]string, 0, len(keys))
					for k := range keys {
						keyNames = append(keyNames, k)
					}
					slices.Sort(keyNames)
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
						for _, val := range coerceConditionValueList(keys[k]) {
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
// fields confirmed in real fixtures belong here. assetTypes scopes
// each path so a same-named scalar on a different asset type is
// skipped (stays silent). For an asset-type-scoped field that IS
// present but not valid JSON, the parser emits a has_malformed_policy
// diagnostic fact (fail-visible) rather than silently dropping it.
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
// Modes that produce zero condition facts (no error — expected when the path
// doesn't apply to this asset):
//   - Field is absent on the asset.
//   - Field is present but not a string (schema variation).
//   - Field is on a non-matching asset type (asset-type scoping skips it).
//   - Parsed JSON has no Statement[] or no Condition blocks.
//
// Fail-visible (does NOT silently produce zero facts): an asset-type-scoped
// field that is present but not valid JSON emits a has_malformed_policy fact, so
// condition-based detections see the gap instead of a false "no conditions".
func stringifiedPolicyFacts(assets []sir.AssetFact) []Fact {
	var out []Fact
	for i := range assets {
		a := &assets[i]
		for _, rule := range stringifiedPolicyAllowlist {
			if len(rule.assetTypes) > 0 {
				match := slices.Contains(rule.assetTypes, a.Type)
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
				m, mok := raw.(map[string]any)
				if !mok {
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
				if len(rule.assetTypes) > 0 {
					// Asset-type-scoped field that is present but not valid JSON
					// is a real malformed policy (not a cross-asset scalar that
					// merely shares the field name). Fail-visible: emit a
					// diagnostic fact so condition-based detections see the gap
					// instead of silently finding zero conditions.
					out = append(out, Fact{
						Subject: a.ID, Predicate: "has_malformed_policy",
						Object: rule.dotPath, Source: "stringified_policy",
						Evidence: fmt.Sprintf("assets[%d].properties.%s present but not valid JSON: %v",
							i, rule.dotPath, err),
					})
				}
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
				out = append(out, resourcePolicyStatementFacts(a.ID, stmtBase, stmt)...)
			}
		}
	}
	return out
}

// resourcePolicyStatementFacts projects one already-parsed resource-policy
// Statement into SIR facts. Split out of stringifiedPolicyFacts to keep that
// function under the cognitive-complexity budget; the extraction is a pure
// move with no behavioral change.
//
// Emits, for the given subject (asset ID) and stmtBase evidence prefix:
//   - resource_policy_principal / resource_policy_action — always (PR 5);
//     the "resource_policy_*" predicate names stay distinct from
//     has_action / has_resource so a reader can tell which trust model
//     produced the fact (resource policy on the bucket vs. identity policy
//     on the role).
//   - has_condition / has_condition_value — only when the Statement carries
//     a non-empty Condition block (PR 4). Operators and keys are sorted so
//     the fact stream is deterministic.
func resourcePolicyStatementFacts(subject, stmtBase string, stmt map[string]any) []Fact {
	var out []Fact
	if p, hasP := stmt["Principal"]; hasP {
		for _, principal := range extractResourcePolicyPrincipals(p) {
			out = append(out, Fact{
				Subject: subject, Predicate: "resource_policy_principal",
				Object: principal, Source: "stringified_policy",
				Evidence: stmtBase + ".Principal",
			})
		}
	}
	for _, action := range coerceStringList(stmt["Action"]) {
		out = append(out, Fact{
			Subject: subject, Predicate: "resource_policy_action",
			Object: action, Source: "stringified_policy",
			Evidence: stmtBase + ".Action",
		})
	}
	cond, ok := stmt["Condition"].(map[string]any)
	if !ok || len(cond) == 0 {
		return out
	}
	evid := stmtBase + ".Condition"
	ops := make([]string, 0, len(cond))
	for op := range cond {
		ops = append(ops, op)
	}
	slices.Sort(ops)
	for _, op := range ops {
		keys, ok := cond[op].(map[string]any)
		if !ok {
			continue
		}
		keyNames := make([]string, 0, len(keys))
		for k := range keys {
			keyNames = append(keyNames, k)
		}
		slices.Sort(keyNames)
		for _, k := range keyNames {
			out = append(out, Fact{
				Subject: subject, Predicate: "has_condition", Object: op + ":" + k,
				Source: "stringified_policy", Evidence: evid,
			})
			for _, val := range coerceStringList(keys[k]) {
				out = append(out, Fact{
					Subject: subject, Predicate: "has_condition_value",
					Object: op + ":" + k + "=" + val,
					Source: "stringified_policy", Evidence: evid,
				})
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
		slices.Sort(blockNames)
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
			slices.Sort(keys)
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
// delegationPrincipalFacts walks
// properties.delegation.external_principals[] on every
// aws_s3_bucket asset and emits one fact per external principal
// with control rights:
//
//	has_delegated_principal(bucket_arn, principal_arn)        — every element
//	has_unknown_delegated_principal(bucket_arn, principal_arn) — element.is_known_vendor == false
//	has_delegation_scope_exceeded_for(bucket_arn, principal_arn) — element.scope_exceeded == true
//
// The scalar booleans on properties.delegation.* (has_*) say
// THAT a defect exists; these per-principal facts say WHICH
// principal carries it. Soufflé / Clingo queries pivot on the
// per-principal predicate to enumerate every offender.
//
// Empty / absent / wrong-shape arrays yield no facts.
func delegationPrincipalFacts(assets []sir.AssetFact) []Fact {
	var out []Fact
	for i := range assets {
		a := &assets[i]
		if a.Type != "aws_s3_bucket" {
			continue
		}
		delegation, ok := a.Properties["delegation"].(map[string]any)
		if !ok {
			continue
		}
		principals, ok := delegation["external_principals"].([]any)
		if !ok {
			continue
		}
		evid := fmt.Sprintf("assets[%d].properties.delegation.external_principals", i)
		for pi, raw := range principals {
			p, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			arn, ok := p["principal_arn"].(string)
			if !ok || arn == "" {
				continue
			}
			elemEvid := fmt.Sprintf("%s[%d]", evid, pi)
			out = append(out, Fact{
				Subject: a.ID, Predicate: "has_delegated_principal", Object: arn,
				Source: "delegation", Evidence: elemEvid + ".principal_arn",
			})
			if known, ok := p["is_known_vendor"].(bool); ok && !known {
				out = append(out, Fact{
					Subject: a.ID, Predicate: "has_unknown_delegated_principal", Object: arn,
					Source: "delegation", Evidence: elemEvid + ".is_known_vendor",
				})
			}
			if exceeded, ok := p["scope_exceeded"].(bool); ok && exceeded {
				out = append(out, Fact{
					Subject: a.ID, Predicate: "has_delegation_scope_exceeded_for", Object: arn,
					Source: "delegation", Evidence: elemEvid + ".scope_exceeded",
				})
			}
		}
	}
	return out
}

// unusedServiceFacts walks
// properties.identity.permission_drift.unused_services[] on
// every aws_iam_role asset and emits
//
//	has_unused_service(role_arn, service_namespace)
//
// per element. Companion to the scalar has_unused_service_ratio
// (which says HOW MUCH drift): this projector says WHICH
// services drifted. Prolog proof trees consume the per-service
// fact to derive "lambda was accessible to this role and never
// used in 90+ days" as the explainable chain.
//
// Empty / absent / wrong-shape arrays yield no facts.
func unusedServiceFacts(assets []sir.AssetFact) []Fact {
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
		drift, ok := identity["permission_drift"].(map[string]any)
		if !ok {
			continue
		}
		services, ok := drift["unused_services"].([]any)
		if !ok {
			continue
		}
		evid := fmt.Sprintf("assets[%d].properties.identity.permission_drift.unused_services", i)
		for si, raw := range services {
			service, ok := raw.(string)
			if !ok || service == "" {
				continue
			}
			out = append(out, Fact{
				Subject: a.ID, Predicate: "has_unused_service", Object: service,
				Source: "permission_drift", Evidence: fmt.Sprintf("%s[%d]", evid, si),
			})
		}
	}
	return out
}

// incompatiblePairFacts walks
// properties.identity.permission_categories.incompatible_pairs[]
// on every aws_iam_role asset. Each element is a 2-element
// array [category_a, category_b]; the projector emits one fact
// per pair with the two category names joined by "+" as the
// object — a stable form Clingo violation rules can match
// against the incompatible-pair taxonomy in
// internal/controldata/taxonomy/permission_categories.yaml.
//
//	has_incompatible_pair(role_arn, "data_read+secrets_access")
//
// Companion to the scalar has_incompatible_categories (which
// says THAT a violation exists): this projector names every
// concrete pair that triggered it.
//
// Empty / absent / wrong-shape arrays yield no facts.
func incompatiblePairFacts(assets []sir.AssetFact) []Fact {
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
		cats, ok := identity["permission_categories"].(map[string]any)
		if !ok {
			continue
		}
		pairs, ok := cats["incompatible_pairs"].([]any)
		if !ok {
			continue
		}
		evid := fmt.Sprintf("assets[%d].properties.identity.permission_categories.incompatible_pairs", i)
		for pi, raw := range pairs {
			pair, ok := raw.([]any)
			if !ok || len(pair) != 2 {
				continue
			}
			a0, ok0 := pair[0].(string)
			a1, ok1 := pair[1].(string)
			if !ok0 || !ok1 || a0 == "" || a1 == "" {
				continue
			}
			out = append(out, Fact{
				Subject: a.ID, Predicate: "has_incompatible_pair", Object: a0 + "+" + a1,
				Source: "permission_categories", Evidence: fmt.Sprintf("%s[%d]", evid, pi),
			})
		}
	}
	return out
}

// forbiddenCategoryFacts walks
// properties.identity.intent_match.forbidden_categories_present[]
// on every aws_iam_role asset and emits
//
//	has_forbidden_category(role_arn, category)
//
// per element. Companion to the scalar has_intent_mismatch
// (which says THAT permissions contradict the declared role
// type): this projector names every concrete forbidden
// category — the Clingo violation rule can quote each
// offending category in the produced answer set.
//
// Empty / absent / wrong-shape arrays yield no facts.
func forbiddenCategoryFacts(assets []sir.AssetFact) []Fact {
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
		intent, ok := identity["intent_match"].(map[string]any)
		if !ok {
			continue
		}
		forbidden, ok := intent["forbidden_categories_present"].([]any)
		if !ok {
			continue
		}
		evid := fmt.Sprintf("assets[%d].properties.identity.intent_match.forbidden_categories_present", i)
		for ci, raw := range forbidden {
			cat, ok := raw.(string)
			if !ok || cat == "" {
				continue
			}
			out = append(out, Fact{
				Subject: a.ID, Predicate: "has_forbidden_category", Object: cat,
				Source: "intent_match", Evidence: fmt.Sprintf("%s[%d]", evid, ci),
			})
		}
	}
	return out
}

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
	trustAdmits := make(map[string]map[string]string, len(assets)) // target → assumer → evid
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
	slices.SortStableFunc(out, func(a, b Fact) int {
		if a.Subject != b.Subject {
			return cmp.Compare(a.Subject, b.Subject)
		}
		return cmp.Compare(a.Object, b.Object)
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
		slices.Sort(result)
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

// coerceConditionValueList renders the value half of an IAM
// Condition entry as a list of strings. Unlike coerceStringList
// (used for Action/Resource, which are always strings or string
// arrays), an IAM condition value is commonly a non-string scalar:
// a JSON boolean (e.g. {"Bool":{"aws:SecureTransport":false}}) parses
// to a Go bool, and numeric conditions (e.g. NumericLessThan) parse
// to float64. Those must survive projection so a closed-world query
// like has_condition_value(p,"Bool:aws:SecureTransport=false") can
// match. Strings and []any-of-mixed-scalars are also handled. Nested
// maps/slices are skipped (no meaningful scalar form).
func coerceConditionValueList(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := conditionScalarString(e); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		if s, ok := conditionScalarString(t); ok {
			return []string{s}
		}
		return nil
	}
}

// conditionScalarString renders a single scalar condition value as a
// string, reporting false for non-scalar (map/slice/nil) inputs so
// callers can skip them.
func conditionScalarString(v any) (string, bool) {
	switch s := v.(type) {
	case string:
		return s, true
	case bool:
		return strconv.FormatBool(s), true
	case float64:
		return scalarString(s), true
	}
	return "", false
}

// purposeFlagFacts parses semicolon-delimited key=value strings on
// the per-asset `properties.purpose` field and emits one
// `has_purpose_flag(asset, "key=value")` triple per parsed pair.
//
// Why a dedicated projector: the `purpose` field is a Stave-side
// convention for asset-tag-like metadata that callers compress
// into a single string (e.g. "signs_uploads;enforce_prefix=false;
// allow_traversal=true" on an app_signer asset). CEL queries
// substring-match the field, but external solvers see no triples
// because propertyFacts emits the whole string as one opaque
// object. Splitting at the projection boundary lets a Z3 / cvc5
// query test each key=value independently — closes the
// substring-extraction gap that `s3-tenant-prefix-isolation`
// surfaced in SMT-QUERY-GAPS.md.
//
// Format contract:
//   - Tokens split on ";". Empty tokens are skipped.
//   - Each token must contain at least one "=". Tokens without
//     "=" are skipped silently (they're declarative tags like
//     "signs_uploads", not key=value pairs, and emitting them
//     would conflate two distinct concerns).
//   - Whitespace around the token, key, and value is trimmed.
//   - The full "key=value" string (lowercased on the key half) is
//     the object so queries can ask
//     `has_purpose_flag(asset, "enforce_prefix=false")` directly.
func purposeFlagFacts(assets []sir.AssetFact, identities []sir.IdentityFact) []Fact {
	var out []Fact
	for i := range assets {
		a := &assets[i]
		evidBase := fmt.Sprintf("assets[%d].properties.purpose", i)
		out = append(out, emitPurposeFlags(a.ID, a.Properties, evidBase)...)
	}
	// Identity side. IdentityFact.Properties was added in the
	// 2026-05-28 SIR-boundary change so the identity attribute
	// bag the observation loader populates survives projection.
	// Until then the s3-tenant-prefix-isolation fixture's
	// discriminating `purpose` field (which lives on an
	// `app_signer` identity, not an asset) was structurally
	// invisible to any solver-side query.
	for i := range identities {
		id := &identities[i]
		evidBase := fmt.Sprintf("identities[%d].properties.purpose", i)
		out = append(out, emitPurposeFlags(id.PrincipalID, id.Properties, evidBase)...)
	}
	return out
}

// emitPurposeFlags is the shared per-entity body of purposeFlagFacts.
// Extracted so the asset and identity loops carry identical parsing
// + key-normalisation semantics — any future change to the
// semicolon-KV grammar lands in one place.
func emitPurposeFlags(subject string, props map[string]any, evidence string) []Fact {
	raw, ok := props["purpose"].(string)
	if !ok || raw == "" {
		return nil
	}
	var out []Fact
	tokens := strings.SplitSeq(raw, ";")
	for t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" || !strings.Contains(t, "=") {
			continue
		}
		k, v, _ := strings.Cut(t, "=")
		key := toLowerTrim(k)
		val := strings.TrimSpace(v)
		if key == "" {
			continue
		}
		out = append(out, Fact{
			Subject:   subject,
			Predicate: "has_purpose_flag",
			Object:    key + "=" + val,
			Source:    "purpose_field",
			Evidence:  evidence,
		})
	}
	return out
}

func exposureFacts(windows []sir.ExposureWindow) []Fact {
	var out []Fact
	for i, w := range windows {
		if !w.UnsafePredicateMatched {
			continue
		}
		evid := fmt.Sprintf("temporal.windows[%d]", i)
		out = append(out, Fact{Subject: w.AssetID, Predicate: "has_exposure_window", Object: "true", Source: "exposure", Evidence: evid})
		// The exposure occurred (has_exposure_window above), but a clamped /
		// zero-dwell window carries no trustworthy duration. Surface the SIR's
		// DurationUnreliable signal as its own triple so a dwell/SLA query can
		// exclude these windows (decline to grade) rather than reading them as
		// a 0-second exposure within any threshold.
		if w.DurationUnreliable {
			out = append(out, Fact{Subject: w.AssetID, Predicate: "has_unreliable_exposure_duration", Object: "true", Source: "exposure", Evidence: evid + ".duration_unreliable"})
		}
		for _, ctrl := range w.ContributingControls {
			out = append(out, Fact{Subject: w.AssetID, Predicate: "contributed_by", Object: ctrl, Source: "exposure", Evidence: evid + ".contributing_controls"})
		}
	}
	return out
}

// SerializeJSONL writes one JSON object per line. The order
// reflects ExtractFacts' deterministic walk of the SIR document.
func SerializeJSONL(facts []Fact, w io.Writer) error {
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
	"has_access_advisor_available",
	"has_action",
	"has_advanced_security_enabled",
	"has_advanced_security_mode",
	"has_agent_action_group_count",
	"has_agent_guardrail",
	"has_agent_iac_managed",
	"has_agent_invocation_logging",
	"has_agent_lambda_scope_broad",
	"has_agent_s3_scope_broad",
	"has_bucket_exists",
	"has_bucket_owned",
	"has_condition",
	"has_condition_value",
	"has_customer_can_revoke",
	"has_data_event_logging",
	"has_declared_role_type",
	"has_delegated_principal",
	"has_delegation_external_principals",
	"has_delegation_review_expired",
	"has_delegation_scope_exceeded",
	"has_delegation_scope_exceeded_for",
	"has_deny_action",
	"has_deny_resource",
	"has_exposed_repo_artifacts",
	"has_exposure_window",
	"has_forbidden_category",
	"has_forbidden_state",
	"has_ghost_trigger",
	"has_incompatible_categories",
	"has_incompatible_pair",
	"has_instance_dual_homed",
	"has_instance_profile_arn",
	"has_instance_profile_overprivileged",
	"has_instance_state",
	"has_instance_stopped_age_days",
	"has_instance_stopped_aged",
	"has_instance_vpc",
	"has_intent_mismatch",
	"has_intent_rationale",
	"has_kb_source_encrypted",
	"has_kb_target_bucket",
	"has_list_via_resource",
	"has_logging_enabled",
	"has_mfa_enforced",
	"has_peering_dns_resolution",
	"has_peering_id",
	"has_peering_peer_account",
	"has_peering_peer_in_org",
	"has_peering_peer_vpc",
	"has_peering_route_broad",
	"has_peering_route_target",
	"has_peering_status",
	"has_permission_action",
	"has_permission_drift_threshold_exceeded",
	"has_permission_resource",
	"has_privilege_level",
	"has_public_access_blocked",
	"has_public_list",
	"has_public_read",
	"has_purpose_flag",
	"has_read_via_resource",
	"has_resource",
	"has_role_age_days",
	"has_severity",
	"has_tag",
	"has_total_services_accessible",
	"has_trigger_lambda_exists",
	"has_trigger_type",
	"has_type",
	"has_unknown_delegated_principal",
	"has_unknown_delegation",
	"has_unreliable_exposure_duration",
	"has_unused_service",
	"has_unused_service_ratio",
	"has_upload_key_mode",
	"has_uses_access_key_id",
	"has_vendor",
	"has_vendor_can_make_public",
	"has_vendor_put_bucket_policy",
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

// SerializeSMT2 writes SMT-LIB v2 declarations, fact assertions,
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
// SMT2Options controls SMT-LIB v2 serialization behavior.
type SMT2Options struct {
	ClosedWorld bool
}

func SerializeSMT2(facts []Fact, w io.Writer, opts SMT2Options) error {
	bw := newBufferedWriter(w)
	bw.writeLine("; Stave SIR facts export — SMT-LIB v2")
	bw.writeLine("; Predicates declared as Bool functions over String args.")
	if opts.ClosedWorld {
		bw.writeLine("; Closed-world axioms emitted per predicate: the predicate is true")
		bw.writeLine("; ONLY for the (subject, object) pairs explicitly asserted; for")
		bw.writeLine("; every other input it is false.")
	} else {
		bw.writeLine("; Open-world mode: no closed-world axioms. Predicates may be true")
		bw.writeLine("; for inputs beyond those explicitly asserted. Use --closed-world")
		bw.writeLine("; for small targeted queries where completeness matters.")
	}
	bw.writeLine("; This file contains FACTS ONLY. Append your query (check-sat / get-model / etc.) before invoking the solver.")
	bw.writeLine("(set-logic ALL)")
	bw.writeLine("")

	predicates := allDeclaredPredicates(facts)
	// Fail loud before emitting anything: a predicate that cannot be rendered
	// as a valid SMT-LIB symbol (one carrying '|' or '\') would otherwise be
	// written as malformed |...| text, silently corrupting the S-expression
	// structure handed to the solver. Refuse rather than emit injectable SMT.
	for _, p := range predicates {
		if !smt2SymbolRepresentable(p) {
			return fmt.Errorf("predicate %q cannot be represented as an SMT-LIB symbol (contains '|' or '\\'); refusing to emit malformed SMT-LIB", p)
		}
	}
	bw.writeLine(fmt.Sprintf("; total_facts: %d", len(facts)))
	bw.writeLine(fmt.Sprintf("; total_predicates: %d", len(predicates)))
	if opts.ClosedWorld {
		bw.writeLine("; mode: closed-world (forall axioms emitted)")
	} else {
		bw.writeLine("; mode: open-world (no forall axioms)")
		bw.writeLine("; recommended: souffle, clingo (enumeration at scale)")
		bw.writeLine("; scoped_queries: z3, cvc5, prolog (append targeted query)")
	}
	bw.writeLine("")
	bw.writeLine("; --- Predicate declarations ---")
	for _, p := range predicates {
		bw.writeLine(fmt.Sprintf("(declare-fun %s (String String) Bool)", smt2Symbol(p)))
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
			bw.writeLine(";; fact_id: " + f.FactID)
		}
		if f.Provenance != nil {
			bw.writeLine(";; projector: " + f.Provenance.Projector)
			if f.Provenance.PropertyPath != "" {
				bw.writeLine(";; path: " + f.Provenance.PropertyPath)
			}
			if f.Provenance.CapturedAt != "" {
				bw.writeLine(";; captured: " + f.Provenance.CapturedAt)
			}
		}
		if f.Freshness != nil {
			// Two integer specifiers, so Sprintf is the natural
			// fit (perfsprint flags the single-%s case, not
			// multi-arg formatters).
			days := f.Freshness.AgeSeconds / 86400
			bw.writeLine(fmt.Sprintf(";; age: %ds (%dd)", f.Freshness.AgeSeconds, days))
		}
		bw.writeLine(fmt.Sprintf("(assert (%s %s %s))", smt2Symbol(f.Predicate), smt2Quote(f.Subject), smt2Quote(f.Object)))
	}

	if opts.ClosedWorld {
		bw.writeLine("")
		bw.writeLine("; --- Closed-world axioms ---")
		bw.writeLine("; Each axiom restricts the predicate to its asserted positive facts.")
		bw.writeLine("; For predicates with no facts, the axiom asserts the predicate is")
		bw.writeLine("; false everywhere.")
		for _, p := range predicates {
			bw.writeLine(closedWorldAxiom(p, factsByPredicate(facts, p)))
		}
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
	slices.Sort(out)
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
	slices.Sort(out)
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
	sym := smt2Symbol(predicate)
	if len(tuples) == 0 {
		return fmt.Sprintf("(assert (forall ((x String) (y String)) (not (%s x y))))", sym)
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
	return fmt.Sprintf("(assert (forall ((x String) (y String)) (=> (%s x y) %s)))", sym, body)
}

// smt2Quote renders a Go string as an SMT-LIB v2 string
// literal: surrounded by ", embedded " escaped as "".
func smt2Quote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// smt2Symbol renders a predicate name as an SMT-LIB v2 symbol.
//
// Curated has_* / can_* predicates and the dot-joined observation
// paths are valid SMT-LIB *simple symbols* and pass through bare —
// so existing output is byte-identical. Names carrying characters
// outside the simple-symbol charset (IAM condition keys such as
// "iam:PassedToService" reach the projector as raw property keys)
// are wrapped in |…| *quoted symbols*, which admit any character
// except '|' and '\'. Property keys never contain those, so the
// quoted form is always well-formed.
//
// Simple-symbol rule (SMT-LIB v2.6 §3.1): a non-empty sequence of
// letters, digits, and the characters ~ ! @ $ % ^ & * _ - + = < >
// . ? / that does not start with a digit.
func smt2Symbol(name string) string {
	if isSimpleSMTSymbol(name) {
		return name
	}
	return "|" + name + "|"
}

// smt2SymbolRepresentable reports whether name can be rendered as a valid
// SMT-LIB v2 symbol. Simple symbols pass through bare; everything else is
// emitted as a |...| quoted symbol, which SMT-LIB v2.6 §3.1 forbids from
// containing '|' or '\' — there is no escape sequence inside a quoted symbol.
// A name carrying either character therefore has NO valid SMT-LIB
// representation: wrapping it in |...| produces malformed text that breaks
// S-expression structure and can inject solver input. SerializeSMT2 calls
// this to fail loud instead of emitting a lie to the reasoning engine.
func smt2SymbolRepresentable(name string) bool {
	if isSimpleSMTSymbol(name) {
		return true
	}
	return !strings.ContainsAny(name, "|\\")
}

func isSimpleSMTSymbol(name string) bool {
	if name == "" {
		return false
	}
	const extra = "~!@$%^&*_-+=<>.?/"
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false // simple symbols cannot start with a digit
			}
		case strings.ContainsRune(extra, r):
		default:
			return false
		}
	}
	return true
}

// bufferedWriter is a minimal error-sticky line writer so the
// serialiser can emit many lines without checking err on each
// call. The first error halts subsequent writes; the final
// err is returned by SerializeSMT2.
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

func toLowerTrim(str string) string {
	trimmed := strings.TrimSpace(str)
	needsLower := false
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] >= 'A' && trimmed[i] <= 'Z' {
			needsLower = true
			break
		}
	}
	if needsLower {
		return strings.ToLower(trimmed)
	}
	return trimmed
}
