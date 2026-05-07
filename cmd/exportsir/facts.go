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
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/sufield/stave/internal/core/sir"
)

// Fact is one (subject, predicate, object) triple plus
// provenance fields for engines that want to trace back to
// the originating SIR slot. Source names the SIR fact category
// the triple was projected from; Evidence is a short SIR path
// (e.g. "controls[0].id", "identities[0].role_chains[0]") so
// downstream code can correlate triples back to the nested
// document without a separate index.
type Fact struct {
	Subject   string `json:"subject"`
	Predicate string `json:"predicate"`
	Object    string `json:"object"`
	Source    string `json:"source"`
	Evidence  string `json:"evidence"`
}

// extractFacts projects a SIR document into the flat triple
// form. The mapping is intentionally lossy: rich SIR fields
// like nested predicate trees and per-rule source refs are
// summarised as boolean flags ("has_forbidden_state=true")
// rather than serialised verbatim, because triple consumers
// — Datalog and ASP especially — work in flat namespaces.
// Consumers who need the full nesting use --format json.
func extractFacts(doc *sir.Document) []Fact {
	if doc == nil {
		return nil
	}
	var facts []Fact
	facts = append(facts, controlFacts(doc.Controls)...)
	facts = append(facts, assetFacts(doc.Assets)...)
	facts = append(facts, cognitoMappingFacts(doc.Assets)...)
	facts = append(facts, iamPolicyFacts(doc.Assets)...)
	facts = append(facts, trustPolicyFacts(doc.Assets)...)
	facts = append(facts, identityFacts(doc.Identities)...)
	facts = append(facts, exposureFacts(doc.Temporal.Windows)...)
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
// reflects extractFacts' deterministic walk of the SIR document.
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
// Adding a new predicate to extractFacts means adding it here.
// The compile-time list is intentional: the SMT contract is
// stable, not implicit.
var baselineSMT2Predicates = []string{
	"allows_unauthenticated",
	"can_assume",
	"contributed_by",
	"cross_account_assumes",
	"first_seen_at",
	"has_action",
	"has_exposure_window",
	"has_forbidden_state",
	"has_intent_rationale",
	"has_permission_action",
	"has_permission_resource",
	"has_privilege_level",
	"has_resource",
	"has_severity",
	"has_type",
	"has_vendor",
	"is_decommissioned",
	"is_provisioned",
	"last_seen_at",
	"maps_auth_to",
	"maps_unauth_to",
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
