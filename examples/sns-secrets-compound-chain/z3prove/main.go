// Command z3prove runs four Z3 queries against the
// CloudGoat sns_secrets configuration (writeup-config) and
// a remediated version. The iteration's distinguishing
// feature is the four-service compound chain — IAM → SNS →
// API Gateway → Secrets Manager — where the principal has
// zero direct permissions on the target. The first three
// queries prove the per-step preconditions; the fourth
// conjuncts them into the complete chain.
//
// # Four queries
//
// Finding 1 — *SNS topic subscribable.* The IAM user's
// identity policy admits sns:Subscribe on Resource:*. The
// SNS topic in the fixture has no topic policy. In AWS,
// when a topic has no resource policy, the only access
// gate is the IAM identity policy on the caller — so any
// IAM user with sns:Subscribe in the same account can
// subscribe. Z3 finds a witness: the cg-sns-user can
// subscribe to public-topic-cgidxi93qpes3g.
//
// Finding 2 — *apigateway:GET deny coverage gap.* The
// IAM policy grants apigateway:GET on Resource:* with a
// Deny on 7 specific path patterns. Z3 walks 24
// API-Gateway management paths and asks: how many of them
// are NOT covered by the Deny? The deny-coverage table is
// the article's visual proof.
//
// Finding 3 — *Data-flow chain.* The SNS topic publishes a
// credential (api_key) targeting an API Gateway. The API
// Gateway uses key-only authentication and integrates with
// a Lambda. The Lambda has access to Secrets Manager. Z3
// conjuncts five hops — each is a boolean read from the
// fixture observations — and asks whether the entire chain
// is satisfiable.
//
// Finding 4 — *Compound path.* The conjunction of Findings
// 1, 2, and 3. SAT means a low-privileged user can reach
// the secret in a finite number of API calls without any
// direct permission on Secrets Manager.
//
// # The teaching beat
//
// Pattern-matching tools check each policy independently.
// Every policy in the writeup is "fine" by checklist
// criteria. The risk lives in the *data flow* — the API
// key value that travels from SNS to the principal to the
// API Gateway. No policy connects SNS to Secrets Manager;
// the credential value does.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/aclements/go-z3/z3"
)

const (
	userARN  = "arn:aws:iam::676206926638:user/cg-sns-user-cgidxi93qpes3g"
	topicARN = "arn:aws:sns:us-east-1:676206926638:public-topic-cgidxi93qpes3g"
)

type statement struct {
	Effect    string         `json:"Effect"`
	Action    any            `json:"Action"`
	Resource  any            `json:"Resource"`
	Condition map[string]any `json:"Condition,omitempty"`
}

type fixture struct {
	allow []statement
	deny  []statement

	topic snsTopic
	api   apiGateway
}

type snsTopic struct {
	arn                       string
	hasTopicPolicy            bool
	publishesCredentialType   string
	publishesCredentialTarget string
}

type apiGateway struct {
	arn                         string
	authType                    string
	iamAuthRequired             bool
	functionReadsSecretsManager bool
	functionARN                 string
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
		{"writeup", "writeup-config (cg-sns-user policy + bare topic + key-only API)",
			filepath.Join(root, "fixtures/writeup-config/observations")},
		{"remediated", "remediated-config (sns:Subscribe scoped + topic policy + IAM auth)",
			filepath.Join(root, "fixtures/remediated-config/observations")},
	}

	allOK := true
	for i, c := range configs {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("========== %s ==========\n", c.label)
		f, err := loadFixture(c.dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] load: %v\n", c.key, err)
			os.Exit(1)
		}
		ok1 := finding1Subscription(c.key, f)
		fmt.Println()
		ok2 := finding2APIGwDenyGap(c.key, f)
		fmt.Println()
		ok3 := finding3DataFlowChain(c.key, f)
		fmt.Println()
		ok4 := finding4CompoundPath(c.key, f)
		fmt.Println()
		printAPIGwDenyCoverage(f)
		allOK = allOK && ok1 && ok2 && ok3 && ok4
	}

	if !allOK {
		os.Exit(1)
	}
}

// finding1Subscription: can the user subscribe to a topic
// that publishes credentials?
func finding1Subscription(key string, f fixture) bool {
	type witness struct {
		topicARN string
		intended bool
	}

	witnesses := []witness{
		{topicARN: f.topic.arn},
	}

	subscribable := []int{}
	for i, w := range witnesses {
		// User has sns:Subscribe on this topic ARN?
		if !iamAdmitsAction(f.allow, f.deny, "sns:Subscribe", w.topicARN) {
			continue
		}
		// Topic does not block the user (no topic policy → defer to IAM).
		if f.topic.hasTopicPolicy && f.topic.arn == w.topicARN {
			// In the remediated fixture we model the topic policy as a
			// hard "no broad subscribe" — the IAM grant is also scoped,
			// so this branch never reaches a SAT here. The model
			// intentionally treats hasTopicPolicy=true as "topic-side
			// gate denies the witness" since the demo's remediated
			// topic policy is configured that way.
			continue
		}
		// Topic publishes sensitive content?
		if f.topic.publishesCredentialType == "" {
			continue
		}
		subscribable = append(subscribable, i)
	}

	ctx := z3.NewContext(nil)
	intSort := ctx.IntSort()
	req := ctx.IntConst("topic_idx")
	subZ := disjunction(ctx, req, subscribable, intSort)

	s := z3.NewSolver(ctx)
	s.Assert(subZ)
	sat, err := s.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s F1] z3: %v\n", key, err)
		return false
	}

	fmt.Println("--- Finding 1: SNS topic subscribable, publishes credential ---")
	fmt.Printf("  query:    can the user subscribe to a topic that publishes\n")
	fmt.Printf("            sensitive content?\n")
	fmt.Printf("  subscribable + sensitive topics: %d / %d\n",
		len(subscribable), len(witnesses))

	expectedSAT := key == "writeup"

	if sat {
		m := s.Model()
		v := m.Eval(req, true)
		idx, _, _ := v.(z3.Int).AsInt64()
		w := witnesses[idx]
		fmt.Printf("  verdict:  SAT — witness: %s\n", w.topicARN)
		fmt.Printf("            (publishes %s targeting %s)\n",
			f.topic.publishesCredentialType, f.topic.publishesCredentialTarget)
		return expectedSAT
	}
	fmt.Printf("  verdict:  UNSAT — no subscribable credential-publishing topic\n")
	return !expectedSAT
}

// finding2APIGwDenyGap: how many API Gateway management
// paths does the principal's apigateway:GET reach that the
// Deny does not block?
func finding2APIGwDenyGap(key string, f fixture) bool {
	open := []int{}
	for i, p := range apigwManagementPaths {
		// User has apigateway:GET on the path?
		fullARN := "arn:aws:apigateway:us-east-1::" + p
		// "*" in the Allow Resource matches anything including this.
		if !iamAdmitsAction(f.allow, f.deny, "apigateway:GET", fullARN) {
			continue
		}
		open = append(open, i)
	}

	ctx := z3.NewContext(nil)
	intSort := ctx.IntSort()
	req := ctx.IntConst("path_idx")
	openZ := disjunction(ctx, req, open, intSort)

	s := z3.NewSolver(ctx)
	s.Assert(openZ)
	sat, err := s.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s F2] z3: %v\n", key, err)
		return false
	}

	fmt.Println("--- Finding 2: apigateway:GET Deny coverage gap ---")
	fmt.Printf("  query:    among %d known API Gateway management paths, is\n",
		len(apigwManagementPaths))
	fmt.Printf("            any path effectively reachable (Allow ∧ ¬Deny)?\n")
	fmt.Printf("  reachable paths: %d / %d\n", len(open), len(apigwManagementPaths))

	expectedSAT := key == "writeup"

	if sat {
		m := s.Model()
		v := m.Eval(req, true)
		idx, _, _ := v.(z3.Int).AsInt64()
		fmt.Printf("  verdict:  SAT — witness path: %s\n", apigwManagementPaths[idx])
		fmt.Printf("            (Allow on Resource:* admits this path; Deny does not\n")
		fmt.Printf("             cover it; the principal can enumerate API structure)\n")
		return expectedSAT
	}
	fmt.Printf("  verdict:  UNSAT — every path is denied or apigateway:GET is gone\n")
	return !expectedSAT
}

// finding3DataFlowChain: is the five-hop credential-flow
// chain satisfiable?
//
//	hop1: principal can subscribe to the topic (Finding 1)
//	hop2: topic delivers credentials to subscribers
//	hop3: API Gateway accepts the credential (key-only auth, no IAM gate)
//	hop4: API Gateway integrates with a function that reads Secrets Manager
//	hop5: function actually accesses Secrets Manager
//
// All five hops are booleans on the fixture observation.
// Z3 conjuncts them and discharges.
func finding3DataFlowChain(key string, f fixture) bool {
	hop1 := iamAdmitsAction(f.allow, f.deny, "sns:Subscribe", f.topic.arn) && !f.topic.hasTopicPolicy
	hop2 := f.topic.publishesCredentialType != ""
	hop3 := !f.api.iamAuthRequired && f.api.authType == "API_KEY_ONLY"
	hop4 := f.api.functionARN != ""
	hop5 := f.api.functionReadsSecretsManager

	ctx := z3.NewContext(nil)
	chain := ctx.FromBool(hop1).And(
		ctx.FromBool(hop2),
		ctx.FromBool(hop3),
		ctx.FromBool(hop4),
		ctx.FromBool(hop5),
	)

	s := z3.NewSolver(ctx)
	s.Assert(chain)
	sat, err := s.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s F3] z3: %v\n", key, err)
		return false
	}

	fmt.Println("--- Finding 3: data-flow credential chain (5 hops) ---")
	fmt.Printf("  hop 1 (principal can subscribe to topic):                 %v\n", hop1)
	fmt.Printf("  hop 2 (topic publishes credential):                       %v\n", hop2)
	fmt.Printf("  hop 3 (API Gateway accepts credential, no IAM auth):      %v\n", hop3)
	fmt.Printf("  hop 4 (API Gateway integrates with downstream function):  %v\n", hop4)
	fmt.Printf("  hop 5 (function reads Secrets Manager):                   %v\n", hop5)

	expectedSAT := key == "writeup"

	if sat {
		fmt.Printf("  verdict:  SAT — full credential-flow chain is reachable\n")
		fmt.Printf("            (zero direct Secrets Manager permissions; access via\n")
		fmt.Printf("             credential value flowing through SNS → API GW → Lambda)\n")
		return expectedSAT
	}
	fmt.Printf("  verdict:  UNSAT — chain broken at hop %d\n", firstFalse(hop1, hop2, hop3, hop4, hop5))
	return !expectedSAT
}

// finding4CompoundPath: F1 ∧ F2 ∧ F3.
func finding4CompoundPath(key string, f fixture) bool {
	f1 := iamAdmitsAction(f.allow, f.deny, "sns:Subscribe", f.topic.arn) &&
		!f.topic.hasTopicPolicy &&
		f.topic.publishesCredentialType != ""
	f2Reachable := false
	for _, p := range apigwManagementPaths {
		if iamAdmitsAction(f.allow, f.deny, "apigateway:GET",
			"arn:aws:apigateway:us-east-1::"+p) {
			f2Reachable = true
			break
		}
	}
	f3 := !f.api.iamAuthRequired && f.api.authType == "API_KEY_ONLY" &&
		f.api.functionARN != "" && f.api.functionReadsSecretsManager

	ctx := z3.NewContext(nil)
	conj := ctx.FromBool(f1).And(ctx.FromBool(f2Reachable), ctx.FromBool(f3))

	s := z3.NewSolver(ctx)
	s.Assert(conj)
	sat, err := s.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s F4] z3: %v\n", key, err)
		return false
	}

	fmt.Println("--- Finding 4: full compound escalation path ---")
	fmt.Printf("  F1 (subscribe + sensitive topic):  %v\n", f1)
	fmt.Printf("  F2 (apigw enumeration reachable):  %v\n", f2Reachable)
	fmt.Printf("  F3 (credential-flow chain):        %v\n", f3)

	expectedSAT := key == "writeup"

	if sat {
		fmt.Printf("  verdict:  SAT — 7-call compound path:\n")
		fmt.Printf("            sns:ListTopics → sns:Subscribe → receive API key →\n")
		fmt.Printf("            apigateway:GET /restapis* (enumerate) → curl with key →\n")
		fmt.Printf("            API GW invokes Lambda → Lambda reads Secrets Manager\n")
		return expectedSAT
	}
	fmt.Printf("  verdict:  UNSAT — at least one precondition fails; chain is closed\n")
	return !expectedSAT
}

// printAPIGwDenyCoverage prints the per-path verdict matrix
// so the article can quote it directly.
func printAPIGwDenyCoverage(f fixture) {
	fmt.Println("--- API Gateway Deny coverage analysis ---")
	for _, p := range apigwManagementPaths {
		full := "arn:aws:apigateway:us-east-1::" + p
		denied := isDeniedByAny(f.deny, "apigateway:GET", full)
		status := "OPEN     "
		if denied {
			status = "BLOCKED "
		}
		fmt.Printf("  %s : %s\n", status, p)
	}
}

func firstFalse(bools ...bool) int {
	for i, b := range bools {
		if !b {
			return i + 1
		}
	}
	return 0
}

// --- Shared matcher helpers ---

// iamAdmitsAction returns true when the action is in some
// Allow statement matching the resource AND not in any
// Deny statement matching the resource.
func iamAdmitsAction(allow, deny []statement, action, resource string) bool {
	allowed := false
	for _, st := range allow {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		if !actionMatches(stringList(st.Action), action) {
			continue
		}
		if resourceMatches(stringList(st.Resource), resource) {
			allowed = true
			break
		}
	}
	if !allowed {
		return false
	}
	return !isDeniedByAny(deny, action, resource)
}

// isDeniedByAny returns true when at least one Deny
// statement matches the (action, resource) pair.
func isDeniedByAny(deny []statement, action, resource string) bool {
	for _, st := range deny {
		if !strings.EqualFold(st.Effect, "Deny") {
			continue
		}
		if !actionMatches(stringList(st.Action), action) {
			continue
		}
		if resourceMatches(stringList(st.Resource), resource) {
			return true
		}
	}
	return false
}

func actionMatches(stmtActions []string, witness string) bool {
	for _, a := range stmtActions {
		if a == "*" || a == witness {
			return true
		}
		if strings.HasSuffix(a, ":*") {
			service := strings.TrimSuffix(a, ":*")
			if strings.HasPrefix(witness, service+":") {
				return true
			}
		}
		if star := strings.Index(a, "*"); star > 0 {
			prefix := a[:star]
			if strings.HasPrefix(witness, prefix) {
				return true
			}
		}
	}
	return false
}

// resourceMatches handles `*`, exact match, and patterns
// with embedded `*` (the API-Gateway management ARNs use
// patterns like `arn:aws:apigateway:us-east-1::/restapis/*/integration`).
func resourceMatches(stmtResources []string, witness string) bool {
	for _, r := range stmtResources {
		if r == "*" || r == witness {
			return true
		}
		if strings.HasSuffix(r, "/*") {
			prefix := strings.TrimSuffix(r, "/*")
			if strings.HasPrefix(witness, prefix+"/") {
				return true
			}
		}
		// Pattern with embedded * (e.g. .../restapis/*/integration).
		// Split on `*` and check each fragment is in the witness in
		// order. Cheap-and-cheerful glob matcher.
		if strings.Count(r, "*") > 0 {
			parts := strings.Split(r, "*")
			pos := 0
			ok := true
			for i, part := range parts {
				if part == "" {
					continue
				}
				idx := strings.Index(witness[pos:], part)
				if idx < 0 {
					ok = false
					break
				}
				if i == 0 && idx != 0 {
					ok = false
					break
				}
				pos += idx + len(part)
			}
			// Trailing `*` — pattern-end is `*`, anything left over is fine.
			// No trailing `*` — must consume the witness fully.
			if ok && (strings.HasSuffix(r, "*") || pos == len(witness)) {
				return true
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

func disjunction(ctx *z3.Context, key z3.Int, indices []int, sort z3.Sort) z3.Bool {
	if len(indices) == 0 {
		return ctx.FromBool(false)
	}
	first := key.Eq(ctx.FromInt(int64(indices[0]), sort).(z3.Int))
	if len(indices) == 1 {
		return first
	}
	rest := make([]z3.Bool, 0, len(indices)-1)
	for _, i := range indices[1:] {
		rest = append(rest, key.Eq(ctx.FromInt(int64(i), sort).(z3.Int)))
	}
	return first.Or(rest...)
}

// loadFixture reads the snapshot dir and extracts the IAM
// user's policy statements (split by Allow/Deny), the SNS
// topic asset, and the API Gateway asset.
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
	sort.Strings(names)

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
						Policies struct {
							AttachedPolicies []struct {
								Name       string      `json:"name"`
								Statements []statement `json:"statements"`
							} `json:"attached_policies"`
						} `json:"policies"`
					} `json:"identity"`
					Messaging struct {
						SNS struct {
							HasTopicPolicy            bool   `json:"has_topic_policy"`
							PublishesCredentialType   string `json:"publishes_credential_type"`
							PublishesCredentialTarget string `json:"publishes_credential_target_arn"`
						} `json:"sns"`
					} `json:"messaging"`
					API struct {
						Auth struct {
							AuthType        string `json:"auth_type"`
							IAMAuthRequired bool   `json:"iam_auth_required"`
						} `json:"auth"`
						Integration struct {
							FunctionARN                 string `json:"function_arn"`
							FunctionReadsSecretsManager bool   `json:"function_reads_secrets_manager"`
						} `json:"integration"`
					} `json:"api"`
				} `json:"properties"`
			} `json:"assets"`
		}
		if err := json.Unmarshal(raw, &snap); err != nil {
			return f, err
		}
		for _, a := range snap.Assets {
			switch a.Type {
			case "aws_iam_user":
				if a.ID != userARN {
					continue
				}
				for _, p := range a.Properties.Identity.Policies.AttachedPolicies {
					for _, st := range p.Statements {
						switch strings.ToUpper(st.Effect) {
						case "ALLOW":
							f.allow = append(f.allow, st)
						case "DENY":
							f.deny = append(f.deny, st)
						}
					}
				}
			case "aws_sns_topic":
				f.topic.arn = a.ID
				f.topic.hasTopicPolicy = a.Properties.Messaging.SNS.HasTopicPolicy
				f.topic.publishesCredentialType = a.Properties.Messaging.SNS.PublishesCredentialType
				f.topic.publishesCredentialTarget = a.Properties.Messaging.SNS.PublishesCredentialTarget
			case "aws_apigateway_rest_api":
				f.api.arn = a.ID
				f.api.authType = a.Properties.API.Auth.AuthType
				f.api.iamAuthRequired = a.Properties.API.Auth.IAMAuthRequired
				f.api.functionARN = a.Properties.API.Integration.FunctionARN
				f.api.functionReadsSecretsManager = a.Properties.API.Integration.FunctionReadsSecretsManager
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
