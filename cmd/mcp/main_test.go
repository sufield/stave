//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRun_InitializeReturnsServerInfo confirms the MCP handshake
// emits a valid JSON-RPC envelope with the server name + protocol
// version. This is the first call any agent makes.
func TestRun_InitializeReturnsServerInfo(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	if resp["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc = %v, want 2.0", resp["jsonrpc"])
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("result = %v, want object", resp["result"])
	}
	info, ok := result["serverInfo"].(map[string]any)
	if !ok {
		t.Fatalf("serverInfo = %v, want object", result["serverInfo"])
	}
	if info["name"] != "stave-mcp" {
		t.Errorf("serverInfo.name = %v, want stave-mcp", info["name"])
	}
}

// TestRun_ToolsListEnumeratesTools confirms the catalogue returned
// to the agent includes every published tool with its JSON Schema.
func TestRun_ToolsListEnumeratesTools(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("result = %v", resp["result"])
	}
	tools, ok := result["tools"].([]any)
	if !ok {
		t.Fatalf("tools = %v, want []any", result["tools"])
	}
	want := map[string]bool{
		"stave.version":         false,
		"stave.search":          false,
		"stave.catalog_explain": false,
		"stave.diff":            false,
		"stave.gaps":            false,
		"stave.readiness":       false,
		"stave.compliance":      false,
		"stave.dashboard":       false,
		"stave.scorecard":       false,
		"stave.chains":          false,
		"stave.context":         false,
		"stave.verify":          false,
		"stave.explain":         false,
		"stave.suggest_fix":     false,
	}
	for _, raw := range tools {
		tt := raw.(map[string]any)
		if _, ok := want[tt["name"].(string)]; ok {
			want[tt["name"].(string)] = true
		}
	}
	for n, found := range want {
		if !found {
			t.Errorf("tool %s missing from tools/list", n)
		}
	}
}

// TestRun_VersionToolReportsCapabilities drives tools/call for
// stave.version and asserts the wrapped body carries real counts
// from the embedded registries (controls > 0, frameworks > 0).
func TestRun_VersionToolReportsCapabilities(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"stave.version","arguments":{}}}` + "\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	if errBlock, ok := resp["error"].(map[string]any); ok {
		t.Fatalf("version returned error: %v", errBlock)
	}
	text := toolResultText(t, resp)
	var caps map[string]any
	if err := json.Unmarshal([]byte(text), &caps); err != nil {
		t.Fatalf("unmarshal capabilities: %v", err)
	}
	if n, _ := caps["controls"].(float64); n <= 0 {
		t.Errorf("controls = %v, want > 0", caps["controls"])
	}
	if n, _ := caps["frameworks"].(float64); n <= 0 {
		t.Errorf("frameworks = %v, want > 0", caps["frameworks"])
	}
	if caps["offline"] != true {
		t.Errorf("offline = %v, want true", caps["offline"])
	}
}

// TestRun_SearchToolRanksCatalog drives tools/call for stave.search
// and asserts the wrapped body returns ranked hits for a known
// intent ("public S3").
func TestRun_SearchToolRanksCatalog(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"stave.search","arguments":{"query":"public S3","limit":5}}}` + "\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	if errBlock, ok := resp["error"].(map[string]any); ok {
		t.Fatalf("search returned error: %v", errBlock)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(toolResultText(t, resp)), &report); err != nil {
		t.Fatalf("unmarshal search report: %v", err)
	}
	hits, ok := report["hits"].([]any)
	if !ok || len(hits) == 0 {
		t.Fatalf("expected ranked hits for \"public S3\", got %v", report["hits"])
	}
	if len(hits) > 5 {
		t.Errorf("limit not honored: got %d hits, want <= 5", len(hits))
	}
}

// TestRun_DiffToolReportsPropertyChanges drives tools/call for
// stave.diff across the s3-public-read before/after fixtures and
// asserts the wrapped body reports the bucket's property changes.
func TestRun_DiffToolReportsPropertyChanges(t *testing.T) {
	t.Parallel()
	before := filepath.Join("..", "..", "examples", "s3-public-read-policy",
		"fixtures", "before", "observations")
	after := filepath.Join("..", "..", "examples", "s3-public-read-policy",
		"fixtures", "after", "observations")
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      7,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "stave.diff",
			"arguments": map[string]any{"before": before, "after": after},
		},
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out bytes.Buffer
	if err := run(context.Background(), bytes.NewReader(append(body, '\n')), &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	if errBlock, ok := resp["error"].(map[string]any); ok {
		t.Fatalf("diff returned error: %v", errBlock)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(toolResultText(t, resp)), &result); err != nil {
		t.Fatalf("unmarshal diff result: %v", err)
	}
	changes, ok := result["property_changes"].([]any)
	if !ok || len(changes) == 0 {
		t.Fatalf("expected property changes between before/after, got %v", result["property_changes"])
	}
}

// TestRun_GapsToolReportsMissingFields drives tools/call for
// stave.gaps and asserts the wrapped body reports field gaps with
// the controls each would unlock.
func TestRun_GapsToolReportsMissingFields(t *testing.T) {
	t.Parallel()
	obs := filepath.Join("..", "..", "examples", "s3-public-read-policy",
		"fixtures", "before", "observations")
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      8,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "stave.gaps",
			"arguments": map[string]any{"observations_dir": obs, "top_n": 5},
		},
	}
	body, _ := json.Marshal(req)
	var out bytes.Buffer
	if err := run(context.Background(), bytes.NewReader(append(body, '\n')), &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	if errBlock, ok := resp["error"].(map[string]any); ok {
		t.Fatalf("gaps returned error: %v", errBlock)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(toolResultText(t, resp)), &report); err != nil {
		t.Fatalf("unmarshal gaps report: %v", err)
	}
	if _, ok := report["gaps"]; !ok {
		t.Errorf("gaps report missing 'gaps' key: %v", report)
	}
	if _, ok := report["summary"]; !ok {
		t.Errorf("gaps report missing 'summary' key: %v", report)
	}
}

// TestRun_ReadinessToolForecastsCoverage drives tools/call for
// stave.readiness and asserts the wrapped body reports the observed
// asset types and a control forecast.
func TestRun_ReadinessToolForecastsCoverage(t *testing.T) {
	t.Parallel()
	obs := filepath.Join("..", "..", "examples", "s3-public-read-policy",
		"fixtures", "before", "observations")
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      9,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "stave.readiness",
			"arguments": map[string]any{"observations_dir": obs, "top_n": 3},
		},
	}
	body, _ := json.Marshal(req)
	var out bytes.Buffer
	if err := run(context.Background(), bytes.NewReader(append(body, '\n')), &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	if errBlock, ok := resp["error"].(map[string]any); ok {
		t.Fatalf("readiness returned error: %v", errBlock)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(toolResultText(t, resp)), &report); err != nil {
		t.Fatalf("unmarshal readiness report: %v", err)
	}
	observed, ok := report["observed_asset_types"].(map[string]any)
	if !ok || len(observed) == 0 {
		t.Fatalf("expected observed asset types, got %v", report["observed_asset_types"])
	}
	if _, ok := observed["aws_s3_bucket"]; !ok {
		t.Errorf("expected aws_s3_bucket in observed types, got %v", observed)
	}
}

// TestRun_ComplianceToolReportsFrameworkPosture drives tools/call for
// stave.compliance against HIPAA and asserts the wrapped body carries
// the framework identity and a requirement breakdown.
func TestRun_ComplianceToolReportsFrameworkPosture(t *testing.T) {
	t.Parallel()
	obs := filepath.Join("..", "..", "examples", "s3-public-read-policy",
		"fixtures", "before", "observations")
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      10,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "stave.compliance",
			"arguments": map[string]any{"observations_dir": obs, "framework": "hipaa"},
		},
	}
	body, _ := json.Marshal(req)
	var out bytes.Buffer
	if err := run(context.Background(), bytes.NewReader(append(body, '\n')), &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	if errBlock, ok := resp["error"].(map[string]any); ok {
		t.Fatalf("compliance returned error: %v", errBlock)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(toolResultText(t, resp)), &report); err != nil {
		t.Fatalf("unmarshal compliance report: %v", err)
	}
	if report["FrameworkID"] != "hipaa" {
		t.Errorf("FrameworkID = %v, want hipaa", report["FrameworkID"])
	}
	if _, ok := report["Requirements"].([]any); !ok {
		t.Errorf("expected Requirements array, got %v", report["Requirements"])
	}
}

// TestRun_ComplianceToolUnknownFrameworkLists asserts an unknown
// framework fails loudly with the available profile list.
func TestRun_ComplianceToolUnknownFrameworkLists(t *testing.T) {
	t.Parallel()
	obs := filepath.Join("..", "..", "examples", "s3-public-read-policy",
		"fixtures", "before", "observations")
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      11,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "stave.compliance",
			"arguments": map[string]any{"observations_dir": obs, "framework": "bogus"},
		},
	}
	body, _ := json.Marshal(req)
	var out bytes.Buffer
	if err := run(context.Background(), bytes.NewReader(append(body, '\n')), &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	errBlock, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error envelope for unknown framework, got %v", resp["result"])
	}
	msg, _ := errBlock["message"].(string)
	if !strings.Contains(msg, "available:") || !strings.Contains(msg, "hipaa") {
		t.Errorf("error should list available profiles, got: %q", msg)
	}
}

// TestRun_CatalogExplainDescribesControl drives tools/call for
// stave.catalog_explain on a known control and asserts the wrapped
// body carries the predicate, required fields, and frameworks.
func TestRun_CatalogExplainDescribesControl(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"stave.catalog_explain","arguments":{"control_id":"CTL.S3.PUBLIC.001"}}}` + "\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	if errBlock, ok := resp["error"].(map[string]any); ok {
		t.Fatalf("catalog_explain returned error: %v", errBlock)
	}
	var exp map[string]any
	if err := json.Unmarshal([]byte(toolResultText(t, resp)), &exp); err != nil {
		t.Fatalf("unmarshal explanation: %v", err)
	}
	if exp["id"] != "CTL.S3.PUBLIC.001" {
		t.Errorf("id = %v, want CTL.S3.PUBLIC.001", exp["id"])
	}
	if s, _ := exp["predicate"].(string); s == "" {
		t.Errorf("expected a rendered predicate, got %v", exp["predicate"])
	}
	if fields, ok := exp["required_fields"].([]any); !ok || len(fields) == 0 {
		t.Errorf("expected required_fields, got %v", exp["required_fields"])
	}
	if fw, ok := exp["frameworks"].(map[string]any); !ok || len(fw) == 0 {
		t.Errorf("expected framework mappings, got %v", exp["frameworks"])
	}
}

// TestRun_CatalogExplainWorksInHostedMode confirms the catalog-query
// tool runs in hosted mode (it touches no snapshot data).
func TestRun_CatalogExplainWorksInHostedMode(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"stave.catalog_explain","arguments":{"control_id":"CTL.S3.PUBLIC.001"}}}` + "\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out, true); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	if errBlock, ok := resp["error"].(map[string]any); ok {
		t.Fatalf("catalog_explain should run in hosted mode, got error: %v", errBlock)
	}
}

// TestRun_CatalogExplainUnknownSuggests confirms an unknown ID yields
// "did you mean?" suggestions instead of a bare failure.
func TestRun_CatalogExplainUnknownSuggests(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":32,"method":"tools/call","params":{"name":"stave.catalog_explain","arguments":{"control_id":"CTL.S3.PUBLIC"}}}` + "\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	var result map[string]any
	if err := json.Unmarshal([]byte(toolResultText(t, resp)), &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	sugg, ok := result["did_you_mean"].([]any)
	if !ok || len(sugg) == 0 {
		t.Fatalf("expected did_you_mean suggestions, got %v", result)
	}
}

// TestRun_VerifyToolCallProducesAssessment drives the canonical
// agent workflow: tools/call with stave.verify on a real fixture
// directory. Asserts the wrapped content body decodes back to
// an Assessment with the expected status.
func TestRun_VerifyToolCallProducesAssessment(t *testing.T) {
	t.Parallel()
	// Use the iter-7a (iam-overpermission-wildcard) before fixture —
	// known to fire CTL.IAM.POLICY.RESOURCE.WILDCARD.001.
	obsDir := filepath.Join("..", "..", "examples", "iam-overpermission-wildcard",
		"fixtures", "before", "observations")
	ctlDir := filepath.Join("..", "..", "examples", "iam-overpermission-wildcard",
		"controls")
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "stave.verify",
			"arguments": map[string]any{
				"observations_dir":    obsDir,
				"controls_dir":        ctlDir,
				"allow_unknown_input": true,
				"format":              "raw",
			},
		},
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	in := bytes.NewReader(append(body, '\n'))
	var out bytes.Buffer
	if err := run(context.Background(), in, &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	if errBlock, ok := resp["error"].(map[string]any); ok {
		t.Fatalf("verify returned error: %v", errBlock)
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("result = %v", resp["result"])
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("content = %v", result["content"])
	}
	textBlock, ok := content[0].(map[string]any)
	if !ok {
		t.Fatalf("content[0] = %v", content[0])
	}
	text, ok := textBlock["text"].(string)
	if !ok || text == "" {
		t.Fatalf("text = %v", textBlock["text"])
	}
	// Decode the wrapped JSON body — it should be a real Assessment.
	var assess map[string]any
	if err := json.Unmarshal([]byte(text), &assess); err != nil {
		t.Fatalf("unmarshal Assessment text: %v", err)
	}
	findings, ok := assess["Findings"].([]any)
	if !ok {
		t.Fatalf("Findings missing or wrong type: %v", assess["Findings"])
	}
	if len(findings) == 0 {
		t.Errorf("expected at least one finding for the iter-7a before fixture")
	}
}

// ctxObs is the demo snapshot used by the context drill-down tests.
const ctxObs = "../../examples/demo-ai-security/fixtures/writeup-config/observations"

// callContext drives a stave.context tools/call and returns the decoded
// result text (or fails on a JSON-RPC error).
func callContext(t *testing.T, args map[string]any) string {
	t.Helper()
	req := map[string]any{
		"jsonrpc": "2.0", "id": 80, "method": "tools/call",
		"params": map[string]any{"name": "stave.context", "arguments": args},
	}
	body, _ := json.Marshal(req)
	var out bytes.Buffer
	if err := run(context.Background(), bytes.NewReader(append(body, '\n')), &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	if errBlock, ok := resp["error"].(map[string]any); ok {
		t.Fatalf("context returned error: %v", errBlock)
	}
	return toolResultText(t, resp)
}

// TestRun_ContextAssetDrillDown asserts type=asset returns every
// finding on the asset.
func TestRun_ContextAssetDrillDown(t *testing.T) {
	t.Parallel()
	text := callContext(t, map[string]any{
		"type":                "asset",
		"id":                  "arn:aws:bedrock:us-east-1:111122223333:agent/CUSTSUPPORTAGENT",
		"observations":        ctxObs,
		"allow_unknown_input": true,
	})
	var res map[string]any
	if err := json.Unmarshal([]byte(text), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if n, _ := res["finding_count"].(float64); n <= 0 {
		t.Errorf("finding_count = %v, want > 0", res["finding_count"])
	}
}

// TestRun_ContextChainDrillDown asserts type=chain returns the chain's
// failing controls and narrative.
func TestRun_ContextChainDrillDown(t *testing.T) {
	t.Parallel()
	text := callContext(t, map[string]any{
		"type":                "chain",
		"id":                  "bedrock_agent_overpermissioned",
		"observations":        ctxObs,
		"chains":              filepath.Join("..", "..", "internal", "chains"),
		"allow_unknown_input": true,
	})
	var res map[string]any
	if err := json.Unmarshal([]byte(text), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cf, ok := res["controls_failing"].([]any); !ok || len(cf) == 0 {
		t.Errorf("expected controls_failing, got %v", res["controls_failing"])
	}
}

// TestRun_ContextUnknownType confirms an unrecognized type errors.
func TestRun_ContextUnknownType(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":81,"method":"tools/call","params":{"name":"stave.context","arguments":{"type":"galaxy","id":"x","observations":"` + ctxObs + `"}}}` + "\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	errBlock, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error for unknown type, got result: %v", resp["result"])
	}
	if msg, _ := errBlock["message"].(string); !strings.Contains(msg, "unknown context type") {
		t.Errorf("error should name the bad type, got: %q", msg)
	}
}

// TestRun_ContextRejectedInHostedMode confirms context is a data tool.
func TestRun_ContextRejectedInHostedMode(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":82,"method":"tools/call","params":{"name":"stave.context","arguments":{"type":"asset","id":"x","observations":"/whatever"}}}` + "\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out, true); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	errBlock, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected hosted rejection, got result: %v", resp["result"])
	}
	if msg, _ := errBlock["message"].(string); !strings.Contains(msg, "requires local installation") {
		t.Errorf("expected install guidance, got: %q", msg)
	}
}

// TestRun_ChainsToolVisualizesCompoundRisk drives tools/call for
// stave.chains on the demo-ai-security snapshot (which fires three
// Bedrock chains against the repo chains catalog) and asserts the
// saved HTML is a self-contained SVG visualizer.
func TestRun_ChainsToolVisualizesCompoundRisk(t *testing.T) {
	t.Parallel()
	obs := filepath.Join("..", "..", "examples", "demo-ai-security", "fixtures", "writeup-config", "observations")
	chains := filepath.Join("..", "..", "internal", "chains")
	req := map[string]any{
		"jsonrpc": "2.0", "id": 70, "method": "tools/call",
		"params": map[string]any{
			"name": "stave.chains",
			"arguments": map[string]any{
				"observations": obs, "chains": chains, "allow_unknown_input": true,
			},
		},
	}
	body, _ := json.Marshal(req)
	var out bytes.Buffer
	if err := run(context.Background(), bytes.NewReader(append(body, '\n')), &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	if errBlock, ok := resp["error"].(map[string]any); ok {
		t.Fatalf("chains returned error: %v", errBlock)
	}
	summary := toolResultText(t, resp)
	if !strings.Contains(summary, "compound risk chain") || !strings.Contains(summary, "saved to:") {
		t.Fatalf("summary missing chains/path: %q", summary)
	}

	path := extractSavedPath(t, summary)
	defer os.Remove(path)
	data, err := os.ReadFile(path) //nolint:gosec // path is the file we just generated
	if err != nil {
		t.Fatalf("read chains file: %v", err)
	}
	doc := string(data)
	if len(data) >= 80*1024 {
		t.Errorf("chains visualizer is %d bytes, want < 80KB", len(data))
	}
	for _, want := range []string{"<!DOCTYPE html>", "Risk Chains", "<svg", "COMPOUND RISK", `class="chainrow`} {
		if !strings.Contains(doc, want) {
			t.Errorf("chains visualizer missing %q", want)
		}
	}
	// Self-contained: no external fetches (the SVG xmlns URI is inert).
	for _, ext := range []string{"src=", "<link", "{{"} {
		if strings.Contains(doc, ext) {
			t.Errorf("chains visualizer not self-contained / unrendered — found %q", ext)
		}
	}
}

// TestRun_ChainsGoodResult confirms a snapshot returns a valid
// chains response — either a "single-resource" message (no chains)
// or a "chain analysis complete" summary (chains found), not an
// error or empty output.
func TestRun_ChainsGoodResult(t *testing.T) {
	t.Parallel()
	obs := filepath.Join("..", "..", "examples", "demo-s3-public-read", "fixtures", "observations")
	chains := filepath.Join("..", "..", "internal", "chains")
	req := map[string]any{
		"jsonrpc": "2.0", "id": 71, "method": "tools/call",
		"params": map[string]any{
			"name": "stave.chains",
			"arguments": map[string]any{
				"observations": obs, "chains": chains, "allow_unknown_input": true,
			},
		},
	}
	body, _ := json.Marshal(req)
	var out bytes.Buffer
	if err := run(context.Background(), bytes.NewReader(append(body, '\n')), &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	if errBlock, ok := resp["error"].(map[string]any); ok {
		t.Fatalf("chains returned error: %v", errBlock)
	}
	msg := toolResultText(t, resp)
	if !strings.Contains(msg, "single-resource") && !strings.Contains(msg, "Chain analysis complete") {
		t.Errorf("expected chains result message, got: %q", msg)
	}
}

// TestRun_ChainsRejectedInHostedMode confirms chains is a data tool.
func TestRun_ChainsRejectedInHostedMode(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":72,"method":"tools/call","params":{"name":"stave.chains","arguments":{"observations":"/whatever"}}}` + "\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out, true); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	errBlock, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected hosted rejection, got result: %v", resp["result"])
	}
	if msg, _ := errBlock["message"].(string); !strings.Contains(msg, "requires local installation") {
		t.Errorf("expected install guidance, got: %q", msg)
	}
}

// TestRun_DashboardToolGeneratesSelfContainedFile drives tools/call
// for stave.dashboard, then reads the saved HTML file and asserts it
// is self-contained (no external references) and well under 100 KB.
func TestRun_DashboardToolGeneratesSelfContainedFile(t *testing.T) {
	t.Parallel()
	obs := filepath.Join("..", "..", "examples", "demo-s3-public-read", "fixtures", "observations")
	req := map[string]any{
		"jsonrpc": "2.0", "id": 50, "method": "tools/call",
		"params": map[string]any{
			"name":      "stave.dashboard",
			"arguments": map[string]any{"observations": obs, "allow_unknown_input": true},
		},
	}
	body, _ := json.Marshal(req)
	var out bytes.Buffer
	if err := run(context.Background(), bytes.NewReader(append(body, '\n')), &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	if errBlock, ok := resp["error"].(map[string]any); ok {
		t.Fatalf("dashboard returned error: %v", errBlock)
	}
	summary := toolResultText(t, resp)
	if !strings.Contains(summary, "Score:") || !strings.Contains(summary, "saved to:") {
		t.Fatalf("summary missing score/path: %q", summary)
	}

	path := extractSavedPath(t, summary)
	defer os.Remove(path)

	data, err := os.ReadFile(path) //nolint:gosec // path is the file we just generated
	if err != nil {
		t.Fatalf("read dashboard file: %v", err)
	}
	doc := string(data)
	if len(data) >= 100*1024 {
		t.Errorf("dashboard is %d bytes, want < 100KB", len(data))
	}
	for _, want := range []string{"<!DOCTYPE html>", "Posture", "<svg", "id=\"findings\""} {
		if !strings.Contains(doc, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	for _, ext := range []string{"http://", "https://", "src=", "<link"} {
		if strings.Contains(doc, ext) {
			t.Errorf("dashboard is not self-contained — found %q", ext)
		}
	}
	if strings.Contains(doc, "{{") {
		t.Errorf("dashboard has unrendered template actions")
	}
}

// TestRun_ScorecardToolGeneratesMultiFramework drives tools/call for
// stave.scorecard across two frameworks and asserts the saved HTML is
// self-contained, has a tab per framework, and shows FAIL evidence
// for the public-read fixture (where mapped requirements fail).
func TestRun_ScorecardToolGeneratesMultiFramework(t *testing.T) {
	t.Parallel()
	obs := filepath.Join("..", "..", "examples", "demo-s3-public-read", "fixtures", "observations")
	req := map[string]any{
		"jsonrpc": "2.0", "id": 60, "method": "tools/call",
		"params": map[string]any{
			"name":      "stave.scorecard",
			"arguments": map[string]any{"observations": obs, "frameworks": "pci_dss_v4.0,cis_aws_v3.0"},
		},
	}
	body, _ := json.Marshal(req)
	var out bytes.Buffer
	if err := run(context.Background(), bytes.NewReader(append(body, '\n')), &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	if errBlock, ok := resp["error"].(map[string]any); ok {
		t.Fatalf("scorecard returned error: %v", errBlock)
	}
	summary := toolResultText(t, resp)
	for _, want := range []string{"pci_dss_v4.0:", "cis_aws_v3.0:", "saved to:"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary missing %q: %s", want, summary)
		}
	}

	path := extractSavedPath(t, summary)
	defer os.Remove(path)
	data, err := os.ReadFile(path) //nolint:gosec // path is the file we just generated
	if err != nil {
		t.Fatalf("read scorecard: %v", err)
	}
	doc := string(data)
	if len(data) >= 80*1024 {
		t.Errorf("scorecard is %d bytes, want < 80KB", len(data))
	}
	if c := strings.Count(doc, `class="tab `); c != 2 {
		t.Errorf("expected 2 framework tabs, found %d", c)
	}
	for _, want := range []string{"<!DOCTYPE html>", "Compliance Scorecard", "Cross-framework", "reqstatus fail", "fail-item"} {
		if !strings.Contains(doc, want) {
			t.Errorf("scorecard missing %q", want)
		}
	}
	for _, ext := range []string{"http://", "https://", "src=", "<link", "{{"} {
		if strings.Contains(doc, ext) {
			t.Errorf("scorecard not self-contained / unrendered — found %q", ext)
		}
	}
}

// TestRun_ScorecardRejectedInHostedMode confirms the scorecard is a
// data tool — unavailable on a hosted server.
func TestRun_ScorecardRejectedInHostedMode(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":61,"method":"tools/call","params":{"name":"stave.scorecard","arguments":{"observations":"/whatever"}}}` + "\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out, true); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	errBlock, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected hosted rejection, got result: %v", resp["result"])
	}
	if msg, _ := errBlock["message"].(string); !strings.Contains(msg, "requires local installation") {
		t.Errorf("expected install guidance, got: %q", msg)
	}
}

// TestRun_DashboardRejectedInHostedMode confirms the dashboard is a
// data tool — unavailable on a hosted server.
func TestRun_DashboardRejectedInHostedMode(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":51,"method":"tools/call","params":{"name":"stave.dashboard","arguments":{"observations":"/whatever"}}}` + "\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out, true); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	errBlock, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected hosted rejection, got result: %v", resp["result"])
	}
	if msg, _ := errBlock["message"].(string); !strings.Contains(msg, "requires local installation") {
		t.Errorf("expected install guidance, got: %q", msg)
	}
}

// extractSavedPath pulls the dashboard file path out of the summary
// line "Interactive dashboard saved to: <path>".
func extractSavedPath(t *testing.T, summary string) string {
	t.Helper()
	_, rest, ok := strings.Cut(summary, "saved to: ")
	if !ok {
		t.Fatalf("no saved-to marker in: %q", summary)
	}
	if line, _, found := strings.Cut(rest, "\n"); found {
		rest = line
	}
	return strings.TrimSpace(rest)
}

// verifyText runs stave.verify with the given format and returns the
// text block. Shared by the summary/detailed format tests.
func verifyText(t *testing.T, format string) string {
	t.Helper()
	obsDir := filepath.Join("..", "..", "examples", "iam-overpermission-wildcard",
		"fixtures", "before", "observations")
	ctlDir := filepath.Join("..", "..", "examples", "iam-overpermission-wildcard", "controls")
	args := map[string]any{
		"observations_dir":    obsDir,
		"controls_dir":        ctlDir,
		"allow_unknown_input": true,
	}
	if format != "" {
		args["format"] = format
	}
	req := map[string]any{
		"jsonrpc": "2.0", "id": 40, "method": "tools/call",
		"params": map[string]any{"name": "stave.verify", "arguments": args},
	}
	body, _ := json.Marshal(req)
	var out bytes.Buffer
	if err := run(context.Background(), bytes.NewReader(append(body, '\n')), &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	if errBlock, ok := resp["error"].(map[string]any); ok {
		t.Fatalf("verify(%s) returned error: %v", format, errBlock)
	}
	return toolResultText(t, resp)
}

// TestRun_VerifyDefaultFormatIsSummary confirms omitting format yields
// the agent-friendly summary text (not raw JSON), with the headline
// security state and a severity breakdown.
func TestRun_VerifyDefaultFormatIsSummary(t *testing.T) {
	t.Parallel()
	text := verifyText(t, "")
	for _, want := range []string{"Security State:", "Posture Score:", "Violations:", "By severity:"} {
		if !strings.Contains(text, want) {
			t.Errorf("summary missing %q in:\n%s", want, text)
		}
	}
	// Summary is text, not the raw Assessment JSON.
	if strings.HasPrefix(strings.TrimSpace(text), "{") {
		t.Errorf("default format should be text summary, got JSON:\n%s", text)
	}
}

// TestRun_VerifyDetailedAddsEvidence confirms detailed format adds the
// per-finding predicate and observed values beyond the summary.
func TestRun_VerifyDetailedAddsEvidence(t *testing.T) {
	t.Parallel()
	text := verifyText(t, "detailed")
	for _, want := range []string{"Detailed violations", "Predicate:", "Observed:"} {
		if !strings.Contains(text, want) {
			t.Errorf("detailed output missing %q in:\n%s", want, text)
		}
	}
}

// TestRun_VerifyUnknownFormatErrors confirms an unknown format is an
// explicit error, not a silent fallback.
func TestRun_VerifyUnknownFormatErrors(t *testing.T) {
	t.Parallel()
	obsDir := filepath.Join("..", "..", "examples", "iam-overpermission-wildcard",
		"fixtures", "before", "observations")
	req := map[string]any{
		"jsonrpc": "2.0", "id": 41, "method": "tools/call",
		"params": map[string]any{
			"name": "stave.verify",
			"arguments": map[string]any{
				"observations_dir": obsDir, "allow_unknown_input": true, "format": "xml",
			},
		},
	}
	body, _ := json.Marshal(req)
	var out bytes.Buffer
	if err := run(context.Background(), bytes.NewReader(append(body, '\n')), &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	errBlock, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error for unknown format, got result: %v", resp["result"])
	}
	if msg, _ := errBlock["message"].(string); !strings.Contains(msg, "unknown format") {
		t.Errorf("error should name the bad format, got: %q", msg)
	}
}

// TestRun_UnknownMethodReturnsErrorEnvelope confirms the server
// emits a JSON-RPC error response (not a panic / silent drop)
// for unknown methods.
func TestRun_UnknownMethodReturnsErrorEnvelope(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`{"jsonrpc":"2.0","id":4,"method":"does/not/exist"}` + "\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	errBlock, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("error = %v, want object", resp["error"])
	}
	code, _ := errBlock["code"].(float64)
	if int(code) != errMethodNotFound {
		t.Errorf("error.code = %v, want %d", code, errMethodNotFound)
	}
}

// TestRun_HostedModeOmitsDataTools confirms tools/list in hosted mode
// advertises only the catalog-query tools — the snapshot-touching
// tools must not appear at all.
func TestRun_HostedModeOmitsDataTools(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`{"jsonrpc":"2.0","id":20,"method":"tools/list"}` + "\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out, true); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	result := resp["result"].(map[string]any)
	tools := result["tools"].([]any)

	got := map[string]bool{}
	for _, raw := range tools {
		got[raw.(map[string]any)["name"].(string)] = true
	}
	// Local (catalog-query) tools must be present.
	for _, n := range []string{"stave.version", "stave.search", "stave.catalog_explain", "stave.explain", "stave.suggest_fix"} {
		if !got[n] {
			t.Errorf("hosted tools/list missing catalog tool %s", n)
		}
	}
	// Data tools must be absent.
	for _, n := range []string{"stave.verify", "stave.diff", "stave.gaps", "stave.readiness", "stave.compliance"} {
		if got[n] {
			t.Errorf("hosted tools/list must not advertise data tool %s", n)
		}
	}
	if len(tools) != 5 {
		t.Errorf("hosted tools/list = %d tools, want 5", len(tools))
	}
}

// TestRun_HostedModeRejectsDataToolCall confirms a direct call to a
// data tool in hosted mode is rejected with the install guidance —
// defense in depth beyond omitting it from tools/list.
func TestRun_HostedModeRejectsDataToolCall(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"stave.verify","arguments":{"observations_dir":"/whatever"}}}` + "\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out, true); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	errBlock, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error envelope, got result: %v", resp["result"])
	}
	msg, _ := errBlock["message"].(string)
	if !strings.Contains(msg, "requires local installation") ||
		!strings.Contains(msg, "go install github.com/sufield/stave/cmd/mcp@latest") {
		t.Errorf("rejection message missing install guidance, got: %q", msg)
	}
}

// TestRun_HostedModeStillRunsCatalogTool confirms a local tool still
// works in hosted mode (the mode gates data tools only).
func TestRun_HostedModeStillRunsCatalogTool(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"stave.version","arguments":{}}}` + "\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out, true); err != nil {
		t.Fatalf("run: %v", err)
	}
	resp := decodeResponse(t, out.Bytes())
	if errBlock, ok := resp["error"].(map[string]any); ok {
		t.Fatalf("version should run in hosted mode, got error: %v", errBlock)
	}
}

// TestRun_InitializeReportsMode confirms the handshake advertises the
// deployment mode and data policy in both modes.
func TestRun_InitializeReportsMode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		hosted     bool
		wantMode   string
		wantPolicy string
	}{
		{true, "hosted", "catalog-only, no customer data accepted"},
		{false, "local", "all tools, snapshots evaluated locally"},
	}
	for _, tc := range cases {
		t.Run(tc.wantMode, func(t *testing.T) {
			in := strings.NewReader(`{"jsonrpc":"2.0","id":23,"method":"initialize"}` + "\n")
			var out bytes.Buffer
			if err := run(context.Background(), in, &out, tc.hosted); err != nil {
				t.Fatalf("run: %v", err)
			}
			resp := decodeResponse(t, out.Bytes())
			info := resp["result"].(map[string]any)["serverInfo"].(map[string]any)
			if info["mode"] != tc.wantMode {
				t.Errorf("serverInfo.mode = %v, want %s", info["mode"], tc.wantMode)
			}
			if info["data_policy"] != tc.wantPolicy {
				t.Errorf("serverInfo.data_policy = %v, want %q", info["data_policy"], tc.wantPolicy)
			}
		})
	}
}

// toolResultText pulls the first text block out of a tools/call
// response envelope — the {"content":[{"type":"text","text":...}]}
// shape every tool returns via wrapToolResult.
func toolResultText(t *testing.T, resp map[string]any) string {
	t.Helper()
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("result = %v", resp["result"])
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("content = %v", result["content"])
	}
	block, ok := content[0].(map[string]any)
	if !ok {
		t.Fatalf("content[0] = %v", content[0])
	}
	text, ok := block["text"].(string)
	if !ok || text == "" {
		t.Fatalf("text = %v", block["text"])
	}
	return text
}

// decodeResponse reads one JSON object from the buffer. The
// server emits one envelope per request; the dec.Decode loop
// preserves trailing newlines.
func decodeResponse(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var out map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	return out
}
