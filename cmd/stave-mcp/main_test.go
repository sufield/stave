package main

import (
	"bytes"
	"context"
	"encoding/json"
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
	if err := run(context.Background(), in, &out); err != nil {
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

// TestRun_ToolsListEnumeratesThreeTools confirms the catalogue
// returned to the agent includes verify / explain / suggest_fix
// with their JSON Schemas.
func TestRun_ToolsListEnumeratesThreeTools(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out); err != nil {
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
	if len(tools) != 3 {
		t.Fatalf("tools count = %d, want 3", len(tools))
	}
	want := map[string]bool{"stave.verify": false, "stave.explain": false, "stave.suggest_fix": false}
	for _, raw := range tools {
		t := raw.(map[string]any)
		if _, ok := want[t["name"].(string)]; ok {
			want[t["name"].(string)] = true
		}
	}
	for n, found := range want {
		if !found {
			t.Errorf("tool %s missing from tools/list", n)
		}
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
			},
		},
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	in := bytes.NewReader(append(body, '\n'))
	var out bytes.Buffer
	if err := run(context.Background(), in, &out); err != nil {
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

// TestRun_UnknownMethodReturnsErrorEnvelope confirms the server
// emits a JSON-RPC error response (not a panic / silent drop)
// for unknown methods.
func TestRun_UnknownMethodReturnsErrorEnvelope(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`{"jsonrpc":"2.0","id":4,"method":"does/not/exist"}` + "\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out); err != nil {
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
