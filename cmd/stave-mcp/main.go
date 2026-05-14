// Command stave-mcp exposes Stave's verification surface as a
// Model Context Protocol (MCP) server over stdio. AI agents
// (Claude Code, Cursor, Copilot, etc.) connect to it via
// JSON-RPC 2.0 to call Stave as a formal-verification tool
// without invoking the human-facing CLI.
//
// # Tools exposed
//
//	stave.verify       Run pkg/stave.Apply over an observation
//	                   directory and return the Assessment.
//	stave.explain      Re-run verify and project one finding's
//	                   reasoning_trace + invariant context.
//	stave.suggest_fix  Re-run verify and project one finding's
//	                   delta_paths and catalog-authored remediation.
//
// # Wire format
//
// JSON-RPC 2.0 over stdio. Each line is one message. The server
// reads a request, dispatches, writes a response. MCP-specific
// methods understood: `initialize`, `tools/list`, `tools/call`.
//
// No external MCP-library dependency — the protocol is small
// enough that a minimal in-house dispatcher is cleaner than
// pulling a library that would bring its own API drift. If a
// canonical Go MCP SDK lands in go.mod later, this file can be
// rewritten as a thin adapter onto it; the tool semantics stay
// the same.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sufield/stave/pkg/stave"
)

const (
	jsonrpcVersion = "2.0"

	// MCP method names — the small subset we implement.
	methodInitialize = "initialize"
	methodToolsList  = "tools/list"
	methodToolsCall  = "tools/call"

	// Tool names we publish to the agent.
	toolVerify     = "stave.verify"
	toolExplain    = "stave.explain"
	toolSuggestFix = "stave.suggest_fix"

	// JSON-RPC 2.0 standard error codes.
	errParseError     = -32700
	errInvalidRequest = -32600
	errMethodNotFound = -32601
	errInvalidParams  = -32602
	errInternalError  = -32603
)

// rpcRequest models the inbound JSON-RPC envelope. Method-specific
// parameters live under Params; tools/call wraps the tool name +
// the tool's own arguments per MCP convention.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// rpcResponse models the outbound envelope. Either Result or Error
// is populated, never both, per JSON-RPC 2.0 §5.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// toolCallParams is the body MCP wraps around a tool invocation.
type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// verifyArgs is the schema for stave.verify.
type verifyArgs struct {
	ObservationsDir   string `json:"observations_dir"`
	ControlsDir       string `json:"controls_dir,omitempty"`
	AllowUnknownInput bool   `json:"allow_unknown_input,omitempty"`
}

// findingArgs is the shared schema for stave.explain and
// stave.suggest_fix — both re-run verify and project one finding.
type findingArgs struct {
	ObservationsDir string `json:"observations_dir"`
	ControlsDir     string `json:"controls_dir,omitempty"`
	FindingID       string `json:"finding_id"`
}

func main() {
	if err := run(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "stave-mcp:", err)
		os.Exit(1)
	}
}

// run is the dispatch loop. Reads one JSON-RPC message per line,
// dispatches, writes the response, repeats until stdin closes.
// Extracted from main() so tests can drive the protocol with
// in-memory pipes.
func run(ctx context.Context, in io.Reader, out io.Writer) error {
	dec := json.NewDecoder(in)
	dec.UseNumber()
	enc := json.NewEncoder(out)
	for {
		var req rpcRequest
		if err := dec.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			// Parse errors keep the loop alive — a malformed
			// message must not crash the server.
			_ = enc.Encode(rpcResponse{
				JSONRPC: jsonrpcVersion,
				Error: &rpcError{
					Code:    errParseError,
					Message: err.Error(),
				},
			})
			continue
		}
		resp := dispatch(ctx, &req)
		if err := enc.Encode(resp); err != nil {
			return fmt.Errorf("encode response: %w", err)
		}
	}
}

// dispatch routes one request to the matching handler. The MCP
// surface is small enough that a switch is cleaner than a
// registry. Errors are wrapped into the rpcResponse — never
// returned, since the JSON-RPC convention is to always emit a
// response (modulo notifications, which we don't support).
func dispatch(ctx context.Context, req *rpcRequest) rpcResponse {
	resp := rpcResponse{
		JSONRPC: jsonrpcVersion,
		ID:      req.ID,
	}
	switch req.Method {
	case methodInitialize:
		resp.Result = handleInitialize()
	case methodToolsList:
		resp.Result = handleToolsList()
	case methodToolsCall:
		var params toolCallParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			resp.Error = &rpcError{Code: errInvalidParams, Message: err.Error()}
			return resp
		}
		result, err := dispatchTool(ctx, &params)
		if err != nil {
			resp.Error = &rpcError{Code: errInternalError, Message: err.Error()}
			return resp
		}
		resp.Result = result
	default:
		resp.Error = &rpcError{
			Code:    errMethodNotFound,
			Message: fmt.Sprintf("method not found: %q", req.Method),
		}
	}
	return resp
}

// handleInitialize returns a minimal MCP initialize response.
// The protocolVersion field signals which spec generation we
// implement; the serverInfo block is for the agent's logs.
func handleInitialize() any {
	return map[string]any{
		"protocolVersion": "2025-03-26",
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo": map[string]any{
			"name":    "stave-mcp",
			"version": "0.1.0",
		},
	}
}

// handleToolsList returns the static list of tools the server
// exposes. JSON Schema bodies follow MCP's inputSchema convention.
func handleToolsList() any {
	return map[string]any{
		"tools": []map[string]any{
			{
				"name":        toolVerify,
				"description": "Run Stave's verification pipeline over a snapshot directory and return the Assessment (findings, status, summary).",
				"inputSchema": map[string]any{
					"type":     "object",
					"required": []string{"observations_dir"},
					"properties": map[string]any{
						"observations_dir":    map[string]string{"type": "string", "description": "Path to the observation snapshot directory."},
						"controls_dir":        map[string]string{"type": "string", "description": "Optional control directory; empty = embedded built-in catalog."},
						"allow_unknown_input": map[string]string{"type": "boolean", "description": "Tolerate observation asset types unknown to the catalog."},
					},
				},
			},
			{
				"name":        toolExplain,
				"description": "Return the reasoning trace and invariant context for one finding by FindingID.",
				"inputSchema": map[string]any{
					"type":     "object",
					"required": []string{"observations_dir", "finding_id"},
					"properties": map[string]any{
						"observations_dir": map[string]string{"type": "string"},
						"controls_dir":     map[string]string{"type": "string"},
						"finding_id":       map[string]string{"type": "string", "description": "The FindingID returned from stave.verify."},
					},
				},
			},
			{
				"name":        toolSuggestFix,
				"description": "Return one finding's delta paths and catalog-authored remediation guidance by FindingID.",
				"inputSchema": map[string]any{
					"type":     "object",
					"required": []string{"observations_dir", "finding_id"},
					"properties": map[string]any{
						"observations_dir": map[string]string{"type": "string"},
						"controls_dir":     map[string]string{"type": "string"},
						"finding_id":       map[string]string{"type": "string"},
					},
				},
			},
		},
	}
}

// dispatchTool routes a tools/call to the named tool. Returns the
// tool's result envelope — MCP wraps tool results under
// {"content": [{"type": "text", "text": "<json>"}]} so even
// structured tools have a consistent surface; we match that
// convention.
func dispatchTool(ctx context.Context, p *toolCallParams) (any, error) {
	switch p.Name {
	case toolVerify:
		var args verifyArgs
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return nil, fmt.Errorf("verify args: %w", err)
		}
		assess, err := runVerify(ctx, args)
		if err != nil {
			return nil, err
		}
		return wrapToolResult(assess)
	case toolExplain:
		var args findingArgs
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return nil, fmt.Errorf("explain args: %w", err)
		}
		out, err := runExplain(ctx, args)
		if err != nil {
			return nil, err
		}
		return wrapToolResult(out)
	case toolSuggestFix:
		var args findingArgs
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return nil, fmt.Errorf("suggest_fix args: %w", err)
		}
		out, err := runSuggestFix(ctx, args)
		if err != nil {
			return nil, err
		}
		return wrapToolResult(out)
	default:
		return nil, fmt.Errorf("unknown tool: %q", p.Name)
	}
}

// runVerify is a thin wrapper over pkg/stave.Apply. Returns the
// full Assessment so the agent can read findings + summary +
// status without a second round-trip.
func runVerify(ctx context.Context, args verifyArgs) (*stave.Assessment, error) {
	if args.ObservationsDir == "" {
		return nil, errors.New("observations_dir is required")
	}
	cfg := stave.Config{
		SnapshotsDir:      args.ObservationsDir,
		ControlsDir:       args.ControlsDir,
		AllowUnknownInput: args.AllowUnknownInput,
	}
	return stave.Apply(ctx, cfg)
}

// runExplain re-runs Apply, then projects one finding's reasoning
// trace + invariant context. The schema is intentionally narrow —
// the agent gets exactly what it needs to decide WHY the finding
// fired, without the rest of the Assessment surface.
func runExplain(ctx context.Context, args findingArgs) (any, error) {
	if args.FindingID == "" {
		return nil, errors.New("finding_id is required")
	}
	assess, err := runVerify(ctx, verifyArgs{
		ObservationsDir: args.ObservationsDir,
		ControlsDir:     args.ControlsDir,
	})
	if err != nil {
		return nil, err
	}
	for i := range assess.Findings {
		f := &assess.Findings[i]
		if string(f.FindingID) != args.FindingID {
			continue
		}
		return map[string]any{
			"finding_id":       f.FindingID,
			"control_id":       f.ControlID,
			"control_name":     f.ControlName,
			"asset_id":         f.AssetID,
			"severity":         f.Severity,
			"reasoning_trace":  f.ReasoningTrace,
			"chain_membership": f.ChainMembership,
			"compliance":       f.ControlCompliance,
		}, nil
	}
	return nil, fmt.Errorf("finding_id %q not found", args.FindingID)
}

// runSuggestFix re-runs Apply, then projects one finding's Delta
// paths and catalog-authored remediation. The Z3-derived
// SuggestedFix surface that originally lived alongside Delta was
// removed when the Python solver was retired (2026-05-06, commit
// 82118471e); this tool now bundles the deterministic prose
// guidance the engine still produces.
func runSuggestFix(ctx context.Context, args findingArgs) (any, error) {
	if args.FindingID == "" {
		return nil, errors.New("finding_id is required")
	}
	assess, err := runVerify(ctx, verifyArgs{
		ObservationsDir: args.ObservationsDir,
		ControlsDir:     args.ControlsDir,
	})
	if err != nil {
		return nil, err
	}
	for i := range assess.Findings {
		f := &assess.Findings[i]
		if string(f.FindingID) != args.FindingID {
			continue
		}
		return map[string]any{
			"finding_id":  f.FindingID,
			"control_id":  f.ControlID,
			"asset_id":    f.AssetID,
			"delta_paths": f.Delta,
			"remediation": f.Remediation,
		}, nil
	}
	return nil, fmt.Errorf("finding_id %q not found", args.FindingID)
}

// wrapToolResult mirrors MCP's tool-result convention: tool
// results live under `content[]` as text blocks. Stave-side
// callers decode the text as JSON to get the structured result.
// Doing the wrapping here keeps every tool return symmetric.
func wrapToolResult(v any) (any, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal tool result: %w", err)
	}
	return map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": string(body)},
		},
	}, nil
}
