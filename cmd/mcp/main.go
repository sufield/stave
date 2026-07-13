// Command stave-mcp exposes Stave's verification surface as a
// Model Context Protocol (MCP) server over stdio. AI agents
// (Claude Code, Cursor, Copilot, etc.) connect to it via
// JSON-RPC 2.0 to call Stave as a formal-verification tool
// without invoking the human-facing CLI.
//
// # Tools exposed
//
//	stave.version      Report build version + capability counts
//	                   (controls, packs, frameworks, tactics).
//	stave.search       Rank the capability catalog against a
//	                   free-form intent ("public S3", "shadow admin").
//	stave.diff         Structured delta between two snapshot
//	                   directories (added / removed / changed).
//	stave.gaps         Field-level coverage gaps: absent observation
//	                   properties and the controls each would unlock.
//	stave.readiness    Forecast which controls can fire against a
//	                   snapshot's asset surface, plus an action plan.
//	stave.compliance   Requirement-level posture for one framework
//	                   (hipaa, pci_dss_v4.0, cis_aws_v3.0, …).
//	stave.verify       Run pkg/stave.Apply over an observation
//	                   directory and return the Assessment.
//	stave.explain      Re-run verify and project one finding's
//	                   reasoning_trace + control context.
//	stave.suggest_fix  Re-run verify and project one finding's
//	                   delta_paths and catalog-authored remediation.
//
// Every tool calls the pkg/stave library directly — never the CLI
// binary, never the network. All evaluation is offline and
// deterministic.
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
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

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
	toolVersion    = "stave.version"
	toolSearch     = "stave.search"
	toolDiff       = "stave.diff"
	toolGaps       = "stave.gaps"
	toolReadiness  = "stave.readiness"
	toolCompliance = "stave.compliance"
	toolCatalogXpl = "stave.catalog_explain"
	toolDashboard  = "stave.dashboard"
	toolScorecard  = "stave.scorecard"
	toolChains     = "stave.chains"
	toolContext    = "stave.context"

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
	ObservationsDir string `json:"observations_dir"`
	ControlsDir     string `json:"controls_dir,omitempty"`
	Format          string `json:"format,omitempty"` // summary (default) | detailed | raw
}

// searchArgs is the schema for stave.search.
type searchArgs struct {
	Query    string `json:"query"`
	Severity string `json:"severity,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

// dashboardArgs is the schema for stave.dashboard.
type dashboardArgs struct {
	Observations string `json:"observations"`
	Controls     string `json:"controls,omitempty"`
}

// chainsArgs is the schema for stave.chains.
type chainsArgs struct {
	Observations string `json:"observations"`
	Controls     string `json:"controls,omitempty"`
	Chains       string `json:"chains,omitempty"`
	Severity     string `json:"severity,omitempty"`
}

// scorecardArgs is the schema for stave.scorecard.
type scorecardArgs struct {
	Observations string `json:"observations"`
	Frameworks   string `json:"frameworks,omitempty"`
}

// catalogExplainArgs is the schema for stave.catalog_explain.
type catalogExplainArgs struct {
	ControlID string `json:"control_id"`
}

// diffArgs is the schema for stave.diff.
type diffArgs struct {
	Before string `json:"before"`
	After  string `json:"after"`
}

// gapsArgs is the schema for stave.gaps.
type gapsArgs struct {
	ObservationsDir string `json:"observations_dir"`
	TopN            int    `json:"top_n,omitempty"`
}

// complianceArgs is the schema for stave.compliance.
type complianceArgs struct {
	ObservationsDir string `json:"observations_dir"`
	Framework       string `json:"framework"`
}

// findingArgs is the shared schema for stave.explain and
// stave.suggest_fix — both re-run verify and project one finding.
type findingArgs struct {
	ObservationsDir string `json:"observations_dir"`
	ControlsDir     string `json:"controls_dir,omitempty"`
	FindingID       string `json:"finding_id"`
}

func main() {
	hosted := flag.Bool("hosted", false,
		"hosted mode: register only catalog-query tools; omit snapshot-touching tools")
	demoDashboard := flag.Bool("demo-dashboard", false,
		"render the posture dashboard for --observations to a standalone HTML file and exit (no MCP server)")
	renderScorecardFlag := flag.Bool("render-scorecard", false,
		"render the compliance scorecard for --observations to a standalone HTML file and exit (no MCP server)")
	renderChainsFlag := flag.Bool("render-chains", false,
		"render the risk chain visualizer for --observations to a standalone HTML file and exit (no MCP server)")
	observations := flag.String("observations", "",
		"observation snapshot directory (used with --demo-dashboard / --render-scorecard)")
	frameworks := flag.String("frameworks", "",
		"comma-separated framework IDs for --render-scorecard (default: all available)")
	flag.Parse()

	// Standalone render modes: evaluate the given snapshot, write the
	// HTML, print its path, and exit. For founder demos where no MCP
	// client is configured — just screen-share the HTML in a browser.
	if *demoDashboard {
		if err := runDemoDashboard(context.Background(), *observations); err != nil {
			fmt.Fprintln(os.Stderr, "stave-mcp:", err)
			os.Exit(1)
		}
		return
	}
	if *renderScorecardFlag {
		if err := runRenderScorecard(context.Background(), *observations, *frameworks); err != nil {
			fmt.Fprintln(os.Stderr, "stave-mcp:", err)
			os.Exit(1)
		}
		return
	}
	if *renderChainsFlag {
		if err := runRenderChains(context.Background(), *observations); err != nil {
			fmt.Fprintln(os.Stderr, "stave-mcp:", err)
			os.Exit(1)
		}
		return
	}

	// Env var is an equivalent switch for container/registry deployments
	// where passing a flag to the server process is awkward.
	hostedMode := *hosted || os.Getenv("STAVE_MCP_HOSTED") == "true"

	if err := run(context.Background(), os.Stdin, os.Stdout, hostedMode); err != nil {
		fmt.Fprintln(os.Stderr, "stave-mcp:", err)
		os.Exit(1)
	}
}

// run is the dispatch loop. Reads one JSON-RPC message per line,
// dispatches, writes the response, repeats until stdin closes.
// Extracted from main() so tests can drive the protocol with
// in-memory pipes.
func run(ctx context.Context, in io.Reader, out io.Writer, hosted bool) error {
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
		resp := dispatch(ctx, &req, hosted)
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
func dispatch(ctx context.Context, req *rpcRequest, hosted bool) rpcResponse {
	resp := rpcResponse{
		JSONRPC: jsonrpcVersion,
		ID:      req.ID,
	}
	switch req.Method {
	case methodInitialize:
		resp.Result = handleInitialize(hosted)
	case methodToolsList:
		resp.Result = handleToolsList(hosted)
	case methodToolsCall:
		var params toolCallParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			resp.Error = &rpcError{Code: errInvalidParams, Message: err.Error()}
			return resp
		}
		result, err := dispatchTool(ctx, &params, hosted)
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

// Hosted mode registers only catalog-query tools (version, search, explain, suggest_fix).
// Snapshot-touching tools (verify, diff, gaps, readiness, compliance) are omitted
// because customer configuration data must never leave the customer's machine.
// This separation is architectural, not policy — hosted mode physically cannot
// receive snapshot data because the tools that process it don't exist in the
// hosted server's tool list.
//
// dataTools is the set of snapshot-touching tools. They take filesystem
// paths to observation data and are registered only in local mode.
var dataTools = map[string]bool{
	toolVerify:     true,
	toolDiff:       true,
	toolGaps:       true,
	toolReadiness:  true,
	toolCompliance: true,
	toolDashboard:  true,
	toolScorecard:  true,
	toolChains:     true,
	toolContext:    true,
}

// isDataTool reports whether name is a snapshot-touching tool.
func isDataTool(name string) bool { return dataTools[name] }

// hostedDataToolMsg is returned when a data tool is called against a
// hosted server — it tells the agent exactly how to get the tool.
const hostedDataToolMsg = "This tool requires local installation. " +
	"Snapshot data never leaves your machine. Install the local binary: " +
	"go install github.com/sufield/stave/cmd/mcp@latest"

// handleInitialize returns a minimal MCP initialize response.
// The protocolVersion field signals which spec generation we
// implement; the serverInfo block is for the agent's logs. The
// mode + data_policy fields let a client see at handshake time
// whether this server will accept snapshot data at all.
func handleInitialize(hosted bool) any {
	mode, policy := "local", "all tools, snapshots evaluated locally"
	if hosted {
		mode, policy = "hosted", "catalog-only, no customer data accepted"
	}
	return map[string]any{
		"protocolVersion": "2025-03-26",
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo": map[string]any{
			"name":        "stave-mcp",
			"version":     "0.1.0",
			"mode":        mode,
			"data_policy": policy,
		},
	}
}

// handleToolsList returns the list of tools the server exposes.
// JSON Schema bodies follow MCP's inputSchema convention. In hosted
// mode the snapshot-touching tools are filtered out (see the data
// trust architecture note above isDataTool) so they are never even
// advertised to the agent.
func handleToolsList(hosted bool) any {
	tools := []map[string]any{
		{
			"name":        toolVersion,
			"description": "Report this build's version and capability counts: built-in controls, policy packs, compliance frameworks, ATT&CK tactics, and output formats. Air-gapped — no credentials required.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name":        toolSearch,
			"description": "Search the capability catalog by free-form intent (e.g. \"public S3\", \"expired access keys\", \"shadow admin\"). Ranks control groups and operational features; synonyms are expanded so you need not know Stave's vocabulary first. Offline.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"query"},
				"properties": map[string]any{
					"query":    map[string]string{"type": "string", "description": "Free-form intent string."},
					"severity": map[string]string{"type": "string", "description": "Optional filter: CRITICAL | HIGH | MEDIUM | LOW."},
					"limit":    map[string]string{"type": "integer", "description": "Max hits to return (default 10)."},
				},
			},
		},
		{
			"name":        toolCatalogXpl,
			"description": "Explain one control from the embedded catalog by ID (e.g. \"CTL.S3.PUBLIC.READ\"): description, severity, asset type, the predicate that fires it, the observation fields it reads, and the compliance frameworks it maps to. Catalog-only — needs no observations and works in hosted mode. An unknown ID returns suggestions.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"control_id"},
				"properties": map[string]any{
					"control_id": map[string]string{"type": "string", "description": "Catalog control ID, e.g. CTL.S3.PUBLIC.READ."},
				},
			},
		},
		{
			"name":        toolDiff,
			"description": "Compare two observation snapshots to see what changed — assets added, assets removed, and per-property changes on fields the catalog evaluates (e.g. a bucket's public_read flipping to true). Loads the newest snapshot from each directory. Offline.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"before", "after"},
				"properties": map[string]any{
					"before": map[string]string{"type": "string", "description": "Path to the earlier snapshot directory."},
					"after":  map[string]string{"type": "string", "description": "Path to the later snapshot directory."},
				},
			},
		},
		{
			"name":        toolGaps,
			"description": "Analyze which observation fields are absent from a snapshot and what built-in controls each missing field would unlock. Helps prioritize what data to collect next for stronger detection. Offline.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"observations_dir"},
				"properties": map[string]any{
					"observations_dir": map[string]string{"type": "string", "description": "Path to the observation snapshot directory."},
					"top_n":            map[string]string{"type": "integer", "description": "How many top gaps the summary rollup considers (default 10)."},
				},
			},
		},
		{
			"name":        toolReadiness,
			"description": "Forecast what the catalog can and cannot evaluate against a snapshot: which asset types are present, how many controls are evaluable vs. blocked, the readiness score, and what to collect next. Offline.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"observations_dir"},
				"properties": map[string]any{
					"observations_dir": map[string]string{"type": "string", "description": "Path to the observation snapshot directory."},
					"top_n":            map[string]string{"type": "integer", "description": "How many unblocking actions to rank (default 10)."},
				},
			},
		},
		{
			"name":        toolCompliance,
			"description": "Show compliance posture against a specific framework (e.g. \"hipaa\", \"pci_dss_v4.0\", \"cis_aws_v3.0\"): per-requirement met / not-met / not-evaluated breakdown and overall coverage percentage. An unknown framework returns the list of available profiles. Offline.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"observations_dir", "framework"},
				"properties": map[string]any{
					"observations_dir": map[string]string{"type": "string", "description": "Path to the observation snapshot directory."},
					"framework":        map[string]string{"type": "string", "description": "Framework profile ID (e.g. hipaa, pci_dss_v4.0, cis_aws_v3.0, soc2)."},
				},
			},
		},
		{
			"name":        toolDashboard,
			"description": "Evaluate a snapshot and render an interactive HTML posture dashboard (gauge, severity breakdown, sortable findings table, SLA status). Saves a self-contained HTML file and returns its path plus a one-line summary. Open the file in a browser for the full interactive view.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"observations"},
				"properties": map[string]any{
					"observations": map[string]string{"type": "string", "description": "Path to the observation snapshot directory."},
					"controls":     map[string]string{"type": "string", "description": "Optional control directory; empty = embedded built-in catalog."},
				},
			},
		},
		{
			"name":        toolScorecard,
			"description": "Evaluate a snapshot's compliance posture across one or more frameworks and render an interactive HTML scorecard (per-framework requirement breakdown with expandable failures + cross-framework comparison). Saves a self-contained HTML file and returns its path. Compliance is evaluated against the embedded catalog.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"observations"},
				"properties": map[string]any{
					"observations": map[string]string{"type": "string", "description": "Path to the observation snapshot directory."},
					"frameworks":   map[string]string{"type": "string", "description": "Optional comma-separated framework IDs (e.g. \"hipaa,pci_dss_v4.0\"). Default: all available."},
				},
			},
		},
		{
			"name":        toolChains,
			"description": "Detect compound risk chains in a snapshot — the multi-condition attack paths a single-resource scanner misses — and render an interactive HTML visualizer: each chain's co-failing controls (its legs) flowing into a compound-risk node, with the attack narrative and a break-any-link remediation. Zero chains is a good result (all risk is single-resource). Needs a chains directory (defaults to ./chains).",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"observations"},
				"properties": map[string]any{
					"observations": map[string]string{"type": "string", "description": "Path to the observation snapshot directory."},
					"controls":     map[string]string{"type": "string", "description": "Optional control directory; empty = embedded built-in catalog."},
					"chains":       map[string]string{"type": "string", "description": "Optional chain-definition directory; empty = ./chains if present."},
					"severity":     map[string]string{"type": "string", "description": "Optional minimum severity: CRITICAL | HIGH | MEDIUM | LOW."},
				},
			},
		},
		{
			"name":        toolContext,
			"description": "Drill into one item by {type, id}: a finding, asset, chain, requirement, or framework. Returns the detail behind it (e.g. every finding on an asset, a chain's legs and narrative, a requirement's failing controls). Called when a user selects something — directly, or via a UI selection event from the dashboard/scorecard/chains visualizers.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"type", "id"},
				"properties": map[string]any{
					"type":         map[string]string{"type": "string", "description": "finding | asset | chain | requirement | framework."},
					"id":           map[string]string{"type": "string", "description": "The item's identifier (finding ID, asset ID, chain ID, requirement ID, or framework ID)."},
					"observations": map[string]string{"type": "string", "description": "Path to the observation snapshot directory (required for all types)."},
					"framework":    map[string]string{"type": "string", "description": "Framework ID — required when type is \"requirement\"."},
					"controls":     map[string]string{"type": "string", "description": "Optional control directory; empty = embedded built-in catalog."},
					"chains":       map[string]string{"type": "string", "description": "Optional chain-definition directory (for type \"chain\"); empty = ./chains if present."},
				},
			},
		},
		{
			"name":        toolVerify,
			"description": "Run Stave's verification pipeline over a snapshot directory. Returns an agent-friendly summary by default (posture score, severity breakdown, SLA split, top findings); 'detailed' adds per-finding evidence (predicate, observed values, fix); 'raw' returns the full Assessment JSON.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"observations_dir"},
				"properties": map[string]any{
					"observations_dir": map[string]string{"type": "string", "description": "Path to the observation snapshot directory."},
					"controls_dir":     map[string]string{"type": "string", "description": "Optional control directory; empty = embedded built-in catalog."},
					"format":           map[string]string{"type": "string", "description": "summary (default) | detailed | raw."},
				},
			},
		},
		{
			"name":        toolExplain,
			"description": "Return the reasoning trace and control context for one finding by FindingID.",
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
	}

	if hosted {
		filtered := tools[:0]
		for _, t := range tools {
			name, _ := t["name"].(string)
			if isDataTool(name) {
				continue
			}
			filtered = append(filtered, t)
		}
		tools = filtered
	}
	return map[string]any{"tools": tools}
}

// dispatchTool routes a tools/call to the named tool. Returns the
// tool's result envelope — MCP wraps tool results under
// {"content": [{"type": "text", "text": "<json>"}]} so even
// structured tools have a consistent surface; we match that
// convention.
func dispatchTool(ctx context.Context, p *toolCallParams, hosted bool) (any, error) {
	// Defense in depth: hosted mode already omits data tools from
	// tools/list, but reject a direct call too in case a client
	// invokes a tool name it cached or guessed.
	if hosted && isDataTool(p.Name) {
		//nolint:staticcheck // ST1005: verbatim agent-facing guidance; the
		// capitalized full sentence is intentional — it is surfaced directly
		// as the JSON-RPC error.message the agent shows the user.
		return nil, errors.New(hostedDataToolMsg)
	}
	if isDataTool(p.Name) {
		return dispatchDataTool(ctx, p)
	}
	// Catalog-query tools (and the unknown-tool fallthrough).
	return dispatchCatalogTool(ctx, p)
}

// dispatchCatalogTool routes the catalog-query tools — those that read
// only the embedded catalog and never touch snapshot data. The
// unknown-tool error lives here as the default branch.
func dispatchCatalogTool(ctx context.Context, p *toolCallParams) (any, error) {
	switch p.Name {
	case toolVersion:
		out, err := runVersion()
		if err != nil {
			return nil, err
		}
		return wrapToolResult(out)
	case toolSearch:
		var args searchArgs
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return nil, fmt.Errorf("search args: %w", err)
		}
		out, err := runSearch(args)
		if err != nil {
			return nil, err
		}
		return wrapToolResult(out)
	case toolCatalogXpl:
		var args catalogExplainArgs
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return nil, fmt.Errorf("catalog_explain args: %w", err)
		}
		out, err := runCatalogExplain(args)
		if err != nil {
			return nil, err
		}
		return wrapToolResult(out)
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

// dispatchDataTool routes the snapshot-touching tools — those that
// require a path to observation data on the local filesystem.
func dispatchDataTool(ctx context.Context, p *toolCallParams) (any, error) {
	switch p.Name {
	case toolVerify:
		var args verifyArgs
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return nil, fmt.Errorf("verify args: %w", err)
		}
		return runVerifyTool(ctx, args)
	case toolDashboard:
		var args dashboardArgs
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return nil, fmt.Errorf("dashboard args: %w", err)
		}
		return runDashboardTool(ctx, args)
	case toolScorecard:
		var args scorecardArgs
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return nil, fmt.Errorf("scorecard args: %w", err)
		}
		return runScorecardTool(ctx, args)
	case toolChains:
		var args chainsArgs
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return nil, fmt.Errorf("chains args: %w", err)
		}
		return runChainsTool(ctx, args)
	case toolContext:
		var args contextArgs
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return nil, fmt.Errorf("context args: %w", err)
		}
		out, err := runContextTool(ctx, args)
		if err != nil {
			return nil, err
		}
		return wrapToolResult(out)
	case toolDiff:
		var args diffArgs
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return nil, fmt.Errorf("diff args: %w", err)
		}
		out, err := runDiff(ctx, args)
		if err != nil {
			return nil, err
		}
		return wrapToolResult(out)
	case toolGaps:
		var args gapsArgs
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return nil, fmt.Errorf("gaps args: %w", err)
		}
		out, err := runGaps(ctx, args)
		if err != nil {
			return nil, err
		}
		return wrapToolResult(out)
	case toolReadiness:
		var args gapsArgs
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return nil, fmt.Errorf("readiness args: %w", err)
		}
		out, err := runReadiness(ctx, args)
		if err != nil {
			return nil, err
		}
		return wrapToolResult(out)
	case toolCompliance:
		var args complianceArgs
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return nil, fmt.Errorf("compliance args: %w", err)
		}
		out, err := runCompliance(ctx, args)
		if err != nil {
			return nil, err
		}
		return wrapToolResult(out)
	default:
		return nil, fmt.Errorf("unknown tool: %q", p.Name)
	}
}

// runCatalogExplain projects pkg/stave.ExplainControl. It is
// catalog-only (no observations), so it works in hosted mode. Bad
// input returns a friendly, non-error result: an empty control_id
// lists example IDs per asset type; an unknown ID returns "did you
// mean?" suggestions rather than a bare failure.
func runCatalogExplain(args catalogExplainArgs) (any, error) {
	id := strings.TrimSpace(args.ControlID)
	if id == "" {
		return map[string]any{
			"message":  "Provide a control_id. Example control IDs by asset type:",
			"examples": stave.AssetTypeExamples(),
		}, nil
	}
	exp, err := stave.ExplainControl(id)
	if errors.Is(err, stave.ErrControlNotFound) {
		// Not found is friendly: offer suggestions rather than fail.
		suggestions := stave.SuggestControlIDs(id, 5)
		msg := fmt.Sprintf("Unknown control %q.", id)
		if len(suggestions) > 0 {
			msg += " Did you mean: " + strings.Join(suggestions, ", ") + "?"
		}
		return map[string]any{"error": msg, "did_you_mean": suggestions}, nil
	}
	if err != nil {
		// A genuine failure (e.g. catalog load) must surface.
		return nil, err
	}
	return exp, nil
}

// runVersion projects pkg/stave.GetCapabilities into the tool
// result. The counts come from the embedded registries, so the
// answer is deterministic and offline — no snapshot or network
// needed. The trailing summary line restates the air-gap guarantee
// for the agent's prose.
func runVersion() (any, error) {
	caps, err := stave.GetCapabilities()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"version":        caps.Version,
		"controls":       caps.Controls,
		"packs":          caps.Packs,
		"frameworks":     caps.Frameworks,
		"attack_tactics": caps.AttackTactics,
		"output_formats": caps.OutputFormats,
		"offline":        caps.Offline,
		"summary":        caps.Tagline,
	}, nil
}

// runSearch is a thin wrapper over pkg/stave.SearchCatalog. Defaults
// the result cap to 10 when the agent omits limit, matching the
// `stave search` CLI default.
func runSearch(args searchArgs) (any, error) {
	if args.Limit <= 0 {
		args.Limit = 10
	}
	hits, err := stave.SearchCatalog(stave.SearchQuery{
		Query:    args.Query,
		Severity: args.Severity,
		Limit:    args.Limit,
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"query":      args.Query,
		"total_hits": len(hits),
		"hits":       hits,
	}, nil
}

// runDiff is a thin wrapper over pkg/stave.DiffSnapshots. Returns the
// structured delta (added / removed / changed) so the agent can
// reason about drift between two captures.
func runDiff(ctx context.Context, args diffArgs) (any, error) {
	if args.Before == "" || args.After == "" {
		return nil, errors.New("before and after are required")
	}
	return stave.DiffSnapshots(ctx, args.Before, args.After)
}

// runGaps is a thin wrapper over pkg/stave.Gaps. Defaults the top-N
// rollup to 10 when the agent omits it.
func runGaps(ctx context.Context, args gapsArgs) (any, error) {
	if args.ObservationsDir == "" {
		return nil, errors.New("observations_dir is required")
	}
	if args.TopN <= 0 {
		args.TopN = 10
	}
	return stave.Gaps(ctx, stave.GapsOptions{
		SnapshotsDir: args.ObservationsDir,
		TopN:         args.TopN,
	})
}

// runReadiness is a thin wrapper over pkg/stave.Readiness. It shares
// gapsArgs (observations_dir + top_n) since the inputs are identical;
// the two tools differ in what they report, not what they take.
func runReadiness(ctx context.Context, args gapsArgs) (any, error) {
	if args.ObservationsDir == "" {
		return nil, errors.New("observations_dir is required")
	}
	if args.TopN <= 0 {
		args.TopN = 10
	}
	return stave.Readiness(ctx, stave.ReadinessOptions{
		SnapshotsDir: args.ObservationsDir,
		TopN:         args.TopN,
	})
}

// runCompliance is a thin wrapper over pkg/stave.Compliance. Returns
// the requirement-level posture for one framework.
func runCompliance(ctx context.Context, args complianceArgs) (any, error) {
	if args.ObservationsDir == "" {
		return nil, errors.New("observations_dir is required")
	}
	if args.Framework == "" {
		return nil, errors.New("framework is required")
	}
	return stave.Compliance(ctx, args.ObservationsDir, args.Framework)
}

// runVerify is a thin wrapper over pkg/stave.Apply. Returns the
// full Assessment so the agent can read findings + summary +
// status without a second round-trip.
func runVerify(ctx context.Context, args verifyArgs) (*stave.Assessment, error) {
	if args.ObservationsDir == "" {
		return nil, errors.New("observations_dir is required")
	}
	cfg := stave.Config{
		SnapshotsDir: args.ObservationsDir,
		ControlsDir:  args.ControlsDir,
	}
	return stave.Apply(ctx, cfg)
}

// runVerifyTool runs verify and renders the result in the requested
// format: "summary" (default) and "detailed" produce agent-friendly
// text; "raw" returns the full Assessment JSON (the original
// behavior). Unknown formats are an explicit error.
func runVerifyTool(ctx context.Context, args verifyArgs) (any, error) {
	assess, err := runVerify(ctx, args)
	if err != nil {
		return nil, err
	}
	switch args.Format {
	case "", "summary":
		return wrapTextResult(formatVerify(assess, scoreOrNil(ctx, assess), false))
	case "detailed":
		return wrapTextResult(formatVerify(assess, scoreOrNil(ctx, assess), true))
	case "raw":
		return wrapToolResult(assess)
	default:
		return nil, fmt.Errorf("unknown format %q (want summary | detailed | raw)", args.Format)
	}
}

// runDashboardTool evaluates a snapshot, renders the HTML posture
// dashboard, writes it to a temp file, and returns a one-line summary
// plus the file path. The HTML is intentionally returned via a file
// rather than inlined into the tool response: a 100 KB HTML blob in a
// text content block does not render in any MCP client (rendering
// needs a ui:// resource) and would flood the agent's context. The
// file path delivers the actual demo — open it in a browser.
func runDashboardTool(ctx context.Context, args dashboardArgs) (any, error) {
	if args.Observations == "" {
		return nil, errors.New("observations is required")
	}
	assess, err := stave.Apply(ctx, stave.Config{
		SnapshotsDir: args.Observations,
		ControlsDir:  args.Controls,
	})
	if err != nil {
		return nil, err
	}
	path, err := writeDashboard(assess)
	if err != nil {
		return nil, err
	}
	return wrapTextResult(dashboardSummary(ctx, assess, path))
}

// runScorecardTool evaluates compliance across the requested
// frameworks, renders the HTML scorecard, writes it to a temp file,
// and returns the file path plus a one-line per-framework summary.
// Like the dashboard, the HTML is delivered via a file, not inlined.
func runScorecardTool(ctx context.Context, args scorecardArgs) (any, error) {
	reports, err := evaluateScorecard(ctx, args.Observations, parseFrameworks(args.Frameworks))
	if err != nil {
		return nil, err
	}
	path, err := writeScorecard(reports)
	if err != nil {
		return nil, err
	}
	return wrapTextResult(scorecardSummary(reports, path))
}

// runRenderScorecard is the --render-scorecard CLI path: evaluate
// compliance and write the scorecard, printing the path to open in a
// browser. Unknown input is tolerated so bundled examples render.
func runRenderScorecard(ctx context.Context, obsDir, frameworks string) error {
	reports, err := evaluateScorecard(ctx, obsDir, parseFrameworks(frameworks))
	if err != nil {
		return err
	}
	path, err := writeScorecard(reports)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, scorecardSummary(reports, path))
	fmt.Fprintf(os.Stdout, "\nfile://%s\n", path)
	return nil
}

// evaluateScorecard runs compliance across the requested frameworks
// (empty = all available) in a single evaluation pass via
// stave.ComplianceMulti. An invalid framework fails the whole call
// with the valid set listed.
func evaluateScorecard(ctx context.Context, obsDir string, frameworks []string) ([]*stave.ComplianceReport, error) {
	if obsDir == "" {
		return nil, errors.New("observations is required")
	}
	return stave.ComplianceMulti(ctx, obsDir, frameworks)
}

// parseFrameworks splits a comma-separated framework list, trimming
// blanks. An empty string yields nil (caller defaults to all).
func parseFrameworks(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// writeScorecard renders the reports to HTML and writes the file.
func writeScorecard(reports []*stave.ComplianceReport) (string, error) {
	htmlDoc, err := renderScorecard(reports)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "stave-scorecard-*.html")
	if err != nil {
		return "", fmt.Errorf("create scorecard file: %w", err)
	}
	path := f.Name()
	if _, err := f.WriteString(htmlDoc); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("write scorecard file: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close scorecard file: %w", err)
	}
	return path, nil
}

// scorecardSummary is the one-line text result: per-framework
// percentage, then the saved path.
func scorecardSummary(reports []*stave.ComplianceReport, path string) string {
	parts := make([]string, 0, len(reports))
	for _, r := range reports {
		parts = append(parts, fmt.Sprintf("%s: %.0f%%", r.FrameworkID, r.CoveragePercent))
	}
	return fmt.Sprintf(
		"Compliance scorecard generated.\n\n%s\n\nInteractive scorecard saved to: %s\nOpen in a browser for the full interactive view.",
		strings.Join(parts, " | "), path)
}

// runChainsTool detects compound risk chains and renders the
// visualizer. Zero chains is reported as a good result (single-
// resource risk only); a severity filter that excludes all chains is
// reported distinctly from "no chains at all".
func runChainsTool(ctx context.Context, args chainsArgs) (any, error) {
	assess, chains, err := evaluateChains(ctx, args)
	if err != nil {
		return nil, err
	}
	if len(assess.ChainFindings) == 0 {
		return wrapTextResult("No compound risk chains detected in this snapshot. All risk is single-resource.")
	}
	if len(chains) == 0 {
		return wrapTextResult(fmt.Sprintf(
			"No compound risk chains at or above severity %q — %d chain(s) exist below that threshold.",
			args.Severity, len(assess.ChainFindings)))
	}
	assess.ChainFindings = chains
	path, err := writeChains(assess)
	if err != nil {
		return nil, err
	}
	return wrapTextResult(chainsSummary(assess, chains, path))
}

// runRenderChains is the --render-chains CLI path.
func runRenderChains(ctx context.Context, obsDir string) error {
	assess, chains, err := evaluateChains(ctx, chainsArgs{Observations: obsDir})
	if err != nil {
		return err
	}
	if len(chains) == 0 {
		fmt.Fprintln(os.Stdout, "No compound risk chains detected. All risk is single-resource.")
		return nil
	}
	assess.ChainFindings = chains
	path, err := writeChains(assess)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, chainsSummary(assess, chains, path))
	fmt.Fprintf(os.Stdout, "\nfile://%s\n", path)
	return nil
}

// evaluateChains runs Apply with chain detection and returns the
// assessment plus the chains filtered by the requested minimum
// severity. ChainsDir defaults to ./chains when present.
func evaluateChains(ctx context.Context, args chainsArgs) (*stave.Assessment, []stave.ChainFinding, error) {
	if args.Observations == "" {
		return nil, nil, errors.New("observations is required")
	}
	assess, err := stave.Apply(ctx, stave.Config{
		SnapshotsDir: args.Observations,
		ControlsDir:  args.Controls,
		ChainsDir:    resolveChainsDir(args.Chains),
	})
	if err != nil {
		return nil, nil, err
	}
	return assess, filterChainsBySeverity(assess.ChainFindings, args.Severity), nil
}

// resolveChainsDir returns the explicit chains dir if given, else
// "chains" when that directory exists, else "" (chain detection off).
func resolveChainsDir(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if fi, err := os.Stat("chains"); err == nil && fi.IsDir() {
		return "chains"
	}
	return ""
}

// filterChainsBySeverity keeps chains at or above the minimum
// severity. An empty minimum keeps all.
func filterChainsBySeverity(chains []stave.ChainFinding, minSeverity string) []stave.ChainFinding {
	if strings.TrimSpace(minSeverity) == "" {
		return chains
	}
	minRank := severityRank(stave.Severity(toLowerTrim(minSeverity)))
	out := make([]stave.ChainFinding, 0, len(chains))
	for i := range chains {
		if severityRank(chains[i].Severity) >= minRank {
			out = append(out, chains[i])
		}
	}
	return out
}

// writeChains renders the chain visualizer and writes it to a file.
func writeChains(a *stave.Assessment) (string, error) {
	htmlDoc, err := renderChains(a)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "stave-chains-*.html")
	if err != nil {
		return "", fmt.Errorf("create chains file: %w", err)
	}
	path := f.Name()
	if _, err := f.WriteString(htmlDoc); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("write chains file: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close chains file: %w", err)
	}
	return path, nil
}

// chainsSummary is the one-line-per-chain text result.
func chainsSummary(a *stave.Assessment, chains []stave.ChainFinding, path string) string {
	var b strings.Builder
	suffix := "s"
	if len(chains) == 1 {
		suffix = ""
	}
	fmt.Fprintf(&b, "Chain analysis complete.\n\n%d compound risk chain%s detected:\n", len(chains), suffix)
	for i := range chains {
		c := &chains[i]
		_, assets := chainAssets(a, c.ChainID)
		fmt.Fprintf(&b, "  [%s] %s — %s (%d assets)\n",
			strings.ToUpper(string(c.Severity)), c.ChainID, chainHeadline(c), len(assets))
	}
	fmt.Fprintf(&b, "\nInteractive chain visualizer saved to: %s\nOpen in a browser for the full interactive view.", path)
	return b.String()
}

// chainHeadline returns the first sentence of a chain's description
// (or narrative), truncated for the summary line.
func chainHeadline(c *stave.ChainFinding) string {
	s := strings.TrimSpace(c.Description)
	if s == "" {
		s = strings.TrimSpace(c.Narrative)
	}
	if i := strings.IndexAny(s, ".\n"); i > 0 {
		s = s[:i]
	}
	if len(s) > 70 {
		s = s[:69] + "…"
	}
	return s
}

// runDemoDashboard is the --demo-dashboard CLI path: evaluate the
// observations directory, write the dashboard, and print the path so
// a presenter can open it in a browser. Unknown input is tolerated so
// bundled examples render without extra flags.
func runDemoDashboard(ctx context.Context, obsDir string) error {
	if obsDir == "" {
		return errors.New("--demo-dashboard requires --observations <dir>")
	}
	assess, err := stave.Apply(ctx, stave.Config{
		SnapshotsDir: obsDir,
	})
	if err != nil {
		return err
	}
	path, err := writeDashboard(assess)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, dashboardSummary(ctx, assess, path))
	fmt.Fprintf(os.Stdout, "\nfile://%s\n", path)
	return nil
}

// writeDashboard renders the assessment to HTML and writes it to a
// uniquely named file in the OS temp directory.
func writeDashboard(a *stave.Assessment) (string, error) {
	htmlDoc, err := renderDashboard(a)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "stave-dashboard-*.html")
	if err != nil {
		return "", fmt.Errorf("create dashboard file: %w", err)
	}
	path := f.Name()
	if _, err := f.WriteString(htmlDoc); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("write dashboard file: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close dashboard file: %w", err)
	}
	return path, nil
}

// dashboardSummary is the one-line text result that accompanies a
// generated dashboard.
func dashboardSummary(ctx context.Context, a *stave.Assessment, path string) string {
	score := 0
	if sr := scoreOrNil(ctx, a); sr != nil {
		score = sr.ScoreInt
	}
	c := a.CountBySeverity()
	return fmt.Sprintf(
		"Dashboard generated.\n\nScore: %d/100 | Critical: %d | High: %d | Medium: %d | Low: %d\n\n"+
			"Interactive dashboard saved to: %s\nOpen in a browser for the full interactive experience.",
		score, c[stave.SeverityCritical], c[stave.SeverityHigh], c[stave.SeverityMedium], c[stave.SeverityLow], path)
}

// scoreOrNil computes the posture score for the assessment, returning
// nil if scoring fails — the text summary degrades to omitting the
// score line rather than failing the whole call.
func scoreOrNil(ctx context.Context, a *stave.Assessment) *stave.ScoreResult {
	sr, err := stave.Score(ctx, stave.ScoreConfig{Assessment: a})
	if err != nil {
		return nil
	}
	return sr
}

// runExplain re-runs Apply, then projects one finding's reasoning
// trace + control context. The schema is intentionally narrow —
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
	return wrapTextResult(string(body))
}

// wrapTextResult wraps already-rendered text in the MCP tool-result
// envelope. Used by tools that produce human-readable text (e.g.
// stave.verify summary/detailed) rather than a JSON projection.
func wrapTextResult(text string) (any, error) {
	return map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": text},
		},
	}, nil
}
