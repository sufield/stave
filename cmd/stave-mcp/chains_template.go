package main

// chainsHTML is the self-contained risk-chain visualizer template,
// rendered by renderChains with a chainsView. Inline CSS/JS and inline
// SVG (no D3, no external refs). Independent of the dashboard and
// scorecard templates. text/template delimiters ({{ }}) are the only
// active markup; the {{add}} func offsets SVG text from node origins.
const chainsHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Stave Risk Chains</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px;
    background: #0F172A; color: #F8FAFC;
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  h1 { font-size: 20px; margin: 0 0 4px; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .08em; color: #94A3B8; margin: 18px 0 8px; }
  .accent { color: #F97316; }
  .sub { color: #94A3B8; font-size: 13px; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; word-break: break-all; }

  .summary { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin: 12px 0 20px; }
  .badge { font-size: 12px; font-weight: 700; color: #0F172A; border-radius: 6px; padding: 3px 9px; }

  .layout { display: grid; grid-template-columns: 280px 1fr; gap: 20px; align-items: start; }
  @media (max-width: 760px) { .layout { grid-template-columns: 1fr; } }

  .list { display: flex; flex-direction: column; gap: 8px; }
  .chainrow { background: #1E293B; border: 1px solid #334155; border-left: 4px solid #334155; border-radius: 8px; padding: 10px 12px; cursor: pointer; }
  .chainrow:hover { border-color: #F97316; }
  .chainrow.active { border-left-color: #F97316; background: #0F172A; }
  .sevbadge { font-size: 10px; font-weight: 700; color: #0F172A; border-radius: 4px; padding: 1px 6px; margin-right: 6px; }
  .cid { display: block; margin-top: 4px; }
  .meta { color: #64748B; font-size: 11px; }

  .card { background: #1E293B; border: 1px solid #334155; border-radius: 12px; padding: 20px; }
  .hidden { display: none; }
  .graph { overflow-x: auto; }
  .detail { margin-top: 16px; border-top: 1px solid #334155; padding-top: 14px; }
  .narr { color: #CBD5E1; }
  .stages { margin: 8px 0; }
  .leg { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; padding: 5px 0; border-top: 1px solid #0F172A; font-size: 12px; }
  .leg .asset { color: #94A3B8; }
  .fix { margin-top: 12px; padding: 10px 12px; background: #0F172A; border-left: 3px solid #22C55E; border-radius: 4px; font-size: 13px; }
</style>
</head>
<body>
  <h1>Stave <span class="accent">Risk Chains</span></h1>
  <div class="summary">
    <strong>{{.Total}} compound risk chain{{if ne .Total 1}}s{{end}}</strong>
    {{range .SevCounts}}{{if .Has}}<span class="badge" style="background:{{.Color}}">{{.Label}} {{.Count}}</span>{{end}}{{end}}
  </div>

  <div class="layout">
    <div class="list">
      {{range .Chains}}<div class="chainrow {{if .Active}}active{{end}}" id="row-{{.TabID}}" data-chain="{{.ID}}" onclick="showChain('{{.TabID}}');staveEmit('chain',this.dataset.chain)" style="border-left-color:{{.SevColor}}">
        <span class="sevbadge" style="background:{{.SevColor}}">{{.Severity}}</span>
        <span class="cid mono">{{.ID}}</span>
        <span class="meta">{{len .Legs}} legs · {{.AssetCount}} assets · score {{.Score}}</span>
      </div>{{end}}
    </div>

    <div class="panels">
      {{range .Chains}}<div class="card panel {{if not .Active}}hidden{{end}}" id="{{.TabID}}">
        <h2>Compound legs <span class="sub">— each must hold; break any one to break the chain</span></h2>
        <div class="graph">
          <svg width="{{.SVGW}}" height="{{.SVGH}}" viewBox="0 0 {{.SVGW}} {{.SVGH}}" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <marker id="ah" markerWidth="10" markerHeight="8" refX="9" refY="4" orient="auto">
                <path d="M0,0 L10,4 L0,8 Z" fill="#EF4444"></path>
              </marker>
            </defs>
            {{range .Arrows}}<line x1="{{.X1}}" y1="{{.Y1}}" x2="{{.X2}}" y2="{{.Y2}}" stroke="#EF4444" stroke-width="2" marker-end="url(#ah)"></line>{{end}}
            {{range .Legs}}<rect x="{{.X}}" y="{{.Y}}" width="{{.W}}" height="{{.H}}" rx="8" fill="#0F172A" stroke="{{.Color}}" stroke-width="2"><title>{{.ControlID}}</title></rect>
            <text x="{{add .X 10}}" y="{{add .Y 24}}" font-size="11" fill="#F8FAFC" font-family="ui-monospace,monospace">{{.Label}}</text>
            <text x="{{add .X 10}}" y="{{add .Y 43}}" font-size="10" fill="#94A3B8">{{.Asset}}</text>{{end}}
            <rect x="{{.Term.X}}" y="{{.Term.Y}}" width="{{.Term.W}}" height="{{.Term.H}}" rx="8" fill="{{.Term.Color}}"></rect>
            <text x="{{add .Term.X 85}}" y="{{add .Term.Y 34}}" text-anchor="middle" font-size="12" font-weight="700" fill="#0F172A">{{.Term.Label}}</text>
          </svg>
        </div>

        <div class="detail">
          <div class="narr">{{.Narrative}}</div>
          {{if .Stages}}<div class="stages sub">Attack stages: {{.Stages}}</div>{{end}}
          <h2>Participating controls</h2>
          {{range .Legs}}<div class="leg"><span class="mono">{{.ControlID}}</span><span class="asset mono">{{if .Asset}}{{.Asset}}{{else}}—{{end}}</span></div>{{end}}
          <div class="fix">Breaking <strong>any one</strong> link drops this compound below its threshold. Each leg above is an independent fix — remediate the cheapest one.</div>
        </div>
      </div>{{end}}
    </div>
  </div>

<script>
"use strict";
// staveEmit posts a UI selection event to a host (MCP Apps) so the
// model can drill in via stave.context. No-op standalone.
function staveEmit(kind, id) {
  try {
    if (window.parent && window.parent !== window) {
      window.parent.postMessage({ source: "stave", kind: kind, id: id }, "*");
    }
  } catch (e) { /* standalone browser: no host */ }
}
function showChain(id) {
  var panels = document.querySelectorAll(".panel");
  for (var i = 0; i < panels.length; i++) {
    panels[i].classList.toggle("hidden", panels[i].id !== id);
  }
  var rows = document.querySelectorAll(".chainrow");
  for (var j = 0; j < rows.length; j++) {
    rows[j].classList.toggle("active", rows[j].id === "row-" + id);
  }
}
</script>
</body>
</html>
`
