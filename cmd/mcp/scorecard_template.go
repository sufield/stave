package main

// scorecardHTML is the self-contained compliance-scorecard template,
// rendered by renderScorecard with a scorecardView. Inline CSS/JS,
// no external references, no storage. Independent of the dashboard
// template. text/template delimiters ({{ }}) are the only active
// markup; single braces in CSS/JS are literal.
const scorecardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Stave Compliance Scorecard</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px;
    background: #0F172A; color: #F8FAFC;
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  h1 { font-size: 20px; margin: 0 0 16px; }
  h2 { font-size: 15px; margin: 0 0 12px; }
  .accent { color: #F97316; }
  .sub { color: #94A3B8; font-size: 13px; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; word-break: break-all; }
  .card { background: #1E293B; border: 1px solid #334155; border-radius: 12px; padding: 20px; margin-bottom: 24px; }
  .hidden { display: none; }

  .tabs { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 16px; }
  .tab {
    background: #1E293B; color: #94A3B8; border: 1px solid #334155;
    border-radius: 8px 8px 0 0; padding: 8px 14px; font-size: 13px; cursor: pointer;
  }
  .tab:hover { color: #F8FAFC; }
  .tab.active { color: #F97316; border-color: #F97316; background: #0F172A; font-weight: 700; }

  .fwhead { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 4px; }
  .pct { font-size: 40px; font-weight: 800; line-height: 1; }

  .reqs { margin-top: 16px; }
  .req { border-left: 4px solid #334155; background: #0F172A; border-radius: 4px; margin-bottom: 6px; }
  .req.pass { border-left-color: #22C55E; }
  .req.fail { border-left-color: #EF4444; }
  .req.na   { border-left-color: #475569; }
  .reqrow { display: grid; grid-template-columns: 120px 1fr 70px 90px; gap: 12px; align-items: center; padding: 10px 14px; }
  .req.fail .reqrow { cursor: pointer; }
  .req.fail .reqrow:hover { background: #1E293B; }
  .reqtitle { color: #CBD5E1; }
  .req.na .reqtitle { font-style: italic; color: #64748B; }
  .reqstatus { font-weight: 700; font-size: 12px; text-align: center; border-radius: 4px; padding: 2px 0; }
  .reqstatus.pass { color: #22C55E; }
  .reqstatus.fail { color: #EF4444; }
  .reqstatus.na   { color: #64748B; }
  .reqcount { color: #94A3B8; font-size: 12px; text-align: right; }
  .fails { padding: 0 14px 12px 14px; }
  .fail-item { display: grid; grid-template-columns: 1fr 1fr auto; gap: 12px; padding: 6px 0; border-top: 1px solid #1E293B; font-size: 12px; }
  .fail-item .asset { color: #94A3B8; }

  .cmprow { display: grid; grid-template-columns: 160px 1fr 50px; gap: 12px; align-items: center; margin-bottom: 8px; }
  .cmpname { font-size: 13px; }
  .cmpbar { height: 18px; background: #334155; border-radius: 4px; overflow: hidden; }
  .cmpfill { height: 100%; }
  .cmppct { font-weight: 700; font-size: 13px; text-align: right; }
</style>
</head>
<body>
  <h1>Stave <span class="accent">Compliance Scorecard</span></h1>

  <div class="tabs">
    {{range .Frameworks}}<button class="tab {{if .Active}}active{{end}}" id="tab-{{.TabID}}" data-fw="{{.FrameworkID}}" onclick="showFw('{{.TabID}}');staveEmit('framework',this.dataset.fw)">{{.Name}}</button>{{end}}
  </div>

  {{range .Frameworks}}{{$fw := .FrameworkID}}
  <div class="card panel {{if not .Active}}hidden{{end}}" id="{{.TabID}}">
    <div class="fwhead">
      <div>
        <h2>{{.Name}}</h2>
        <div class="sub">{{.Version}}</div>
      </div>
      <div class="pct" style="color:{{.PercentColor}}">{{.Percent}}%</div>
    </div>
    <div class="sub">{{.Met}} met · {{.NotMet}} not met · {{.NotEval}} N/A · {{.Total}} requirements</div>

    <div class="reqs">
      {{range .Requirements}}<div class="req {{.Class}}" data-req="{{.ID}}" data-fw="{{$fw}}">
        <div class="reqrow"{{if .CanExpand}} onclick="toggleReq(this);staveEmit('requirement', this.parentElement.dataset.req, this.parentElement.dataset.fw)"{{end}}>
          <span class="reqid mono">{{.ID}}</span>
          <span class="reqtitle">{{.Title}}</span>
          <span class="reqstatus {{.Class}}">{{.Status}}</span>
          <span class="reqcount">{{if .Findings}}{{.Findings}} failing{{end}}</span>
        </div>
        {{if .CanExpand}}<div class="fails hidden">
          {{range .Fails}}<div class="fail-item"><span class="mono">{{.ControlID}}</span><span class="mono asset">{{.Asset}}</span><span>{{.Name}}</span></div>{{end}}
        </div>{{end}}
      </div>{{end}}
    </div>
  </div>
  {{end}}

  <div class="card">
    <h2>Cross-framework comparison <span class="sub">(lowest first)</span></h2>
    {{range .Compare}}<div class="cmprow">
      <span class="cmpname">{{.Name}}</span>
      <div class="cmpbar"><div class="cmpfill" style="width:{{.Width}}%;background:{{.Color}}"></div></div>
      <span class="cmppct" style="color:{{.Color}}">{{.PercentStr}}%</span>
    </div>{{end}}
  </div>

<script>
"use strict";
// staveEmit posts a UI selection event to a host (MCP Apps) so the
// model can drill in via stave.context. No-op standalone.
function staveEmit(kind, id, framework) {
  try {
    if (window.parent && window.parent !== window) {
      var msg = { source: "stave", kind: kind, id: id };
      if (framework) { msg.framework = framework; }
      window.parent.postMessage(msg, "*");
    }
  } catch (e) { /* standalone browser: no host */ }
}
function showFw(id) {
  var panels = document.querySelectorAll(".panel");
  for (var i = 0; i < panels.length; i++) {
    panels[i].classList.toggle("hidden", panels[i].id !== id);
  }
  var tabs = document.querySelectorAll(".tab");
  for (var j = 0; j < tabs.length; j++) {
    tabs[j].classList.toggle("active", tabs[j].id === "tab-" + id);
  }
}
function toggleReq(row) {
  var fails = row.parentElement.querySelector(".fails");
  if (fails) { fails.classList.toggle("hidden"); }
}
</script>
</body>
</html>
`
