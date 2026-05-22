package main

// dashboardHTML is the self-contained posture dashboard template,
// rendered by renderDashboard with a dashboardView. All CSS and JS
// are inline; there are no external references, no network calls, no
// storage — safe to open as a local file or render in a sandboxed
// iframe. text/template delimiters ({{ }}) are the only active
// markup; single braces in CSS/JS are literal.
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Stave Posture Dashboard</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px;
    background: #0F172A; color: #F8FAFC;
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  h1 { font-size: 20px; margin: 0 0 4px; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .08em; color: #94A3B8; margin: 0 0 12px; }
  .sub { color: #94A3B8; margin: 0 0 24px; }
  .accent { color: #F97316; }
  .grid { display: grid; grid-template-columns: 220px 1fr; gap: 24px; align-items: start; }
  @media (max-width: 720px) { .grid { grid-template-columns: 1fr; } }
  .card { background: #1E293B; border: 1px solid #334155; border-radius: 12px; padding: 20px; margin-bottom: 24px; }
  .gauge { display: flex; flex-direction: column; align-items: center; }
  .gauge svg { cursor: help; }
  .state { font-weight: 700; margin-top: 8px; }
  .bar { display: flex; height: 28px; border-radius: 6px; overflow: hidden; background: #334155; }
  .seg { display: flex; align-items: center; justify-content: center; color: #0F172A; font-weight: 700; font-size: 13px; min-width: 0; }
  .legend { display: flex; flex-wrap: wrap; gap: 16px; margin-top: 12px; color: #94A3B8; font-size: 13px; }
  .legend span::before { content: ""; display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 6px; vertical-align: middle; }
  .controls { display: flex; gap: 12px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
  select, button {
    background: #0F172A; color: #F8FAFC; border: 1px solid #334155;
    border-radius: 6px; padding: 6px 10px; font-size: 13px; cursor: pointer;
  }
  button:hover, select:hover { border-color: #F97316; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 8px 10px; color: #94A3B8; border-bottom: 1px solid #334155; cursor: pointer; user-select: none; white-space: nowrap; }
  th:hover { color: #F97316; }
  td { padding: 8px 10px; border-bottom: 1px solid #1E293B; vertical-align: top; }
  tr { background: #1E293B; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; word-break: break-all; }
  .sev { font-weight: 700; font-size: 12px; }
  .sla-item { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #1E293B; }
  .sla-over { color: #EF4444; font-weight: 700; }
  footer { color: #64748B; font-size: 12px; margin-top: 8px; }
  .empty { color: #22C55E; }
</style>
</head>
<body>
  <h1>Stave <span class="accent">Posture Dashboard</span></h1>
  <p class="sub">{{.SecurityState}} — {{.Findings}} findings across {{.Assets}} assets</p>

  <div class="grid">
    <div class="card gauge">
      <svg width="180" height="180" viewBox="0 0 180 180">
        <circle cx="90" cy="90" r="80" fill="none" stroke="#334155" stroke-width="14"></circle>
        <circle cx="90" cy="90" r="80" fill="none" stroke="{{.ScoreColor}}" stroke-width="14"
                stroke-linecap="round" stroke-dasharray="{{.GaugeDash}}" transform="rotate(-90 90 90)">
          <title>Posture score: {{.Score}}/100</title>
        </circle>
        <text x="90" y="86" text-anchor="middle" font-size="46" font-weight="700" fill="{{.ScoreColor}}">{{.Score}}</text>
        <text x="90" y="112" text-anchor="middle" font-size="13" fill="#94A3B8">/ 100</text>
      </svg>
      <div class="state" style="color:{{.ScoreColor}}">{{.SecurityState}}</div>
      <div class="sub" style="margin:4px 0 0">{{.Findings}} findings · {{.Assets}} assets</div>
    </div>

    <div>
      <div class="card">
        <h2>Severity breakdown</h2>
        <div class="bar">
          {{range .Severities}}{{if .Has}}<div class="seg" style="width:{{.Pct}}%;background:{{.Color}}" title="{{.Label}}: {{.Count}}">{{.Count}}</div>{{end}}{{end}}
        </div>
        <div class="legend">
          {{range .Severities}}<span style="--c:{{.Color}}"><span style="background:{{.Color}};display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px"></span>{{.Label}} {{.Count}}</span>{{end}}
        </div>
      </div>

      {{if .SLABreaches}}
      <div class="card">
        <h2>SLA status — {{.SLABreaches}} past deadline</h2>
        {{range .SLAItems}}<div class="sla-item"><span class="mono">{{.ControlID}}</span><span class="sla-over">{{.OverdueDays}} days overdue</span></div>{{end}}
      </div>
      {{end}}
    </div>
  </div>

  <div class="card">
    <h2>Findings</h2>
    {{if .Rows}}
    <div class="controls">
      <select id="sevFilter" onchange="filterSev(this.value)">
        <option value="all">All severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <button id="toggleAll" onclick="toggleAll()">Show all</button>
      <span class="sub" style="margin:0">Click a column header to sort.</span>
    </div>
    <table id="findings">
      <thead><tr>
        <th onclick="sortTable(0)">Severity</th>
        <th onclick="sortTable(1)">Control ID</th>
        <th onclick="sortTable(2)">Asset</th>
        <th onclick="sortTable(3)">Message</th>
      </tr></thead>
      <tbody>
        {{range .Rows}}<tr class="{{if .Extra}}extra{{end}}" data-sev="{{.Severity}}" data-rank="{{.SevRank}}" data-asset="{{.Asset}}" onclick="staveEmit('asset', this.dataset.asset)" style="border-left:4px solid {{.Color}};cursor:pointer">
          <td><span class="sev" style="color:{{.Color}}">{{.Severity}}</span></td>
          <td class="mono">{{.ControlID}}</td>
          <td class="mono">{{.Asset}}</td>
          <td>{{.Message}}</td>
        </tr>{{end}}
      </tbody>
    </table>
    {{else}}
    <p class="empty">No findings — all evaluated controls passed.</p>
    {{end}}
  </div>

  <footer>
    Evaluated {{.EvaluatedAt}} · {{.Findings}} findings · {{.Assets}} assets · {{.Snapshots}} snapshots · generated by stave-mcp
  </footer>

<script>
"use strict";
// staveEmit posts a UI selection event to a host (MCP Apps) so the
// model can drill in via stave.context. No-op in a standalone browser
// (no parent to receive it).
function staveEmit(kind, id, framework) {
  try {
    if (window.parent && window.parent !== window) {
      var msg = { source: "stave", kind: kind, id: id };
      if (framework) { msg.framework = framework; }
      window.parent.postMessage(msg, "*");
    }
  } catch (e) { /* standalone browser: no host */ }
}
var showAll = false, sevFilter = "all";
function rows() { return Array.prototype.slice.call(document.querySelectorAll("#findings tbody tr")); }
function refresh() {
  rows().forEach(function (tr) {
    var isExtra = tr.classList.contains("extra");
    var sevOk = (sevFilter === "all" || tr.getAttribute("data-sev") === sevFilter);
    var extraOk = (showAll || !isExtra);
    tr.style.display = (sevOk && extraOk) ? "" : "none";
  });
}
function filterSev(v) { sevFilter = v; refresh(); }
function toggleAll() {
  showAll = !showAll;
  document.getElementById("toggleAll").textContent = showAll ? "Show top 20" : "Show all";
  refresh();
}
function sortTable(col) {
  var tbody = document.querySelector("#findings tbody");
  var rs = rows();
  var asc = !(tbody.getAttribute("data-col") === String(col) && tbody.getAttribute("data-asc") === "true");
  rs.sort(function (a, b) {
    var x, y;
    if (col === 0) { x = +a.getAttribute("data-rank"); y = +b.getAttribute("data-rank"); }
    else { x = a.children[col].textContent.toLowerCase(); y = b.children[col].textContent.toLowerCase(); }
    if (x < y) return asc ? -1 : 1;
    if (x > y) return asc ? 1 : -1;
    return 0;
  });
  tbody.setAttribute("data-col", col);
  tbody.setAttribute("data-asc", asc ? "true" : "false");
  rs.forEach(function (r, i) {
    tbody.appendChild(r);
    if (i < 20) r.classList.remove("extra"); else r.classList.add("extra");
  });
  refresh();
}
refresh();
</script>
</body>
</html>
`
