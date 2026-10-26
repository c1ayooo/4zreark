package report

// reportTemplate 自包含 HTML 报告模板（面向甲方交付）：
//   - 内嵌 CSS、@media print 分页；浏览器打开 Ctrl+P 即可存 PDF
//   - 报文策略：请求永远全量；响应 smart 模式超长节选（details 可展开全量，打印时保持节选）
//   - 章节固定编号（一~八 + 附录），空数据渲染占位说明，保证项目/会话两种报告编号一致
const reportTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>{{.Title}}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: "Noto Sans CJK SC","Microsoft YaHei","PingFang SC",sans-serif; color:#1f2328; margin:0; background:#fff; line-height:1.65; font-size:14px; }
  .page { max-width: 980px; margin: 0 auto; padding: 48px 40px; }
  h1 { font-size:26px; text-align:center; margin:40px 0 8px; }
  h2 { font-size:19px; border-left:4px solid #b91c1c; padding-left:10px; margin:36px 0 14px; page-break-after:avoid; }
  h3 { font-size:16px; margin:22px 0 8px; page-break-after:avoid; }
  .cover { text-align:center; padding:120px 0 60px; page-break-after:always; }
  .cover .meta { margin-top:48px; display:inline-block; text-align:left; }
  .cover .meta td { padding:6px 18px; border-bottom:1px solid #e5e7eb; }
  .cover .meta td:first-child { color:#6b7280; white-space:nowrap; }
  .cover .desc { max-width:720px; margin:18px auto 0; color:#4b5563; font-size:13px; text-align:left; white-space:pre-wrap; }
  table.stats { width:100%; border-collapse:collapse; margin:10px 0 8px; }
  table.stats th, table.stats td { border:1px solid #d1d5db; padding:7px 10px; text-align:left; }
  table.stats th { background:#f3f4f6; }
  .status-line { color:#4b5563; font-size:13px; margin:4px 0 16px; }
  .conclusion { background:#f9fafb; border-left:3px solid #b91c1c; padding:10px 14px; margin:10px 0 16px; }
  .sev-bars { margin:6px 0 16px; }
  .sev-bar-row { display:flex; align-items:center; gap:10px; margin:4px 0; }
  .sev-bar-row .lbl { min-width:74px; }
  .sev-bar-row .track { flex:1; background:#f3f4f6; border-radius:4px; height:18px; overflow:hidden; }
  .sev-bar-row .fill { height:100%; min-width:2px; border-radius:4px; }
  .sev-bar-row .num { min-width:32px; text-align:right; color:#4b5563; font-size:13px; }
  table.ovw { width:100%; border-collapse:collapse; margin:10px 0 18px; font-size:13px; }
  table.ovw th, table.ovw td { border:1px solid #d1d5db; padding:6px 9px; text-align:left; vertical-align:top; }
  table.ovw th { background:#f3f4f6; }
  table.ovw tr { page-break-inside:avoid; }
  table.ovw td.num { white-space:nowrap; color:#6b7280; }
  table.ovw th:nth-child(4), table.ovw td:nth-child(4) { white-space:nowrap; }
  table.ovw th:last-child, table.ovw td:last-child { white-space:nowrap; }
  table.ovw td.tgt { word-break:break-all; max-width:280px; }
  table.ovw a { color:#1d4ed8; text-decoration:none; }
  table.ovw a:hover { text-decoration:underline; }
  .badge { display:inline-block; padding:1px 10px; border-radius:10px; color:#fff; font-size:12px; font-weight:600; }
  .sev-critical { background:#7f1d1d; } .sev-high { background:#dc2626; }
  .sev-medium { background:#d97706; } .sev-low { background:#2563eb; } .sev-info { background:#6b7280; }
  .bar-critical { background:#7f1d1d; } .bar-high { background:#dc2626; }
  .bar-medium { background:#d97706; } .bar-low { background:#2563eb; } .bar-info { background:#6b7280; }
  .vuln { border:1px solid #d1d5db; border-radius:8px; padding:16px 18px; margin:14px 0 26px; page-break-inside:auto; }
  .vuln-head { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
  .vuln-head .no { color:#6b7280; font-size:13px; }
  .vuln-head .title { font-weight:700; font-size:15px; flex:1; }
  .kv { margin:8px 0; }
  .kv b { color:#374151; }
  .field { margin:8px 0; }
  .field .fname { font-weight:600; color:#111827; margin-bottom:2px; page-break-after:avoid; break-after:avoid; }
  .field .fbody { white-space:pre-wrap; word-break:break-word; background:#f9fafb; border:1px solid #e5e7eb; border-radius:6px; padding:8px 12px; }
  .evd-card { border:1px solid #9ca3af; border-radius:8px; margin:10px 0; page-break-inside:auto; }
  .evd-head { display:flex; gap:8px; align-items:center; padding:6px 12px; background:#f3f4f6; border-bottom:1px solid #d1d5db; font-size:13px; flex-wrap:wrap; }
  .evd-head .t { font-weight:700; flex:1; }
  .evd-head .meta { color:#6b7280; font-size:12px; }
  pre.pkt { margin:0; padding:10px 12px; background:#0f172a; color:#e5e7eb; font-family:"JetBrains Mono",Consolas,"Courier New",monospace; font-size:11.5px; line-height:1.5; white-space:pre-wrap; word-break:break-all; }
  pre.pkt mark.hl { background:#fde047; color:#0f172a; padding:0 1px; border-radius:2px; font-weight:600; }
  pre.pkt mark.hl-proof { background:#fb923c; color:#0f172a; padding:0 2px; border-radius:2px; font-weight:700; }
  pre.pkt img.resp-img { display:block; max-width:100%; max-height:420px; margin:4px 0; border:1px solid #334155; border-radius:4px; background:#fff; }
  .pkt-sep { color:#94a3b8; font-weight:700; }
  details.resp-full { border:1px solid #d1d5db; border-top:none; background:#f9fafb; }
  details.resp-full summary { cursor:pointer; padding:5px 12px; font-size:12px; color:#6b7280; }
  details.resp-full pre.pkt { border-top:1px solid #d1d5db; }
  .cmp { display:grid; grid-template-columns:1fr 1fr; gap:10px; margin:10px 0; }
  .cmp .cell { border:1px solid #9ca3af; border-radius:8px; overflow:hidden; page-break-inside:avoid; display:flex; flex-direction:column; }
  .cmp .cell-label { padding:5px 10px; background:#fef3c7; border-bottom:1px solid #d1d5db; font-size:12px; font-weight:700; color:#92400e; }
  .cmp .cell pre.pkt { flex:1; }
  .rem-group { border:1px solid #e5e7eb; border-radius:8px; padding:12px 16px; margin:10px 0; page-break-inside:avoid; }
  .rem-group .rem-head { font-weight:700; margin-bottom:4px; }
  .rem-group .rem-hint { color:#6b7280; font-size:13px; margin-bottom:8px; }
  .rem-group ol { margin:4px 0 0 20px; padding:0; }
  .rem-group li { margin:2px 0; }
  .facts td, .tools td { border-bottom:1px solid #e5e7eb; padding:5px 8px; font-size:13px; }
  .facts, .tools { width:100%; border-collapse:collapse; margin:8px 0; }
  .chain-path { background:#f9fafb; border:1px solid #e5e7eb; border-radius:6px; padding:10px 14px; margin:8px 0; }
  .chain-step { display:flex; gap:8px; align-items:center; margin:4px 0; }
  .chain-step .n { min-width:22px; height:22px; border-radius:50%; background:#b91c1c; color:#fff; font-size:12px; display:flex; align-items:center; justify-content:center; }
  .chain-step .node-t { color:#6b7280; font-size:12px; border:1px solid #d1d5db; border-radius:4px; padding:0 6px; margin-left:auto; }
  .chain-edges { color:#6b7280; font-size:12px; margin-top:8px; word-break:break-all; }
  .placeholder { color:#9ca3af; font-size:13px; }
  .footer-note { color:#9ca3af; font-size:12px; text-align:center; margin-top:40px; border-top:1px solid #e5e7eb; padding-top:10px; }
  img.shot { display:block; max-width:100%; border-bottom:1px solid #d1d5db; }
  .cmp img.shot { border-bottom:none; }
  @media print {
    .page { padding:0; max-width:none; }
    .vuln { border:1px solid #9ca3af; }
    details.resp-full summary { display:none; }
  }
</style>
</head>
<body class="profile-{{.Profile.ID}}"><div class="page">

{{define "pktPre"}}{{if or .ReqText .RespText .RespHTML}}<pre class="pkt">{{if .ReqText}}<span class="pkt-sep">── 请求 ──</span>
{{.ReqText}}

{{end}}<span class="pkt-sep">── 响应 ──</span>{{if .RespHTML}}{{.RespHTML}}{{else}}
{{.RespText}}{{end}}</pre>{{end}}{{if .RespOmitted}}<details class="resp-full"><summary>展开完整响应（另有 {{.RespOmitted}} 字节未展示）</summary>
<pre class="pkt">{{if .RespFullHTML}}{{.RespFullHTML}}{{else}}
{{.RespFull}}{{end}}</pre></details>{{end}}{{end}}

<div class="cover">
  <h1>{{.ProjectName}} {{.Profile.CoverSubject}}</h1>
  <div class="meta"><table>
    <tr><td>报告名称</td><td>{{.Title}}</td></tr>
    <tr><td>项目</td><td>{{.ProjectName}}</td></tr>
    {{if .Delivery.ClientName}}<tr><td>客户名称</td><td>{{.Delivery.ClientName}}</td></tr>{{end}}
    {{if .Delivery.ReportNo}}<tr><td>报告编号</td><td>{{.Delivery.ReportNo}}</td></tr>{{end}}
    {{if .Delivery.Classification}}<tr><td>密级</td><td>{{.Delivery.Classification}}</td></tr>{{end}}
    {{if .Delivery.Tester}}<tr><td>测试人员</td><td>{{.Delivery.Tester}}</td></tr>{{end}}
    {{if .Delivery.Contact}}<tr><td>联系方式</td><td>{{.Delivery.Contact}}</td></tr>{{end}}
    {{if .Description}}<tr><td>项目描述</td><td>{{.Description}}</td></tr>{{end}}
    <tr><td>交付模板</td><td>{{.Profile.Name}}</td></tr>
    <tr><td>测试范围</td><td>{{.Range}}</td></tr>
    <tr><td>风险等级</td><td><span class="badge {{.Stats.TopSeverity|severityClass}}">{{.Stats.TopSeverity}}</span></td></tr>
    <tr><td>发现漏洞</td><td>{{.Stats.Total}} 个（严重 {{index .Stats.BySeverity "critical"}} / 高危 {{index .Stats.BySeverity "high"}} / 中危 {{index .Stats.BySeverity "medium"}} / 低危 {{index .Stats.BySeverity "low"}}）</td></tr>
    <tr><td>生成时间</td><td>{{.GeneratedAt}}</td></tr>
    <tr><td>生成引擎</td><td>4zreark</td></tr>
  </table></div>
</div>

<h2>{{.SectionNo.Summary}}执行摘要</h2>
{{if .SummaryConclusion}}<div class="conclusion">{{.SummaryConclusion}}</div>{{end}}
<p>本次测试共发现 <b>{{.Stats.Total}}</b> 个漏洞，涉及 {{.Stats.Conversations}} 个测试会话，
沉淀确认事实 {{.Stats.FactCount}} 条，执行工具调用 {{.Stats.ToolCalls}} 次。</p>
<div class="sev-bars">
  {{range .Stats.SeverityDist}}<div class="sev-bar-row">
    <span class="lbl"><span class="badge {{.Severity|severityClass}}">{{.Severity}}</span></span>
    <span class="track"><span class="fill bar-{{.Severity}}" style="width:{{.Percent}}%"></span></span>
    <span class="num">{{.Count}}</span>
  </div>{{end}}
</div>
<ul>
  {{range .SummaryItems}}<li>{{.}}</li>{{end}}
</ul>

<h2>{{.SectionNo.Scope}}测试范围与评级标准</h2>
<table class="stats">
  <tr><th>项目</th><th>说明</th></tr>
  <tr><td>测试范围</td><td>{{.Range}}</td></tr>
  <tr><td>测试会话</td><td>{{.Stats.Conversations}} 个</td></tr>
  <tr><td>执行工具调用</td><td>{{.Stats.ToolCalls}} 次（原始输出存于平台证据库，可按证据 ID 复核）</td></tr>
</table>
<p>本报告漏洞严重度按以下标准评定：</p>
{{if .Profile.ShowRatingStandard}}<table class="stats">
  <tr><th>等级</th><th>判定标准</th></tr>
  <tr><td><span class="badge sev-critical">critical</span></td><td>可直接导致系统失陷、核心数据泄露或具备无条件的远程利用能力</td></tr>
  <tr><td><span class="badge sev-high">high</span></td><td>可获取敏感数据或关键权限，或需较少前置条件即可显著影响机密性/完整性/可用性</td></tr>
  <tr><td><span class="badge sev-medium">medium</span></td><td>需一定前置条件或组合利用，影响范围与程度有限</td></tr>
  <tr><td><span class="badge sev-low">low</span></td><td>信息泄露类、影响轻微，可作为进一步攻击的辅助条件</td></tr>
  <tr><td><span class="badge sev-info">info</span></td><td>安全观察项，不构成直接风险</td></tr>
</table>{{end}}
{{if .Profile.ShowLimitations}}{{if .Stats.StatusSummary}}<p class="status-line">状态分布：{{.Stats.StatusSummary}}</p>{{end}}
{{if .Limitations}}
<p style="font-weight:600;margin:14px 0 4px;">范围限制与授权边界：</p>
<ul>
  {{range .Limitations}}<li>{{.}}</li>{{end}}
</ul>
{{end}}{{end}}

{{if .Profile.ShowAssetOverview}}<h2>{{.SectionNo.Stats}}资产概览</h2>
{{if .AssetOverview}}
<table class="stats">
  <tr><th>指标</th><th>数量</th></tr>
  <tr><td>纳入资产</td><td>共 {{.AssetOverview.Total}} 条，涉及主机 {{.AssetOverview.Hosts}} 台、域名 {{.AssetOverview.Domains}} 个</td></tr>
</table>
{{if .AssetOverview.Services}}
<p>主要端口/服务分布：</p>
<table class="stats">
  <tr><th>协议</th><th>端口</th><th>资产数</th></tr>
  {{range .AssetOverview.Services}}<tr><td>{{.Protocol}}</td><td>{{.Port}}</td><td>{{.Count}}</td></tr>{{end}}
</table>
{{end}}
{{end}}{{else}}<p class="placeholder">{{if .AssetNote}}{{.AssetNote}}{{else}}（未同步资产数据）{{end}}</p>{{end}}

{{if .Profile.ShowOverview}}<h2>{{.SectionNo.Vulns}}漏洞总览</h2>
{{if .Overview}}
<table class="ovw">
  <thead><tr><th>#</th><th>漏洞标题</th><th>等级</th><th>状态</th><th>目标</th><th>证据</th></tr></thead>
  <tbody>
  {{range .Overview}}
  <tr>
    <td class="num">#{{.Number}}</td>
    <td><a href="#vuln-{{.Number}}">{{.Title}}</a></td>
    <td><span class="badge {{.Severity|severityClass}}">{{.Severity}}</span></td>
    <td>{{.Status}}</td>
    <td class="tgt">{{.Target}}</td>
    <td>{{.EvidenceCount}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}<p class="placeholder">（本次测试未发现漏洞，或全部为误报已排除。）</p>{{end}}{{end}}

<h2>{{.SectionNo.Details}}漏洞明细</h2>
{{range .Vulns}}
<div class="vuln" id="vuln-{{.Number}}">
  <div class="vuln-head">
    <span class="no">#{{.Number}}</span>
    <span class="title">{{.Title}}</span>
    <span class="badge {{.Severity|severityClass}}">{{.Severity}}</span>
    <span class="badge sev-info">{{.Status}}</span>
  </div>
  <div class="kv"><b>类型:</b> {{.Type}} &nbsp; <b>目标:</b> {{.Target}} &nbsp; <b>发现时间:</b> {{.CreatedAt}}</div>
  {{if .Description}}<div class="field"><div class="fname">漏洞描述</div><div class="fbody">{{.Description}}</div></div>{{end}}
  {{if .Preconditions}}<div class="field"><div class="fname">前置条件</div><div class="fbody">{{.Preconditions}}</div></div>{{end}}
  {{if .ReproductionSteps}}<div class="field"><div class="fname">复现步骤</div><div class="fbody">{{.ReproductionSteps}}</div></div>{{end}}
  {{if $.Profile.ShowEvidence}}{{if .EvidencePacket}}<div class="field"><div class="fname">POC / 证据（报文）</div>
    <div class="evd-card"><div class="evd-head"><span class="t">📦 {{.EvidencePacket.Title}}</span></div>{{template "pktPre" .EvidencePacket}}</div>
  </div>{{else if .Evidence}}<div class="field"><div class="fname">POC / 证据</div><div class="fbody">{{.Evidence}}</div></div>{{end}}
  {{if .PoCScript}}<div class="field"><div class="fname">一键验证脚本</div><pre class="pkt">{{.PoCScript}}</pre></div>{{end}}{{end}}
  {{if .Impact}}<div class="field"><div class="fname">影响</div><div class="fbody">{{.Impact}}</div></div>{{end}}
  {{if .Recommendation}}<div class="field"><div class="fname">修复建议</div><div class="fbody">{{.Recommendation}}</div></div>{{end}}
  {{if .RetestNotes}}<div class="field"><div class="fname">复测方式</div><div class="fbody">{{.RetestNotes}}</div></div>{{end}}

  {{if $.Profile.ShowEvidence}}{{range .EvidenceGroups}}
    {{if gt (len .Items) 1}}
    <div class="field"><div class="fname">数据包对比 {{if .Title}}— {{.Title}}{{end}}（{{len .Items}} 个报文）</div>
      {{if .Wide}}
      {{range .Items}}
        <div class="evd-card">
          <div class="evd-head"><span class="t">{{if .Label}}{{.Label}}{{else}}{{.Title}}{{end}}</span><span class="meta">{{.SourceTool}} · {{.CreatedAt}} · {{.ID}}</span></div>
          {{if eq .Kind "screenshot"}}{{if .ImageSrc}}<img class="shot" src="{{.ImageSrc|safeURL}}" alt="{{.Title}}">{{end}}
          {{if .Content}}<pre class="pkt">{{.Content}}</pre>{{end}}{{else}}{{template "pktPre" .}}{{end}}
        </div>
      {{end}}
      {{else}}
      <div class="cmp">
      {{range .Items}}
        <div class="cell">
          <div class="cell-label">{{if .Label}}{{.Label}}{{else}}{{.Title}}{{end}}</div>
          {{if eq .Kind "screenshot"}}{{if .ImageSrc}}<img class="shot" src="{{.ImageSrc|safeURL}}" alt="{{.Title}}">{{end}}
          {{if .Content}}<pre class="pkt">{{.Content}}</pre>{{end}}{{else}}{{template "pktPre" .}}{{end}}
        </div>
      {{end}}
      </div>
      {{end}}
    </div>
    {{else if eq (len .Items) 1}}
      {{range .Items}}
        {{if eq .Kind "http"}}
        <div class="evd-card">
          <div class="evd-head"><span class="t">📦 {{.Title}}</span>{{if .Label}}<span class="badge sev-info">{{.Label}}</span>{{end}}<span class="meta">{{.SourceTool}} · {{.CreatedAt}} · {{.ID}}</span></div>
          {{template "pktPre" .}}
        </div>
        {{else if eq .Kind "screenshot"}}
        <div class="evd-card">
          <div class="evd-head"><span class="t">🖼 {{.Title}}</span>{{if .Label}}<span class="badge sev-info">{{.Label}}</span>{{end}}<span class="meta">{{.SourceTool}} · {{.CreatedAt}} · {{.ID}}</span></div>
          {{if .ImageSrc}}<img class="shot" src="{{.ImageSrc|safeURL}}" alt="{{.Title}}">{{end}}
          {{if .Content}}<pre class="pkt">{{.Content}}</pre>{{end}}
        </div>
        {{else}}
        <div class="evd-card">
          <div class="evd-head"><span class="t">📄 {{.Title}}</span>{{if .Label}}<span class="badge sev-info">{{.Label}}</span>{{end}}<span class="meta">{{.SourceTool}} · {{.CreatedAt}} · {{.ID}}</span></div>
          <pre class="pkt">{{.Content}}</pre>
        </div>
        {{end}}
      {{end}}
    {{end}}
  {{end}}{{end}}
</div>
{{end}}

{{if .Profile.ShowRemediation}}<h2>{{.SectionNo.Remediation}}修复优先级建议</h2>
{{if .Remediation}}
{{range .Remediation}}
<div class="rem-group">
  <div class="rem-head">{{.Priority}}</div>
  <div class="rem-hint">{{.Hint}}</div>
  <ol>
    {{range .Items}}<li><span class="badge {{.Severity|severityClass}}">{{.Severity}}</span> #{{.Number}} {{.Title}}</li>{{end}}
  </ol>
</div>
{{end}}
{{else}}<p class="placeholder">（无漏洞记录，无需安排修复。）</p>{{end}}{{end}}

{{if .Profile.ShowFacts}}<h2>{{.SectionNo.Facts}}事实与未确认线索（黑板）</h2>
<p class="status-line">已确认事实为可复核的测试结论；未确认线索（tentative）为候选发现，不构成正式漏洞，验收时需补证或证伪。</p>
{{if .Facts}}
<table class="facts">
  {{range .Facts}}<tr><td><b>{{.Key}}</b></td><td>{{.Summary}}</td><td>{{.Category}}</td><td>{{.Confidence}}</td></tr>{{end}}
</table>
{{else}}<p class="placeholder">{{if .FactsNote}}{{.FactsNote}}{{else}}（暂无已确认事实。）{{end}}</p>{{end}}
{{if .Tentative}}
<h3>未确认线索（tentative，不进漏洞结论）</h3>
<table class="facts">
  {{range .Tentative}}<tr><td><b>{{.Key}}</b></td><td>{{.Summary}}</td><td>{{.Category}}</td><td>tentative</td></tr>{{end}}
</table>
{{end}}
{{end}}

{{if .Profile.ShowToolStats}}<h2>{{.SectionNo.Tools}}工具执行统计</h2>
{{if .ToolStats}}
<table class="tools">
  <tr><th>工具</th><th>调用次数</th><th>成功</th><th>平均耗时</th></tr>
  {{range .ToolStats}}<tr><td>{{.Name}}</td><td>{{.Calls}}</td><td>{{.OKCount}}</td><td>{{.AvgMs}}ms</td></tr>{{end}}
</table>
{{else}}<p class="placeholder">（无工具执行记录。）</p>{{end}}{{end}}

{{if .Profile.ShowAttackChains}}{{if .AttackChains}}
<h2>{{.SectionNo.Chains}}攻击链</h2>
{{range .AttackChains}}
<div class="chain-path">
  <h3>{{.ConversationTitle}}</h3>
  {{range $i, $n := .Nodes}}<div class="chain-step"><span class="n">{{seq $i}}</span><span>{{.Label}}</span><span class="node-t">{{.Type}}{{if .Risk}} · risk {{.Risk}}{{end}}</span></div>{{end}}
  {{if .Edges}}<div class="chain-edges">链路关系：{{range $j, $e := .Edges}}{{if $j}}；{{end}}{{index $e 0}} → {{index $e 1}}{{end}}</div>{{end}}
</div>
{{end}}
{{end}}
{{end}}

{{if .Profile.ShowAppendix}}<h2>附录：证据索引</h2>
{{if .Appendix}}
<div class="appendix">
{{range .Appendix}}
  <div class="evd-card">
    <div class="evd-head"><span class="t">{{if eq .Kind "http"}}📦{{else}}📄{{end}} {{.Title}}{{if .Label}} · {{.Label}}{{end}}</span><span class="meta">{{.SourceTool}} · {{.CreatedAt}} · {{.ID}}</span></div>
    {{if eq .Kind "http"}}{{template "pktPre" .}}{{else if eq .Kind "screenshot"}}{{if .ImageSrc}}<img class="shot" src="{{.ImageSrc|safeURL}}" alt="{{.Title}}">{{end}}{{if .Content}}<pre class="pkt">{{.Content}}</pre>{{end}}{{else}}<pre class="pkt">{{.Content}}</pre>{{end}}
  </div>
{{end}}
</div>
{{else}}<p class="placeholder">（无未关联漏洞的项目级证据。）</p>{{end}}{{end}}

<div class="footer-note">本报告由 4zreark 自动生成 · 交付模板：{{.Profile.Name}}{{if .Delivery.Classification}} · 密级：{{.Delivery.Classification}}{{end}}{{if .Delivery.ReportNo}} · 报告编号：{{.Delivery.ReportNo}}{{end}} · 证据数据包存于平台证据库，可按证据 ID 复核</div>
</div></body></html>`
