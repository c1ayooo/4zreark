package report

// assetTemplate 是信息收集 / 资产测绘报告的自包含 HTML 模板。
//   - 内嵌 CSS、@media print 分页；浏览器打开 Ctrl+P 即可存 PDF
//   - 章节按 Profile 启用集合连续编号（委托 Profiles 的 SectionNumbers）
//   - 清单表格按 MaxRows 截断，截断说明写在表格下方，不静默丢行
const assetTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>{{.Title}}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: "Noto Sans CJK SC","Microsoft YaHei","PingFang SC",sans-serif; color:#1f2328; margin:0; background:#fff; line-height:1.6; font-size:13.5px; }
  .page { max-width: 1040px; margin: 0 auto; padding: 48px 40px; }
  h1 { font-size: 26px; text-align:center; margin:40px 0 8px; }
  h2 { font-size:19px; border-left:4px solid #1d4ed8; padding-left:10px; margin:34px 0 12px; page-break-after:avoid; }
  h3 { font-size:15px; margin:20px 0 8px; page-break-after:avoid; }
  .cover { text-align:center; padding:110px 0 60px; page-break-after:always; }
  .cover .meta { margin-top:44px; display:inline-block; text-align:left; }
  .cover .meta td { padding:6px 18px; border-bottom:1px solid #e5e7eb; }
  .cover .meta td:first-child { color:#6b7280; white-space:nowrap; }
  .cover .desc { max-width:720px; margin:18px auto 0; color:#4b5563; font-size:13px; text-align:left; white-space:pre-wrap; }
  table { width:100%; border-collapse:collapse; margin:8px 0 14px; font-size:12.5px; }
  th, td { border:1px solid #d1d5db; padding:5px 8px; text-align:left; vertical-align:top; }
  th { background:#f3f4f6; }
  tr { page-break-inside:avoid; }
  td.mono, th.mono { font-family:"JetBrains Mono",Consolas,monospace; word-break:break-all; }
  td.num { text-align:right; white-space:nowrap; }
  td.tgt { word-break:break-all; max-width:260px; }
  .kpi { display:grid; grid-template-columns:repeat(4, 1fr); gap:10px; margin:14px 0 18px; }
  .kpi .card { border:1px solid #d1d5db; border-radius:8px; padding:10px 14px; background:#fafafa; }
  .kpi .card .v { font-size:22px; font-weight:700; color:#111827; }
  .kpi .card .k { color:#6b7280; font-size:12px; margin-top:2px; }
  .badge { display:inline-block; padding:1px 9px; border-radius:10px; color:#fff; font-size:11.5px; font-weight:600; }
  .st-reachable { background:#15803d; } .st-lost { background:#6b7280; } .st-pending { background:#d97706; }
  .bars { margin:8px 0 14px; }
  .bar-row { display:flex; align-items:center; gap:10px; margin:3px 0; }
  .bar-row .lbl { min-width:110px; }
  .bar-row .track { flex:1; background:#f3f4f6; border-radius:4px; height:16px; overflow:hidden; }
  .bar-row .fill { height:100%; min-width:2px; border-radius:4px; background:#1d4ed8; }
  .bar-row .num { min-width:44px; text-align:right; color:#4b5563; }
  .note { background:#f9fafb; border-left:3px solid #1d4ed8; padding:9px 13px; margin:10px 0 14px; }
  .warn { background:#fffbeb; border-left:3px solid #d97706; padding:9px 13px; margin:10px 0 14px; }
  .placeholder { color:#9ca3af; }
  .footer-note { color:#9ca3af; font-size:12px; text-align:center; margin-top:36px; border-top:1px solid #e5e7eb; padding-top:10px; }
  @media print { .page { padding:0; max-width:none; } }
</style>
</head>
<body class="profile-{{.Profile.ID}}"><div class="page">

<div class="cover">
  <h1>{{.ProjectName}} {{.Profile.CoverSubject}}</h1>
  <div class="meta"><table>
    <tr><td>报告名称</td><td>{{.Title}}</td></tr>
    <tr><td>项目</td><td>{{.ProjectName}}</td></tr>
    <tr><td>项目编码</td><td>{{.ProjectCode}}</td></tr>
    {{if .Region}}<tr><td>区域</td><td>{{.Region}}</td></tr>{{end}}
    {{if .Delivery.ClientName}}<tr><td>客户名称</td><td>{{.Delivery.ClientName}}</td></tr>{{end}}
    {{if .Delivery.ReportNo}}<tr><td>报告编号</td><td>{{.Delivery.ReportNo}}</td></tr>{{end}}
    {{if .Delivery.Classification}}<tr><td>密级</td><td>{{.Delivery.Classification}}</td></tr>{{end}}
    {{if .Delivery.Tester}}<tr><td>测试人员</td><td>{{.Delivery.Tester}}</td></tr>{{end}}
    {{if .Delivery.Contact}}<tr><td>联系方式</td><td>{{.Delivery.Contact}}</td></tr>{{end}}
    <tr><td>交付模板</td><td>{{.Profile.Name}}</td></tr>
    <tr><td>测试范围</td><td>{{.Range}}</td></tr>
    <tr><td>域名 / 站点</td><td>{{.Summary.Domains}} 个域名 · {{.Summary.Sites}} 个站点</td></tr>
    <tr><td>生成时间</td><td>{{.GeneratedAt}}</td></tr>
    <tr><td>生成引擎</td><td>4zreark</td></tr>
  </table></div>
  {{if .Description}}<div class="desc">{{.Description}}</div>{{end}}
</div>

<h2>{{.SectionNo.Summary}}执行摘要</h2>
<div class="kpi">
  <div class="card"><div class="v">{{.Summary.Domains}}</div><div class="k">域名（根域种子 {{.Summary.SeedCount}}）</div></div>
  <div class="card"><div class="v">{{.Summary.Sites}}</div><div class="k">站点</div></div>
  <div class="card"><div class="v">{{.Summary.Endpoints}}</div><div class="k">入口（协议+端口）</div></div>
  <div class="card"><div class="v">{{.Summary.Reachable}}</div><div class="k">可达站点</div></div>
</div>
<div class="note">{{.Summary.CollectState}}。首见 {{.Summary.FirstSeen}}，最近观测 {{.Summary.LastSeen}}；近 7 天新增 {{.Summary.NewWithin7d}} 个站点。</div>
{{if .Notes}}<ul>
  {{range .Notes}}<li>{{.}}</li>{{end}}
</ul>{{end}}

<h2>{{.SectionNo.Scope}}测试范围与采集口径</h2>
<table>
  <tr><th style="width:180px;">项目</th><th>说明</th></tr>
  <tr><td>测试范围</td><td>{{.Range}}</td></tr>
  <tr><td>采集状态</td><td>{{.Summary.CollectState}}</td></tr>
  <tr><td>原始记录</td><td>{{.Summary.Records}} 条（同一目标多次采集只累加证据，站点不重复）</td></tr>
  <tr><td>首见时间</td><td>{{.Summary.FirstSeen}}</td></tr>
  <tr><td>最近观测</td><td>{{.Summary.LastSeen}}</td></tr>
</table>
{{if .Profile.ShowLimitations}}{{if .Limitations}}
<h3>范围限制与授权边界</h3>
<ul>
  {{range .Limitations}}<li>{{.}}</li>{{end}}
</ul>
{{end}}{{end}}

<h2>{{.SectionNo.Stats}}资产统计</h2>
{{if .Stats.ByState}}
<h3>状态分布</h3>
<div class="bars">
  {{range .Stats.ByState}}<div class="bar-row">
    <span class="lbl"><span class="badge {{stateClass .Name}}">{{stateLabel .Name}}</span></span>
    <span class="track"><span class="fill" style="width:{{.Pct}}%"></span></span>
    <span class="num">{{.Count}}</span>
  </div>{{end}}
</div>
{{end}}
{{if .Stats.ByProto}}
<h3>协议分布</h3>
<table>
  <tr><th>协议</th><th>站点数</th></tr>
  {{range .Stats.ByProto}}<tr><td>{{.Name}}</td><td class="num">{{.Count}}</td></tr>{{end}}
</table>
{{end}}
{{if .Stats.ByDiscovery}}
<h3>发现来源</h3>
<table>
  <tr><th>来源</th><th>站点数</th></tr>
  {{range .Stats.ByDiscovery}}<tr><td>{{.Name}}</td><td class="num">{{.Count}}</td></tr>{{end}}
</table>
{{end}}
{{if .PortSummary}}
<h3>端口 / 服务分布（TOP {{len .PortSummary}}）</h3>
<table>
  <tr><th>协议</th><th>端口</th><th>站点数</th></tr>
  {{range .PortSummary}}<tr><td>{{.Scheme}}</td><td class="mono">{{.Port}}</td><td class="num">{{.Count}}</td></tr>{{end}}
</table>
{{end}}
{{if .TechSummary}}
<h3>指纹 / 技术栈 TOP {{len .TechSummary}}</h3>
<table>
  <tr><th>技术</th><th>站点数</th></tr>
  {{range .TechSummary}}<tr><td>{{.Name}}</td><td class="num">{{.Count}}</td></tr>{{end}}
</table>
{{end}}
{{if and (not .Stats.ByState) (not .Stats.ByProto) (not .Stats.ByDiscovery) (not .PortSummary) (not .TechSummary)}}
<p class="placeholder">（该项目暂无已归并的站点数据。）</p>
{{end}}

<h2>{{.SectionNo.Domains}}域名清单</h2>
{{if .Domains}}
<table>
  <thead><tr><th>域名</th><th>根域种子</th><th>站点数</th><th>可达</th><th>端口</th><th>最近观测</th></tr></thead>
  <tbody>
  {{range .Domains}}
  <tr>
    <td class="mono">{{.Host}}</td>
    <td>{{if .IsSeedBase}}是{{end}}</td>
    <td class="num">{{.SiteCount}}</td>
    <td class="num">{{.Reachable}}</td>
    <td class="mono">{{.Ports}}</td>
    <td>{{.LastSeen}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}<p class="placeholder">（该项目暂无域名资产。）</p>{{end}}

<h2>{{.SectionNo.Sites}}站点清单</h2>
{{if .Sites}}
<table>
  <thead><tr><th>主机</th><th>IP</th><th>入口</th><th>状态</th><th>标题</th><th>指纹</th><th>来源</th><th>首见</th></tr></thead>
  <tbody>
  {{range .Sites}}
  <tr>
    <td class="mono">{{.Host}}</td>
    <td class="mono">{{.IP}}</td>
    <td class="mono">{{if .Scheme}}{{.Scheme}}{{end}}{{if .Port}}:{{.Port}}{{end}}</td>
    <td><span class="badge {{stateClass .State}}">{{stateLabel .State}}</span></td>
    <td class="tgt">{{.Title}}</td>
    <td>{{.Tech}}</td>
    <td>{{.Discovery}}</td>
    <td>{{.FirstSeen}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}<p class="placeholder">（该项目暂无站点资产。）</p>{{end}}
{{if .Truncated}}<div class="warn">{{.Truncated}}</div>{{end}}
{{if .HighRisk}}
<h3>高风险站点（按评分）</h3>
<table>
  <tr><th>主机</th><th>入口</th><th>评分</th><th>优先级</th><th>标题</th></tr>
  {{range .HighRisk}}<tr><td class="mono">{{.Host}}</td><td class="mono">{{if .Scheme}}{{.Scheme}}{{end}}{{if .Port}}:{{.Port}}{{end}}</td><td class="num">{{.RiskScore}}</td><td>{{.Priority}}</td><td class="tgt">{{.Title}}</td></tr>{{end}}
</table>
{{end}}

<div class="footer-note">本报告由 4zreark 自动生成 · 交付模板：{{.Profile.Name}}{{if .Delivery.Classification}} · 密级：{{.Delivery.Classification}}{{end}}{{if .Delivery.ReportNo}} · 报告编号：{{.Delivery.ReportNo}}{{end}} · 资产数据来自平台台账，可按站点与原始记录回溯</div>
</div></body></html>`
