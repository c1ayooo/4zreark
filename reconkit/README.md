# reconkit

可独立接入的信息收集（recon）能力包。它是从 4zrec 的 `internal/capability/recon`
抽取出来的**纯 Go、无 Agent、无数据库、无 UI** 版本：

- 不依赖 LLM、Agent 框架、工具协议或前端；
- 不依赖 PostgreSQL，也不依赖任何宿主的资产表结构；
- 发现结果既可以作为返回值批量拿到，也可以通过 `Sink` 边跑边落库；
- 主动阶段（爆破、端口扫描、HTTP 探测）需要调用方自行做授权校验。

适合把信息收集能力嵌进自己的扫描器、资产平台、SRC 工具链或定时任务。

---

## 目录结构

```
reconkit/
├── recon.go                    # 门面：Run / PassiveSubdomains / Brute + 类型别名
├── pipeline/                   # 四阶段流水线（已去掉 DB 依赖）
│   ├── pipeline.go
│   └── types.go                # Options / Result / Sink / Stats
├── subdomain/                  # 被动子域聚合（CT 日志、被动 DNS、国内源、工件）
├── brute/                      # 主动子域爆破（字典 + 泛解析过滤 + 限速）
├── permute/                    # 子域候选派生
├── dnsres/                     # DNS 解析池、泛解析检测、记录画像/AXFR
├── portscan/                   # TCP connect 端口扫描
├── svcid/                      # 开放端口协议识别（fingerprintx）
├── exposure/                   # 无凭据暴露面探测（Redis/ES/FTP 等）
├── fingerprint/                # HTTP 指纹：探测 + DSL 匹配 + 内置规则
│   ├── sync.go                 # 上游规则同步 / PostgreSQL 规则存储
│   └── custom.go               # 自定义规则增删
├── githubsearch/               # GitHub Code Search 泄露检索（dork 模板 + 客户端）
├── githubpoc/                  # GitHub CVE PoC 搜索 + GHSA + 仓库分诊全流程
├── triage/                     # 仓库五档分诊（纯规则，无网络依赖）
├── vulnmonitor/                # 9 个公开漏洞源轮询 + 归一化（无 DB）
│   ├── grab/                   # 微步/长亭/奇安信/OSCS/Seebug/AVD/KEV/Struts2/启明星辰
│   └── util/                   # 抓取 HTTP 客户端与 UA 池
├── score/                      # 资产优先级评分（P0-P4）
├── successsignal/              # 高产路径先验
├── spacemap/                   # FOFA/ZoomEye/Quake/Shodan/Hunter 五引擎
│   ├── icpquery/
│   ├── certquery/
│   └── asnquery/
├── collect/                    # 源级限速/重试/熔断与周期 worker（可选）
├── cdnmatch/ cdnorigin/        # CDN/WAF/云识别、源站候选
├── cloudassets/                # CNAME → 云资源提取
├── takeover/                   # 子域接管检测
├── legacyhunter/               # Wayback 遗留系统线索
├── saasdetect/                 # SaaS 域名识别（规则已嵌入）
├── directhttp/                 # 直连 Transport
└── examples/basic/             # 可运行示例
```

未包含（与宿主耦合太深或不属于 recon 能力）：

- `enrich`：依赖 4zrec 的资产图和录制代理；
- `datasource`：企业数据源密钥库；
- `vulnintel` 的下游分析/生成部分（analyzer、fpgen、localize、pocgen、tplgen）：
  源监控、GitHub PoC 与 `triage` 已拆出，LLM/模板生成未包含；
- `platform/server/*`、`orchestration/agent`、`web/`：工具壳、Agent 与前端。

---

## 安装/接入

### 方式一：作为独立模块引用

仓库发布后：

```bash
go get github.com/c1ayooo/reconkit
```

本地开发时，在你的 `go.mod` 里加：

```go
require github.com/c1ayooo/reconkit v0.0.0

replace github.com/c1ayooo/reconkit => ../reconkit
```

### 方式二：直接复制目录

把整个 `reconkit/` 复制到你的项目里，修改 `go.mod` 的 `module` 路径，然后批量替换
import 前缀即可。包之间只通过相对模块路径互相引用，没有其他宿主依赖。

---

## 快速开始

### 1. 完整四阶段流水线

```go
package main

import (
	"context"
	"log"
	"time"

	recon "github.com/c1ayooo/reconkit"
	"github.com/c1ayooo/reconkit/fingerprint"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	res, err := recon.Run(ctx, recon.Options{
		Domains:          []string{"example.com"},
		EnableSubdomain:  true,  // 被动枚举
		EnablePermute:    true,  // 候选派生
		EnableBrute:      false, // 主动 DNS，按需开
		EnableDNS:        true,
		EnablePortscan:   true,  // 主动
		EnableHTTP:       true,  // 主动
		PortsSet:         "top100",
		QPS:              300,
		Rate:             500,
		FingerprintRules: fingerprint.DefaultRules(), // 不传则 technologies 为空
	}, func(stage string, st recon.Stats) {
		log.Printf("[%s] candidates=%d live=%d ports=%d http=%d",
			stage, st.Candidates, st.Live, st.OpenPorts, st.HTTPAlive)
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("subdomains=%d ips=%d services=%d",
		len(res.Subdomains), len(res.IPs), len(res.Services))
}
```

每个阶段结束后 `Progress` 会被调用一次，阶段名为
`subdomain` / `dns` / `portscan` / `http`。

### 2. 只做被动子域（不向目标发包）

```go
import "github.com/c1ayooo/reconkit/subdomain"

res, err := subdomain.Enumerate(ctx, "example.com", subdomain.Options{
	EnableCT:           true, // crt.sh / CertSpotter
	EnablePassiveDNS:   true, // HackerTarget / OTX / RapidDNS
	EnableCNPassiveDNS: true, // 千讯 / ip138 / chinaz
	Timeout:            60 * time.Second,
	Limit:              5000,
})
```

单源失败只进入 `res.Errors`，不会中断其他源。

### 3. 主动爆破

```go
import "github.com/c1ayooo/reconkit/brute"

hits, stats, err := brute.Brute(ctx, "example.com", brute.Options{
	QPS:       300,
	Resolvers: []string{"223.5.5.5:53", "119.29.29.29:53"},
})
```

内置约 400 词字典；泛解析会自动基线过滤；`QPS` 是每秒 DNS 查询上限。

### 4. 端口扫描 + 服务识别

```go
import (
	"github.com/c1ayooo/reconkit/portscan"
	"github.com/c1ayooo/reconkit/svcid"
)

results := portscan.Scan(ctx, []string{"203.0.113.10"}, portscan.Options{
	Ports:      portscan.ResolvePorts("top100", ""),
	RatePerSec: 500,
	Timeout:    2 * time.Second,
})
for _, r := range results {
	svcs := svcid.Scan(ctx, r.IP, []int{r.Port}, svcid.Options{Timeout: 3 * time.Second})
	_ = svcs
}
```

### 5. HTTP 指纹

```go
import "github.com/c1ayooo/reconkit/fingerprint"

obs, err := fingerprint.ProbeHTTPObservation(ctx, "https://example.com", nil)
if err == nil {
	matches := fingerprint.MatchObservation(fingerprint.DefaultRules(), obs)
	for _, m := range matches {
		fmt.Println(m.Product)
	}
}
```

`ProbeHTTPObservation` 不跟随跳转，会顺带提取标题、favicon mmh3、ICP 备案号和页面链接。

### 6. 空间测绘五引擎

```go
import "github.com/c1ayooo/reconkit/spacemap"

c := spacemap.NewClient()
c.KeyResolver = func(provider string) string {
	return os.Getenv(spacemap.EnvKeyNames[provider])
}

results, rawRows, total, err := c.SearchEngineAssets(
	ctx, "fofa", `domain="example.com"`, 100, 1,
)
```

支持的 provider：`fofa`、`zoomeye`、`quake`、`shodan`、`hunter`。
`env` 变量名见 `spacemap.EnvKeyNames`；也可以用 `BaseURLResolver` 指向自建反代。

### 7. GitHub 代码泄露检索（dork）

`githubsearch` 提供内置 dork 模板、GitHub Code Search 客户端、10 次/分钟配额排队
与 1000 条截断提示：

```go
import "github.com/c1ayooo/reconkit/githubsearch"

// 从 GITHUB_TOKEN 读取；也可以 NewClient(tokenFn) 自己控制 token 来源。
client := githubsearch.NewClientFromEnv()

// 列出内置模板
for _, t := range githubsearch.Templates() {
	fmt.Println(t.ID, t.Category, t.Title)
}

// 用模板 + org/domain 构造查询
t, _ := githubsearch.TemplateByID("org-aws")
query := githubsearch.BuildQuery(t, "target-org", "")

res, err := client.Search(ctx, query, 1, 30)
for _, hit := range res.Items {
	fmt.Println(hit.Repo, hit.Path, hit.Fragments)
}
```

模板分类包括：云厂商密钥、文件名定向、服务指纹、私钥块、org/domain 定向。
`Search` 只报告“疑似泄露 + 证据位置”，**不验证密钥有效性**；验证他人凭据属于
独立的高风险动作，应在你的授权流程里单独处理。

### 8. GitHub PoC 搜索（CVE → 仓库 → 分诊）

`githubpoc` 把 4zrec 的 GitHub PoC 富化流程完整拆了出来：

1. `SearchRepos`：按 CVE 搜 GitHub 仓库（stars 倒序，默认 5 条）；
2. `FetchAdvisory`：拉 GHSA 公告，补 CVSS/CWE/受影响包；
3. `triage.Triage`：对每个仓库做五档分诊（MALICIOUS / ACT / WATCH / NOISE / LAB_ONLY）；
4. `Enrich`：过滤恶意、噪音、实验室仓库，按 stars 排序返回可用 PoC。

```go
import (
	"github.com/c1ayooo/reconkit/githubpoc"
	"github.com/c1ayooo/reconkit/triage"
)

client := githubpoc.NewClientFromEnv() // GITHUB_TOKEN
inKEV := true
res, err := client.Enrich(ctx, triage.CVEMeta{
	CVEID:       "CVE-2024-0001",
	Description: "remote code execution in Foo",
	CVSSScore:   9.8,
	CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	CWE:         []int{78},
	InKEV:       &inKEV, // 可选：EPSS/KEV 由调用方提供
})
if err != nil {
	return err
}
for _, poc := range res.POCs {
	fmt.Println(poc.FullName, poc.Stars, poc.Verdict, poc.TriageScore)
}
```

`triage` 是纯规则实现，无网络、无第三方依赖。分诊结论：

| 结论 | 含义 | 处理 |
|---|---|---|
| `MALICIOUS` | 疑似木马/钓鱼仓库 | 隔离，禁止克隆/执行 |
| `ACT` | 可信利用代码 | 优先使用 |
| `WATCH` | 高危但暂无可信 PoC | 进监控队列，不丢弃 |
| `NOISE` | 扫描器/情报转载/空壳 | 丢弃仓库 |
| `LAB_ONLY` | 漏洞本身不适合实战 | 丢弃该漏洞 |

如果调用方没有 EPSS/KEV/NVD 数据，只传 `CVEID`/`Description`/`CVSS`/`CWE`
也能跑；缺失的信号不会参与打分。`githubpoc` **不负责**抓取 EPSS/KEV/NVD。

### 9. 多漏洞源监控（微步 / 长亭等 9 源）

`vulnmonitor` 是 4zrec `vulnintel` 抓取层的无 DB 版本，内置 9 个公开源：

| provider | 来源 |
|---|---|
| `aliyun-avd` | 阿里云漏洞库 |
| `chaitin` | 长亭漏洞库 |
| `qianxin-ti` | 奇安信 TI |
| `oscs` | OSCS |
| `threatbook` | 微步在线研究响应中心 |
| `seebug` | Seebug |
| `KEV` | CISA KEV |
| `Struts2` | Apache Struts2 公告 |
| `venustech` | 启明星辰 |

```go
import (
	"time"

	"github.com/c1ayooo/reconkit/vulnmonitor"
	"github.com/c1ayooo/reconkit/vulnmonitor/grab"
)

store := vulnmonitor.NewMemoryStore() // 或实现自己的 Store

m := vulnmonitor.New(store,
	vulnmonitor.WithInterval(30*time.Minute),
	vulnmonitor.WithPageLimit(3),
	vulnmonitor.WithMinSeverity(grab.High), // 默认 Medium
)

// 单次轮询
res := m.Poll(ctx)
fmt.Printf("new=%d updated=%d failed=%d\n", res.New, res.Updated, res.Failed)

// 或常驻轮询（首次立即跑，之后按间隔；Refresh 可插队）
m.Start(ctx)
defer m.Refresh()

for _, item := range store.Items() {
	fmt.Println(item.Source, item.Severity, item.Title, item.From)
}
```

落库只需要实现一个方法：

```go
type Store interface {
	UpsertIntel(ctx context.Context, intel vulnmonitor.Intel) (created bool, err error)
}
```

`Intel` 字段：`UniqueKey`、`Title`、`Description`、`Severity`、`CVE`、
`Disclosure`、`Solutions`、`Source`、`SourceName`、`SourceURL`、`From`、
`Tags`、`References`。建议按 `UniqueKey` 做幂等 upsert，并返回是否新增，
用于 `New`/`Updated` 统计与高危通知。

行为说明：

- 每个源并发抓取，单源失败只计入 `Failed`/`Errors`，不影响其他源；
- 默认只保留 Medium 及以上（与原 `ingest` 的 `intakeAllowed` 一致）；
- `WithValuableFilter(true)` 会额外调用各源的 `IsValuable`（原平台未启用）；
- `PollResult.Items` 始终包含本轮通过过滤的记录，即使不接 Store；
- `WithNotifyHook` 可在新增高危/严重时触发通知。

`vulnintel` 的 LLM 分析、中文翻译、nuclei 模板生成、指纹草稿生成属于下游
管线，未包含在这个监控包里。

---

## 指纹规则库同步与自定义规则

`fingerprint` 除了内置快照/种子，还保留了 PostgreSQL 规则库能力：

```go
import (
	"database/sql"
	"time"

	_ "github.com/lib/pq" // 或你的 PostgreSQL driver
	"github.com/c1ayooo/reconkit/fingerprint"
)

db, _ := sql.Open("postgres", dsn)
store, err := fingerprint.NewStore(db) // 自动建 fingerprint_rules/fingerprint_sources
if err != nil {
	return err
}

// 手动触发一次上游同步（wappalyzergo / webanalyze / dddd）
updater := fingerprint.NewUpdater(store, func() string {
	return os.Getenv("GITHUB_TOKEN") // 可选，用于提高 GitHub 配额
}, func() string { return "" })     // 可选出站代理
outcomes := updater.SyncAll(ctx)

// 取当前启用的规则注入 pipeline
rules, err := store.EnabledRules(ctx)
opts.FingerprintRules = rules

// 自定义规则
id, err := store.SaveCustomRule(ctx, "MyProduct", "custom", `body="MyProduct" && status==200`)
_ = id
fingerprint.CacheInvalidate() // 规则变更后让匹配缓存失效
```

说明：

- `NewStore` 的 DDL 与占位符是 **PostgreSQL** 方言（`$1`、`TIMESTAMPTZ`、`ON CONFLICT`）。
  目标项目用 MySQL/SQLite 时需要改写 `sync.go` 里的建表与查询语句。
- `NewUpdater.Start()` 会按 24h 周期在后台同步；库为空或上游不可达时会用内置快照兜底。
- 不想引入数据库时，直接用 `fingerprint.DefaultRules()` 即可，内置快照和种子已 `go:embed`。

---

## 结果落库：实现 Sink

`pipeline.Options.Sink` 是可选的。实现下面三个方法即可边跑边落库：

```go
type Sink interface {
	SaveSubdomain(ctx context.Context, f SubdomainFinding) (created bool, err error)
	SaveIP(ctx context.Context, f IPFinding) (created bool, err error)
	SaveHTTPService(ctx context.Context, f HTTPServiceFinding) (created bool, err error)
}
```

- `created` 表示这条记录是否是**新增**；`Stats.NewAssets` 会按它累加。
  `NewAssets` 统计的是子域 + IP + 服务三类中所有 `created=true` 的记录，不只是子域。
- 实现应当幂等（按自然键 upsert），因为同一资产可能被多个源发现。
- 返回 error 不会中断流水线，只会记入 `Stats.Errors`。

快速接入可以用函数适配器：

```go
sink := recon.SinkFunc{
	Subdomain: func(ctx context.Context, f recon.SubdomainFinding) (bool, error) {
		return saveSubdomain(ctx, f) // 你的 upsert，返回是否新增
	},
	IP: func(ctx context.Context, f recon.IPFinding) (bool, error) {
		return saveIP(ctx, f)
	},
	HTTPService: func(ctx context.Context, f recon.HTTPServiceFinding) (bool, error) {
		return saveHTTPService(ctx, f)
	},
}

res, err := recon.Run(ctx, recon.Options{
	Domains:         []string{"example.com"},
	EnableSubdomain: true,
	EnableDNS:       true,
	EnablePortscan:  true,
	EnableHTTP:      true,
	Sink:            sink,
}, nil)
```

一个 PostgreSQL upsert 的形态（示意）：

```sql
INSERT INTO recon_subdomains(name, ips, cname, score, level, last_seen)
VALUES ($1, $2, $3, $4, $5, now())
ON CONFLICT (name) DO UPDATE SET
  ips = EXCLUDED.ips,
  cname = EXCLUDED.cname,
  score = EXCLUDED.score,
  level = EXCLUDED.level,
  last_seen = now()
RETURNING (xmax = 0) AS created;  -- Postgres: xmax=0 表示本次是 INSERT
```

### 建议的落库字段

| 类型 | 字段 |
|---|---|
| Subdomain | `name`、`ips`、`cname`、`score`、`level`、`first_seen`、`last_seen` |
| IP | `ip`、`open_ports`（`[{port,service}]`）、`last_seen` |
| HTTPService | `url`、`status_code`、`page_title`、`favicon_mmh3`、`technologies`、`last_seen` |

如果要做增量通知，比较 `Stats.NewAssets` 或 sink 返回的 `created` 即可。

---

## 核心类型

```go
type SubdomainFinding struct {
	Name  string
	IPs   []string
	CNAME string
	Score int      // 0-100
	Level string   // P0-P4
}

type IPFinding struct {
	IP        string
	OpenPorts []PortService
}

type HTTPServiceFinding struct {
	URL          string
	StatusCode   int
	PageTitle    string
	FaviconMMH3  string
	Technologies []string
}
```

`Stats` 包含各阶段计数：

```
Candidates, FromPassive, FromPermute, FromBrute, WildcardFiltered,
Live, Dead, NewAssets, ScanIPs, OpenPorts, HTTPProbed, HTTPAlive,
Levels (P0-P4 分布), Errors
```

---

## 限速与资源控制

| 参数 | 位置 | 默认/说明 |
|---|---|---|
| `QPS` | `pipeline.Options` / `brute.Options` | 子域爆破每秒 DNS 查询数，默认 300 |
| `Rate` | `pipeline.Options` / `portscan.Options.RatePerSec` | 端口扫描每秒新建连接数，默认 500 |
| `Resolvers` | `pipeline.Options` / `dnsres.NewPool` | 自定义 DNS 解析器 |
| `Timeout` | `subdomain.Options`、`portscan.Options`、`svcid.Options` | 各阶段超时 |
| `PortsSet` | `pipeline.Options` | `top100` / `web` / `22,80,3306` / `8000-8100` |
| `Limit` | `subdomain.Options` | 单源结果上限 |

`collect` 包提供源级预算与调度：

- `collect.PolicyFor(source)`：每源并发/最小间隔；
- `collect.Scheduler.RunUnits`：轮转调度 + 瞬态重试 + 同源熔断；
- `collect.RunScheduleWorker`：30s tick 的周期任务骨架。

如果目标项目已经有 cron/队列，可以只用 `Scheduler`，不用 worker。

---

## 安全与授权

这个包不会替你做授权判断。**主动阶段必须由调用方先校验授权范围**：

- 被动：`subdomain`、`spacemap` 查询第三方数据源，不直接向目标发包；
- 主动：`brute`、`portscan`、`svcid`、`pipeline` 的 portscan/HTTP 阶段、
  `exposure`、`legacyhunter` 的当前探测、`webrecon` 类能力。

建议在调用 `Run` 前做一次白名单校验：

```go
for _, d := range domains {
	if !scope.Allowed(d) {
		return fmt.Errorf("target %s is not authorized", d)
	}
}
```

同时：

- 默认不要把 `EnableBrute` / `EnablePortscan` / `EnableHTTP` 全部打开；
- 生产环境保留 `collect.ClassifyError` 的退避/熔断，避免被上游封禁；
- 不要对公网随机目标做大规模扫描。

---

## 与 4zrec 原实现的差异

| 能力 | 原 4zrec | reconkit |
|---|---|---|
| 驱动方式 | Agent 调工具 | 代码直接调用 |
| 持久化 | `AssetStore` + PostgreSQL | 返回值 + 可选 `Sink` |
| 运行记录 | `recon_runs` 表 | 调用方自行记录（`Stats`/`Progress`） |
| 授权 | 项目范围 + 人工审批 | 调用方自行校验 |
| 指纹规则 | DB 规则表 + 24h 同步 | 内置快照/种子 + 可选 PostgreSQL 规则库（`sync.go`/`custom.go`） |
| GitHub 泄露检索 | Agent 工具 `github_dork` | `githubsearch` 包（模板 + Code Search 客户端） |
| GitHub PoC 搜索 | `vulnintel/enrich` 内嵌（DB 写回） | `githubpoc` + `triage`（无 DB，返回结果） |
| 漏洞源监控 | `vulnintel.Manager`（DB + settings） | `vulnmonitor`（9 源 + Store 接口） |
| EPSS/KEV/NVD 富化 | `vulnintel` 内置 | 不含；调用方通过 `triage.CVEMeta` 传入 |
| UI/HTTP | 内置 | 无 |
| `enrich` 异步补全 | 有 | 不含 |
| 企业数据源密钥库 | 有 | 不含 |

`pipeline` 的评分逻辑保持原样：阶段 2 只按网络面计算 P0-P4，端口/HTTP
维度需要调用方在后续阶段用 `score.Compute` 重算。

---

## 扩展

### 增加一个被动子域源

在 `subdomain/` 下仿照 `extra_sources.go` 写查询函数，然后在
`subdomain.Enumerate` 里注册一个 goroutine。约定：

- 返回 `[]Hit`；
- 单源错误返回 error，由 `Enumerate` 收进 `Result.Errors`；
- 结果统一经过 `normalizeName` 清洗。

### 增加指纹规则

```go
import "github.com/c1ayooo/reconkit/fingerprint"

expr, err := fingerprint.ParseExpression(`body="MyProduct" && status==200`)
rules := append(fingerprint.DefaultRules(), fingerprint.CompiledRule{
	ID: "custom-1", Name: "MyProduct", Expression: `body="MyProduct" && status==200`, Expr: expr,
})
```

把 `rules` 传给 `pipeline.Options.FingerprintRules` 即可。

### 自定义 DNS / HTTP 出口

- DNS：`pipeline.Options.Resolvers` 或 `dnsres.NewPool`；
- HTTP：`pipeline.Options.HTTPClient`（可注入代理、超时、TLS 配置）。

---

## 构建与验证

```bash
cd reconkit
go mod tidy
go build ./...
go test ./...
```

当前模块只包含能力代码与内嵌资源，不包含 4zrec 的 server/agent/UI。

---

## 已知限制

- **没有内置增量状态**：`NewAssets` 依赖 Sink 的 `created` 返回值；不接 Sink 时为 0。
- **`pipeline` 不返回原始引擎行**：空间测绘的原始行需要通过 `spacemap` 单独调用。
- **`subdomain.CollectFromArtifacts` 未接入 `Enumerate`**：需要 robots/sitemap/证书 SAN
  提取时手动调用。
- **泛解析过滤会误杀**：与泛解析同 IP 的真实子域会被当作噪音剔除，这是刻意取舍。
- **指纹规则库是 PostgreSQL 方言**：`fingerprint/sync.go` 的建表与查询使用 `$1`、
  `TIMESTAMPTZ`、`ON CONFLICT`；MySQL/SQLite 需要自行改写。
- **GitHub 检索需要 Token**：`githubsearch` 依赖 GitHub Code Search（已验证用户
  10 次/分钟）；`githubpoc` 依赖 Repository Search（30 次/分钟，默认 2.2s 间隔）。
  无 token 时两者都会跳过而不是报错。
- **GitHub PoC 流程不抓 EPSS/KEV/NVD**：需要这些信号时，调用方先取好并通过
  `triage.CVEMeta` 的 `InKEV`/`EPSS`/`EPSSPercentile` 传入。
- **GHSA 公告拉取失败会静默降级**：`Enrich` 只在仓库搜索失败时返回 error；
  公告失败只影响 CVSS/CWE/affected 的补全。
- **漏洞源是公开网页/接口**：9 个抓取器依赖上游页面/API 结构，改版或 WAF 挑战
  会导致单源失败；`vulnmonitor` 只计数并继续跑其他源，不会自动修复解析。
- **监控包里没有分析流水线**：LLM 中文分析、nuclei 模板生成、指纹草稿生成
  未包含；需要时在 `Store` 落库后自行接下游。
- **`enrich` 未包含**：域名→IP→HTTP 的异步补全请按目标项目的资产模型自行实现。
