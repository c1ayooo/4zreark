# recon 能力包

`internal/recon` 是从 4zrec 的 `internal/capability/recon` 抽取、并入本仓的纯 Go 侦察能力库：不依赖 Agent、不依赖数据库、不依赖 UI，也不依赖本仓的资产表结构。

它只负责「产出」和「判定」，写库由调用方通过接口注入。

## 为什么在 `internal/` 下

它是实现细节，不是对外 API。放在 `internal/` 下由 Go 编译器强制约束——仓外代码无法 import，避免被误当作稳定接口分发。

## 目录

```text
internal/recon/
├── recon.go            门面：Run / PassiveSubdomains / Brute + 类型别名
├── pipeline/           四阶段流水线（被动/派生/爆破 → DNS → 端口+服务 → HTTP 指纹）
├── subdomain/          被动子域聚合（CT 日志、被动 DNS、国内源、robots/sitemap/CSP 工件）
├── brute/              主动子域爆破（内置词表 + 泛解析基线 + 限速）
├── permute/            子域候选派生
├── dnsres/             解析池、泛解析检测、记录画像 / AXFR
├── portscan/           TCP connect 端口扫描（非 SYN）
├── svcid/              协议识别（fingerprintx 真实握手）
├── exposure/           无凭据暴露面探测（29 协议）
├── fingerprint/        HTTP 指纹：探测 + 表达式引擎 + 上游规则同步
├── githubsearch/       GitHub 代码泄露检索（dork 模板）
├── githubpoc/          GitHub CVE PoC 搜索 + GHSA + 仓库分诊
├── triage/             仓库五档分诊（纯规则，无网络）
├── vulnmonitor/        9 个公开漏洞源轮询 + 归一化
├── score/              资产优先级评分（P0-P4）
├── successsignal/      高产路径先验
├── spacemap/           FOFA / ZoomEye / Quake / Shodan / Hunter 五引擎
├── collect/            源级限速 / 重试 / 熔断 / 周期 worker
├── cdnmatch/            CDN / WAF / 云识别
├── cdnorigin/          源站候选发现
├── cloudassets/        CNAME → 云资源提取
├── takeover/           子域接管判定（纯函数）
├── legacyhunter/       Wayback 遗留系统线索
├── saasdetect/         SaaS 域名识别
└── directhttp/         直连 Transport
```

## 与宿主（本仓）的接缝

三个接口是全部耦合点，实现都在本仓的 `service/` 与 `repo/` 层：

| 接口 | 方法 | 宿主实现落点 |
|---|---|---|
| `pipeline.Sink` | `SaveSubdomain` / `SaveIP` / `SaveHTTPService` | 资产落库，`created` 表示是否新增 |
| `vulnmonitor.Store` | `UpsertIntel` | `vuln_intel` 表，按 `unique_key` 幂等 |
| `fingerprint` 的调用面 | `MatchObservation(rules, obs) []Match` | 指纹命中判定与持久化 |

不实现这些接口时，能力仍然可用——结果从返回值里取，只是不落库。

## 授权边界

主动阶段（爆破、端口扫描、HTTP 探测、暴露面探测）会向目标发包，**调用方负责授权校验**。本包不做 scope 判定，因为它不知道宿主的授权模型。

`takeover` 明确只做检测、不做自动接管（接管属红线，命中只产出待复核发现）。

## 已知约束

- **fingerprint 的规则同步自带建表语句**，与 `schema_init.sql` 里的 `fingerprint_rules` 列形态不兼容。宿主迁移前不要调用它的 `NewStore`，否则会静默保留旧表、后续写入因缺列失败。
- **`vulnmonitor` 输出的 severity 是中文**（`低危/中危/高危/严重`），落 `vulnerabilities` 前必须映射到 `critical/high/medium/low/info`。
- **favicon 哈希用 MIME base64（76 列折行）**，与 dddd / FOFA / 鹰图口径一致；本仓旧的 `scanner/fingerprint` 用单行 StdEncoding，两者哈希空间不同。
- **工具链要求 Go 1.26.3**，低于此版本在 `GOTOOLCHAIN=local` 下会拒编。
