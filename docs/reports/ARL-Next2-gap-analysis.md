# ARL-Next2 vs 4zreark 功能差距分析与改造记录

> 分析对象：`ARL-Next2-main.zip`（解压于 `reports/arl-next2-analysis/ARL-Next2-main`）——基于 ARL 灯塔重构的资产测绘平台（Python 3.13 / Flask-RESTX + Celery + MongoDB + Vue 3）。
> 本项目：4zreark（Go + Gin + PostgreSQL/River + React 18/AntD 6）。
> 分析日期：2026-11-10。本轮改造已实施项见 §3，遗留规划项见 §4。

---

## 1. ARL-Next2 功能架构概览

后端按「任务调度 / 采集流水线 / 资产库 / 企业测绘 / 威胁情报 / 系统域」六大域组织：

- **任务系统**：Celery 四队列（heavy/light/osint/github）轻重分离；16 种 CeleryAction 命令路由；域名任务 17 阶段流水线（massdns 子域爆破 → 第三方 API → alt_dns → 递归爆破 → nmap → 证书 SAN 提子域 → 站点识别 → 指纹/截图/爬虫 → WIH → vhost → NPoC/弱口令 → fileLeak → nuclei → 统计推送），每阶段 safe_phase 容错 + 心跳。
- **资产数据**：task 维度 13 张结果集合（site/domain/ip/cert/service/url/fileleak/vuln/npoc_service/cip/stat_finger/nuclei_result/wih）+ 任务结束后分块同步进 asset_* 资产库（scope_id 判重、字段级 diff）。
- **资产组**：集团（asset_group）→ 资产范围（asset_scope）→ 绑定企业；ICP 自动建组 CAS 领取。
- **指纹/插件**：8894 条 webapp 指纹 + Aho-Corasick 预筛；109 个 Python 插件（PoC/未授权/弱口令/嗅探/回连）；nuclei CLI（模板同步/黑名单/自建模板工作台）。
- **威胁情报三雷达**：CVE-{年} 仓库雷达、安全工具 Release 监控、研究员新仓库监控；GitHub 泄露监控 + 历史去重推送。
- **PyInfoHunter**：纯 Python 敏感信息引擎，Webpack/Vite/Next chunk 四级瀑布展开。
- **工程亮点**：safe_insert upsert 三件套防重、假 404 双防线（双探针 + SimHash + 特赦）、catch-all 默认后端聚类、队列并发热扩缩容 + 容量探测、OOM score 分级、僵尸任务双确认收敛、6 通道告警、备份恢复、在线更新流。
- **MCP**：单工具 `get_asset_profile`（stdio JSON-RPC，四段并行聚合单标的画像）+ 可导出单文件客户端。

## 2. 差距矩阵（4zreark 视角）

### 2.1 4zreark 已覆盖（多数更强）

| 能力 | ARL-Next2 | 4zreark |
| --- | --- | --- |
| 任务队列 | Celery/RabbitMQ，进程内存风险 | River/PG 持久化 + 僵尸回收 + 并发预算 |
| 子域名/接管/端口/指纹/爬虫/目录/敏感信息 | 全 | 全（自研被动面 + 托管工具链） |
| 指纹库规模 | 8894 条 webapp.json | 8100+ 编译生效（dddd 快照 + 种子 + 三上游 24h 同步） |
| 企业测绘 | 天眼查 + 工信部直连爬虫 | 五源 Provider（aqc/tyc/kuaicha/fengniao/小蓝本含无头浏览器签名）+ ICP 备案 |
| GitHub 泄露监控 | 关键字规则 + 去重 | gitleaks 规则 + token 池 + 限速三方共享 |
| 威胁情报源 | CVE/工具/研究员三雷达（GitHub 侧） | 9 公开源 + CISA KEV |
| 软 404 对抗 | 双探针 + SimHash | 随机路径基线 + UniformSoft404 整站判定 |
| MCP | 单工具画像 | 多域 20+ 工具 + API key 治理/限流/开关 |
| 告警通道 | 6 通道 | 6 通道 + 5 级门槛 + 脱敏 + 定向 |
| 分布式 | Celery worker | WebSocket 节点 + TLS 网关 + 二进制热更 |

### 2.2 ARL-Next2 有、4zreark 缺（本轮处理情况）

| # | 差距 | 处理 |
| --- | --- | --- |
| 1 | **全局禁扫黑名单**（security_policy：IP 段 + 域名后缀，默认护 gov.cn） | ✅ 已实施（§3.1） |
| 2 | **Nuclei 模板误报黑名单**（template-id 级持久化排除 + UI 管理） | ✅ 已实施（§3.2） |
| 3 | **GitHub CVE 仓库雷达**（CVE-{年} 新仓库监听 → 情报库） | ✅ 已实施（§3.3） |
| 4 | **资产详情缺漏洞维度**（ARL 画像 13 维含 vuln/nuclei） | ✅ 已实施（§3.4） |
| 5 | **collection 模块配置未接线**（对应 ARL 的策略/插件可选体系；本项目 config 的 default/exclude_modules 是死配置） | ✅ 已接线（§3.5） |
| 6 | **文件泄露 fileLeak**（.git/.svn/.env/备份 + 魔数校验 + 1337 扰动 + 相似度） | ✅ 已实施（§4.1；2026-11-10 补 scan_types/UI 接线） |
| 7 | **vhost 发现**（同 IP 多域名绑定探测；本项目只有反向去噪） | ✅ 已实施（§4.2；2026-11-10 补 scan_types/UI/scope 接线） |
| 8 | 安全工具 Release 雷达 / 研究员仓库雷达 | ⏳ 规划（§4.3） |
| 9 | CVE→自有资产自动匹配引擎（情报×指纹命中生成候选） | ⏳ 规划（§4.4，4zreark 数据底子更好：fingerprint_hits + vuln_intel 都在 PG） |
| 10 | nuclei 社区模板版本 diff | ⏳ 规划（现有 sync 无 diff 展示） |
| 11 | 任务结果服务端 Excel/CSV 导出（本项目前端有客户端 CSV） | ⏳ 规划 |
| 12 | 队列并发热扩缩容 + 容量探测推荐 | ⏳ 暂缓（本项目并发走 config + 预算器，形态不同） |

### 2.3 接线审计（「功能是否未接线」专项）

后端启动入口、River 7 种 JobKind（worker↔入队双向）、Sidebar 全部菜单路由、12 个流水线模块映射均核查通过。修复与清理如下：

**真实断链（已修）**
- `collection.default_modules / exclude_modules`：config 定义了但零消费，README 宣称的「漏洞扫描默认关闭靠 exclude 控制」实际是硬编码。→ 已接入 `CollectionModuleSet`（service/pipeline/module_set.go）。
- 孤岛页 `/takeover`：页面在、无菜单入口，且 `getProviders`/`getHistory` 调不存在的端点。→ 指纹库改接真实端点 `GET /scan/takeover/fingerprints`，删除无数据来源的「历史记录」页签，API 类型与后端 json tag 重新对齐，菜单「侦察任务 → 接管检测」补入口。
- `/api/queue` 三个内置 handler（port_scan/vuln_scan/subdomain_enum）是返回假结果的演示代码。→ 删除 stub 与入队端点（`HasHandler` 校验会拒绝一切入队，避免任务静默空转进死信）；作业查询/死信等真实端点保留，队列页不受影响。

**内存桩域（已下线）**
- `service/monitor` + `api/monitor_handler.go` + `/api/monitor/*` 全域 + 前端 MonitorPage：页面监控无 Start 循环（从不检查）、变化记录存 handler 内存（重启即失）、前后端类型/分页协议不匹配（单 type vs 数组、秒 vs 分钟、数组 vs {list,total}）。真实能力由已接线的 `site_watch_service`（站点巡检）+ 变更时间线 `/events` 承担。整域删除。

**死代码（已删）**
- 后端：`PipelineManager`（被 StreamingPipeline 取代的旧编排器，删类型与测试，保留 BaseModule/DuplicateChecker 等共享件）；`IntelHandler.GetIntel` + `IntelService.GetIntel` + 前端 `intelApi.get`；`CompatHandler.RecentAssets`；`VulnHandler.GetVulnsByTask`/`TogglePOC` + `VulnService.TogglePOC`；config 死字段 `sentinel.enable_audit_queue`/`queue_poll_seconds`、`collection.min_online_nodes/max_fail_rate/stage_timeout_minutes`。
- 前端：指向不存在端点的 `testPOC`/`exportVulnerabilities`/`enqueueTask`/`getTaskResult` 及死常量 `VULN_STATUSES`。

**审计误报澄清（未改，留档）**
- `POST /tools/browser/update`：`toolsGroup.POST("/:name/update")` 参数路由已覆盖 browser，且 handler 内有 browser 分支走 `UpdateBrowser`——已接线。
- `node.tags/capabilities`：被 node_runtime/remote_agent 节点注册上报消费——已接线。
- 前端 `updatePlugin`/`getUser`/`artifactDownloadURL`/vuln 与 poc 的 CRUD 系列指向的端点全部真实存在，仅当前无页面调用——保留（合理的 API 面）。
- `sentinel_repro/sentinel_poc_verify` 双 kind 哑 worker：真消费方是独立进程 `cmd/pocsmith`，代码注释已说明，属部署形态设计。

**存量问题（非本轮引入，已顺手修复）**
- `scanner/webscan/katana_args_test.go` 编译失败（`commonArgs` 双参数 vs 单参调用）——HEAD 上即坏，已补参修复。
- `service.TestProbeFallsBackToMobileUA` 失败——经 git worktree 在干净 HEAD 上复现，属存量问题，本轮不处理。

## 3. 本轮已实施项

### 3.1 全局禁扫黑名单
- `config/config.go`：`ScannerConfig` 新增 `deny_domain_suffixes`（默认 `["gov.cn"]`，显式 `[]` 可关）与 `deny_cidrs`；`NormalizeScanner` 在 LoadConfig/LoadConfigRaw 双入口挂接；config.yaml 带注释示例。
- `scanner/scope/denylist.go`（新）：`DenyList`（后缀匹配 + 网段含 `DeniesPrefix` 覆盖判定）；`Scope.New` 自动携带全局黑名单，`NewWithDeny` 支持显式注入；`AllowsHost` 黑名单优先于授权判定（含空 scope 场景）——所有流水线模块经 scope 收口自动继承。
- `service/task_service.go`：`CreateTask` 增加创建期校验（`deniedTargets`，含 CIDR 整体覆盖判定），命中直接拒绝并回显目标。
- API：`GET /api/scanner/denylist`（只读展示）；前端设置页新增「扫描安全」页签展示生效值。
- 设计取舍：黑名单只走 config 而非 KV 设置——worker 不连数据库，master/worker 必须读同一份配置才能保证两端判定一致。

### 3.2 Nuclei 误报黑名单
- 双层存储：`app_settings` 的 `nuclei.deny_template_ids`（KV，可运行时改）∪ `config` 的 `scanner.nuclei_deny_template_ids`（兜底），取并集去重（`service/nuclei_denylist.go`）。
- 生效链路全覆盖：任务流水线（master 创建时盖章进 `task.Config.deny_template_ids` → worker 消费）、手动扫描 API（scan_service / nuclei_handler）、自动验证（vulnverify 召回侧过滤）。
- 执行层：`scanner/vulnscan` 与 `internal/nucleiruntime` 的命令构造统一追加 `-eid`。
- API：`GET/PUT /api/nuclei/denylist`；设置页「扫描安全」页签可增删（逗号/空格/换行批量粘贴），admin/operator 可写。

### 3.3 GitHub CVE 雷达（情报第 10 源）
- `internal/recon/vulnmonitor/grab/githubcve.go`（新）：搜 GitHub 当日新建的 `CVE-{当年}` 相关仓库（每轮 1 次搜索，按 CVE 聚合仓库列表与 star），`unique_key=CVE号` 由 Store upsert 天然去重；严重级别记「中危」（仓库情报无评级，不拔高），支持注入 token 解析器。
- `vulnmonitor.WithExtraSources` 新选项；`intel_service.build` 注入本服务已有的 GitHub 凭据链（环境变量 → sources 表 → token 池）。无新配置项，跟随 vulnintel.enabled 开关。

### 3.4 资产详情补漏洞维度（对齐 ARL 13 维画像）
- `repo.GetAssetDetail` 新增 `vulns` 摘要（等级排序、不含 request/response 长文本）。漏洞表 `asset_id` 列从未被摄取链路写入，改按 `target` 的 host 词边界正则匹配（`evil-a.com` 不会误吞 `a.com`）。
- 自动惠及：MCP `get_asset` 工具（描述同步更新）与前端资产详情（抽屉新增「漏洞」页签、全页详情新增「命中漏洞」区块），等级配色复用 StatusTag 口径。

### 3.5 验证结果
- `go build ./...` 通过；`go test ./...` 除存量失败 `TestProbeFallsBackToMobileUA`（HEAD 已坏）外全部通过；新增 `scanner/scope` 黑名单单测（含 host:port、CIDR 覆盖、黑名单优先于授权范围）全过。
- 前端 `tsc --noEmit` 与 `vite build` 通过。
- 设计规范：沿用 4zreark 现有 token（`index.css` HSL 变量 / statusTagClass / SectionCard / Card+Tag 组合），未引入新色值与硬编码样式。

## 4. 第二轮实施记录（规划项全部落地）

1. **fileLeak 模块**（`scanner/webscan/fileleak.go` + `service/pipeline/fileleak_module.go`）：24 条固定路径探测（.git/.svn/.env/.DS_Store/.idea/备份压缩包/SQL 导出/swagger/actuator/heapdump/metrics/druid），三道闸判定——路径命中 + 内容强特征（zip/gzip/7z/rar 魔数、SQLite 头、`[core]`、`KEY=` 格式、heapdump 魔数等）+ 每 origin 随机路径软 404 基线。请求预算固定（每站点 ≈26 次），链位置在敏感信息同层，分阶段编排进 Enrich 阶段；结果落 `scan_results(type=fileleak)`，任务详情页新增「文件泄露」页签（规则/证据/级别列）。单测覆盖 git 命中、zip 魔数、统一响应页零误报、.env 格式要求。
2. **CVE→资产匹配引擎**（`service/intel_asset_match.go` + `repo/assets_repo.go ListSitesForRules`）：复用 componentprofile 的 CVE 边挖掘（PoC 库模板 × 指纹规则名 token 归一求交），把 `vuln_intel` 最近 7 天带 CVE 的情报与 `fingerprint_hits` 命中站点求交；命中写资产事件（`asset_events(event_type=intel_match)`，进变更时间线）+ 汇总通知；已处理台账存 app_settings（cap 2000 防膨胀）。触发点：每轮情报轮询落库后异步执行 + 手动 API `POST /vuln-intel/match-assets`（情报页新增「资产匹配」按钮）。刻意不自动建漏洞记录——「指纹相似」不等于「漏洞存在」。
3. **威胁雷达扩展**（`grab/githubradar.go`）：工具 Release 雷达（监听配置的 owner/repo 最近 24h Release，unique_key=repo@tag）+ 研究员仓库雷达（监听 GitHub 用户新建仓库）。目标列表走情报设置（`vulnintel.threat_tools_targets/threat_hackers_targets`，逗号分隔，保存即重建轮询器）；情报页新增「设置」弹窗（轮询开关/间隔/通知/两路雷达目标）。
4. **vhost 发现**（`service/pipeline/vhost_module.go`）：链位置在端口扫描与指纹之间，透传流量同时收集 PortAlive 目标与候选域名；输入关闭后对每个 web 端口（80/443/8080/8443）先打无效 Host 基线，再用候选域名改 Host 头探测，响应不同形记为绑定。预算封顶（单任务 300 次探测、单目标 100 候选、并发 4）。产物落 `scan_results(type=vhost)` 结果页供人工确认——弱证据不自动建站点，走指纹/爬虫正式链路才进资产域。与 vhostdedup（剔假站）方向互补。scan_types 名 `vhost`/`findvhost`，默认关闭、显式开启。
5. **nuclei 模板版本 diff**（`internal/nucleiruntime/templates_sync.go`）：`nuclei -update-templates` 前后各走一遍目录快照，diff 出新增/移除条目数，从输出解析上游版本，存 `nuclei.templates_sync` 设置；`Status` 与 `UpdateResult` 透出，工具运行时面板 nuclei 行显示「上游 x.y.z · 快照 N · 上次同步 +a/-r」。
6. **服务端 CSV 导出**：`GET /api/assets/export` 与 `GET /api/vulnerabilities/export`（分页遍历、上限 10 万行、`= + - @` 开头单元格统一防公式注入）；资产页新增「导出全部」、漏洞页新增「导出 CSV」按钮（blob 下载，带当前筛选参数）。

## 5. 附：改动文件清单

后端：`config/config.go`、`config/config.yaml`、`scanner/scope/{denylist.go,denylist_test.go,scope.go}`、`scanner/vulnscan/nuclei_cli.go`、`internal/nucleiruntime/run.go`、`internal/vulnverify/{config.go,execute.go}`、`internal/recon/vulnmonitor/{monitor.go,grab/githubcve.go}`、`service/{nuclei_denylist.go,task_service.go,intel_service.go,vuln_verify_service.go,scan_service.go,task_executor.go,vuln_service.go}`、`service/pipeline/{module_set.go,streaming_pipeline.go,vuln_module.go,manager.go}`、`repo/assets_detail.go`、`service/mcp_tools_assets.go`、`api/{scanner_denylist_handler.go,nuclei_handler.go,intel_handler.go,compat_handler.go,vuln_handler.go,queue_handler.go}`、`router/router.go`、删除 `service/monitor/`、`api/monitor_handler.go`。

前端：`src/api/{assets.ts,takeover.ts,queue.ts,intel.ts,auth.ts,notify.ts,dashboard.ts,vulnerabilities.ts,scanner.ts(新),results.ts,index.ts}`、`src/pages/assets/components/AssetDetailDrawer.tsx`、`src/pages/assets/{AssetsPage.tsx,AssetDetailPage.tsx}`、`src/pages/takeover/TakeoverPage.tsx`、`src/components/settings/ScanSafetyPanel.tsx(新)`、`src/pages/settings/SettingsPage.tsx`、`src/components/layout/Sidebar.tsx`、`src/pages/intel/IntelPage.tsx`、`src/pages/tools/ToolUpdatePanel.tsx`、`src/pages/vulnerabilities/VulnerabilitiesPage.tsx`、`src/pages/tasks/{taskMeta.ts,TaskDetailPage.tsx,components/results/{FileLeakResultsTable.tsx(新),VhostResultsTable.tsx(新),index.ts}}`、`src/App.tsx`、删除 `src/pages/monitor/`、`src/api/monitor.ts`。

第二轮新增：`scanner/webscan/{fileleak.go,fileleak_test.go}`、`service/pipeline/{fileleak_module.go,vhost_module.go}`、`service/intel_asset_match.go`、`internal/recon/vulnmonitor/grab/githubradar.go`、`internal/nucleiruntime/templates_sync.go`、`repo/assets_repo.go`（ListSitesForRules）、`config/config.{go,yaml}`（fileleak 默认模块）。

## 6. 2026-11-10 后续审计修复

本轮按代码级复核补齐“文档已写、实际未接线/已回退”的项：

- vhost：`ModuleSetFromScanTypes` 增加 `vhost/findvhost`，旧 `buildCustomConfig` 同步；前端创建页新增「虚拟主机」；`VhostModule.SetScope` 接入全局黑名单，流水线构造时注入。
- fileLeak：`ModuleSetFromScanTypes` 增加 `file_leak/fileleak`，旧 `buildCustomConfig` 同步；前端创建页新增「文件泄露」，默认不勾选。
- JSAudit：不再从预设移除。执行器按 `custom-templates/keys` → `templates/file/keys` → `templates/keys` 回退；本机 `templates/file/keys` 已有 156 条官方 keys 规则。`CollectionModuleSet.JSAudit` 恢复 true，config 默认模块保留 `js_audit`。
- config：删除零消费的 `min_online_nodes/max_fail_rate/stage_timeout_minutes`；`exclude_modules` 移除无对应模块名的 `bruteforce`。
- 自动验证：`vuln_verify_service` 的 DenyTemplateIDs 改为 `ResolveNucleiDenyTemplateIDs`（KV ∪ config），设置页运行时增删生效。
- 资产详情：`siteVulns` 通过 `vulnerabilities.task_id` 关联 `tasks.project_id` 做项目隔离，避免跨项目同 host 漏洞串入。
- 情报资产匹配：`runIntelAssetMatch` 移出 `NotifyEnabled` 分支，通知开关只控制消息，不影响匹配。
- 队列：删除零调用的 `RegisterHandler/HasHandler` 与三个演示 handler 元数据；`/api/queue/types` 只返回真实注册类型。
- 手动扫描：`DeniedTargets` 复用到 nuclei 手动扫描、`ScanService.NucleiScan`、takeover 单目标/批量入口。
- 文案：前端工具运行时改为 5 个受管工具，删除 naabu；README 删除 `sentinel.enable_audit_queue` 描述；tools/README 删除 naabu UA 例外。
- GitHub 泄露：`github_leak_findings` 增加 `project_id`，扫描候选携带规则所属项目；项目面板按 `project_id` 查询，项目处置接口只允许改本项目命中；唯一键改为 `(project_id, repository, path, blob_sha, keyword, secret_type, line_number, fingerprint)`，同一仓库/密钥被多个项目规则命中时各自保留。迁移见 `docs/sql/migration_github_leak_project.sql`，存量按 `项目名: 规则名` 前缀回填。

仍保留的边界：漏洞扫描/自动验证/弱口令/PoC/gogo POC 默认关闭；naabu 已移除，端口统一 gogo。
