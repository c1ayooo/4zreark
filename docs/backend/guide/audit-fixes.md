# 审计修复记录：从「启动成功」到「真能出数」

这份文档记录一次完整的代码审计 + 链路验证 + 修复过程。目标只有一个：
**输入一个公司名，能稳定拿到备案域名、站点、技术栈、指纹与接口，并且失败时看得见。**

它不是变更日志，而是「为什么这么改」的说明——尤其是那些看起来多余、
其实是在堵静默失效的改动。

## 1. 结论先行

| 维度 | 修复前 | 修复后 |
|------|--------|--------|
| 全新库建库 | 按 `ls` 顺序执行会在 `schema_governance.sql` 整段回滚，缺 20+ 表 | `apply_all.sh` 按 core→migration→backfill 顺序 + 依赖重试，76 张表一次建好 |
| 启动自检 | 只校验 8 张基础表，缺表也能正常监听端口 | 校验 24 张核心表，缺表直接以退出码 2 失败并列出缺哪些 |
| 公司名 → 域名 | ICP 结果只落 `icp_filings`，没有任何下游消费 | 查询完成自动回灌 `seeds` + `monitoring_plans`，幂等 |
| 回灌 → 扫描任务 | 不生成任务，需要手工建 | 回灌后触发 onboard，自动建 4 类任务 |
| 代理环境出网 | 配了代理后所有请求报「SSRF 拒绝」 | 代理出口按 `ip:port` 豁免，真实目标另做校验 |
| 扫描结果落库 | `sites`/`site_endpoints` schema 漂移，写入全失败但任务显示 completed | 补 2 个迁移，落库失败写 `task_logs(ingest,error)` |
| 指纹命中 | `fingerprint_hits` 只有读方，三处统计恒为 0 | 入库事务内写命中事实行 |
| 安全 H-1 | `100.64.0.0/10` 未封，元数据 100.100.100.200 可访问 | CGNAT 段纳入禁止集合 |
| 安全 H-2 | 改用户 role 无白名单，可自提权 | 仅 admin 可改，且角色必须在 `roles` 表内 |

实测（本项目环境，5 个备案域名）：`sites=5`、`site_endpoints=11`、
`raw_records=20`、`fingerprint_hits=4`、技术栈命中 `Nginx`/`OpenResty`/`Next.js`。

## 2. 修复清单

### 2.1 P0：链路断点

**① 建库脚本顺序不可靠**

`schema_governance.sql` 里第一条语句就 `ALTER TABLE projects`，而 `projects` 由
`migration_assets_p0.sql` 建。按文件名/`ls` 顺序执行时它先跑，整段事务回滚，
`seeds`、`runs`、`monitoring_plans` 等表全缺——但服务照样起来了，直到用户点
「建项目」才报 `relation "seeds" does not exist`。

- 新增 `docs/sql/apply_all.sh`：显式 core → migration → backfill，`ON_ERROR_STOP=1`，
  无 `BEGIN` 的文件用 `--single-transaction` 包一层，依赖未就绪的脚本自动延后重试。
- `schema_governance.sql` 头部加依赖守卫，缺 `projects` 直接给出可读报错而不是语法错误。
- `repo.requiredTables` 从 8 张扩到 24 张，启动即失败。

**② ICP 备案没有下游**

`icp_filings` 此前零引用：查完就躺在表里。改动：

- `migration_icp_promote.sql`：`icp_queries` 加 `promoted_count` / `promote_interval_hours` / `auto_promote`。
- `repo.PromoteICPFilings`：一个事务里写 `seeds` + `monitoring_plans`，幂等靠
  `seeds(project_id, kind, value)` 与 `monitoring_plans(seed_id)` 唯一键。
- `service.ICPService.Enqueue(..., autoPromote, intervalHours)`：查询完成后按需自动回灌，
  回灌后调 onboard 生成扫描任务。
- 新增 `POST /api/icp/queries/:id/promote` 支持手动补跑。

**③ 回灌后不建任务**

`onboard_service.go` 里已有 `createOnboardFollowupTasks`，只是没人调用。回灌完成后
直接复用它，避免再写一套任务模板。

**④ 中文域名把整批任务拖挂**

备案里有 `mi.中国` 这类 IDN，`IsPlausibleDomainTarget` 判定非法，`CreateTask` 整体
失败，4 个任务一个都没建。

- 回灌时 `idna` 转 punycode（`mi.中国` → `xn--fiq...`）；
- 建任务前逐个过滤非法目标，跳过数量打进日志，**个别坏目标不能拖垮整批**。

**⑤ 代理 = 全网失败**

`safehttp` 的 `Dialer.Control` 在走代理时看到的是代理地址（`127.0.0.1:43433`），
loopback 直接命中 SSRF 禁止集合，于是被动子域源、爬虫、指纹全部失败。

修复分两层：

- 连接层：`proxyAwareControlFor` 按 `ip:port` 精确匹配放行代理出口（不是放行整个 IP，
  否则该 IP 上任何端口都成了后门）；
- 请求层：对**真实目标**做 `CheckHost`，解析结果落受限网段仍拒绝。

`outbound.HTTPClient` 同步改成代理感知策略，避免只有显式拨号器才受保护。

**⑥ 扫描结果写不进库**

`sites` 缺 `body_hash`/`cert_org`/`cookie_names`/`js_frameworks`/`api_hosts` 五列；
`site_endpoints` 是旧结构（缺 `last_seen_at`、缺 `(site_id,scheme,port)` 唯一键，
还留着废弃的 `project_id`）。代码每写必失败，`Ingest` 错误只进 stderr，任务仍记
`completed`。

- `migration_sites_enrich_columns.sql`、`migration_site_endpoints_reconcile.sql` 对齐结构；
- `Ingest` 失败写 `task_logs(category=ingest, level=error)`，界面上能看见。

**⑦ 指纹命中表没有写方**

`fingerprint_hits` 只有读方（资产表指纹数、看板 24h 命中、按指纹筛资产），全库
没有一个 `INSERT`，三处数字恒为 0。识别结果只以名字留在 `sites.tech`。

`ImportRecords` 在站点 upsert 之后、入口写入之前补一条：

```sql
insert into fingerprint_hits (site_id, rule_id, observed_at, record_id, evidence)
select $1, fr.id, now(), $2, jsonb_build_object('host',$3,'port',$4,'source',$5)
  from fingerprint_rules fr where fr.name = any($6::text[])
on conflict (site_id, rule_id) do update set observed_at = now(), ...
```

规则名 → `rule_id` 走 `fingerprint_rules.name`（有唯一索引）。**库里没有的规则名直接
跳过**——宁可少记，也不给命中结果伪造一个规则 ID。

### 2.2 安全

| 编号 | 位置 | 问题 | 修法 |
|------|------|------|------|
| H-1 | `internal/safehttp/safehttp.go` | `100.64.0.0/10` 不在 `IsPrivate`，云元数据 `100.100.100.200` 在 `ModeScan` 放行 | `Forbidden` 显式封 CGNAT；`MetadataTargetGuard` 之外再加连接级兜底 |
| H-2 | `api/user_handler.go` | `role` 无白名单，配合中间件对 admin 硬放行可自提权 | 仅 admin 可改角色，目标角色必须存在于 `roles` |

H-1 的既有单测曾把 `100.64.0.1` 标为「放行」，等于把漏洞固化成了期望值——这次一并
改成拒绝，并补了代理豁免的反向断言。

### 2.3 数据完整性

`monitoring_plans` 没有指向 `seeds` 的外键，删种子后计划变成孤儿继续跑。
`migration_monitoring_plans_fk.sql` 加 `UNIQUE(seed_id)` + `ON DELETE CASCADE`。

### 2.4 指纹命中链路的静默丢数

`fingerprint_hits` 长期为 0、任务日志却写着命中若干条，根因不是「没写入」，而是
**两个写入方互相判定对方的结果已消失**。

| 写入方 | 触发点 | 规则来源 | 写什么 |
|--------|--------|----------|--------|
| 扫描器引擎 | `AssetRepo.ImportRecords` | 原生引擎（dddd 快照 + 种子，按名称） | `evidence.source` = 采集来源（`scan`/`manual`） |
| 探测复核 | `FingerprintService.ApplyToSite` | 数据库 DSL 规则（按 rule_id） | 追加 `evidence.source = dsl_probe` |

`ApplyToSite` 写完自己的命中后会调 `PruneHits` 做「指纹消失」老化。旧实现的 SQL 是：

```sql
delete from fingerprint_hits
 where site_id = $1 and ($2::char(24)[] is null or rule_id <> all($2::char(24)[]))
```

两个致命点：

1. **作用域是整个站点**。凡是本轮没命中的行一律删除，包括扫描器引擎按名称写的那批。
   两套规则宇宙不同（原生引擎能命中的 `OpenResty-product`，DSL 匹配器未必复现），
   于是探活复核一跑，扫描阶段的命中就被清空。
2. **`keep` 为 nil 时 SQL 变成 NULL 而不是「全删」**。pgx 把 nil 切片编成 SQL NULL，
   `rule_id <> all(NULL)` 求值为 NULL，整条 DELETE 变 0 行——「一条都没命中」这个最该
   清理的场景反而不清理，行为完全不可预期。

修法（`repo/fingerprint_repo.go` + `service/fingerprint_service.go`）：

- `Match` 额外返回 `universe`（本轮真正参与判定的规则 ID 全集）；
- `PruneHits(siteID, keep, universe)` 三重限定：`rule_id ∈ universe` **且** `rule_id ∉ keep`
  **且** `evidence->>'source' = 'dsl_probe'`——只清理自己写过、且本轮确实评估过的行；
- `universe` 为空（规则库没加载出来）时一条都不删；`keep` 的 nil 统一成空数组。

配套可观测性（此前「静默 0 行」查不出原因就卡在这里）：

- `ImportResult` 新增 `fingerprint_hits` / `unmatched_rules`，每批导入打一行
  `[assets] 指纹命中入库: 命中 N 行，未收录规则名 M 个`；
- 任务日志摘要变成 `扫描结果并入资产: 记录 N，新站点 N，新入口 N，指纹命中 N 行（覆盖 N 条记录，未收录规则名 N 个）`；
- 导入接口返回文案带上命中数与未收录数，界面不再只显示「导入 N 条」；
- `ImportUpstream` 清理失效规则前先数出会被级联删除的命中行，并打
  `[FpSync] 清理失效规则: 删除规则 N 条，连带删除历史命中 M 行`；
- 规则集合异常收缩（>20% 且基数 ≥50）时**跳过**失效清理并告警——上游抓取被截断时
  按差集删下去等于把规则库和命中历史一起推平。

## 3. 验证方式

```bash
# 1) 空库一次建好
createdb zreark_fresh
PGURL='postgres://user:pass@127.0.0.1:5432/zreark_fresh?sslmode=disable' \
  bash docs/sql/apply_all.sh
# 断言：sites 5 个补齐列、site_endpoints 有 last_seen_at 无 project_id、
#       monitoring_plans 有外键、seeds 有唯一索引、public 下 76 张表

# 2) 公司名 → 域名
curl -X POST /api/icp/queries -d '{"project_id":1,"query":"小米科技有限责任公司",
  "service_type":1,"page_size":100,"auto_promote":true,"promote_interval_hours":24}'
# 断言：status=done，fetched=77，promoted_count=77；再跑一次 promoted_count=0（幂等）

# 3) 回灌 → 任务
# 断言：seeds=77（含 2 条 xn--），monitoring_plans=77，tasks 自动新增 4 条

# 4) 扫描 → 落库
# 断言：sites/site_endpoints/raw_records 全部 >0，task_logs 无 ingest,error
```

本次实测数据：ICP `total=92 / fetched=77`；回灌 77 域名 → 77 种子 → 77 计划 →
4 任务；5 目标指纹任务产出 `sites=5 / endpoints=11 / raw=20 / fp_hits=4`。

命中链路的端到端复测（空库 `zreark_v6`，含 banner 与 prune 修复的构建）：

```
# 1) 指纹任务：1 目标 mi.cn
[assets] 指纹命中入库: 命中 1 行，未收录规则名 0 个（source=scan project=1）
sites: 1|mi.cn|["Nginx"]        fingerprint_hits: 1 → Nginx

# 2) 修复前：任务说命中 3 行，探活复核后库里 0 行（丢数）
# 3) 修复后：同一站点再探活，扫描侧命中保留
[probe] {"message":"探测完成：reachable","status_code":200}
fingerprint_hits: 5|OpenResty-product|source=scan   ← 未被清理
```

## 4. 遗留项与处理状态

| # | 项 | 状态 | 落地位置 |
|---|----|------|----------|
| 1 | 内置指纹种子不落库 | 已修 | `FingerprintSyncService.SyncSeedRules`；启动日志 `内置指纹种子已落库: 规则 276 条` |
| 2 | 上游多候选错误只报最后一个 | 已修 | `fingerprint_upstream_service.go` / `internal/recon/fingerprint/sync.go` 改错误聚合 |
| 3 | banner-only 规则永不命中 | 已修 | `fingerprint.HTTPBanner`（状态行 + 响应头，8KB 截断），扫描与原生引擎都填 `Observation.Banner` |
| 4 | 指纹误报去噪 | 已修 | 敏感抽取器规则打 `Source=sensitive` 并在写技术栈前跳过；启动清洗把历史脏词从 `sites.tech` 剥离 |
| 5 | 测试门禁 | 已修 | `.github/workflows/ci.yml`：`build` + `vet` + `test -count=1`；本地 `go test ./...` 全绿 |
| 6 | 巨型函数拆分 | **未做**（转入待修清单） | 见 [`pending-fixes.md`](./pending-fixes.md) P1-1 / P1-2 |
| 7 | 命中表静默丢数 | 已修 | 见 2.4；回归用例 `test/fingerprint_hit_prune_scope_test.go` |

第 6 项之所以暂不动：这两处都是「大量闭包 + 路由表」结构，搬代码很容易把参数顺序、
中间件顺序改错，而这类错误 `go build` 查不出来。本次先把验证前置条件补齐——新增
`router/routes_snapshot_test.go`：把 `engine.Routes()` 导成 `方法\t路径\t处理器名`
快照，改前存基线、改后逐条比对，任何一条路由增删改都会失败并打印差异。

> 现状核对（2026-11-04）：原记录的「`processTask` 744 行」已过时，该函数当前为 325 行；
> 真正的巨石是 `executeStreamingPipeline`（752 行）与 `setupRouter`（764 行）。
> `setupRouter` 已有快照保护，可随时拆；`executeStreamingPipeline` 仍需先补契约快照。

```bash
# 生成/比对路由基线（420 条）
CONFIG_PATH=/etc/4zreark/config.yaml ZRE_ROUTE_SNAPSHOT=/tmp/routes.tsv \
  go test ./router -run TestRouteSnapshot -v
```

有了这层保护，下次拆 `router.Register` 只需按分组把路由表搬进
`registerAssetRoutes` / `registerTaskRoutes` / … 再跑一次快照即可。`processTask` 的
拆分仍建议单独排期：它没有等价的契约快照，需要先补一条「同输入同产出」的回归测试。

## 5. 部署顺序

迁移必须按下面顺序应用（`apply_all.sh` 已内置，手工执行时注意）：

```
schema_init.sql
→ migration_assets_p0.sql
→ schema_governance.sql
→ migration_monitoring_plans_fk.sql
→ migration_sites_enrich_columns.sql
→ migration_site_endpoints_reconcile.sql
→ migration_icp_promote.sql
```

`migration_sites_enrich_columns` 与 `migration_site_endpoints_reconcile` 是**幂等**的，
重复执行安全；`monitoring_plans` 外键在存量孤儿数据上会失败，脚本里先清理再建约束。
